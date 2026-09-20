/*
 * AWS ENA (Elastic Network Adapter) device model.
 *
 * Written against Amazon's own permissively-licensed sources: FreeBSD
 * sys/contrib/ena-com/ (BSD-3-Clause) for the register map, the admin ABI and
 * the descriptor layouts, and sys/dev/ena/ (BSD-2-Clause) for the order a
 * driver does things in. The ABI headers under ena_defs/ are those files
 * verbatim, not a transcription -- see the note there for why that matters.
 *
 * Scope is what a driver needs to bring a port up and move packets: the
 * register file including readless reads, the reset handshake, the admin and
 * async-event queues, seven admin opcodes, and host-memory placement for one
 * or more queue pairs. Not implemented: LLQ (Tx descriptors in device
 * memory), RSS, TSO, checksum offload, PHC.
 *
 * Copyright (c) 2026 Contributors as noted in the AUTHORS file
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/msix.h"
#include "hw/pci/pcie.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "system/memory.h"
#include "net/net.h"
#include "system/dma.h"

/*
 * The vendored headers spell their bitfields with the kernel's GENMASK. BIT()
 * QEMU already has; GENMASK it calls something else.
 */
#ifndef GENMASK
#define GENMASK(h, l) MAKE_64BIT_MASK(l, (h) - (l) + 1)
#endif

#include "ena_defs/ena_includes.h"

#define TYPE_ENA "ena"
OBJECT_DECLARE_SIMPLE_TYPE(EnaState, ENA)

#define PCI_VENDOR_ID_AMAZON        0x1d0f
#define PCI_DEV_ID_ENA_VF           0xec20

/*
 * BAR0 holds the register file and, well above it, the doorbells. Their
 * offsets are not architectural: the device chooses them and hands each one
 * back in the completion of the command that created the queue, so the three
 * ranges only have to be disjoint from each other and from the registers.
 * Getting that wrong is how a gVNIC interrupt acknowledgement ended up in a
 * transmit doorbell, so the layout is stated once, here.
 */
#define ENA_REG_BAR                 0
/*
 * Real ENA puts the MSI-X table either in BAR0 beside the registers or in
 * BAR1 -- FreeBSD's driver says exactly that where it looks the table up --
 * so BAR1 it is. The register BAR is therefore 32-bit, leaving BAR1 free,
 * and BAR2 stays clear for the LLQ window a later model will want.
 */
#define ENA_MSIX_BAR                1
#define ENA_REG_BAR_SIZE            0x2000
#define ENA_SQ_DB_BASE              0x1000
#define ENA_CQ_DB_BASE              0x1400
#define ENA_CQ_UNMASK_BASE          0x1800
#define ENA_CQ_NUMA_BASE            0x1c00

/*
 * The LLQ window. A transmit queue in device-memory placement has its
 * descriptor ring here rather than in guest RAM: the guest writes whole
 * entries across the bus and the device reads them back out of this BAR,
 * which is why it is plain RAM rather than an io region -- there is nothing
 * to do on the write, and the doorbell is what says an entry is ready.
 */
#define ENA_MEM_BAR                 2
#define ENA_LLQ_QUEUE_SIZE          (256 * KiB)     /* 1024 * 256B entries */
#define ENA_LLQ_BAR_SIZE            (ENA_LLQ_QUEUE_SIZE * ENA_MAX_QUEUES)
#define ENA_LLQ_MAX_DEPTH           1024
#define ENA_TX_DESC_SIZE            ((uint32_t)sizeof(struct ena_eth_io_tx_desc))

#define ENA_MAX_QUEUES              8
#define ENA_MSIX_VECTORS            8
#define ENA_ADMIN_ENTRY_SIZE        64
#define ENA_MAX_FRAME               (16 * KiB)
#define ENA_MAX_MTU                 9216
#define ENA_DMA_ADDR_BITS           48

/* The controller version the HAL refuses to run below is 0.0.1. */
#define ENA_DEVICE_VERSION_MAJOR    0
#define ENA_DEVICE_VERSION_MINOR    10
#define ENA_CTRL_VERSION            0x01000001  /* impl 1, 0.0.1 */

/* The queue-ext feature version the HAL asks for; ena_com.h calls it
 * ENA_FEATURE_MAX_QUEUE_EXT_VER. */
#define ENA_MAX_QUEUE_EXT_VERSION   1

#define ENA_SQ_DIRECTION_TX         1
#define ENA_SQ_DIRECTION_RX         2

/*
 * Tracing is capped. An unbounded doorbell trace on the gVNIC model filled
 * the disk, and the file could not be reclaimed until QEMU exited because it
 * still held it open.
 */
#define ENA_TRACE_MAX 400
static int ena_trace_left = ENA_TRACE_MAX;
#define ENA_TRACE(fmt, ...) do { \
    if (ena_trace_left > 0) { \
        ena_trace_left--; \
        qemu_log_mask(LOG_UNIMP, "ena: " fmt "\n", ## __VA_ARGS__); \
    } \
} while (0)

typedef struct EnaQueue {
    bool active;
    uint16_t depth;             /* entries; a power of two */
    uint64_t base;              /* guest address of the ring */
    uint16_t head;              /* the device's position, free-running */
    uint8_t phase;
    uint16_t entry_size;        /* bytes, as the driver declared it */

    /* Submission queues. */
    uint8_t direction;
    uint8_t placement;          /* HOST, or DEV for a low-latency queue */
    uint64_t llq_offset;        /* where in the LLQ window this ring lives */
    uint16_t cq_idx;
    uint16_t tail;              /* last doorbell the guest wrote */

    /* Completion queues. */
    uint32_t msix_vector;
    bool masked;
} EnaQueue;

struct EnaState {
    PCIDevice parent_obj;

    MemoryRegion reg_bar;
    MemoryRegion llq_bar;
    uint8_t *llq_mem;
    NICState *nic;
    NICConf conf;

    /* Registers the guest writes. */
    uint32_t dev_ctl;
    uint32_t dev_sts;
    uint32_t aq_base_lo, aq_base_hi, aq_caps;
    uint32_t acq_base_lo, acq_base_hi, acq_caps;
    uint32_t aenq_base_lo, aenq_base_hi, aenq_caps;
    uint32_t intr_mask;
    uint32_t mmio_resp_lo, mmio_resp_hi;

    /* Admin queue, its completion queue, and the async event queue. */
    uint16_t aq_head;
    uint8_t aq_phase;
    uint16_t aq_tail;           /* the admin doorbell, which is its own */
    uint16_t acq_tail;
    uint8_t acq_phase;
    uint16_t aenq_tail;
    uint8_t aenq_phase;
    uint16_t aenq_head;

    EnaQueue sq[ENA_MAX_QUEUES];
    EnaQueue cq[ENA_MAX_QUEUES];

    uint32_t aenq_enabled_groups;
    /* What the guest chose during LLQ negotiation. */
    uint16_t llq_entry_size;            /* bytes: 128, 192 or 256 */
    uint16_t llq_descs_before_header;
    uint16_t llq_stride_ctrl;
    uint16_t llq_header_location;
    uint32_t mtu;
    bool link_up_sent;
    bool firmware_bus_master;

    /* Basic statistics, which the drivers poll for. */
    uint64_t tx_bytes, tx_pkts, rx_bytes, rx_pkts, rx_drops;
};

static void ena_tx_run(EnaState *s, EnaQueue *sq);

/* ENA is little-endian on the wire regardless of what the host is. */
static uint64_t ena_mem_addr(const struct ena_common_mem_addr *a)
{
    return (uint64_t)le32_to_cpu(a->mem_addr_low) |
           ((uint64_t)le16_to_cpu(a->mem_addr_high) << 32);
}

/*
 * Readless register reads.
 *
 * A driver does not load from the register file. It writes the offset it
 * wants, paired with a sequence number, to MMIO_REG_READ and then polls a
 * buffer in its own memory whose address it published in MMIO_RESP_LO/HI.
 * The value and the offset have to land before the sequence number does,
 * because the sequence number is what the driver waits on.
 */
static void ena_mmio_resp_write(EnaState *s, uint16_t req_id, uint16_t off,
                                uint32_t val)
{
    uint64_t addr = (uint64_t)s->mmio_resp_lo | ((uint64_t)s->mmio_resp_hi << 32);
    struct ena_admin_ena_mmio_req_read_less_resp resp;

    if (addr == 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ena: register read before the response buffer was "
                      "published\n");
        return;
    }

    ENA_TRACE("reg read off=0x%x seq=%u -> 0x%x  resp@0x%" PRIx64
              " pci_command=0x%04x%s", off, req_id, val, addr,
              pci_get_word(PCI_DEVICE(s)->config + PCI_COMMAND),
              (pci_get_word(PCI_DEVICE(s)->config + PCI_COMMAND) &
               PCI_COMMAND_MASTER) ? "" : " (BUS MASTER OFF -- DMA DROPPED)");

    resp.reg_off = cpu_to_le16(off);
    resp.reg_val = cpu_to_le32(val);
    pci_dma_write(PCI_DEVICE(s), addr + offsetof(typeof(resp), reg_off),
                  &resp.reg_off, sizeof(resp.reg_off));
    pci_dma_write(PCI_DEVICE(s), addr + offsetof(typeof(resp), reg_val),
                  &resp.reg_val, sizeof(resp.reg_val));

    resp.req_id = cpu_to_le16(req_id);
    pci_dma_write(PCI_DEVICE(s), addr + offsetof(typeof(resp), req_id),
                  &resp.req_id, sizeof(resp.req_id));
}

static uint32_t ena_reg_value(EnaState *s, uint16_t off)
{
    switch (off) {
    case ENA_REGS_VERSION_OFF:
        return (ENA_DEVICE_VERSION_MAJOR <<
                ENA_REGS_VERSION_MAJOR_VERSION_SHIFT) |
               ENA_DEVICE_VERSION_MINOR;
    case ENA_REGS_CONTROLLER_VERSION_OFF:
        return ENA_CTRL_VERSION;
    case ENA_REGS_CAPS_OFF:
        /*
         * reset_timeout and admin_cmd_to are in units of 100ms and must not
         * be zero: ena_com_dev_reset() treats a zero reset timeout as a dead
         * device and gives up before it has done anything.
         */
        return ENA_REGS_CAPS_CONTIGUOUS_QUEUE_REQUIRED_MASK |
               ((5u << ENA_REGS_CAPS_RESET_TIMEOUT_SHIFT) &
                ENA_REGS_CAPS_RESET_TIMEOUT_MASK) |
               ((ENA_DMA_ADDR_BITS << ENA_REGS_CAPS_DMA_ADDR_WIDTH_SHIFT) &
                ENA_REGS_CAPS_DMA_ADDR_WIDTH_MASK) |
               ((3u << ENA_REGS_CAPS_ADMIN_CMD_TO_SHIFT) &
                ENA_REGS_CAPS_ADMIN_CMD_TO_MASK);
    case ENA_REGS_CAPS_EXT_OFF:
        return 0;
    case ENA_REGS_DEV_STS_OFF:
        return s->dev_sts;
    case ENA_REGS_DEV_CTL_OFF:
        return s->dev_ctl;
    case ENA_REGS_AQ_CAPS_OFF:
        return s->aq_caps;
    case ENA_REGS_ACQ_CAPS_OFF:
        return s->acq_caps;
    case ENA_REGS_AENQ_CAPS_OFF:
        return s->aenq_caps;
    case ENA_REGS_AENQ_TAIL_OFF:
        return s->aenq_tail;
    case ENA_REGS_ACQ_TAIL_OFF:
        return s->acq_tail;
    case ENA_REGS_INTR_MASK_OFF:
        return s->intr_mask;
    default:
        return 0;
    }
}

static void ena_queues_reset(EnaState *s)
{
    memset(s->sq, 0, sizeof(s->sq));
    memset(s->cq, 0, sizeof(s->cq));
}

static void ena_reset_state(EnaState *s)
{
    s->aq_head = 0;
    s->aq_phase = 1;
    s->acq_tail = 0;
    s->acq_phase = 1;
    s->aenq_tail = 0;
    s->aenq_phase = 1;
    s->aenq_head = 0;
    s->aq_caps = s->acq_caps = s->aenq_caps = 0;
    s->aq_base_lo = s->aq_base_hi = 0;
    s->acq_base_lo = s->acq_base_hi = 0;
    s->aenq_base_lo = s->aenq_base_hi = 0;
    s->aenq_enabled_groups = 0;
    s->llq_entry_size = 0;
    s->llq_descs_before_header = 0;
    s->llq_stride_ctrl = 0;
    s->llq_header_location = 0;
    s->link_up_sent = false;
    s->mtu = ENA_MAX_MTU;
    ena_queues_reset(s);
    /*
     * Not the readless response address: ena_com_dev_reset() re-publishes it
     * in the middle of the handshake precisely because a reset drops it, and
     * a model that kept it would hide a driver that forgot to.
     */
    s->mmio_resp_lo = s->mmio_resp_hi = 0;
    s->dev_sts = ENA_REGS_DEV_STS_READY_MASK;
}

/* ---------------------------------------------------------------- AENQ */

/*
 * Async events. The ring is the guest's; the device owns the tail and must
 * not run more than a ring ahead of the head doorbell the guest writes back.
 */
static bool ena_aenq_post(EnaState *s, uint16_t group, uint16_t syndrome,
                          uint32_t inline_w0)
{
    uint64_t base = (uint64_t)s->aenq_base_lo | ((uint64_t)s->aenq_base_hi << 32);
    uint16_t depth = s->aenq_caps & ENA_REGS_AENQ_CAPS_AENQ_DEPTH_MASK;
    struct ena_admin_aenq_entry e;
    uint16_t slot;

    if (base == 0 || depth == 0) {
        ENA_TRACE("aenq not ready for group %u (base=0x%" PRIx64 " depth=%u)",
                  group, base, depth);
        return false;
    }
    if (!(s->aenq_enabled_groups & BIT(group))) {
        ENA_TRACE("aenq group %u not enabled (0x%x)", group,
                  s->aenq_enabled_groups);
        return false;
    }
    if ((uint16_t)(s->aenq_tail - s->aenq_head) >= depth) {
        qemu_log_mask(LOG_GUEST_ERROR, "ena: aenq full, event %u dropped\n",
                      group);
        return false;
    }

    slot = s->aenq_tail & (depth - 1);
    memset(&e, 0, sizeof(e));
    e.aenq_common_desc.group = cpu_to_le16(group);
    e.aenq_common_desc.syndrome = cpu_to_le16(syndrome);
    e.aenq_common_desc.flags = s->aenq_phase &
        ENA_ADMIN_AENQ_COMMON_DESC_PHASE_MASK;
    /*
     * The first word after the common descriptor, which each group defines
     * for itself -- for a link change it is the one that says whether the
     * link came up or went down. An event that carries nothing here is a
     * perfectly well-formed announcement that the link is still down.
     */
    e.inline_data_w4[0] = cpu_to_le32(inline_w0);

    pci_dma_write(PCI_DEVICE(s), base + (uint64_t)slot * sizeof(e), &e,
                  sizeof(e));
    ENA_TRACE("aenq[%u] group=%u syndrome=%u w0=0x%x phase=%u", slot, group,
              syndrome, inline_w0, s->aenq_phase);

    s->aenq_tail++;
    if ((s->aenq_tail & (depth - 1)) == 0) {
        s->aenq_phase = !s->aenq_phase;
    }
    if (msix_enabled(PCI_DEVICE(s))) {
        msix_notify(PCI_DEVICE(s), 0);
    }
    return true;
}

/*
 * Say the link is up, once, as soon as there is somewhere to say it. The
 * latch belongs to the event actually reaching the guest and not to the
 * attempt: the first attempts come before the guest has published an async
 * event queue or asked for link events, and a latch set on those would eat
 * the only announcement the guest was ever going to get -- leaving a device
 * that works perfectly and an interface that never comes up.
 */
static void ena_link_up(EnaState *s)
{
    if (s->link_up_sent) {
        return;
    }
    s->link_up_sent = ena_aenq_post(s, ENA_ADMIN_LINK_CHANGE, 0,
                                    ENA_ADMIN_AENQ_LINK_CHANGE_DESC_LINK_STATUS_MASK);
}

/* ------------------------------------------------------------- features */

static uint32_t ena_supported_features(void)
{
    /*
     * RSS is absent deliberately -- one receive queue, and no indirection
     * table to get wrong.
     */
    return BIT(ENA_ADMIN_DEVICE_ATTRIBUTES) |
           BIT(ENA_ADMIN_MAX_QUEUES_NUM) |
           BIT(ENA_ADMIN_MAX_QUEUES_EXT) |
           BIT(ENA_ADMIN_LLQ) |
           BIT(ENA_ADMIN_STATELESS_OFFLOAD_CONFIG) |
           BIT(ENA_ADMIN_MTU) |
           BIT(ENA_ADMIN_AENQ_CONFIG) |
           BIT(ENA_ADMIN_LINK_CONFIG) |
           BIT(ENA_ADMIN_HOST_ATTR_CONFIG);
}

static uint8_t ena_get_feature(EnaState *s, const struct ena_admin_get_feat_cmd *cmd,
                               struct ena_admin_get_feat_resp *resp)
{
    uint8_t id = cmd->feat_common.feature_id;

    switch (id) {
    case ENA_ADMIN_DEVICE_ATTRIBUTES: {
        struct ena_admin_device_attr_feature_desc *d = &resp->u.dev_attr;

        d->impl_id = cpu_to_le32(1);
        d->device_version = cpu_to_le32(1);
        d->supported_features = cpu_to_le32(ena_supported_features());
        d->capabilities = 0;
        d->phys_addr_width = cpu_to_le32(ENA_DMA_ADDR_BITS);
        d->virt_addr_width = cpu_to_le32(ENA_DMA_ADDR_BITS);
        memcpy(d->mac_addr, s->conf.macaddr.a, sizeof(d->mac_addr));
        d->max_mtu = cpu_to_le32(ENA_MAX_MTU);
        ENA_TRACE("get_feature device_attributes supported=0x%x max_mtu=%u",
                  ena_supported_features(), ENA_MAX_MTU);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_MAX_QUEUES_EXT: {
        struct ena_admin_queue_ext_feature_desc *d = &resp->u.max_queue_ext;

        d->version = ENA_MAX_QUEUE_EXT_VERSION;
        d->max_queue_ext.max_tx_sq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_queue_ext.max_tx_cq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_queue_ext.max_rx_sq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_queue_ext.max_rx_cq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_queue_ext.max_tx_sq_depth = cpu_to_le32(1024);
        d->max_queue_ext.max_tx_cq_depth = cpu_to_le32(1024);
        d->max_queue_ext.max_rx_sq_depth = cpu_to_le32(1024);
        d->max_queue_ext.max_rx_cq_depth = cpu_to_le32(1024);
        d->max_queue_ext.max_tx_header_size = cpu_to_le32(1024);
        d->max_queue_ext.max_per_packet_tx_descs = cpu_to_le16(16);
        /*
         * One buffer per received packet. The driver then never has to
         * reassemble, and this model never has to split.
         */
        d->max_queue_ext.max_per_packet_rx_descs = cpu_to_le16(1);
        ENA_TRACE("get_feature max_queues_ext ver=%u depths tx=%u rx=%u "
                  "hdr=%u", d->version, 1024, 1024, 256);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_MAX_QUEUES_NUM: {
        struct ena_admin_queue_feature_desc *d = &resp->u.max_queue;

        d->max_sq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_cq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_sq_depth = cpu_to_le32(1024);
        d->max_cq_depth = cpu_to_le32(1024);
        d->max_header_size = cpu_to_le32(1024);
        d->max_packet_tx_descs = cpu_to_le16(16);
        d->max_packet_rx_descs = cpu_to_le16(1);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_AENQ_CONFIG: {
        struct ena_admin_feature_aenq_desc *d = &resp->u.aenq;

        /*
         * KEEP_ALIVE is not offered. A driver that sees it arms a watchdog
         * and resets the device when the heartbeats stop, so offering it
         * would commit this model to a timer for no gain; a driver that does
         * not see it simply runs without the watchdog.
         */
        d->supported_groups = cpu_to_le32(BIT(ENA_ADMIN_LINK_CHANGE) |
                                          BIT(ENA_ADMIN_FATAL_ERROR) |
                                          BIT(ENA_ADMIN_WARNING) |
                                          BIT(ENA_ADMIN_NOTIFICATION));
        d->enabled_groups = cpu_to_le32(s->aenq_enabled_groups);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_LINK_CONFIG: {
        struct ena_admin_get_feature_link_desc *d = &resp->u.link;

        d->speed = cpu_to_le32(10000);
        /* The link-type enumerators are already bit values, not indices. */
        d->supported = cpu_to_le32(ENA_ADMIN_LINK_SPEED_10G);
        d->flags = cpu_to_le32(ENA_ADMIN_GET_FEATURE_LINK_DESC_DUPLEX_MASK);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_LLQ: {
        struct ena_admin_feature_llq_desc *d = &resp->u.llq;

        d->max_llq_num = cpu_to_le32(ENA_MAX_QUEUES);
        d->max_llq_depth = cpu_to_le32(ENA_LLQ_MAX_DEPTH);
        /*
         * Inline header only. The alternative, a separate header ring, forces
         * 16-byte entries and a second window to maintain, and no driver asks
         * for it by preference.
         */
        d->header_location_ctrl_supported = cpu_to_le16(ENA_ADMIN_INLINE_HEADER);
        d->entry_size_ctrl_supported =
            cpu_to_le16(ENA_ADMIN_LIST_ENTRY_SIZE_128B |
                        ENA_ADMIN_LIST_ENTRY_SIZE_256B);
        d->entry_size_recommended = ENA_ADMIN_LIST_ENTRY_SIZE_128B;
        d->desc_num_before_header_supported =
            cpu_to_le16(ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_1 |
                        ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_2 |
                        ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_4 |
                        ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_8);
        d->descriptors_stride_ctrl_supported =
            cpu_to_le16(ENA_ADMIN_SINGLE_DESC_PER_ENTRY |
                        ENA_ADMIN_MULTIPLE_DESCS_PER_ENTRY);
        d->feature_version = ENA_ADMIN_LLQ_FEATURE_VERSION_1;
        /*
         * Equal to max_llq_depth, so a driver choosing 256-byte entries is
         * not told to halve its transmit ring.
         */
        d->max_wide_llq_depth = cpu_to_le32(ENA_LLQ_MAX_DEPTH);
        /* No acceleration flags: no meta caching to disable, no burst limit. */
        d->accel_mode.u.get.supported_flags = 0;
        d->accel_mode.u.get.max_tx_burst_size = 0;
        ENA_TRACE("get_feature llq: entry sizes 128|256, descs before header "
                  "1|2|4|8, inline header");
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_STATELESS_OFFLOAD_CONFIG:
        /* No offloads claimed: the guest checksums and segments in software. */
        memset(&resp->u, 0, sizeof(resp->u));
        return ENA_ADMIN_SUCCESS;
    case ENA_ADMIN_MTU:
        resp->u.raw[0] = cpu_to_le32(s->mtu);
        return ENA_ADMIN_SUCCESS;
    default:
        ENA_TRACE("get_feature %u unsupported", id);
        return ENA_ADMIN_UNSUPPORTED_OPCODE;
    }
}

static uint8_t ena_set_feature(EnaState *s, const struct ena_admin_set_feat_cmd *cmd)
{
    uint8_t id = cmd->feat_common.feature_id;

    switch (id) {
    case ENA_ADMIN_MTU: {
        uint32_t mtu = le32_to_cpu(cmd->u.mtu.mtu);

        if (mtu == 0 || mtu > ENA_MAX_MTU) {
            return ENA_ADMIN_ILLEGAL_PARAMETER;
        }
        s->mtu = mtu;
        ENA_TRACE("set mtu %u", mtu);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_AENQ_CONFIG:
        s->aenq_enabled_groups = le32_to_cpu(cmd->u.aenq.enabled_groups);
        ENA_TRACE("aenq groups enabled 0x%x", s->aenq_enabled_groups);
        /* Now that the guest wants events, tell it about the link. */
        ena_link_up(s);
        return ENA_ADMIN_SUCCESS;
    case ENA_ADMIN_LLQ: {
        static const uint16_t entry_bytes[] = {
            [ENA_ADMIN_LIST_ENTRY_SIZE_128B] = 128,
            [ENA_ADMIN_LIST_ENTRY_SIZE_192B] = 192,
            [ENA_ADMIN_LIST_ENTRY_SIZE_256B] = 256,
        };
        uint16_t size_ctrl = le16_to_cpu(cmd->u.llq.entry_size_ctrl_enabled);
        uint16_t location = le16_to_cpu(cmd->u.llq.header_location_ctrl_enabled);
        uint16_t descs = le16_to_cpu(cmd->u.llq.desc_num_before_header_enabled);
        uint16_t stride = le16_to_cpu(cmd->u.llq.descriptors_stride_ctrl_enabled);

        if (size_ctrl >= ARRAY_SIZE(entry_bytes) ||
            entry_bytes[size_ctrl] == 0) {
            return ENA_ADMIN_ILLEGAL_PARAMETER;
        }
        if (location != ENA_ADMIN_INLINE_HEADER) {
            return ENA_ADMIN_ILLEGAL_PARAMETER;
        }
        /*
         * The header sits after this many descriptors, so it has to leave
         * room for itself inside one entry.
         */
        if (descs == 0 ||
            (uint32_t)descs * ENA_TX_DESC_SIZE >= entry_bytes[size_ctrl]) {
            return ENA_ADMIN_ILLEGAL_PARAMETER;
        }
        s->llq_entry_size = entry_bytes[size_ctrl];
        s->llq_descs_before_header = descs;
        s->llq_stride_ctrl = stride;
        s->llq_header_location = location;
        ENA_TRACE("llq configured: entry=%uB descs_before_header=%u stride=%u",
                  s->llq_entry_size, descs, stride);
        return ENA_ADMIN_SUCCESS;
    }
    case ENA_ADMIN_HOST_ATTR_CONFIG:
        /* The guest describes itself. Nothing here needs to know. */
        return ENA_ADMIN_SUCCESS;
    default:
        ENA_TRACE("set_feature %u unsupported", id);
        return ENA_ADMIN_UNSUPPORTED_OPCODE;
    }
}

/* ----------------------------------------------------------- io queues */

static uint8_t ena_create_cq(EnaState *s, const struct ena_admin_aq_create_cq_cmd *cmd,
                             struct ena_admin_acq_create_cq_resp_desc *resp)
{
    uint16_t depth = le16_to_cpu(cmd->cq_depth);
    uint8_t words = cmd->cq_caps_2 & ENA_ADMIN_AQ_CREATE_CQ_CMD_CQ_ENTRY_SIZE_WORDS_MASK;
    EnaQueue *q = NULL;
    unsigned idx;

    if (depth == 0 || (depth & (depth - 1)) != 0 || words == 0) {
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    for (idx = 0; idx < ENA_MAX_QUEUES; idx++) {
        if (!s->cq[idx].active) {
            q = &s->cq[idx];
            break;
        }
    }
    if (q == NULL) {
        return ENA_ADMIN_RESOURCE_ALLOCATION_FAILURE;
    }

    q->active = true;
    q->depth = depth;
    q->base = ena_mem_addr(&cmd->cq_ba);
    q->head = 0;
    q->phase = 1;
    /*
     * The entry size is whatever the driver said, not what this model would
     * have chosen: transmit completions are eight bytes and receive
     * completions sixteen, and the HAL sends 2 and 4 words respectively --
     * which the header's own comment, claiming only 4 and 8 are valid, does
     * not lead you to expect.
     */
    q->entry_size = words * 4;
    q->msix_vector = le32_to_cpu(cmd->msix_vector);
    q->masked = false;

    resp->cq_idx = cpu_to_le16(idx);
    resp->cq_actual_depth = cpu_to_le16(depth);
    resp->cq_head_db_register_offset = cpu_to_le32(ENA_CQ_DB_BASE + idx * 4);
    resp->cq_interrupt_unmask_register_offset =
        cpu_to_le32(ENA_CQ_UNMASK_BASE + idx * 4);
    resp->numa_node_register_offset = cpu_to_le32(ENA_CQ_NUMA_BASE + idx * 4);

    ENA_TRACE("create cq %u depth=%u entry=%uB vector=%u base=0x%" PRIx64,
              idx, depth, q->entry_size, q->msix_vector, q->base);
    return ENA_ADMIN_SUCCESS;
}

static uint8_t ena_create_sq(EnaState *s, const struct ena_admin_aq_create_sq_cmd *cmd,
                             struct ena_admin_acq_create_sq_resp_desc *resp)
{
    uint16_t depth = le16_to_cpu(cmd->sq_depth);
    uint8_t dir = (cmd->sq_identity &
                   ENA_ADMIN_AQ_CREATE_SQ_CMD_SQ_DIRECTION_MASK) >>
                  ENA_ADMIN_AQ_CREATE_SQ_CMD_SQ_DIRECTION_SHIFT;
    uint8_t policy = cmd->sq_caps_2 &
        ENA_ADMIN_AQ_CREATE_SQ_CMD_PLACEMENT_POLICY_MASK;
    uint16_t cq_idx = le16_to_cpu(cmd->cq_idx);
    EnaQueue *q = NULL;
    unsigned idx;

    if (depth == 0 || (depth & (depth - 1)) != 0) {
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    if (dir != ENA_SQ_DIRECTION_TX && dir != ENA_SQ_DIRECTION_RX) {
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    if (policy != ENA_ADMIN_PLACEMENT_POLICY_HOST &&
        policy != ENA_ADMIN_PLACEMENT_POLICY_DEV) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "ena: unknown placement policy %u\n", policy);
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    if (policy == ENA_ADMIN_PLACEMENT_POLICY_DEV) {
        /*
         * A low-latency queue is transmit-only, and it cannot be created
         * before the guest has said how it intends to lay the window out.
         */
        if (dir != ENA_SQ_DIRECTION_TX || s->llq_entry_size == 0) {
            return ENA_ADMIN_ILLEGAL_PARAMETER;
        }
        if ((uint64_t)depth * s->llq_entry_size > ENA_LLQ_QUEUE_SIZE) {
            return ENA_ADMIN_ILLEGAL_PARAMETER;
        }
    }
    if (cq_idx >= ENA_MAX_QUEUES || !s->cq[cq_idx].active) {
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    for (idx = 0; idx < ENA_MAX_QUEUES; idx++) {
        if (!s->sq[idx].active) {
            q = &s->sq[idx];
            break;
        }
    }
    if (q == NULL) {
        return ENA_ADMIN_RESOURCE_ALLOCATION_FAILURE;
    }

    q->active = true;
    q->depth = depth;
    q->base = ena_mem_addr(&cmd->sq_ba);
    q->head = 0;
    q->tail = 0;
    q->phase = 1;
    q->direction = dir;
    q->placement = policy;
    q->cq_idx = cq_idx;
    q->entry_size = (dir == ENA_SQ_DIRECTION_TX) ?
        ENA_TX_DESC_SIZE : sizeof(struct ena_eth_io_rx_desc);
    q->llq_offset = (uint64_t)idx * ENA_LLQ_QUEUE_SIZE;

    resp->sq_idx = cpu_to_le16(idx);
    resp->sq_doorbell_offset = cpu_to_le32(ENA_SQ_DB_BASE + idx * 4);
    /*
     * Where in the memory BAR this queue's entries live. Like the doorbell
     * offsets, the device chooses it and the guest reads it back.
     */
    resp->llq_descriptors_offset =
        (policy == ENA_ADMIN_PLACEMENT_POLICY_DEV) ?
        cpu_to_le32(q->llq_offset) : 0;
    resp->llq_headers_offset = 0;

    ENA_TRACE("create sq %u dir=%s depth=%u cq=%u %s=0x%" PRIx64, idx,
              dir == ENA_SQ_DIRECTION_TX ? "tx" : "rx", depth, cq_idx,
              policy == ENA_ADMIN_PLACEMENT_POLICY_DEV ? "llq" : "base",
              policy == ENA_ADMIN_PLACEMENT_POLICY_DEV ? q->llq_offset
                                                       : q->base);

    if (dir == ENA_SQ_DIRECTION_RX) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
    ena_link_up(s);
    return ENA_ADMIN_SUCCESS;
}

static uint8_t ena_destroy_sq(EnaState *s, const struct ena_admin_aq_destroy_sq_cmd *cmd)
{
    uint16_t idx = le16_to_cpu(cmd->sq.sq_idx);

    if (idx >= ENA_MAX_QUEUES || !s->sq[idx].active) {
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    s->sq[idx].active = false;
    return ENA_ADMIN_SUCCESS;
}

static uint8_t ena_destroy_cq(EnaState *s, const struct ena_admin_aq_destroy_cq_cmd *cmd)
{
    uint16_t idx = le16_to_cpu(cmd->cq_idx);

    if (idx >= ENA_MAX_QUEUES || !s->cq[idx].active) {
        return ENA_ADMIN_ILLEGAL_PARAMETER;
    }
    s->cq[idx].active = false;
    return ENA_ADMIN_SUCCESS;
}

static uint8_t ena_get_stats(EnaState *s, const struct ena_admin_aq_get_stats_cmd *cmd,
                             struct ena_admin_acq_get_stats_resp *resp)
{
    struct ena_admin_basic_stats *b = &resp->u.basic_stats;

    if (cmd->type != ENA_ADMIN_GET_STATS_TYPE_BASIC) {
        return ENA_ADMIN_UNSUPPORTED_OPCODE;
    }
    b->tx_bytes_low = cpu_to_le32((uint32_t)s->tx_bytes);
    b->tx_bytes_high = cpu_to_le32((uint32_t)(s->tx_bytes >> 32));
    b->tx_pkts_low = cpu_to_le32((uint32_t)s->tx_pkts);
    b->tx_pkts_high = cpu_to_le32((uint32_t)(s->tx_pkts >> 32));
    b->rx_bytes_low = cpu_to_le32((uint32_t)s->rx_bytes);
    b->rx_bytes_high = cpu_to_le32((uint32_t)(s->rx_bytes >> 32));
    b->rx_pkts_low = cpu_to_le32((uint32_t)s->rx_pkts);
    b->rx_pkts_high = cpu_to_le32((uint32_t)(s->rx_pkts >> 32));
    b->rx_drops_low = cpu_to_le32((uint32_t)s->rx_drops);
    b->rx_drops_high = cpu_to_le32((uint32_t)(s->rx_drops >> 32));
    return ENA_ADMIN_SUCCESS;
}

/* ------------------------------------------------------- admin queue */

static void ena_acq_post(EnaState *s, uint16_t command_id, uint8_t status,
                         const void *specific, size_t specific_len)
{
    uint64_t base = (uint64_t)s->acq_base_lo | ((uint64_t)s->acq_base_hi << 32);
    uint16_t depth = s->acq_caps & ENA_REGS_ACQ_CAPS_ACQ_DEPTH_MASK;
    uint8_t entry[ENA_ADMIN_ENTRY_SIZE];
    struct ena_admin_acq_common_desc *c = (void *)entry;
    uint16_t slot;

    if (base == 0 || depth == 0) {
        return;
    }
    slot = s->acq_tail & (depth - 1);

    memset(entry, 0, sizeof(entry));
    if (specific_len > 0) {
        /*
         * The caller built a whole response entry; take everything past the
         * common descriptor from it.
         */
        memcpy(entry, specific, MIN(specific_len, sizeof(entry)));
    }
    c->command = cpu_to_le16(command_id &
                             ENA_ADMIN_ACQ_COMMON_DESC_COMMAND_ID_MASK);
    c->status = status;
    c->flags = s->acq_phase & ENA_ADMIN_ACQ_COMMON_DESC_PHASE_MASK;
    c->extended_status = 0;
    c->sq_head_indx = cpu_to_le16(s->aq_head);

    pci_dma_write(PCI_DEVICE(s), base + (uint64_t)slot * sizeof(entry), entry,
                  sizeof(entry));

    s->acq_tail++;
    if ((s->acq_tail & (depth - 1)) == 0) {
        s->acq_phase = !s->acq_phase;
    }
    if (msix_enabled(PCI_DEVICE(s))) {
        msix_notify(PCI_DEVICE(s), 0);
    }
}

static void ena_admin_run(EnaState *s)
{
    uint64_t base = (uint64_t)s->aq_base_lo | ((uint64_t)s->aq_base_hi << 32);
    uint16_t depth = s->aq_caps & ENA_REGS_AQ_CAPS_AQ_DEPTH_MASK;

    if (base == 0 || depth == 0) {
        return;
    }

    /*
     * Bounded by the ring. The tail is guest-supplied, and a wild value must
     * cost a complaint rather than an unbreakable spin inside a device write.
     */
    for (uint32_t budget = depth; budget > 0; budget--) {
        uint8_t cmd[ENA_ADMIN_ENTRY_SIZE];
        uint8_t rsp[ENA_ADMIN_ENTRY_SIZE];
        struct ena_admin_aq_common_desc *ac = (void *)cmd;
        uint16_t slot = s->aq_head & (depth - 1);
        uint16_t command_id;
        uint8_t status;

        pci_dma_read(PCI_DEVICE(s), base + (uint64_t)slot * sizeof(cmd), cmd,
                     sizeof(cmd));

        /*
         * The phase bit is what says an entry is the guest's latest and not
         * last time round's leftovers. Stop at the first one that is stale.
         */
        if ((ac->flags & ENA_ADMIN_AQ_COMMON_DESC_PHASE_MASK) != s->aq_phase) {
            break;
        }

        command_id = le16_to_cpu(ac->command_id) &
            ENA_ADMIN_AQ_COMMON_DESC_COMMAND_ID_MASK;
        memset(rsp, 0, sizeof(rsp));

        switch (ac->opcode) {
        case ENA_ADMIN_CREATE_SQ:
            status = ena_create_sq(s, (void *)cmd, (void *)rsp);
            break;
        case ENA_ADMIN_DESTROY_SQ:
            status = ena_destroy_sq(s, (void *)cmd);
            break;
        case ENA_ADMIN_CREATE_CQ:
            status = ena_create_cq(s, (void *)cmd, (void *)rsp);
            break;
        case ENA_ADMIN_DESTROY_CQ:
            status = ena_destroy_cq(s, (void *)cmd);
            break;
        case ENA_ADMIN_GET_FEATURE: {
            const struct ena_admin_get_feat_cmd *g = (const void *)cmd;

            status = ena_get_feature(s, g, (void *)rsp);
            ENA_TRACE("get_feature id=%u ver=%u -> %u  payload "
                      "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
                      "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
                      "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
                      "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                      g->feat_common.feature_id, g->feat_common.feature_version,
                      status,
                      rsp[8], rsp[9], rsp[10], rsp[11],
                      rsp[12], rsp[13], rsp[14], rsp[15],
                      rsp[16], rsp[17], rsp[18], rsp[19],
                      rsp[20], rsp[21], rsp[22], rsp[23],
                      rsp[24], rsp[25], rsp[26], rsp[27],
                      rsp[28], rsp[29], rsp[30], rsp[31],
                      rsp[32], rsp[33], rsp[34], rsp[35],
                      rsp[36], rsp[37], rsp[38], rsp[39],
                      rsp[40], rsp[41], rsp[42], rsp[43],
                      rsp[44], rsp[45], rsp[46], rsp[47],
                      rsp[48], rsp[49], rsp[50], rsp[51],
                      rsp[52], rsp[53], rsp[54], rsp[55]);
            break;
        }
        case ENA_ADMIN_SET_FEATURE:
            status = ena_set_feature(s, (void *)cmd);
            break;
        case ENA_ADMIN_GET_STATS:
            status = ena_get_stats(s, (void *)cmd, (void *)rsp);
            break;
        default:
            ENA_TRACE("admin opcode %u unknown", ac->opcode);
            status = ENA_ADMIN_UNSUPPORTED_OPCODE;
            break;
        }

        if (status != ENA_ADMIN_SUCCESS) {
            ENA_TRACE("admin opcode %u -> status %u", ac->opcode, status);
        }

        s->aq_head++;
        if ((s->aq_head & (depth - 1)) == 0) {
            s->aq_phase = !s->aq_phase;
        }
        ena_acq_post(s, command_id, status, rsp, sizeof(rsp));
    }
}

/* ------------------------------------------------------------ transmit */

static void ena_tx_complete(EnaState *s, EnaQueue *sq, uint16_t req_id)
{
    EnaQueue *cq = &s->cq[sq->cq_idx];
    struct ena_eth_io_tx_cdesc c;
    uint16_t slot;

    if (!cq->active) {
        return;
    }
    slot = cq->head & (cq->depth - 1);

    memset(&c, 0, sizeof(c));
    c.req_id = cpu_to_le16(req_id);
    c.status = 0;
    c.flags = cq->phase & ENA_ETH_IO_TX_CDESC_PHASE_MASK;
    c.sub_qid = cpu_to_le16(sq - s->sq);
    c.sq_head_idx = cpu_to_le16(sq->head & (sq->depth - 1));

    pci_dma_write(PCI_DEVICE(s), cq->base + (uint64_t)slot * cq->entry_size,
                  &c, sizeof(c));

    cq->head++;
    if ((cq->head & (cq->depth - 1)) == 0) {
        cq->phase = !cq->phase;
    }
    if (!cq->masked && msix_enabled(PCI_DEVICE(s)) &&
        cq->msix_vector < ENA_MSIX_VECTORS) {
        msix_notify(PCI_DEVICE(s), cq->msix_vector);
    }
}

/*
 * Transmit from a low-latency queue.
 *
 * The ring is in the device's own memory window and the guest writes whole
 * entries into it, so the unit of the doorbell here is an entry, not a
 * descriptor. Inside an entry the layout is the one the guest asked for
 * during negotiation: descriptors from offset zero, and -- in the entry that
 * begins a packet -- the packet's own header immediately after
 * descs_before_header of them. An entry that continues a packet carries
 * descriptors and no header.
 *
 * Only the header travels in device memory. Everything after it is still
 * fetched from guest RAM through the descriptors, which is what makes this
 * worth doing: the small write that used to cost a round trip is pushed
 * across the bus with the descriptor that describes it.
 */
static const uint8_t *ena_llq_entry(EnaState *s, EnaQueue *sq, uint16_t pos)
{
    uint64_t off = sq->llq_offset +
        (uint64_t)(pos & (sq->depth - 1)) * s->llq_entry_size;

    return s->llq_mem + off;
}

static unsigned ena_llq_descs_per_entry(EnaState *s)
{
    if (s->llq_stride_ctrl == ENA_ADMIN_SINGLE_DESC_PER_ENTRY) {
        return 1;
    }
    return s->llq_entry_size / ENA_TX_DESC_SIZE;
}

static void ena_tx_run_llq(EnaState *s, EnaQueue *sq)
{
    uint8_t frame[ENA_MAX_FRAME];

    if (s->llq_entry_size == 0) {
        return;
    }

    for (uint32_t budget = sq->depth; budget > 0 && sq->head != sq->tail;
         budget--) {
        uint32_t got = 0;
        uint16_t req_id = 0;
        bool first_entry = true, started = false, last = false;

        while (sq->head != sq->tail && !last) {
            const uint8_t *entry = ena_llq_entry(s, sq, sq->head);
            unsigned ndesc = first_entry ? s->llq_descs_before_header
                                         : ena_llq_descs_per_entry(s);

            sq->head++;

            for (unsigned i = 0; i < ndesc && !last; i++) {
                struct ena_eth_io_tx_desc d;
                uint32_t len_ctrl, meta_ctrl, hi;
                uint64_t addr;
                uint16_t seg_len;

                memcpy(&d, entry + i * ENA_TX_DESC_SIZE, sizeof(d));
                len_ctrl = le32_to_cpu(d.len_ctrl);
                meta_ctrl = le32_to_cpu(d.meta_ctrl);
                hi = le32_to_cpu(d.buff_addr_hi_hdr_sz);

                if (len_ctrl & ENA_ETH_IO_TX_DESC_META_DESC_MASK) {
                    continue;   /* offload hints, which this model has none of */
                }
                if (!started) {
                    uint16_t hdr_len =
                        (hi & ENA_ETH_IO_TX_DESC_HEADER_LENGTH_MASK) >>
                        ENA_ETH_IO_TX_DESC_HEADER_LENGTH_SHIFT;
                    uint32_t hdr_off =
                        s->llq_descs_before_header * ENA_TX_DESC_SIZE;

                    req_id = ((len_ctrl & ENA_ETH_IO_TX_DESC_REQ_ID_HI_MASK) >>
                              ENA_ETH_IO_TX_DESC_REQ_ID_HI_SHIFT) << 10;
                    req_id |= (meta_ctrl & ENA_ETH_IO_TX_DESC_REQ_ID_LO_MASK) >>
                              ENA_ETH_IO_TX_DESC_REQ_ID_LO_SHIFT;

                    if (hdr_len > 0) {
                        if (hdr_off + hdr_len > s->llq_entry_size) {
                            qemu_log_mask(LOG_GUEST_ERROR,
                                          "ena: inline header of %u bytes at "
                                          "%u does not fit a %u-byte entry\n",
                                          hdr_len, hdr_off, s->llq_entry_size);
                            return;
                        }
                        memcpy(frame, entry + hdr_off, hdr_len);
                        got = hdr_len;
                    }
                    started = true;
                }
                last = (len_ctrl & ENA_ETH_IO_TX_DESC_LAST_MASK) != 0;

                seg_len = len_ctrl & ENA_ETH_IO_TX_DESC_LENGTH_MASK;
                addr = (uint64_t)le32_to_cpu(d.buff_addr_lo) |
                       ((uint64_t)(hi &
                           ~ENA_ETH_IO_TX_DESC_HEADER_LENGTH_MASK) << 32);
                if (seg_len == 0 || got + seg_len > sizeof(frame)) {
                    continue;
                }
                pci_dma_read(PCI_DEVICE(s), addr, frame + got, seg_len);
                got += seg_len;
            }
            first_entry = false;
        }

        if (!last) {
            /* The packet runs into entries the guest has not posted yet. */
            break;
        }
        ENA_TRACE("tx llq req_id=%u len=%u", req_id, got);
        if (got > 0) {
            qemu_send_packet(qemu_get_queue(s->nic), frame, got);
            s->tx_bytes += got;
            s->tx_pkts++;
        }
        ena_tx_complete(s, sq, req_id);
    }
}

/*
 * A packet is a run of descriptors from the one with FIRST set to the one
 * with LAST set; each carries a segment. In host placement the buffer
 * address is an ordinary guest address rather than an offset into anything.
 */
static void ena_tx_run(EnaState *s, EnaQueue *sq)
{
    uint8_t frame[ENA_MAX_FRAME];

    for (uint32_t budget = sq->depth; budget > 0 && sq->head != sq->tail;
         budget--) {
        uint32_t got = 0;
        uint16_t req_id = 0;
        bool first = true, last = false;

        while (sq->head != sq->tail && !last) {
            struct ena_eth_io_tx_desc d;
            uint16_t slot = sq->head & (sq->depth - 1);
            uint32_t len_ctrl, meta_ctrl;
            uint64_t addr;
            uint16_t seg_len;

            pci_dma_read(PCI_DEVICE(s),
                         sq->base + (uint64_t)slot * sizeof(d), &d, sizeof(d));
            len_ctrl = le32_to_cpu(d.len_ctrl);
            meta_ctrl = le32_to_cpu(d.meta_ctrl);
            sq->head++;

            if (len_ctrl & ENA_ETH_IO_TX_DESC_META_DESC_MASK) {
                /* A metadata descriptor: TSO and checksum hints we ignore. */
                continue;
            }
            if (first) {
                /*
                 * req_id is split across two fields -- the top six bits in
                 * len_ctrl and the bottom ten in meta_ctrl. It is the value
                 * the driver uses to find the buffer it is waiting to free,
                 * so assembling it wrongly strands every packet.
                 */
                req_id = ((len_ctrl & ENA_ETH_IO_TX_DESC_REQ_ID_HI_MASK) >>
                          ENA_ETH_IO_TX_DESC_REQ_ID_HI_SHIFT) << 10;
                req_id |= (meta_ctrl & ENA_ETH_IO_TX_DESC_REQ_ID_LO_MASK) >>
                          ENA_ETH_IO_TX_DESC_REQ_ID_LO_SHIFT;
                first = false;
            }
            last = (len_ctrl & ENA_ETH_IO_TX_DESC_LAST_MASK) != 0;

            seg_len = len_ctrl & ENA_ETH_IO_TX_DESC_LENGTH_MASK;
            addr = (uint64_t)le32_to_cpu(d.buff_addr_lo) |
                   ((uint64_t)(le32_to_cpu(d.buff_addr_hi_hdr_sz) &
                               ~ENA_ETH_IO_TX_DESC_HEADER_LENGTH_MASK) << 32);

            if (seg_len == 0 || got + seg_len > sizeof(frame)) {
                continue;
            }
            pci_dma_read(PCI_DEVICE(s), addr, frame + got, seg_len);
            got += seg_len;
        }

        if (!last) {
            /* Ran out of posted descriptors mid-packet; wait for the rest. */
            break;
        }
        ENA_TRACE("tx req_id=%u len=%u", req_id, got);
        if (got > 0) {
            qemu_send_packet(qemu_get_queue(s->nic), frame, got);
            s->tx_bytes += got;
            s->tx_pkts++;
        }
        ena_tx_complete(s, sq, req_id);
    }
}

/* ------------------------------------------------------------- receive */

static EnaQueue *ena_rx_sq(EnaState *s)
{
    for (unsigned i = 0; i < ENA_MAX_QUEUES; i++) {
        if (s->sq[i].active && s->sq[i].direction == ENA_SQ_DIRECTION_RX) {
            return &s->sq[i];
        }
    }
    return NULL;
}

static bool ena_can_receive(NetClientState *nc)
{
    EnaState *s = qemu_get_nic_opaque(nc);
    EnaQueue *sq = ena_rx_sq(s);

    /*
     * The receive submission queue holds buffers the guest has handed over.
     * Without one there is nowhere to put a packet, and taking it anyway
     * would mean writing over memory the guest still owns.
     */
    return sq != NULL && sq->head != sq->tail;
}

static ssize_t ena_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    EnaState *s = qemu_get_nic_opaque(nc);
    EnaQueue *sq = ena_rx_sq(s);
    EnaQueue *cq;
    struct ena_eth_io_rx_desc d;
    struct ena_eth_io_rx_cdesc_base c;
    uint64_t addr;
    uint16_t slot, req_id, buf_len;
    uint32_t status;

    if (sq == NULL || sq->head == sq->tail) {
        return 0;
    }
    cq = &s->cq[sq->cq_idx];
    if (!cq->active) {
        return 0;
    }

    slot = sq->head & (sq->depth - 1);
    pci_dma_read(PCI_DEVICE(s), sq->base + (uint64_t)slot * sizeof(d), &d,
                 sizeof(d));

    /*
     * The phase bit, which says whether this position holds a descriptor the
     * driver has published on this lap or last lap's leftovers. A real
     * adapter refuses to consume the latter and so does this.
     *
     * Not checking it is a way for a model to be kinder than the device, and
     * this one was: a driver that wrote each descriptor at the position of
     * the buffer it was recycling rather than at the ring's tail left a
     * correct-looking descriptor at every position -- the stale one names a
     * different buffer, but every buffer is the same size and the driver
     * finds its data through req_id, so the packets kept flowing here and
     * stopped dead on hardware after exactly one trip around the ring.
     */
    if ((d.ctrl & ENA_ETH_IO_RX_DESC_PHASE_MASK) != sq->phase) {
        return 0;
    }

    buf_len = le16_to_cpu(d.length);
    req_id = le16_to_cpu(d.req_id);
    addr = (uint64_t)le32_to_cpu(d.buff_addr_lo) |
           ((uint64_t)le16_to_cpu(d.buff_addr_hi) << 32);

    if (buf_len != 0 && size > buf_len) {
        /*
         * One buffer per packet is what MAX_QUEUES_EXT promised, so a packet
         * that does not fit is dropped rather than split across buffers the
         * driver is not expecting to have to join.
         */
        s->rx_drops++;
        return size;
    }

    pci_dma_write(PCI_DEVICE(s), addr, buf, size);
    sq->head++;
    if ((sq->head & (sq->depth - 1)) == 0) {
        sq->phase = !sq->phase;
    }

    status = ENA_ETH_IO_RX_CDESC_BASE_FIRST_MASK |
             ENA_ETH_IO_RX_CDESC_BASE_LAST_MASK |
             ((uint32_t)(cq->phase & 1) << ENA_ETH_IO_RX_CDESC_BASE_PHASE_SHIFT);

    memset(&c, 0, sizeof(c));
    c.status = cpu_to_le32(status);
    c.length = cpu_to_le16((uint16_t)size);
    c.req_id = cpu_to_le16(req_id);
    c.sub_qid = cpu_to_le16(sq - s->sq);
    c.offset = 0;

    slot = cq->head & (cq->depth - 1);
    pci_dma_write(PCI_DEVICE(s), cq->base + (uint64_t)slot * cq->entry_size,
                  &c, sizeof(c));
    ENA_TRACE("rx req_id=%u len=%zu phase=%u", req_id, size, cq->phase);

    cq->head++;
    if ((cq->head & (cq->depth - 1)) == 0) {
        cq->phase = !cq->phase;
    }

    s->rx_bytes += size;
    s->rx_pkts++;

    if (!cq->masked && msix_enabled(PCI_DEVICE(s)) &&
        cq->msix_vector < ENA_MSIX_VECTORS) {
        msix_notify(PCI_DEVICE(s), cq->msix_vector);
    }
    return size;
}

/* ------------------------------------------------------------ the BAR */

static uint64_t ena_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    EnaState *s = opaque;

    /*
     * A plain load is the fallback path, used only by a driver that found
     * readless reads disabled in the PCI revision id. It is served anyway,
     * because refusing it would make this model disagree with hardware for
     * no reason.
     */
    if (addr < 0x100) {
        return ena_reg_value(s, addr);
    }
    return 0;
}

static void ena_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                           unsigned size)
{
    EnaState *s = opaque;
    uint32_t v = (uint32_t)val;

    if (addr >= ENA_SQ_DB_BASE) {
        unsigned idx = (addr - ENA_SQ_DB_BASE) / 4;

        if (addr < ENA_CQ_DB_BASE) {
            if (idx < ENA_MAX_QUEUES && s->sq[idx].active) {
                s->sq[idx].tail = (uint16_t)v;
                if (s->sq[idx].direction == ENA_SQ_DIRECTION_TX) {
                    if (s->sq[idx].placement ==
                        ENA_ADMIN_PLACEMENT_POLICY_DEV) {
                        ena_tx_run_llq(s, &s->sq[idx]);
                    } else {
                        ena_tx_run(s, &s->sq[idx]);
                    }
                } else {
                    qemu_flush_queued_packets(qemu_get_queue(s->nic));
                }
            }
            return;
        }
        idx = (addr - ENA_CQ_DB_BASE) / 4;
        if (addr < ENA_CQ_UNMASK_BASE) {
            /* The guest saying how far it has read. Nothing to do. */
            return;
        }
        idx = (addr - ENA_CQ_UNMASK_BASE) / 4;
        if (addr < ENA_CQ_NUMA_BASE) {
            if (idx < ENA_MAX_QUEUES) {
                struct ena_eth_io_intr_reg r = { .intr_control = v };
                s->cq[idx].masked = (r.intr_control &
                                     ENA_ETH_IO_INTR_REG_INTR_UNMASK_MASK) == 0;
            }
            return;
        }
        return;         /* the NUMA hint; this model has one node */
    }

    switch (addr) {
    case ENA_REGS_AQ_BASE_LO_OFF:
        s->aq_base_lo = v;
        break;
    case ENA_REGS_AQ_BASE_HI_OFF:
        s->aq_base_hi = v;
        break;
    case ENA_REGS_AQ_CAPS_OFF:
        s->aq_caps = v;
        break;
    case ENA_REGS_ACQ_BASE_LO_OFF:
        s->acq_base_lo = v;
        break;
    case ENA_REGS_ACQ_BASE_HI_OFF:
        s->acq_base_hi = v;
        break;
    case ENA_REGS_ACQ_CAPS_OFF:
        s->acq_caps = v;
        break;
    case ENA_REGS_AENQ_BASE_LO_OFF:
        s->aenq_base_lo = v;
        break;
    case ENA_REGS_AENQ_BASE_HI_OFF:
        s->aenq_base_hi = v;
        break;
    case ENA_REGS_AENQ_CAPS_OFF:
        s->aenq_caps = v;
        break;
    case ENA_REGS_AENQ_HEAD_DB_OFF:
        s->aenq_head = (uint16_t)v;
        break;
    case ENA_REGS_AQ_DB_OFF:
        /*
         * The admin tail. It is free-running rather than masked, so the
         * device masks it; the phase bit in each entry is the real authority
         * on what is ready, which is why ena_admin_run() needs no argument.
         * It is emphatically not submission queue 0's doorbell -- that lives
         * up at ENA_SQ_DB_BASE, and conflating the two is how gVNIC put an
         * interrupt acknowledgement into a transmit queue.
         */
        s->aq_tail = (uint16_t)v;
        ena_admin_run(s);
        break;
    case ENA_REGS_INTR_MASK_OFF:
        s->intr_mask = v;
        break;
    case ENA_REGS_MMIO_RESP_LO_OFF:
        s->mmio_resp_lo = v;
        break;
    case ENA_REGS_MMIO_RESP_HI_OFF:
        s->mmio_resp_hi = v;
        break;
    case ENA_REGS_MMIO_REG_READ_OFF: {
        uint16_t off = (v & ENA_REGS_MMIO_REG_READ_REG_OFF_MASK) >>
            ENA_REGS_MMIO_REG_READ_REG_OFF_SHIFT;
        uint16_t seq = v & ENA_REGS_MMIO_REG_READ_REQ_ID_MASK;

        ena_mmio_resp_write(s, seq, off, ena_reg_value(s, off));
        break;
    }
    case ENA_REGS_DEV_CTL_OFF:
        s->dev_ctl = v;
        if (v & ENA_REGS_DEV_CTL_DEV_RESET_MASK) {
            /*
             * The guest starts a reset and then waits to see it in progress;
             * clearing DEV_CTL is what tells the device to finish.
             */
            ENA_TRACE("reset requested, reason %u",
                      (v & ENA_REGS_DEV_CTL_RESET_REASON_MASK) >>
                      ENA_REGS_DEV_CTL_RESET_REASON_SHIFT);
            ena_reset_state(s);
            s->dev_sts = ENA_REGS_DEV_STS_READY_MASK |
                         ENA_REGS_DEV_STS_RESET_IN_PROGRESS_MASK;
        } else if (s->dev_sts & ENA_REGS_DEV_STS_RESET_IN_PROGRESS_MASK) {
            s->dev_sts = ENA_REGS_DEV_STS_READY_MASK |
                         ENA_REGS_DEV_STS_RESET_FINISHED_MASK;
        }
        break;
    default:
        break;
    }
}

static const MemoryRegionOps ena_bar0_ops = {
    .read = ena_bar0_read,
    .write = ena_bar0_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/* -------------------------------------------------------------- device */

static void ena_set_link_status(NetClientState *nc)
{
    EnaState *s = qemu_get_nic_opaque(nc);

    if (!nc->link_down) {
        s->link_up_sent = false;
        ena_link_up(s);
    }
}

static NetClientInfo net_ena_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = ena_can_receive,
    .receive = ena_receive,
    .link_status_changed = ena_set_link_status,
};

/*
 * EC2's firmware leaves bus mastering enabled on the ENA function, and at
 * least one production driver depends on that: FreeBSD's ena(4) never calls
 * pci_enable_busmaster() anywhere in its sources, so under a firmware that
 * leaves the bit clear -- SeaBIOS and EDK2 both do, correctly, since it is
 * the OS's job -- the device is unable to answer a single register read. The
 * failure is silent and total: every readless read returns the driver's own
 * poison value and it reports a timeout against a device that is working.
 *
 * Honouring the bit is the correct emulation and this model does. This
 * property exists only so that such a driver can be run as an oracle here,
 * and it is off by default: a guest that wants DMA should ask for it.
 */
static void ena_config_write(PCIDevice *d, uint32_t addr, uint32_t val, int l)
{
    EnaState *s = ENA(d);
    uint16_t cmd;

    pci_default_write_config(d, addr, val, l);
    if (!s->firmware_bus_master || !ranges_overlap(addr, l, PCI_COMMAND, 2)) {
        return;
    }
    cmd = pci_get_word(d->config + PCI_COMMAND);
    if (!(cmd & PCI_COMMAND_MASTER)) {
        pci_default_write_config(d, PCI_COMMAND, cmd | PCI_COMMAND_MASTER, 2);
    }
}

static void ena_reset(DeviceState *dev)
{
    EnaState *s = ENA(dev);

    ena_reset_state(s);
    s->mmio_resp_lo = s->mmio_resp_hi = 0;
    s->dev_ctl = 0;
}

static void ena_realize(PCIDevice *pci_dev, Error **errp)
{
    EnaState *s = ENA(pci_dev);

    pci_dev->config[PCI_INTERRUPT_PIN] = 0;
    /*
     * Revision zero leaves ENA_MMIO_DISABLE_REG_READ clear, which is what
     * tells a driver that readless register reads work. They do.
     */
    pci_config_set_revision(pci_dev->config, 0);

    memory_region_init_io(&s->reg_bar, OBJECT(s), &ena_bar0_ops, s,
                          "ena-regs", ENA_REG_BAR_SIZE);
    pci_register_bar(pci_dev, ENA_REG_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &s->reg_bar);

    /*
     * A real ENA is a PCI Express virtual function, and saying so is not
     * cosmetic: FreeBSD refuses MSI-X outright on a machine where it has
     * found neither a PCI Express nor a PCI-X chipset, so a device that
     * presents itself as conventional PCI can be denied interrupts for a
     * reason that has nothing to do with the device.
     */
    if (pcie_endpoint_cap_init(pci_dev, 0xa0) < 0) {
        error_setg(errp, "failed to initialise the PCI Express capability");
        return;
    }

    if (!memory_region_init_ram(&s->llq_bar, OBJECT(s), "ena-llq",
                                ENA_LLQ_BAR_SIZE, errp)) {
        return;
    }
    s->llq_mem = memory_region_get_ram_ptr(&s->llq_bar);
    pci_register_bar(pci_dev, ENA_MEM_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64 |
                     PCI_BASE_ADDRESS_MEM_PREFETCH, &s->llq_bar);

    if (msix_init_exclusive_bar(pci_dev, ENA_MSIX_VECTORS, ENA_MSIX_BAR,
                                errp) < 0) {
        return;
    }
    for (unsigned i = 0; i < ENA_MSIX_VECTORS; i++) {
        msix_vector_use(pci_dev, i);
    }

    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    s->nic = qemu_new_nic(&net_ena_info, &s->conf, object_get_typename(OBJECT(s)),
                          pci_dev->qdev.id, &pci_dev->qdev.mem_reentrancy_guard,
                          s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);

    ena_reset_state(s);
}

static void ena_exit(PCIDevice *pci_dev)
{
    EnaState *s = ENA(pci_dev);

    qemu_del_nic(s->nic);
    msix_uninit_exclusive_bar(pci_dev);
}

static const VMStateDescription vmstate_ena = {
    .name = TYPE_ENA,
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, EnaState),
        VMSTATE_END_OF_LIST()
    }
};

static const Property ena_properties[] = {
    DEFINE_NIC_PROPERTIES(EnaState, conf),
    DEFINE_PROP_BOOL("firmware-bus-master", EnaState, firmware_bus_master,
                     false),
};

static void ena_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = ena_realize;
    k->exit = ena_exit;
    k->config_write = ena_config_write;
    k->vendor_id = PCI_VENDOR_ID_AMAZON;
    k->device_id = PCI_DEV_ID_ENA_VF;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    k->revision = 0;

    dc->desc = "AWS Elastic Network Adapter";
    dc->vmsd = &vmstate_ena;
    device_class_set_props(dc, ena_properties);
    device_class_set_legacy_reset(dc, ena_reset);
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static const TypeInfo ena_types[] = {
    {
        .name          = TYPE_ENA,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(EnaState),
        .class_init    = ena_class_init,
        .interfaces    = (const InterfaceInfo[]) {
            { INTERFACE_PCIE_DEVICE },
            { },
        },
    },
};

DEFINE_TYPES(ena_types)
