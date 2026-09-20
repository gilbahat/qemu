/*
 * gVNIC (Google Virtual NIC) device model
 *
 * Copyright (c) 2026 Contributors as noted in the AUTHORS file
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * gVNIC is the network device Google Compute Engine presents to its guests.
 * It is not virtio, and on newer GCE machine families -- the Arm T2A line, C3,
 * and every high-bandwidth tier -- it is the only thing on offer. Nothing
 * emulated it before this, which made a guest driver for it impossible to
 * develop anywhere but inside GCE.
 *
 * Written from the two published drivers, both of which Google wrote:
 *
 *   FreeBSD  sys/dev/gve/            BSD-3-Clause
 *   Linux    drivers/net/ethernet/google/gve/   GPL-2.0 OR MIT
 *
 * The wire format is pinned by static assertions in both, which is what makes
 * a device model tractable: every admin command is 64 bytes, every multi-byte
 * field is big-endian, and the descriptor sizes are fixed.
 *
 * Scope: the GQI-QPL datapath only. A queue page list is a set of guest pages
 * registered up front, through which the device copies -- so descriptors carry
 * offsets into that list rather than addresses, and the device never touches
 * guest memory it was not explicitly handed. The DQO formats are newer, faster
 * and out-of-order, and are not implemented here.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/msix.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "net/net.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qom/object.h"
#include "system/dma.h"

#define TYPE_GVNIC "gvnic"
OBJECT_DECLARE_SIMPLE_TYPE(GvnicState, GVNIC)

#define PCI_VENDOR_ID_GOOGLE    0x1ae0
#define PCI_DEVICE_ID_GVNIC     0x0042

/*
 * BAR0, the register file. Offsets are from gve_register.h; every field is
 * big-endian, including the ones the guest only reads.
 */
#define GVNIC_BAR0_SIZE         0x1000
#define GVNIC_REG_DEVICE_STATUS     0x00
#define GVNIC_REG_DRIVER_STATUS     0x04
#define GVNIC_REG_MAX_TX_QUEUES     0x08
#define GVNIC_REG_MAX_RX_QUEUES     0x0c
#define GVNIC_REG_ADMINQ_PFN        0x10
#define GVNIC_REG_ADMINQ_DOORBELL   0x14
#define GVNIC_REG_ADMINQ_EVENT_CNT  0x18
#define GVNIC_REG_DRIVER_VERSION    0x1f
#define GVNIC_REG_ADMINQ_BASE_HI    0x20
#define GVNIC_REG_ADMINQ_BASE_LO    0x24
#define GVNIC_REG_ADMINQ_LENGTH     0x28

#define GVNIC_DEVICE_STATUS_RESET   (1u << 1)
#define GVNIC_DEVICE_STATUS_LINK_UP (1u << 2)

/* What the guest writes to DRIVER_STATUS to say it is running. */
#define GVNIC_DRIVER_STATUS_RUN     (1u << 0)

#define GVNIC_MSIX_VECTORS      8

/* The largest frame this model will assemble or deliver. */
#define GVNIC_MAX_FRAME         (16 * 1024)

/* How many distinct guest addresses the differential trace will name. */
#define GVNIC_SYMS_MAX 64

/* BAR2, the doorbells: an array of big-endian words, one per queue index. */
#define GVNIC_BAR2_SIZE         0x1000
#define GVNIC_MAX_QUEUES        16
/*
 * BAR2 is one flat array of 4-byte doorbells, and queue doorbells are not the
 * only things in it: every notification block owns one too, used to
 * acknowledge and mask its interrupt. Both sets are assigned by the device --
 * the guest reads back where they landed -- so they must not overlap, and the
 * device is the only party in a position to keep them apart.
 */
#define GVNIC_DB_SLOTS          (GVNIC_BAR2_SIZE / 4)
#define GVNIC_MAX_NTFY          32

/* Values the guest writes to a notification block's doorbell. */
#define GVNIC_IRQ_ACK           (1u << 31)
#define GVNIC_IRQ_MASK          (1u << 30)
#define GVNIC_IRQ_EVENT         (1u << 29)

/* Admin queue. */
#define GVNIC_ADMINQ_CMD_SIZE   64
#define GVNIC_ADMINQ_MAX_CMDS   (GVNIC_BAR0_SIZE / GVNIC_ADMINQ_CMD_SIZE)

enum {
    GVNIC_ADMINQ_DESCRIBE_DEVICE            = 0x1,
    GVNIC_ADMINQ_CONFIGURE_DEVICE_RESOURCES = 0x2,
    GVNIC_ADMINQ_REGISTER_PAGE_LIST         = 0x3,
    GVNIC_ADMINQ_UNREGISTER_PAGE_LIST       = 0x4,
    GVNIC_ADMINQ_CREATE_TX_QUEUE            = 0x5,
    GVNIC_ADMINQ_CREATE_RX_QUEUE            = 0x6,
    GVNIC_ADMINQ_DESTROY_TX_QUEUE           = 0x7,
    GVNIC_ADMINQ_DESTROY_RX_QUEUE           = 0x8,
    GVNIC_ADMINQ_DECONFIGURE_DEVICE_RESOURCES = 0x9,
    GVNIC_ADMINQ_SET_DRIVER_PARAMETER       = 0xB,
    GVNIC_ADMINQ_REPORT_STATS               = 0xC,
    GVNIC_ADMINQ_REPORT_LINK_SPEED          = 0xD,
    GVNIC_ADMINQ_GET_PTYPE_MAP              = 0xE,
    GVNIC_ADMINQ_VERIFY_DRIVER_COMPATIBILITY = 0xF,
};

/* Admin command status, as the driver polls for it. */
/*
 * Status codes, which are gRPC's canonical codes counted down from
 * 0xffffffff. The two this model returns had the wrong values: 0xFFFFFFF8 is
 * NOT_FOUND and 0xFFFFFFF2 is CANCELLED, so a guest that printed what it was
 * told was told something that happened to be adjacent to the truth. A
 * driver author reading "NOT_FOUND" looks for a missing resource; the model
 * meant "you asked wrongly".
 */
#define GVNIC_ADMINQ_PASSED                 0x1
#define GVNIC_ADMINQ_ERR_INVALID_ARGUMENT   0xFFFFFFF7
#define GVNIC_ADMINQ_ERR_UNIMPLEMENTED      0xFFFFFFFE

/* Device option ids, as they appear in the DESCRIBE_DEVICE reply. */
#define GVNIC_DEV_OPT_ID_GQI_QPL            0x3
#define GVNIC_DEV_OPT_REQ_FEAT_GQI_QPL      0x0

/* Queue formats, as CONFIGURE_DEVICE_RESOURCES selects them. */
#define GVNIC_GQI_RDA_FORMAT    0x1
#define GVNIC_GQI_QPL_FORMAT    0x2
#define GVNIC_DQO_RDA_FORMAT    0x3
#define GVNIC_DQO_QPL_FORMAT    0x4

/* A registered page list: the pages the device may copy through. */
#define GVNIC_MAX_QPLS          4
#define GVNIC_MAX_QPL_PAGES     1024

typedef struct GvnicQpl {
    bool active;
    uint32_t id;
    uint32_t num_pages;
    uint64_t page_size;
    uint64_t pages[GVNIC_MAX_QPL_PAGES];
} GvnicQpl;

typedef struct GvnicQueue {
    bool active;
    uint32_t id;
    uint32_t qpl_id;
    uint64_t resources_addr;    /* where the device publishes db/counter idx */
    uint64_t desc_ring_addr;
    uint64_t data_ring_addr;    /* rx only */
    uint32_t ring_size;
    uint32_t db_index;
    uint32_t counter_index;
    uint32_t ntfy_id;           /* notification block, hence MSI-X vector */
    uint32_t head;              /* device's position in the ring */
    uint16_t buffer_size;       /* rx: what the guest said a slot may hold */
    uint8_t seqno;              /* rx: the 1..7 sequence the driver expects */
} GvnicQueue;

struct GvnicState {
    PCIDevice parent_obj;

    MemoryRegion bar0;
    MemoryRegion bar2;

    NICState *nic;
    NICConf conf;

    /* BAR0 registers the guest writes. */
    uint32_t device_status;
    uint32_t driver_status;
    uint32_t adminq_pfn;
    uint32_t adminq_doorbell;   /* commands the guest has posted, cumulative */
    uint32_t adminq_event_cnt;  /* commands the device has consumed */
    uint32_t adminq_base_hi;
    uint32_t adminq_base_lo;
    uint32_t adminq_length;     /* in bytes */
    uint8_t driver_version;

    /* Doorbells, as written to BAR2. */
    uint32_t doorbell[GVNIC_DB_SLOTS];

    /* Configured by CONFIGURE_DEVICE_RESOURCES. */
    bool resources_configured;
    uint64_t counter_array;
    uint32_t num_counters;
    uint8_t queue_format;
    uint32_t num_ntfy;          /* notification blocks, each owning a doorbell */
    uint32_t ntfy_msix_base;    /* MSI-X vector of notification block 0 */
    bool ntfy_masked[GVNIC_MAX_NTFY];

    GvnicQpl qpl[GVNIC_MAX_QPLS];
    GvnicQueue tx;
    GvnicQueue rx;

    /* Differential trace. */
    char *trace_path;
    FILE *tf;
    int nsyms;
    uint64_t sym_addr[GVNIC_SYMS_MAX];
    char sym_name[GVNIC_SYMS_MAX][8];

    /* Properties. */
    uint16_t mtu;
    uint16_t tx_queue_entries;
    uint16_t rx_queue_entries;
    uint16_t tx_pages_per_qpl;
};

/*
 * Temporary tracing, hard-capped.
 *
 * The doorbell is rung continuously by a busy guest, so an unbounded trace on
 * it does not produce a log, it produces a full filesystem. This one stops
 * after GVNIC_TRACE_MAX lines, which is enough to see how a datapath starts
 * and cannot cost anything if it never stops.
 */
#define GVNIC_TRACE_MAX 200
static int gvnic_trace_left = GVNIC_TRACE_MAX;
#define GVNIC_TRACE(fmt, ...) do { \
    if (gvnic_trace_left > 0) { \
        gvnic_trace_left--; \
        qemu_log_mask(LOG_UNIMP, "gvnic: " fmt "\n", ## __VA_ARGS__); \
    } \
} while (0)

static void gvnic_reset_state(GvnicState *s);
static void gvnic_tx_run(GvnicState *s);

/* ---------------------------------------------------- differential trace */

/*
 * A trace meant to be diffed against another guest's, not read on its own.
 *
 * Google publishes no gVNIC specification, so the only way to settle what a
 * field means is to look at what a driver written by the people who designed
 * the device puts in it. That driver is available and runs against this
 * model; what was missing was a way to capture what it does in a form that
 * can be compared, line by line, with what another driver does.
 *
 * Two things make the output comparable across guests that share nothing:
 *
 *   - **No addresses.** Every guest address is replaced by a symbol assigned
 *     in first-seen order, @A1, @A2 and so on. Two drivers that hand the
 *     device the same *shape* of thing then produce the same text, even
 *     though one is Linux at 0x7f... and the other a unikernel at 0x1000...
 *
 *   - **No timestamps and no counters that only measure the host.** A line
 *     appears when the guest causes it and says only what the guest said.
 *
 * Each admin command is dumped twice: once as raw big-endian words, which is
 * what settles a field's *width* when the two drivers disagree about it, and
 * once decoded. Where a field's width is itself in question the decode prints
 * both readings rather than choosing, because choosing is the bug being
 * looked for.
 *
 * Enabled with -device gvnic,trace=FILE. Off, it costs a branch.
 */
static const char *gvnic_sym(GvnicState *s, uint64_t addr)
{
    if (addr == 0) {
        return "0";
    }
    for (int i = 0; i < s->nsyms; i++) {
        if (s->sym_addr[i] == addr) {
            return s->sym_name[i];
        }
    }
    if (s->nsyms < GVNIC_SYMS_MAX) {
        int i = s->nsyms++;
        s->sym_addr[i] = addr;
        snprintf(s->sym_name[i], sizeof(s->sym_name[i]), "@A%d", i + 1);
        return s->sym_name[i];
    }
    return "@A?";
}

static void G_GNUC_PRINTF(2, 3) gvnic_tr(GvnicState *s, const char *fmt, ...)
{
    va_list ap;

    if (s->tf == NULL) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(s->tf, fmt, ap);
    va_end(ap);
    fputc('\n', s->tf);
    fflush(s->tf);
}

static const char *gvnic_opcode_name(uint32_t op)
{
    switch (op) {
    case GVNIC_ADMINQ_DESCRIBE_DEVICE:              return "DESCRIBE_DEVICE";
    case GVNIC_ADMINQ_CONFIGURE_DEVICE_RESOURCES:   return "CONFIGURE_RESOURCES";
    case GVNIC_ADMINQ_REGISTER_PAGE_LIST:           return "REGISTER_PAGE_LIST";
    case GVNIC_ADMINQ_UNREGISTER_PAGE_LIST:         return "UNREGISTER_PAGE_LIST";
    case GVNIC_ADMINQ_CREATE_TX_QUEUE:              return "CREATE_TX_QUEUE";
    case GVNIC_ADMINQ_CREATE_RX_QUEUE:              return "CREATE_RX_QUEUE";
    case GVNIC_ADMINQ_DESTROY_TX_QUEUE:             return "DESTROY_TX_QUEUE";
    case GVNIC_ADMINQ_DESTROY_RX_QUEUE:             return "DESTROY_RX_QUEUE";
    case GVNIC_ADMINQ_DECONFIGURE_DEVICE_RESOURCES: return "DECONFIGURE_RESOURCES";
    case GVNIC_ADMINQ_SET_DRIVER_PARAMETER:         return "SET_DRIVER_PARAMETER";
    case GVNIC_ADMINQ_REPORT_STATS:                 return "REPORT_STATS";
    case GVNIC_ADMINQ_REPORT_LINK_SPEED:            return "REPORT_LINK_SPEED";
    case GVNIC_ADMINQ_GET_PTYPE_MAP:                return "GET_PTYPE_MAP";
    case GVNIC_ADMINQ_VERIFY_DRIVER_COMPATIBILITY:  return "VERIFY_DRIVER_COMPAT";
    default:                                        return "UNKNOWN";
    }
}

/*
 * The raw command as sixteen big-endian words. Word 1 is the status, which
 * the device fills in, so it is printed as -- : it is not something the
 * driver said and two drivers must not be made to differ over it.
 */
static void gvnic_trace_raw(GvnicState *s, const uint8_t *cmd)
{
    char line[16 * 9 + 8];
    int n = 0;

    for (int i = 0; i < 16; i++) {
        if (i == 1) {
            n += snprintf(line + n, sizeof(line) - n, "-------- ");
        } else {
            n += snprintf(line + n, sizeof(line) - n, "%08x ",
                          ldl_be_p(cmd + i * 4));
        }
    }
    gvnic_tr(s, "  raw %s", line);
}

static void gvnic_trace_adminq(GvnicState *s, const uint8_t *cmd,
                               uint32_t status)
{
    uint32_t op = ldl_be_p(cmd);

    if (s->tf == NULL) {
        return;
    }
    gvnic_tr(s, "ADMINQ %s(0x%x) status=%s", gvnic_opcode_name(op), op,
             status == GVNIC_ADMINQ_PASSED ? "PASSED" : "REFUSED");
    gvnic_trace_raw(s, cmd);

    switch (op) {
    case GVNIC_ADMINQ_DESCRIBE_DEVICE:
        gvnic_tr(s, "  desc=%s version=%u avail_len=%u",
                 gvnic_sym(s, ldq_be_p(cmd + 8)), ldl_be_p(cmd + 16),
                 ldl_be_p(cmd + 20));
        break;
    case GVNIC_ADMINQ_CONFIGURE_DEVICE_RESOURCES:
        gvnic_tr(s, "  counters=%s irq_db=%s num_counters=%u num_irq_dbs=%u "
                    "irq_db_stride=%u ntfy_msix_base=%u queue_format=%u",
                 gvnic_sym(s, ldq_be_p(cmd + 8)),
                 gvnic_sym(s, ldq_be_p(cmd + 16)),
                 ldl_be_p(cmd + 24), ldl_be_p(cmd + 28), ldl_be_p(cmd + 32),
                 ldl_be_p(cmd + 36), cmd[40]);
        break;
    case GVNIC_ADMINQ_REGISTER_PAGE_LIST:
        gvnic_tr(s, "  qpl_id=%u num_pages=%u list=%s page_size=%" PRIu64,
                 ldl_be_p(cmd + 8), ldl_be_p(cmd + 12),
                 gvnic_sym(s, ldq_be_p(cmd + 16)), ldq_be_p(cmd + 24));
        break;
    case GVNIC_ADMINQ_UNREGISTER_PAGE_LIST:
        gvnic_tr(s, "  qpl_id=%u", ldl_be_p(cmd + 8));
        break;
    case GVNIC_ADMINQ_CREATE_TX_QUEUE:
        /*
         * tx_ring_size is sixteen bits at 48 and packet_format the sixteen
         * after it; both readings are printed because a driver that writes a
         * 32-bit value there puts the number in the half this does not read.
         */
        gvnic_tr(s, "  queue_id=%u res=%s ring=%s qpl_id=%u ntfy_id=%u "
                    "comp_ring=%s ring_size16=%u packet_format16=%u "
                    "[word48=0x%08x]",
                 ldl_be_p(cmd + 8), gvnic_sym(s, ldq_be_p(cmd + 16)),
                 gvnic_sym(s, ldq_be_p(cmd + 24)), ldl_be_p(cmd + 32),
                 ldl_be_p(cmd + 36), gvnic_sym(s, ldq_be_p(cmd + 40)),
                 lduw_be_p(cmd + 48), lduw_be_p(cmd + 50),
                 ldl_be_p(cmd + 48));
        break;
    case GVNIC_ADMINQ_CREATE_RX_QUEUE:
        /*
         * And the same question at 52, which is the one that matters most:
         * if rx_ring_size is 32 bits there, a driver writing sixteen puts the
         * ring size in the high half and the device reads zero.
         */
        gvnic_tr(s, "  queue_id=%u index=%u ntfy_id=%u res=%s desc_ring=%s "
                    "data_ring=%s qpl_id=%u ring_size=%u packet_buffer_size=%u "
                    "[word52=0x%08x word56=0x%08x]",
                 ldl_be_p(cmd + 8), ldl_be_p(cmd + 12), ldl_be_p(cmd + 20),
                 gvnic_sym(s, ldq_be_p(cmd + 24)),
                 gvnic_sym(s, ldq_be_p(cmd + 32)),
                 gvnic_sym(s, ldq_be_p(cmd + 40)), ldl_be_p(cmd + 48),
                 lduw_be_p(cmd + 52), lduw_be_p(cmd + 54),
                 ldl_be_p(cmd + 52), ldl_be_p(cmd + 56));
        break;
    case GVNIC_ADMINQ_DESTROY_TX_QUEUE:
    case GVNIC_ADMINQ_DESTROY_RX_QUEUE:
        gvnic_tr(s, "  queue_id=%u", ldl_be_p(cmd + 8));
        break;
    case GVNIC_ADMINQ_VERIFY_DRIVER_COMPATIBILITY:
        gvnic_tr(s, "  driver_info=%s len=%u",
                 gvnic_sym(s, ldq_be_p(cmd + 16)), ldl_be_p(cmd + 8));
        break;
    default:
        break;
    }
}

/*
 * A QPL is an ordered list of pages and a descriptor addresses it by byte
 * offset, so every access has to be split at a page boundary. Both helpers
 * refuse an offset the list does not cover rather than clamping: a driver bug
 * should look like a driver bug, not like a short packet.
 */
static bool gvnic_qpl_rw(GvnicState *s, GvnicQpl *qpl, uint64_t offset,
                         void *buf, size_t len, bool is_write)
{
    uint8_t *p = buf;

    if (!qpl->active || qpl->page_size == 0) {
        return false;
    }
    if (offset + len > (uint64_t)qpl->num_pages * qpl->page_size) {
        return false;
    }

    while (len > 0) {
        uint64_t page = offset / qpl->page_size;
        uint64_t in_page = offset % qpl->page_size;
        size_t n = MIN(len, qpl->page_size - in_page);

        if (page >= qpl->num_pages) {
            return false;
        }
        if (is_write) {
            pci_dma_write(PCI_DEVICE(s), qpl->pages[page] + in_page, p, n);
        } else {
            pci_dma_read(PCI_DEVICE(s), qpl->pages[page] + in_page, p, n);
        }
        p += n;
        offset += n;
        len -= n;
    }
    return true;
}

static GvnicQpl *gvnic_qpl_find(GvnicState *s, uint32_t id)
{
    for (int i = 0; i < GVNIC_MAX_QPLS; i++) {
        if (s->qpl[i].active && s->qpl[i].id == id) {
            return &s->qpl[i];
        }
    }
    return NULL;
}

/*
 * DESCRIBE_DEVICE: the device writes a descriptor, then a list of options, to
 * an address the guest supplies. Only GQI-QPL is offered -- a driver that
 * cannot use it will say so rather than negotiating something this model does
 * not implement.
 */
static uint32_t gvnic_describe_device(GvnicState *s, const uint8_t *cmd)
{
    uint64_t addr = ldq_be_p(cmd + 8);
    uint32_t avail = ldl_be_p(cmd + 20);
    uint8_t buf[40 + 8 + 4];
    uint8_t *d = buf;
    uint8_t *o = buf + 40;

    if (avail < sizeof(buf)) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }

    memset(buf, 0, sizeof(buf));

    /* struct gve_device_descriptor, 40 bytes. */
    stq_be_p(d + 0, GVNIC_MAX_QPLS * GVNIC_MAX_QPL_PAGES); /* max_registered_pages */
    stw_be_p(d + 10, s->tx_queue_entries);
    stw_be_p(d + 12, s->rx_queue_entries);
    stw_be_p(d + 14, 1);                    /* default_num_queues */
    stw_be_p(d + 16, s->mtu);
    stw_be_p(d + 18, 1);                    /* counters */
    /*
     * tx_pages_per_qpl, and worth a note because the two references disagree
     * about this field: FreeBSD's struct calls offset 20 "reserved2" and
     * Linux calls it tx_pages_per_qpl and sizes its transmit FIFO from it.
     * Leaving it zero is not benign -- Linux then vmaps a zero-page FIFO,
     * which fails, and reports "Failed to vmap fifo" with -ENOMEM, an error
     * that says nothing about where the zero came from.
     */
    stw_be_p(d + 20, s->tx_pages_per_qpl);
    stw_be_p(d + 22, s->rx_queue_entries);  /* rx_pages_per_qpl */
    memcpy(d + 24, s->conf.macaddr.a, 6);
    stw_be_p(d + 30, 1);                    /* num_device_options */
    stw_be_p(d + 32, sizeof(buf));          /* total_length */

    /* struct gve_device_option, 8 bytes, then its 4-byte GQI-QPL body. */
    stw_be_p(o + 0, GVNIC_DEV_OPT_ID_GQI_QPL);
    stw_be_p(o + 2, 4);
    stl_be_p(o + 4, GVNIC_DEV_OPT_REQ_FEAT_GQI_QPL);
    stl_be_p(o + 8, 0);                     /* supported_features_mask */

    pci_dma_write(PCI_DEVICE(s), addr, buf, sizeof(buf));
    return GVNIC_ADMINQ_PASSED;
}

/*
 * Offsets below are into the whole 64-byte command, so every field of a
 * command's own structure sits 8 bytes further along than its declaration
 * suggests: opcode and status come first. Getting that wrong is silent --
 * queue_format lives at 40, and reading 36 finds ntfy_blk_msix_base_idx,
 * which is a perfectly plausible zero.
 */
static uint32_t gvnic_configure_resources(GvnicState *s, const uint8_t *cmd)
{
    uint8_t format = cmd[40];

    if (format != GVNIC_GQI_QPL_FORMAT) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "gvnic: driver asked for queue format %u; this model "
                      "implements GQI-QPL (%u) only\n",
                      format, GVNIC_GQI_QPL_FORMAT);
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }

    uint64_t irq_db_addr = ldq_be_p(cmd + 16);
    uint32_t num_irq_dbs = ldl_be_p(cmd + 28);
    uint32_t irq_db_stride = ldl_be_p(cmd + 32);

    if (num_irq_dbs > GVNIC_MAX_NTFY ||
        num_irq_dbs + GVNIC_MAX_QUEUES > GVNIC_DB_SLOTS) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }

    s->counter_array = ldq_be_p(cmd + 8);
    s->num_counters = ldl_be_p(cmd + 24);
    s->num_ntfy = num_irq_dbs;
    s->ntfy_msix_base = ldl_be_p(cmd + 36);
    memset(s->ntfy_masked, 0, sizeof(s->ntfy_masked));

    /*
     * Notification block i acknowledges through doorbell slot i, and the
     * queues are pushed up above them by gvnic_queue_db_index(). The guest
     * allocated this array and left it zeroed; a device that leaves it that
     * way sends every interrupt acknowledgement into queue 0's doorbell,
     * where it is read as a wild descriptor count -- GVE_IRQ_ACK|GVE_IRQ_EVENT
     * decodes as a request to transmit 0xa0000000 descriptors.
     */
    for (uint32_t i = 0; i < num_irq_dbs; i++) {
        uint32_t be = cpu_to_be32(i);

        pci_dma_write(PCI_DEVICE(s), irq_db_addr + (uint64_t)i * irq_db_stride,
                      &be, 4);
    }

    s->queue_format = format;
    s->resources_configured = true;
    GVNIC_TRACE("configure: counters@0x%" PRIx64 " n=%u ntfy=%u stride=%u "
                "msix_base=%u format=%u", s->counter_array, s->num_counters,
                num_irq_dbs, irq_db_stride, s->ntfy_msix_base, format);
    return GVNIC_ADMINQ_PASSED;
}

static uint32_t gvnic_register_page_list(GvnicState *s, const uint8_t *cmd)
{
    uint32_t id = ldl_be_p(cmd + 8);
    uint32_t num_pages = ldl_be_p(cmd + 12);
    uint64_t list_addr = ldq_be_p(cmd + 16);
    uint64_t page_size = ldq_be_p(cmd + 24);
    GvnicQpl *qpl = NULL;

    /*
     * page_size is younger than the structure that carries it. Linux 6.1
     * memsets the command and fills only the id, the count and the list
     * address, so a device that insists on a non-zero page size refuses a
     * perfectly good registration from any driver of that vintage -- and
     * says only "failed to register queue page list 0" while doing it.
     * Zero means the host page size, which is the only value anything has
     * ever used here.
     */
    if (page_size == 0) {
        page_size = 4096;
    }
    if (num_pages == 0 || num_pages > GVNIC_MAX_QPL_PAGES) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    if (gvnic_qpl_find(s, id) != NULL) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    for (int i = 0; i < GVNIC_MAX_QPLS; i++) {
        if (!s->qpl[i].active) {
            qpl = &s->qpl[i];
            break;
        }
    }
    if (qpl == NULL) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < num_pages; i++) {
        uint64_t be;

        pci_dma_read(PCI_DEVICE(s), list_addr + i * 8, &be, 8);
        qpl->pages[i] = be64_to_cpu(be);
    }
    gvnic_tr(s, "  QPL id=%u pages=%u page_size=%" PRIu64 " first=%s last=%s",
             id, num_pages, page_size, gvnic_sym(s, qpl->pages[0]),
             gvnic_sym(s, qpl->pages[num_pages - 1]));

    qpl->id = id;
    qpl->num_pages = num_pages;
    qpl->page_size = page_size;
    qpl->active = true;
    return GVNIC_ADMINQ_PASSED;
}

static uint32_t gvnic_unregister_page_list(GvnicState *s, const uint8_t *cmd)
{
    GvnicQpl *qpl = gvnic_qpl_find(s, ldl_be_p(cmd + 8));

    if (qpl == NULL) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    qpl->active = false;
    return GVNIC_ADMINQ_PASSED;
}

/*
 * The device tells the guest, through the queue resources block, which
 * doorbell slot and which counter belong to this queue. Both drivers read
 * those back rather than assuming, so they have to be written.
 */
static uint32_t gvnic_queue_db_index(GvnicState *s, uint32_t which)
{
    return s->num_ntfy + which;
}

static void gvnic_publish_queue_resources(GvnicState *s, GvnicQueue *q)
{
    uint8_t res[64];

    memset(res, 0, sizeof(res));
    stl_be_p(res + 0, q->db_index);
    stl_be_p(res + 4, q->counter_index);
    pci_dma_write(PCI_DEVICE(s), q->resources_addr, res, sizeof(res));
}

/*
 * Ring sizes, judged the way a real adapter judges them.
 *
 * Zero means "your choice", which is what Linux sends and so must stay valid.
 * Anything else is checked, and checked strictly: a real device refuses a
 * 64-entry transmit ring with INVALID_ARGUMENT and accepts 256, so there is a
 * minimum somewhere in between that this model previously did not have at
 * all. It took whatever it was given, which is how a driver that asked for 64
 * passed every local test and was refused by the first instance it met.
 *
 * GVNIC_RING_MIN is 256 because that is the smallest size observed to be
 * accepted; the true threshold is somewhere in (64, 256] and untested. Being
 * stricter than the device is the safe direction for a fixture -- a guest
 * that satisfies this satisfies hardware -- and being more permissive is
 * precisely the failure this model has already made once.
 */
#define GVNIC_RING_MIN 256

static bool gvnic_ring_size_ok(uint32_t size, uint16_t advertised)
{
    if (size == 0) {
        return true;            /* the device's own default */
    }
    if (size < GVNIC_RING_MIN || size > advertised) {
        return false;
    }
    return (size & (size - 1)) == 0;
}

static uint32_t gvnic_create_tx_queue(GvnicState *s, const uint8_t *cmd)
{
    GvnicQueue *q = &s->tx;

    if (!s->resources_configured || q->active) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    q->id = ldl_be_p(cmd + 8);
    q->resources_addr = ldq_be_p(cmd + 16);
    q->desc_ring_addr = ldq_be_p(cmd + 24);
    q->qpl_id = ldl_be_p(cmd + 32);
    /* ntfy_id sits at 36 for tx and at 20 for rx; the structures differ. */
    /* Sixteen bits here -- and thirty-two in the receive command. */
    q->ring_size = lduw_be_p(cmd + 48);
    if (!gvnic_ring_size_ok(q->ring_size, s->tx_queue_entries)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "gvnic: transmit ring of %u entries refused; the device "
                      "advertised %u and will not go below %u\n",
                      q->ring_size, s->tx_queue_entries, GVNIC_RING_MIN);
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    if (q->ring_size == 0) {
        q->ring_size = s->tx_queue_entries;
    }
    if (gvnic_qpl_find(s, q->qpl_id) == NULL) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    q->ntfy_id = ldl_be_p(cmd + 36);
    q->db_index = gvnic_queue_db_index(s, 0);
    q->counter_index = 0;
    q->head = 0;
    q->active = true;
    gvnic_publish_queue_resources(s, q);
    return GVNIC_ADMINQ_PASSED;
}

static uint32_t gvnic_create_rx_queue(GvnicState *s, const uint8_t *cmd)
{
    GvnicQueue *q = &s->rx;

    if (!s->resources_configured || q->active) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    q->id = ldl_be_p(cmd + 8);
    q->resources_addr = ldq_be_p(cmd + 24);
    q->desc_ring_addr = ldq_be_p(cmd + 32);
    q->data_ring_addr = ldq_be_p(cmd + 40);
    q->qpl_id = ldl_be_p(cmd + 48);
    /* Sixteen bits, as in the transmit command; the buffer size follows it. */
    q->ring_size = lduw_be_p(cmd + 52);
    q->buffer_size = lduw_be_p(cmd + 54);
    /*
     * A receive queue whose buffers hold nothing is not a queue, and a model
     * that never read this field could not say so: a driver that omitted it
     * entirely looked exactly like one that sent 2048, right up until it met
     * an adapter that reported success and then never wrote a descriptor.
     */
    if (q->buffer_size == 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "gvnic: receive queue created with packet_buffer_size 0 "
                      "at command offset 54; the device has been asked for "
                      "buffers that hold nothing\n");
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    if (q->buffer_size > GVNIC_MAX_FRAME) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    if (!gvnic_ring_size_ok(q->ring_size, s->rx_queue_entries)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "gvnic: receive ring of %u entries refused; the device "
                      "advertised %u and will not go below %u\n",
                      q->ring_size, s->rx_queue_entries, GVNIC_RING_MIN);
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    if (q->ring_size == 0) {
        q->ring_size = s->rx_queue_entries;
    }
    if (gvnic_qpl_find(s, q->qpl_id) == NULL) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    q->ntfy_id = ldl_be_p(cmd + 20);
    q->db_index = gvnic_queue_db_index(s, 1);
    q->counter_index = 0;
    q->head = 0;
    /* The sequence number the driver expects first is 1, not 0. */
    q->seqno = 1;
    q->active = true;
    gvnic_publish_queue_resources(s, q);
    return GVNIC_ADMINQ_PASSED;
}

static uint32_t gvnic_destroy_queue(GvnicQueue *q)
{
    if (!q->active) {
        return GVNIC_ADMINQ_ERR_INVALID_ARGUMENT;
    }
    q->active = false;
    return GVNIC_ADMINQ_PASSED;
}

static uint32_t gvnic_adminq_execute(GvnicState *s, const uint8_t *cmd)
{
    uint32_t opcode = ldl_be_p(cmd);

    switch (opcode) {
    case GVNIC_ADMINQ_DESCRIBE_DEVICE:
        return gvnic_describe_device(s, cmd);
    case GVNIC_ADMINQ_CONFIGURE_DEVICE_RESOURCES:
        return gvnic_configure_resources(s, cmd);
    case GVNIC_ADMINQ_REGISTER_PAGE_LIST:
        return gvnic_register_page_list(s, cmd);
    case GVNIC_ADMINQ_UNREGISTER_PAGE_LIST:
        return gvnic_unregister_page_list(s, cmd);
    case GVNIC_ADMINQ_CREATE_TX_QUEUE:
        return gvnic_create_tx_queue(s, cmd);
    case GVNIC_ADMINQ_CREATE_RX_QUEUE:
        return gvnic_create_rx_queue(s, cmd);
    case GVNIC_ADMINQ_DESTROY_TX_QUEUE:
        return gvnic_destroy_queue(&s->tx);
    case GVNIC_ADMINQ_DESTROY_RX_QUEUE:
        return gvnic_destroy_queue(&s->rx);
    case GVNIC_ADMINQ_DECONFIGURE_DEVICE_RESOURCES:
        s->resources_configured = false;
        return GVNIC_ADMINQ_PASSED;
    /*
     * Accepted and ignored. A driver treats these as advisory -- they report
     * statistics, describe the driver, or ask for a packet-type map that only
     * matters to the DQO datapath -- and failing them turns a working link
     * into a probe failure for no benefit.
     */
    case GVNIC_ADMINQ_VERIFY_DRIVER_COMPATIBILITY:
    case GVNIC_ADMINQ_REPORT_STATS:
    case GVNIC_ADMINQ_SET_DRIVER_PARAMETER:
        return GVNIC_ADMINQ_PASSED;
    default:
        qemu_log_mask(LOG_UNIMP, "gvnic: admin opcode 0x%x\n", opcode);
        return GVNIC_ADMINQ_ERR_UNIMPLEMENTED;
    }
}

/*
 * The doorbell is a cumulative count of commands the guest has posted, so the
 * device runs everything between what it has already consumed and that count.
 * The status is written back into each command and the event counter is
 * bumped, which is what the driver polls.
 */
static void gvnic_adminq_run(GvnicState *s)
{
    uint64_t base = ((uint64_t)s->adminq_base_hi << 32) | s->adminq_base_lo;
    uint32_t slots;

    if (base == 0 || s->adminq_length < GVNIC_ADMINQ_CMD_SIZE) {
        return;
    }
    slots = s->adminq_length / GVNIC_ADMINQ_CMD_SIZE;

    while (s->adminq_event_cnt != s->adminq_doorbell) {
        uint32_t slot = s->adminq_event_cnt % slots;
        uint64_t addr = base + (uint64_t)slot * GVNIC_ADMINQ_CMD_SIZE;
        uint8_t cmd[GVNIC_ADMINQ_CMD_SIZE];
        uint32_t status;

        pci_dma_read(PCI_DEVICE(s), addr, cmd, sizeof(cmd));
        status = gvnic_adminq_execute(s, cmd);
        gvnic_trace_adminq(s, cmd, status);
        stl_be_p(cmd + 4, status);
        pci_dma_write(PCI_DEVICE(s), addr + 4, cmd + 4, 4);

        s->adminq_event_cnt++;
    }
}

static uint64_t gvnic_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    GvnicState *s = opaque;
    uint32_t v = 0;

    switch (addr) {
    case GVNIC_REG_DEVICE_STATUS:
        v = s->device_status;
        break;
    case GVNIC_REG_DRIVER_STATUS:
        v = s->driver_status;
        break;
    /*
     * How many queues the device has room for, which is not how many it
     * creates. Reporting one of each was convenient and wrong in a way that
     * hid a whole class of bug: queue page list ids live in one namespace
     * split at max_tx_queues, so a device advertising one transmit queue
     * makes "receive's first page list" and "id 1" the same number, and a
     * driver that hardcodes 1 is indistinguishable from one that computes it.
     * A real adapter advertises considerably more.
     */
    case GVNIC_REG_MAX_TX_QUEUES:
        v = GVNIC_MAX_QUEUES;
        break;
    case GVNIC_REG_MAX_RX_QUEUES:
        v = GVNIC_MAX_QUEUES;
        break;
    case GVNIC_REG_ADMINQ_PFN:
        v = s->adminq_pfn;
        break;
    case GVNIC_REG_ADMINQ_DOORBELL:
        v = s->adminq_doorbell;
        break;
    case GVNIC_REG_ADMINQ_EVENT_CNT:
        v = s->adminq_event_cnt;
        break;
    case GVNIC_REG_ADMINQ_BASE_HI:
        v = s->adminq_base_hi;
        break;
    case GVNIC_REG_ADMINQ_BASE_LO:
        v = s->adminq_base_lo;
        break;
    case GVNIC_REG_ADMINQ_LENGTH:
        v = s->adminq_length;
        break;
    default:
        return 0;
    }

    /* Every register in this BAR is big-endian on the wire. */
    return size == 4 ? bswap32(v) : v;
}

static const char *gvnic_reg_name(hwaddr addr)
{
    switch (addr) {
    case GVNIC_REG_DEVICE_STATUS:   return "DEVICE_STATUS";
    case GVNIC_REG_DRIVER_STATUS:   return "DRIVER_STATUS";
    case GVNIC_REG_ADMINQ_PFN:      return "ADMINQ_PFN";
    case GVNIC_REG_ADMINQ_DOORBELL: return "ADMINQ_DOORBELL";
    case GVNIC_REG_ADMINQ_BASE_HI:  return "ADMINQ_BASE_HI";
    case GVNIC_REG_ADMINQ_BASE_LO:  return "ADMINQ_BASE_LO";
    case GVNIC_REG_ADMINQ_LENGTH:   return "ADMINQ_LENGTH";
    case GVNIC_REG_DRIVER_VERSION:  return "DRIVER_VERSION";
    default:                        return "?";
    }
}

static void gvnic_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                             unsigned size)
{
    GvnicState *s = opaque;
    uint32_t v = size == 4 ? bswap32((uint32_t)val) : (uint32_t)val;

    /*
     * Register writes, not only admin commands.
     *
     * The first version of this trace covered the admin queue and the
     * doorbells and stopped there, on the reasoning that the registers are a
     * handful of well-understood words. That reasoning hid the one register a
     * driver writes that is not a number: DRIVER_VERSION, which Google's
     * driver fills a byte at a time with a version string before it does
     * anything else. A trace that does not show it cannot show that another
     * driver never wrote it.
     */
    if (addr == GVNIC_REG_DRIVER_VERSION) {
        gvnic_tr(s, "REG %s <- '%c' (0x%02x)", gvnic_reg_name(addr),
                 isprint((int)(uint8_t)val) ? (int)(uint8_t)val : '.',
                 (unsigned)(uint8_t)val);
    } else {
        gvnic_tr(s, "REG %s(0x%02x) <- 0x%08x", gvnic_reg_name(addr),
                 (unsigned)addr, v);
    }

    switch (addr) {
    case GVNIC_REG_DRIVER_STATUS:
        s->driver_status = v;
        /*
         * The base-address path says "run" here rather than by writing a page
         * frame number, so this is where that path leaves reset -- and where
         * clearing it puts the device back into it.
         */
        if (v & GVNIC_DRIVER_STATUS_RUN) {
            s->device_status &= ~GVNIC_DEVICE_STATUS_RESET;
        } else {
            gvnic_reset_state(s);
        }
        break;
    case GVNIC_REG_ADMINQ_PFN:
        /*
         * The legacy way of siting the admin queue: a page frame number rather
         * than a base and a length. Writing zero is how a driver asks for a
         * device reset, and both drivers do that before setting up.
         */
        s->adminq_pfn = v;
        if (v == 0) {
            gvnic_reset_state(s);
        } else {
            s->adminq_base_hi = (uint32_t)(((uint64_t)v << 12) >> 32);
            s->adminq_base_lo = (uint32_t)((uint64_t)v << 12);
            s->adminq_length = GVNIC_BAR0_SIZE;
            /* Out of reset: the guest has given it somewhere to work. */
            s->device_status &= ~GVNIC_DEVICE_STATUS_RESET;
        }
        break;
    case GVNIC_REG_ADMINQ_DOORBELL:
        s->adminq_doorbell = v;
        gvnic_adminq_run(s);
        break;
    case GVNIC_REG_ADMINQ_BASE_HI:
        s->adminq_base_hi = v;
        break;
    case GVNIC_REG_ADMINQ_BASE_LO:
        s->adminq_base_lo = v;
        break;
    case GVNIC_REG_ADMINQ_LENGTH:
        s->adminq_length = v;
        break;
    case GVNIC_REG_DRIVER_VERSION:
        s->driver_version = (uint8_t)val;
        break;
    default:
        break;
    }
}

static const MemoryRegionOps gvnic_bar0_ops = {
    .read = gvnic_bar0_read,
    .write = gvnic_bar0_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static uint64_t gvnic_bar2_read(void *opaque, hwaddr addr, unsigned size)
{
    GvnicState *s = opaque;
    unsigned idx = addr / 4;

    if (idx >= GVNIC_DB_SLOTS) {
        return 0;
    }
    return bswap32(s->doorbell[idx]);
}

static void gvnic_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                             unsigned size)
{
    GvnicState *s = opaque;
    unsigned idx = addr / 4;

    if (idx >= GVNIC_DB_SLOTS) {
        return;
    }
    s->doorbell[idx] = bswap32((uint32_t)val);

    gvnic_tr(s, "DOORBELL %s[%u] = %u",
             idx < s->num_ntfy ? "ntfy" :
             (s->tx.active && idx == s->tx.db_index) ? "tx" :
             (s->rx.active && idx == s->rx.db_index) ? "rx" : "?",
             idx, s->doorbell[idx]);

    if (idx < s->num_ntfy) {
        /*
         * A notification block's doorbell, not a queue's: a set of flags
         * acknowledging the interrupt and saying whether the guest wants the
         * next one. Nothing here is a descriptor count.
         */
        s->ntfy_masked[idx] = (s->doorbell[idx] & GVNIC_IRQ_MASK) != 0;
        GVNIC_TRACE("irq db[%u] = 0x%x (%s)", idx, s->doorbell[idx],
                    s->ntfy_masked[idx] ? "masked" : "unmasked");
        return;
    }
    GVNIC_TRACE("doorbell addr=0x%" HWADDR_PRIx " size=%u raw=0x%" PRIx64
                " -> [%u]=%u", addr, size, val, idx, s->doorbell[idx]);

    if (s->tx.active && idx == s->tx.db_index) {
        gvnic_tx_run(s);
    }
    if (s->rx.active && idx == s->rx.db_index) {
        /* The guest posted buffers; anything queued can now be delivered. */
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}

static const MemoryRegionOps gvnic_bar2_ops = {
    .read = gvnic_bar2_read,
    .write = gvnic_bar2_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

/*
 * Vector 0 is the management interrupt; the queues' vectors start at the base
 * the driver chose in CONFIGURE_DEVICE_RESOURCES, indexed by the notification
 * block the queue was created against.
 */
static void gvnic_raise_irq(GvnicState *s, GvnicQueue *q)
{
    uint32_t vector = s->ntfy_msix_base + q->ntfy_id;

    if (q->ntfy_id < GVNIC_MAX_NTFY && s->ntfy_masked[q->ntfy_id]) {
        return;
    }
    if (msix_enabled(PCI_DEVICE(s)) && vector < GVNIC_MSIX_VECTORS) {
        msix_notify(PCI_DEVICE(s), vector);
    }
}

/*
 * Transmit.
 *
 * The doorbell is a cumulative count of descriptors the guest has posted, so
 * everything between the device's head and that count is ready. A packet is
 * one STD descriptor carrying the total length, optionally followed by
 * further descriptors whose segments continue it; in QPL mode each segment
 * address is a byte offset into the queue page list rather than a guest
 * address, which is the whole point of the format -- the device copies only
 * through pages it was handed.
 */
#define GVNIC_TXD_TYPE_MASK     0xf0
#define GVNIC_TXD_STD           0x00
#define GVNIC_TXD_TSO           0x10
#define GVNIC_TXD_SEG           0x20
#define GVNIC_TXD_MTD           0x30

#define GVNIC_TX_DESC_SIZE      16

static void gvnic_tx_bump_counter(GvnicState *s, uint32_t done)
{
    uint32_t be;

    if (s->counter_array == 0 || s->num_counters == 0) {
        return;
    }
    be = cpu_to_be32(done);
    GVNIC_TRACE("tx counter[%u] <- %u at 0x%" PRIx64, s->tx.counter_index,
                done, s->counter_array + s->tx.counter_index * 4);
    pci_dma_write(PCI_DEVICE(s), s->counter_array + s->tx.counter_index * 4,
                  &be, 4);
    gvnic_raise_irq(s, &s->tx);
}

static void gvnic_tx_run(GvnicState *s)
{
    GvnicQueue *q = &s->tx;
    GvnicQpl *qpl;
    uint32_t target = s->doorbell[q->db_index];

    if (!q->active || q->ring_size == 0) {
        return;
    }
    qpl = gvnic_qpl_find(s, q->qpl_id);
    if (qpl == NULL) {
        GVNIC_TRACE("tx has no qpl %u", q->qpl_id);
        return;
    }
    if (q->head != target) {
        GVNIC_TRACE("tx_run head=%u target=%u ring=%u", q->head, target,
                    q->ring_size);
    }

    /*
     * At most one ring's worth per doorbell. The guest supplies `target` and
     * a wild value -- whether from a driver bug or deliberately -- would
     * otherwise spin this loop billions of times inside a device write, which
     * is a hang QEMU cannot be talked out of.
     */
    for (uint32_t budget = q->ring_size; budget > 0 && q->head != target;
         budget--) {
        uint8_t frame[GVNIC_MAX_FRAME];
        uint8_t desc[GVNIC_TX_DESC_SIZE];
        uint32_t slot = q->head % q->ring_size;
        uint16_t total, got = 0;
        uint8_t type, cnt;

        pci_dma_read(PCI_DEVICE(s),
                     q->desc_ring_addr + (uint64_t)slot * GVNIC_TX_DESC_SIZE,
                     desc, sizeof(desc));
        type = desc[0] & GVNIC_TXD_TYPE_MASK;
        cnt = desc[3];
        total = lduw_be_p(desc + 4);

        if (type != GVNIC_TXD_STD && type != GVNIC_TXD_TSO) {
            /*
             * Not the start of a packet. Either the guest posted a metadata
             * descriptor on its own or the ring is out of step; skip it
             * rather than guessing at a length.
             */
            q->head++;
            continue;
        }
        if (cnt == 0) {
            cnt = 1;
        }
        if (total > sizeof(frame)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "gvnic: tx frame of %u bytes discarded\n", total);
            q->head += cnt;
            continue;
        }

        for (uint8_t i = 0; i < cnt && q->head != target; i++) {
            uint16_t seg_len;
            uint64_t seg_addr;

            slot = q->head % q->ring_size;
            pci_dma_read(PCI_DEVICE(s),
                         q->desc_ring_addr +
                             (uint64_t)slot * GVNIC_TX_DESC_SIZE,
                         desc, sizeof(desc));
            seg_len = lduw_be_p(desc + 6);
            seg_addr = ldq_be_p(desc + 8);
            gvnic_tr(s, "  TXSEG i=%u slot=%u type=0x%02x seg_len=%u "
                        "qpl_off=0x%" PRIx64, i, slot, desc[0], seg_len,
                     seg_addr);

            if (got + seg_len <= total &&
                !gvnic_qpl_rw(s, qpl, seg_addr, frame + got, seg_len, false)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "gvnic: tx segment at qpl offset 0x%" PRIx64
                              " is outside the page list\n", seg_addr);
                got = 0;
                q->head++;
                break;
            }
            if (got + seg_len <= total) {
                got += seg_len;
            }
            q->head++;
        }

        GVNIC_TRACE("tx desc type=0x%02x cnt=%u total=%u got=%u",
                    type, cnt, total, got);
        gvnic_tr(s, "TX slot=%u type=0x%02x cnt=%u total=%u got=%u",
                 (unsigned)(q->head % q->ring_size), type, cnt, total, got);
        if (got > 0) {
            qemu_send_packet(qemu_get_queue(s->nic), frame, got);
        }
    }

    gvnic_tx_bump_counter(s, q->head);
}

/*
 * Receive.
 *
 * The guest posts buffers as offsets in the data ring -- one slot per
 * descriptor -- and the device fills the corresponding descriptor when it has
 * copied a packet in. There is no generation bit: the low three bits of
 * flags_seq carry a sequence number that runs 1..7 and wraps, and the driver
 * compares it with what it expects next, which is why the device has to keep
 * that counter rather than the ring position alone.
 */
#define GVNIC_RX_DESC_SIZE      64
#define GVNIC_RX_DATA_SLOT_SIZE 8
#define GVNIC_RX_PAD            2
/*
 * struct gve_rx_desc is 64 bytes and its last four are the two that matter:
 * 48 bytes of padding, rss_hash, mss, reserved, hdr_len, hdr_off, csum, then
 * len at 60 and flags_seq at 62. Writing them two bytes early lands len in
 * csum and flags_seq in len, so the driver reads its sequence number out of
 * the two bytes nobody wrote, finds zero, and concludes the device has not
 * produced a packet -- forever, and silently.
 */
#define GVNIC_RXD_LEN_OFF       60
#define GVNIC_RXD_FLAGS_SEQ_OFF 62

static bool gvnic_can_receive(NetClientState *nc)
{
    GvnicState *s = qemu_get_nic_opaque(nc);

    if (!s->rx.active || !(s->device_status & GVNIC_DEVICE_STATUS_LINK_UP)) {
        return false;
    }
    /*
     * The RX doorbell is a cumulative count of buffers the guest has posted.
     * Writing past it would overwrite descriptors it has not read and reuse
     * buffers it still owns, so refuse the packet instead and let QEMU
     * re-offer it once the guest rings again.
     */
    return s->doorbell[s->rx.db_index] - s->rx.head > 0;
}

static ssize_t gvnic_receive(NetClientState *nc, const uint8_t *buf,
                             size_t size)
{
    GvnicState *s = qemu_get_nic_opaque(nc);
    GvnicQueue *q = &s->rx;
    GvnicQpl *qpl;
    uint8_t desc[GVNIC_RX_DESC_SIZE];
    uint64_t slot_off;
    uint64_t be_off;
    uint32_t slot;
    uint16_t flags_seq;

    if (!q->active || q->ring_size == 0) {
        return -1;
    }
    if (size + GVNIC_RX_PAD > GVNIC_MAX_FRAME ||
        (q->buffer_size != 0 && size + GVNIC_RX_PAD > q->buffer_size)) {
        /*
         * Longer than the guest said a slot may hold. Dropped rather than
         * written short, because a device that overruns the size it was given
         * is a worse thing to model than one that loses a packet.
         */
        return size;    /* dropped, but accepted from the network */
    }
    qpl = gvnic_qpl_find(s, q->qpl_id);
    if (qpl == NULL) {
        return -1;
    }

    /*
     * No credit accounting beyond the ring itself: the guest owns every slot
     * it has not been handed back, and running into its own unread
     * descriptors is a driver problem rather than one to paper over here.
     */
    slot = q->head % q->ring_size;

    pci_dma_read(PCI_DEVICE(s),
                 q->data_ring_addr + (uint64_t)slot * GVNIC_RX_DATA_SLOT_SIZE,
                 &be_off, sizeof(be_off));
    slot_off = be64_to_cpu(be_off);

    /*
     * Two bytes of padding first, so that the Ethernet header lands on an
     * even address and the IP header on a four-byte one. The drivers expect
     * it and skip it; a device that does not add it hands them a misaligned
     * packet.
     */
    if (!gvnic_qpl_rw(s, qpl, slot_off + GVNIC_RX_PAD, (void *)buf, size,
                      true)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "gvnic: rx buffer at qpl offset 0x%" PRIx64
                      " is outside the page list\n", slot_off);
        return -1;
    }

    memset(desc, 0, sizeof(desc));
    /* len covers the padding: the driver subtracts GVE_RX_PAD from it. */
    stw_be_p(desc + GVNIC_RXD_LEN_OFF, (uint16_t)(size + GVNIC_RX_PAD));
    /*
     * Sequence number only. The remaining flags are offload hints -- IPV4,
     * TCP, UDP and the csum field -- and a device that claims none leaves
     * both drivers to checksum in software, which is correct and slow rather
     * than fast and wrong.
     */
    flags_seq = (uint16_t)(q->seqno & 0x7);
    stw_be_p(desc + GVNIC_RXD_FLAGS_SEQ_OFF, flags_seq);
    GVNIC_TRACE("rx slot=%u qpl_off=0x%" PRIx64 " len=%zu seq=%u",
                slot, slot_off, size, q->seqno & 0x7);

    pci_dma_write(PCI_DEVICE(s),
                  q->desc_ring_addr + (uint64_t)slot * GVNIC_RX_DESC_SIZE,
                  desc, sizeof(desc));

    gvnic_tr(s, "RX slot=%u qpl_off=0x%" PRIx64 " len=%zu seq=%u",
             slot, slot_off, size, q->seqno & 0x7);

    q->head++;
    q->seqno++;
    if ((q->seqno & 0x7) == 0) {
        q->seqno = 1;   /* the sequence is 1..7; zero means "not written" */
    }

    gvnic_raise_irq(s, &s->rx);
    return size;
}

static NetClientInfo net_gvnic_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = gvnic_can_receive,
    .receive = gvnic_receive,
};

static void gvnic_reset_state(GvnicState *s)
{
    s->driver_status = 0;
    s->adminq_doorbell = 0;
    s->adminq_event_cnt = 0;
    s->adminq_base_hi = 0;
    s->adminq_base_lo = 0;
    s->adminq_length = 0;
    s->resources_configured = false;
    s->counter_array = 0;
    s->num_counters = 0;
    s->queue_format = 0;
    memset(s->doorbell, 0, sizeof(s->doorbell));
    memset(s->qpl, 0, sizeof(s->qpl));
    memset(&s->tx, 0, sizeof(s->tx));
    memset(&s->rx, 0, sizeof(s->rx));
    /*
     * In reset, and saying so. A real adapter raises DEVICE_STATUS_RESET when
     * it has let go of its admin queue and clears it once a new one is
     * established, and a driver is entitled to wait for that -- waiting on
     * ADMINQ_PFN alone returns instantly on a device that was never set up,
     * which is not the same question and is how a guest ends up configuring
     * resources on a device that has not reset.
     *
     * This model left the bit clear forever, so a driver that waits for it
     * waits for its whole timeout against a device that is perfectly ready.
     * Being less like the device than the device is costs as much as being
     * more permissive than it.
     */
    s->device_status = GVNIC_DEVICE_STATUS_RESET |
                       GVNIC_DEVICE_STATUS_LINK_UP;
}

static void gvnic_reset(DeviceState *dev)
{
    gvnic_reset_state(GVNIC(dev));
}

static void gvnic_realize(PCIDevice *pci_dev, Error **errp)
{
    GvnicState *s = GVNIC(pci_dev);
    Error *local_err = NULL;

    pci_dev->config[PCI_INTERRUPT_PIN] = 0;
    pci_dev->config_write = pci_default_write_config;

    memory_region_init_io(&s->bar0, OBJECT(s), &gvnic_bar0_ops, s,
                          "gvnic-regs", GVNIC_BAR0_SIZE);
    memory_region_init_io(&s->bar2, OBJECT(s), &gvnic_bar2_ops, s,
                          "gvnic-doorbells", GVNIC_BAR2_SIZE);

    /*
     * BAR0 and BAR2, both 64-bit, which is why they are numbered two apart --
     * a 64-bit BAR consumes the slot after it. That is the layout the real
     * device has and the one both drivers ask for by index.
     */
    pci_register_bar(pci_dev, 0,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &s->bar0);
    pci_register_bar(pci_dev, 2,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &s->bar2);

    /*
     * MSI-X, on its own BAR. Solo5 will never enable it -- every driver in
     * that tree polls -- but the Linux and FreeBSD drivers require it, and
     * they are the oracle this model is judged against.
     *
     * They want one vector for management plus one per queue pair, and refuse
     * to probe with fewer: "gve needs at least 3 MSI-x vectors, but only has
     * 2" is what two got. Eight leaves room for the driver to ask for more
     * queues than this model creates.
     */
    if (msix_init_exclusive_bar(pci_dev, GVNIC_MSIX_VECTORS, 4,
                                &local_err) < 0) {
        error_propagate(errp, local_err);
        return;
    }
    for (int i = 0; i < GVNIC_MSIX_VECTORS; i++) {
        msix_vector_use(pci_dev, i);
    }

    if (s->trace_path != NULL) {
        s->tf = fopen(s->trace_path, "w");
        if (s->tf == NULL) {
            error_setg_errno(errp, errno, "gvnic: cannot open trace file %s",
                             s->trace_path);
            return;
        }
    }

    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    s->nic = qemu_new_nic(&net_gvnic_info, &s->conf,
                          object_get_typename(OBJECT(s)), pci_dev->qdev.id,
                          &pci_dev->qdev.mem_reentrancy_guard, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);

    gvnic_reset_state(s);
}

static void gvnic_uninit(PCIDevice *pci_dev)
{
    GvnicState *s = GVNIC(pci_dev);

    qemu_del_nic(s->nic);
    msix_uninit_exclusive_bar(pci_dev);
    if (s->tf != NULL) {
        fclose(s->tf);
        s->tf = NULL;
    }
}

static const VMStateDescription vmstate_gvnic = {
    .name = "gvnic",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, GvnicState),
        VMSTATE_UINT32(device_status, GvnicState),
        VMSTATE_UINT32(driver_status, GvnicState),
        VMSTATE_UINT32(adminq_doorbell, GvnicState),
        VMSTATE_UINT32(adminq_event_cnt, GvnicState),
        VMSTATE_UINT32(adminq_base_hi, GvnicState),
        VMSTATE_UINT32(adminq_base_lo, GvnicState),
        VMSTATE_UINT32(adminq_length, GvnicState),
        VMSTATE_END_OF_LIST()
    }
};

static const Property gvnic_properties[] = {
    DEFINE_NIC_PROPERTIES(GvnicState, conf),
    DEFINE_PROP_UINT16("mtu", GvnicState, mtu, 1460),
    DEFINE_PROP_UINT16("tx-queue-entries", GvnicState, tx_queue_entries, 256),
    DEFINE_PROP_UINT16("rx-queue-entries", GvnicState, rx_queue_entries, 256),
    DEFINE_PROP_UINT16("tx-pages-per-qpl", GvnicState, tx_pages_per_qpl, 128),
    DEFINE_PROP_STRING("trace", GvnicState, trace_path),
};

static void gvnic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = gvnic_realize;
    k->exit = gvnic_uninit;
    k->vendor_id = PCI_VENDOR_ID_GOOGLE;
    k->device_id = PCI_DEVICE_ID_GVNIC;
    k->revision = 0;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;

    device_class_set_legacy_reset(dc, gvnic_reset);
    dc->desc = "Google Virtual NIC (gVNIC)";
    dc->vmsd = &vmstate_gvnic;
    device_class_set_props(dc, gvnic_properties);
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static const TypeInfo gvnic_types[] = {
    {
        .name          = TYPE_GVNIC,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(GvnicState),
        .class_init    = gvnic_class_init,
        .interfaces    = (const InterfaceInfo[]) {
            { INTERFACE_CONVENTIONAL_PCI_DEVICE },
            { },
        },
    },
};

DEFINE_TYPES(gvnic_types)
