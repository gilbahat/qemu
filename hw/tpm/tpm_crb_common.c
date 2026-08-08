/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * tpm_crb_common.c - QEMU's TPM CRB interface emulator
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * tpm_crb is a device for TPM 2.0 Command Response Buffer (CRB) Interface
 * as defined in TCG PC Client Platform TPM Profile (PTP) Specification
 * Family “2.0” Level 00 Revision 01.03 v22
 *
 * This file holds the register and command handling logic shared by the
 * fixed-address (tpm-crb) and relocatable sysbus (tpm-crb-device) front ends.
 */

#include "qemu/osdep.h"

#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/pci/pci_ids.h"
#include "hw/acpi/tpm.h"
#include "system/tpm_backend.h"
#include "system/tpm_util.h"
#include "tpm_crb.h"
#include "tpm_ppi.h"
#include "trace.h"

#define CRB_INTF_TYPE_CRB_ACTIVE 0b1
#define CRB_INTF_VERSION_CRB 0b1
#define CRB_INTF_CAP_LOCALITY_0_ONLY 0b0
#define CRB_INTF_CAP_IDLE_FAST 0b0
#define CRB_INTF_CAP_XFER_SIZE_64 0b11
#define CRB_INTF_CAP_FIFO_NOT_SUPPORTED 0b0
#define CRB_INTF_CAP_CRB_SUPPORTED 0b1
#define CRB_INTF_IF_SELECTOR_CRB 0b1
#define CRB_INTF_CAP_CRB_CHUNK 0b1

#define TPM_HEADER_SIZE 10

enum crb_loc_ctrl {
    CRB_LOC_CTRL_REQUEST_ACCESS = BIT(0),
    CRB_LOC_CTRL_RELINQUISH = BIT(1),
    CRB_LOC_CTRL_SEIZE = BIT(2),
    CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT = BIT(3),
};

enum crb_ctrl_req {
    CRB_CTRL_REQ_CMD_READY = BIT(0),
    CRB_CTRL_REQ_GO_IDLE = BIT(1),
};

enum crb_start {
    CRB_START_INVOKE = BIT(0),
    CRB_START_RSP_RETRY = BIT(1),
    CRB_START_NEXT_CHUNK = BIT(2),
};

enum crb_cancel {
    CRB_CANCEL_INVOKE = BIT(0),
};

#define TPM_CRB_NO_LOCALITY 0xff

static void tpm_crb_clear_internal_buffers(TPMCRBState *s)
{
    g_byte_array_set_size(s->response_buffer, 0);
    g_byte_array_set_size(s->command_buffer, 0);
    s->response_offset = 0;
}

static uint64_t tpm_crb_mmio_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    TPMCRBState *s = opaque;
    void *regs = (void *)&s->regs + (addr & ~3);
    unsigned offset = addr & 3;
    uint32_t val = *(uint32_t *)regs >> (8 * offset);

    switch (addr) {
    case A_CRB_LOC_STATE:
        val |= !tpm_backend_get_tpm_established_flag(s->tpmbe);
        break;
    }

    trace_tpm_crb_mmio_read(addr, size, val);

    return val;
}

static uint8_t tpm_crb_get_active_locty(TPMCRBState *s)
{
    if (!ARRAY_FIELD_EX32(s->regs, CRB_LOC_STATE, locAssigned)) {
        return TPM_CRB_NO_LOCALITY;
    }
    return ARRAY_FIELD_EX32(s->regs, CRB_LOC_STATE, activeLocality);
}

static bool tpm_crb_append_command_request(TPMCRBState *s)
{
    /*
     * The linux guest writes the TPM command to the MMIO region in chunks.
     * This function appends a chunk from the MMIO region to internal
     * command_buffer.
     */
    void *mem = memory_region_get_ram_ptr(&s->cmdmem);
    uint32_t to_copy = 0;
    uint32_t total_request_size = 0;

    /*
     * The initial call extracts the total TPM command size
     * from its header. For the subsequent calls, the data already
     * appended in the command_buffer is used to calculate the total
     * size, as its header stays the same.
     */
    if (s->command_buffer->len == 0) {
        total_request_size = tpm_cmd_get_size(mem);
        if (total_request_size < TPM_HEADER_SIZE) {
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_STS, tpmSts, 1);
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, Start, 0);
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, nextChunk, 0);
            tpm_crb_clear_internal_buffers(s);
            error_report("Command size %" PRIu32 " less than "
                         "TPM header size %" PRIu32,
                         total_request_size, (uint32_t)TPM_HEADER_SIZE);
            return false;
        }
    } else {
        total_request_size = tpm_cmd_get_size(s->command_buffer->data);
    }
    total_request_size = MIN(total_request_size, s->be_buffer_size);

    if (total_request_size > s->command_buffer->len) {
        uint32_t remaining = total_request_size - s->command_buffer->len;
        to_copy = MIN(remaining, CRB_CTRL_CMD_SIZE);
        g_byte_array_append(s->command_buffer, (guint8 *)mem, to_copy);
    }
    return true;
}

static void tpm_crb_fill_command_response(TPMCRBState *s)
{
    /*
     * Response from the tpm backend will be stored in the internal
     * response_buffer. This function will serve that accumulated response
     * to the linux guest in chunks by writing it back to MMIO region.
     */
    void *mem = memory_region_get_ram_ptr(&s->cmdmem);
    uint32_t remaining = s->response_buffer->len - s->response_offset;
    uint32_t to_copy = MIN(CRB_CTRL_CMD_SIZE, remaining);

    memcpy(mem, s->response_buffer->data + s->response_offset, to_copy);

    if (to_copy < CRB_CTRL_CMD_SIZE) {
        memset((guint8 *)mem + to_copy, 0, CRB_CTRL_CMD_SIZE - to_copy);
    }

    s->response_offset += to_copy;
    memory_region_set_dirty(&s->cmdmem, 0, CRB_CTRL_CMD_SIZE);
}

static void tpm_crb_mmio_write(void *opaque, hwaddr addr,
                               uint64_t val, unsigned size)
{
    TPMCRBState *s = opaque;
    uint8_t locty =  addr >> 12;

    trace_tpm_crb_mmio_write(addr, size, val);

    switch (addr) {
    case A_CRB_CTRL_REQ:
        switch (val) {
        case CRB_CTRL_REQ_CMD_READY:
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_STS,
                             tpmIdle, 0);
            break;
        case CRB_CTRL_REQ_GO_IDLE:
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_STS,
                             tpmIdle, 1);
            break;
        }
        break;
    case A_CRB_CTRL_CANCEL:
        if (val == CRB_CANCEL_INVOKE) {
            if (s->regs[R_CRB_CTRL_START] & CRB_START_INVOKE) {
                tpm_backend_cancel_cmd(s->tpmbe);
            }
            tpm_crb_clear_internal_buffers(s);
        }
        break;
    case A_CRB_CTRL_START:
        if (tpm_crb_get_active_locty(s) != locty) {
            break;
        }
        if (s->regs[R_CRB_CTRL_START] & CRB_START_INVOKE) {
            /*
             * Backend TPM is busy processing a request.
             */
            break;
        }
        if (val & CRB_START_INVOKE) {
            if (!tpm_crb_append_command_request(s)) {
                break;
            }
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, Start, 1);
            g_byte_array_set_size(s->response_buffer, s->be_buffer_size);
            s->cmd = (TPMBackendCmd) {
                .in = s->command_buffer->data,
                .in_len = s->command_buffer->len,
                .out = s->response_buffer->data,
                .out_len = s->response_buffer->len,
            };
            tpm_backend_deliver_request(s->tpmbe, &s->cmd);
        } else if (val & CRB_START_NEXT_CHUNK) {
            if (!s->cap_chunk) {
                break;
            }
            /*
             * nextChunk is used both while sending and receiving data.
             * To distinguish between the two, response_buffer is checked.
             * If it does not have data, then that means we have not yet
             * sent the command to the tpm backend, and therefore call
             * tpm_crb_append_command_request().
             */
            if (s->response_buffer->len > 0 &&
                s->response_offset < s->response_buffer->len) {
                tpm_crb_fill_command_response(s);
            } else {
                if (!tpm_crb_append_command_request(s)) {
                    break;
                }
            }
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, nextChunk, 0);
        } else if (val & CRB_START_RSP_RETRY) {
            if (!s->cap_chunk) {
                break;
            }
            if (s->response_buffer->len > 0) {
                s->response_offset = 0;
                tpm_crb_fill_command_response(s);
            }
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, crbRspRetry, 0);
            ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, nextChunk, 0);
        }
        break;
    case A_CRB_LOC_CTRL:
        switch (val) {
        case CRB_LOC_CTRL_RESET_ESTABLISHMENT_BIT:
            /* not loc 3 or 4 */
            break;
        case CRB_LOC_CTRL_RELINQUISH:
            ARRAY_FIELD_DP32(s->regs, CRB_LOC_STATE,
                             locAssigned, 0);
            ARRAY_FIELD_DP32(s->regs, CRB_LOC_STS,
                             Granted, 0);
            break;
        case CRB_LOC_CTRL_REQUEST_ACCESS:
            ARRAY_FIELD_DP32(s->regs, CRB_LOC_STS,
                             Granted, 1);
            ARRAY_FIELD_DP32(s->regs, CRB_LOC_STS,
                             beenSeized, 0);
            ARRAY_FIELD_DP32(s->regs, CRB_LOC_STATE,
                             locAssigned, 1);
            break;
        }
        break;
    }
}

static const MemoryRegionOps tpm_crb_memory_ops = {
    .read = tpm_crb_mmio_read,
    .write = tpm_crb_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

void tpm_crb_request_completed(TPMCRBState *s, int ret)
{
    ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, Start, 0);
    if (ret != 0) {
        ARRAY_FIELD_DP32(s->regs, CRB_CTRL_STS,
                         tpmSts, 1); /* fatal error */
        tpm_crb_clear_internal_buffers(s);
    } else {
        uint32_t actual_resp_size = tpm_cmd_get_size(s->response_buffer->data);
        uint32_t total_resp_size = MIN(actual_resp_size, s->be_buffer_size);
        g_byte_array_set_size(s->response_buffer, total_resp_size);
        s->response_offset = 0;
    }
    /*
     * Send the first chunk. Subsequent chunks will be sent
     * on receiving nextChunk from the guest
     */
    tpm_crb_fill_command_response(s);
    ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, nextChunk, 0);
    ARRAY_FIELD_DP32(s->regs, CRB_CTRL_START, crbRspRetry, 0);
    g_byte_array_set_size(s->command_buffer, 0);
}

enum TPMVersion tpm_crb_get_version(TPMCRBState *s)
{
    return tpm_backend_get_tpm_version(s->tpmbe);
}

int tpm_crb_pre_save(TPMCRBState *s)
{
    tpm_backend_finish_sync(s->tpmbe);

    return 0;
}

bool tpm_crb_chunk_needed(TPMCRBState *s)
{
    return ((s->command_buffer && s->command_buffer->len > 0) ||
            (s->response_buffer && s->response_buffer->len > 0));
}

bool tpm_crb_chunk_post_load(TPMCRBState *s, Error **errp)
{
    /*
     * The external TPM emulator (example swtpm) determines the backend
     * buffer capacity (s->be_buffer_size). This check ensures that if we
     * migrate from a source with a PQC-enabled emulator that supports
     * larger buffers to a destination with a non-PQC emulator, the
     * migrated data does not exceed the destination's capacity.
     */
    if (s->response_buffer->len > s->be_buffer_size ||
        s->command_buffer->len > s->be_buffer_size) {
        error_setg(errp, "tpm-crb: Buffer sizes exceed backend capacity");
        return false;
    }
    return true;
}

void tpm_crb_reset(TPMCRBState *s, uint64_t baseaddr)
{
    uint64_t databuf = baseaddr + A_CRB_DATA_BUFFER;

    tpm_ppi_reset(&s->ppi);
    tpm_backend_reset(s->tpmbe);
    tpm_crb_clear_internal_buffers(s);

    memset(s->regs, 0, sizeof(s->regs));

    ARRAY_FIELD_DP32(s->regs, CRB_LOC_STATE,
                     tpmRegValidSts, 1);
    ARRAY_FIELD_DP32(s->regs, CRB_CTRL_STS,
                     tpmIdle, 1);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     InterfaceType, CRB_INTF_TYPE_CRB_ACTIVE);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     InterfaceVersion, CRB_INTF_VERSION_CRB);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapLocality, CRB_INTF_CAP_LOCALITY_0_ONLY);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapCRBIdleBypass, CRB_INTF_CAP_IDLE_FAST);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapDataXferSizeSupport, CRB_INTF_CAP_XFER_SIZE_64);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapFIFO, CRB_INTF_CAP_FIFO_NOT_SUPPORTED);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapCRB, CRB_INTF_CAP_CRB_SUPPORTED);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     InterfaceSelector, CRB_INTF_IF_SELECTOR_CRB);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapCRBChunk, s->cap_chunk ? CRB_INTF_CAP_CRB_CHUNK : 0);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     RID, 0b0000);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID2,
                     VID, PCI_VENDOR_ID_IBM);

    s->regs[R_CRB_CTRL_CMD_SIZE] = CRB_CTRL_CMD_SIZE;
    s->regs[R_CRB_CTRL_CMD_LADDR] = (uint32_t)databuf;
    s->regs[R_CRB_CTRL_CMD_HADDR] = (uint32_t)(databuf >> 32);
    s->regs[R_CRB_CTRL_RSP_SIZE] = CRB_CTRL_CMD_SIZE;
    /*
     * CRB_CTRL_RSP_ADDR is a single 64 bit register spanning 0x68..0x6f, so
     * the upper half lands in the following uint32 of the register file.
     * Both halves must be written for a base address above 4 GiB, and the
     * upper half must be cleared for one below it.
     */
    s->regs[R_CRB_CTRL_RSP_ADDR] = (uint32_t)databuf;
    s->regs[R_CRB_CTRL_RSP_ADDR + 1] = (uint32_t)(databuf >> 32);

    s->be_buffer_size = tpm_backend_get_buffer_size(s->tpmbe);

    if (tpm_backend_startup_tpm(s->tpmbe, s->be_buffer_size) < 0) {
        exit(1);
    }
}

void tpm_crb_init_memory(Object *obj, TPMCRBState *s, Error **errp)
{
    memory_region_init_io(&s->mmio, obj, &tpm_crb_memory_ops, s,
        "tpm-crb-mmio", sizeof(s->regs));
    memory_region_init_ram(&s->cmdmem, obj,
        "tpm-crb-cmd", CRB_CTRL_CMD_SIZE, errp);

    s->command_buffer = g_byte_array_new();
    s->response_buffer = g_byte_array_new();
}
