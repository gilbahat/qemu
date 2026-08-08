/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * tpm_crb.h - QEMU's TPM CRB interface emulator
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * tpm_crb is a device for TPM 2.0 Command Response Buffer (CRB) Interface
 * as defined in TCG PC Client Platform TPM Profile (PTP) Specification
 * Family “2.0” Level 00 Revision 01.03 v22
 */

#ifndef TPM_TPM_CRB_H
#define TPM_TPM_CRB_H

#include "exec/hwaddr.h"
#include "hw/acpi/tpm.h"
#include "system/memory.h"
#include "system/tpm_backend.h"
#include "tpm_ppi.h"

#define CRB_CTRL_CMD_SIZE (TPM_CRB_ADDR_SIZE - A_CRB_DATA_BUFFER)

/*
 * Shared state between the fixed-address (tpm-crb) and the relocatable
 * sysbus (tpm-crb-device) front ends.  Everything that touches the CRB
 * register file lives here; the front ends only differ in how the two
 * memory regions below get placed into the guest address space.
 */
typedef struct TPMCRBState {
    TPMBackend *tpmbe;
    TPMBackendCmd cmd;
    uint32_t regs[TPM_CRB_R_MAX];
    size_t be_buffer_size;

    MemoryRegion mmio;
    MemoryRegion cmdmem;

    GByteArray *command_buffer;
    GByteArray *response_buffer;
    uint32_t response_offset;

    TPMPPI ppi;

    bool cap_chunk;
} TPMCRBState;

/**
 * tpm_crb_init_memory:
 * @obj: owner object of the memory regions
 * @s: the CRB state
 * @errp: error object
 *
 * Create the CRB register window (@s->mmio, %A_CRB_DATA_BUFFER bytes) and the
 * command/response buffer (@s->cmdmem, %CRB_CTRL_CMD_SIZE bytes), plus the
 * internal command and response byte arrays.  Placing the regions in the guest
 * address space is left to the caller.
 */
void tpm_crb_init_memory(Object *obj, TPMCRBState *s, Error **errp);

/**
 * tpm_crb_reset:
 * @s: the CRB state
 * @baseaddr: guest physical address the CRB register window is mapped at
 *
 * Reset the register file.  @baseaddr is used to fill in the command and
 * response buffer address registers, which the guest uses to locate the
 * data buffer.
 */
void tpm_crb_reset(TPMCRBState *s, uint64_t baseaddr);

void tpm_crb_request_completed(TPMCRBState *s, int ret);
enum TPMVersion tpm_crb_get_version(TPMCRBState *s);
int tpm_crb_pre_save(TPMCRBState *s);
bool tpm_crb_chunk_needed(TPMCRBState *s);
bool tpm_crb_chunk_post_load(TPMCRBState *s, Error **errp);

#endif /* TPM_TPM_CRB_H */
