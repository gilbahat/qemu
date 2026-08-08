/*
 * tpm_crb.c - QEMU's TPM CRB interface emulator
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * tpm_crb is a device for TPM 2.0 Command Response Buffer (CRB) Interface
 * as defined in TCG PC Client Platform TPM Profile (PTP) Specification
 * Family “2.0” Level 00 Revision 01.03 v22
 *
 * This is the fixed-address front end, mapping the CRB window at the
 * PC-specific %TPM_CRB_ADDR_BASE.  See tpm_crb_sysbus.c for the relocatable
 * variant and tpm_crb_common.c for the shared register logic.
 */

#include "qemu/osdep.h"

#include "qemu/module.h"
#include "qapi/error.h"
#include "system/address-spaces.h"
#include "hw/core/qdev-properties.h"
#include "hw/acpi/tpm.h"
#include "migration/vmstate.h"
#include "migration/blocker.h"
#include "system/tpm_backend.h"
#include "system/reset.h"
#include "system/xen.h"
#include "tpm_prop.h"
#include "tpm_crb.h"
#include "tpm_ppi.h"
#include "qom/object.h"

struct CRBState {
    DeviceState parent_obj;

    TPMCRBState state;

    bool allow_chunk_migration;
    Error *migration_blocker;
};
typedef struct CRBState CRBState;

DECLARE_INSTANCE_CHECKER(CRBState, CRB,
                         TYPE_TPM_CRB)

static void tpm_crb_none_request_completed(TPMIf *ti, int ret)
{
    CRBState *s = CRB(ti);

    tpm_crb_request_completed(&s->state, ret);
}

static enum TPMVersion tpm_crb_none_get_version(TPMIf *ti)
{
    CRBState *s = CRB(ti);

    return tpm_crb_get_version(&s->state);
}

static int tpm_crb_none_pre_save(void *opaque)
{
    CRBState *s = opaque;

    return tpm_crb_pre_save(&s->state);
}

static bool tpm_crb_none_chunk_needed(void *opaque)
{
    CRBState *s = opaque;

    if (!s->allow_chunk_migration) {
        return false;
    }

    return tpm_crb_chunk_needed(&s->state);
}

static bool tpm_crb_none_chunk_post_load(void *opaque, int version_id,
                                         Error **errp)
{
    CRBState *s = opaque;

    return tpm_crb_chunk_post_load(&s->state, errp);
}

static const VMStateDescription vmstate_tpm_crb_chunk = {
    .name = "tpm-crb/chunk",
    .version_id = 0,
    .needed = tpm_crb_none_chunk_needed,
    .post_load_errp = tpm_crb_none_chunk_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_GBYTEARRAY(state.command_buffer, CRBState, 0),
        VMSTATE_GBYTEARRAY(state.response_buffer, CRBState, 0),
        VMSTATE_UINT32(state.response_offset, CRBState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_tpm_crb = {
    .name = "tpm-crb",
    .pre_save = tpm_crb_none_pre_save,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(state.regs, CRBState, TPM_CRB_R_MAX),
        VMSTATE_END_OF_LIST(),
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_tpm_crb_chunk,
        NULL,
    }
};

static const Property tpm_crb_properties[] = {
    DEFINE_PROP_TPMBE("tpmdev", CRBState, state.tpmbe),
    DEFINE_PROP_BOOL("cap-chunk", CRBState, state.cap_chunk, true),
    DEFINE_PROP_BOOL("x-allow-chunk-migration", CRBState,
                     allow_chunk_migration, true),
};

static void tpm_crb_none_reset(void *dev)
{
    CRBState *s = CRB(dev);

    return tpm_crb_reset(&s->state, TPM_CRB_ADDR_BASE);
}

static void tpm_crb_realize(DeviceState *dev, Error **errp)
{
    CRBState *s = CRB(dev);
    int ret;

    if (!tpm_find()) {
        error_setg(errp, "at most one TPM device is permitted");
        return;
    }
    if (!s->state.tpmbe) {
        error_setg(errp, "'tpmdev' property is required");
        return;
    }
    if (s->state.cap_chunk && !s->allow_chunk_migration) {
        error_setg(&s->migration_blocker,
                   "The tpm-crb device does not support chunk migration with "
                   "machine version less than 11.1");
        ret = migrate_add_blocker_normal(&s->migration_blocker, errp);
        if (ret < 0) {
            return;
        }
    }

    tpm_crb_init_memory(OBJECT(s), &s->state, errp);

    memory_region_add_subregion(get_system_memory(),
        TPM_CRB_ADDR_BASE, &s->state.mmio);
    memory_region_add_subregion(get_system_memory(),
        TPM_CRB_ADDR_BASE + A_CRB_DATA_BUFFER, &s->state.cmdmem);

    tpm_ppi_init(&s->state.ppi, get_system_memory(),
                 TPM_PPI_ADDR_BASE, OBJECT(s));

    if (xen_enabled()) {
        tpm_crb_none_reset(dev);
    } else {
        qemu_register_reset(tpm_crb_none_reset, dev);
    }
}

static void tpm_crb_unrealize(DeviceState *dev)
{
    CRBState *s = CRB(dev);

    g_clear_pointer(&s->state.command_buffer, g_byte_array_unref);
    g_clear_pointer(&s->state.response_buffer, g_byte_array_unref);

    if (s->migration_blocker) {
        migrate_del_blocker(&s->migration_blocker);
    }
}

static void tpm_crb_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    dc->realize = tpm_crb_realize;
    dc->unrealize = tpm_crb_unrealize;
    device_class_set_props(dc, tpm_crb_properties);
    dc->vmsd  = &vmstate_tpm_crb;
    dc->user_creatable = true;
    tc->model = TPM_MODEL_TPM_CRB;
    tc->ppi_enabled = true;
    tc->get_version = tpm_crb_none_get_version;
    tc->request_completed = tpm_crb_none_request_completed;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo tpm_crb_info = {
    .name = TYPE_TPM_CRB,
    /* could be TYPE_SYS_BUS_DEVICE (or LPC etc) */
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(CRBState),
    .class_init  = tpm_crb_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    }
};

static void tpm_crb_register(void)
{
    type_register_static(&tpm_crb_info);
}

type_init(tpm_crb_register)
