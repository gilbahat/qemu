/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * tpm_crb_sysbus.c - QEMU's TPM CRB interface emulator, sysbus front end
 *
 * Relocatable variant of the TPM 2.0 Command Response Buffer (CRB) interface.
 * Unlike tpm-crb, which hardcodes the PC chipset addresses, this device
 * exposes its register window and its PPI buffer as sysbus MMIO regions so a
 * machine can place them anywhere -- in practice on the dynamic platform bus
 * of the arm/riscv/loongarch "virt" machines.
 *
 * CRB is discovered by the guest through ACPI (_HID MSFT0101 plus the TPM2
 * table), so no device tree node is generated for it.
 */

#include "qemu/osdep.h"

#include "qemu/module.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "hw/core/qdev-properties.h"
#include "hw/acpi/tpm.h"
#include "hw/core/sysbus.h"
#include "migration/vmstate.h"
#include "system/tpm_backend.h"
#include "qemu/memalign.h"
#include "tpm_prop.h"
#include "tpm_crb.h"
#include "tpm_ppi.h"
#include "qom/object.h"

struct TPMCRBStateSysBus {
    SysBusDevice parent_obj;

    TPMCRBState state;

    /* the whole CRB window: registers followed by the data buffer */
    MemoryRegion crb_window;

    bool ppi_enabled;
};

OBJECT_DECLARE_SIMPLE_TYPE(TPMCRBStateSysBus, TPM_CRB_SYSBUS)

/*
 * Absolute guest physical address of sysbus MMIO region @n, or 0 if it is
 * not mapped yet.  The region may sit inside a container (the platform bus),
 * so walk up the container chain accumulating offsets.
 */
static hwaddr tpm_crb_sysbus_mmio_addr(SysBusDevice *sbd, int n)
{
    MemoryRegion *mr = sysbus_mmio_get_region(sbd, n);
    hwaddr addr = 0;

    while (mr && memory_region_is_mapped(mr)) {
        Object *container;

        addr += object_property_get_uint(OBJECT(mr), "addr", &error_abort);
        container = object_property_get_link(OBJECT(mr), "container",
                                             &error_abort);
        mr = container ? MEMORY_REGION(container) : NULL;
    }

    return addr;
}

/*
 * Read-only property used by build_tpm2() to fill in the "Address of Control
 * Area" field of the TPM2 ACPI table.  It is computed on demand because the
 * platform bus only assigns an address once the machine is wired up.
 */
static void tpm_crb_sysbus_get_ctrl_area(Object *obj, Visitor *v,
                                         const char *name, void *opaque,
                                         Error **errp)
{
    uint64_t value = tpm_crb_sysbus_mmio_addr(SYS_BUS_DEVICE(obj), 0);

    if (value) {
        value += A_CRB_CTRL_REQ;
    }
    visit_type_uint64(v, name, &value, errp);
}

static void tpm_crb_sysbus_request_completed(TPMIf *ti, int ret)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(ti);

    tpm_crb_request_completed(&s->state, ret);
}

static enum TPMVersion tpm_crb_sysbus_get_version(TPMIf *ti)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(ti);

    return tpm_crb_get_version(&s->state);
}

static int tpm_crb_sysbus_pre_save(void *opaque)
{
    TPMCRBStateSysBus *s = opaque;

    return tpm_crb_pre_save(&s->state);
}

static bool tpm_crb_sysbus_chunk_needed(void *opaque)
{
    TPMCRBStateSysBus *s = opaque;

    return tpm_crb_chunk_needed(&s->state);
}

static bool tpm_crb_sysbus_chunk_post_load(void *opaque, int version_id,
                                           Error **errp)
{
    TPMCRBStateSysBus *s = opaque;

    return tpm_crb_chunk_post_load(&s->state, errp);
}

static const VMStateDescription vmstate_tpm_crb_sysbus_chunk = {
    .name = "tpm-crb-sysbus/chunk",
    .version_id = 0,
    .needed = tpm_crb_sysbus_chunk_needed,
    .post_load_errp = tpm_crb_sysbus_chunk_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_GBYTEARRAY(state.command_buffer, TPMCRBStateSysBus, 0),
        VMSTATE_GBYTEARRAY(state.response_buffer, TPMCRBStateSysBus, 0),
        VMSTATE_UINT32(state.response_offset, TPMCRBStateSysBus),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_tpm_crb_sysbus = {
    .name = "tpm-crb-sysbus",
    .pre_save = tpm_crb_sysbus_pre_save,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(state.regs, TPMCRBStateSysBus, TPM_CRB_R_MAX),
        VMSTATE_END_OF_LIST(),
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_tpm_crb_sysbus_chunk,
        NULL,
    }
};

static const Property tpm_crb_sysbus_properties[] = {
    DEFINE_PROP_TPMBE("tpmdev", TPMCRBStateSysBus, state.tpmbe),
    DEFINE_PROP_BOOL("cap-chunk", TPMCRBStateSysBus, state.cap_chunk, true),
    DEFINE_PROP_BOOL("ppi", TPMCRBStateSysBus, ppi_enabled, true),
};

static void tpm_crb_sysbus_reset(DeviceState *dev)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);

    tpm_crb_reset(&s->state, tpm_crb_sysbus_mmio_addr(SYS_BUS_DEVICE(dev), 0));
}

static void tpm_crb_sysbus_realizefn(DeviceState *dev, Error **errp)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(dev);

    if (!tpm_find()) {
        error_setg(errp, "at most one TPM device is permitted");
        return;
    }
    if (!s->state.tpmbe) {
        error_setg(errp, "'tpmdev' property is required");
        return;
    }

    tpm_crb_init_memory(OBJECT(s), &s->state, errp);
    if (*errp) {
        return;
    }

    /*
     * Present the register file and the data buffer as one contiguous
     * TPM_CRB_ADDR_SIZE window so the machine only has to place a single
     * region, and so the guest sees the layout the PTP spec describes.
     */
    memory_region_init(&s->crb_window, OBJECT(s), "tpm-crb",
                       TPM_CRB_ADDR_SIZE);
    memory_region_add_subregion(&s->crb_window, 0, &s->state.mmio);
    memory_region_add_subregion(&s->crb_window, A_CRB_DATA_BUFFER,
                                &s->state.cmdmem);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->crb_window);

    if (s->ppi_enabled) {
        tpm_ppi_init_memory(&s->state.ppi, OBJECT(s));
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->state.ppi.ram);
    }
}

static void tpm_crb_sysbus_initfn(Object *obj)
{
    object_property_add(obj, "ctrl-area-addr", "uint64",
                        tpm_crb_sysbus_get_ctrl_area, NULL, NULL, NULL);
}

static void tpm_crb_sysbus_finalize(Object *obj)
{
    TPMCRBStateSysBus *s = TPM_CRB_SYSBUS(obj);

    g_clear_pointer(&s->state.command_buffer, g_byte_array_unref);
    g_clear_pointer(&s->state.response_buffer, g_byte_array_unref);
    qemu_vfree(s->state.ppi.buf);
}

static void tpm_crb_sysbus_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    device_class_set_props(dc, tpm_crb_sysbus_properties);
    dc->vmsd = &vmstate_tpm_crb_sysbus;
    dc->user_creatable = true;
    dc->realize = tpm_crb_sysbus_realizefn;
    device_class_set_legacy_reset(dc, tpm_crb_sysbus_reset);
    tc->model = TPM_MODEL_TPM_CRB;
    tc->ppi_enabled = true;
    tc->get_version = tpm_crb_sysbus_get_version;
    tc->request_completed = tpm_crb_sysbus_request_completed;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo tpm_crb_sysbus_info = {
    .name = TYPE_TPM_CRB_SYSBUS,
    .parent = TYPE_DYNAMIC_SYS_BUS_DEVICE,
    .instance_size = sizeof(TPMCRBStateSysBus),
    .instance_init = tpm_crb_sysbus_initfn,
    .instance_finalize = tpm_crb_sysbus_finalize,
    .class_init = tpm_crb_sysbus_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    }
};

static void tpm_crb_sysbus_register(void)
{
    type_register_static(&tpm_crb_sysbus_info);
}

type_init(tpm_crb_sysbus_register)
