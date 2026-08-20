/*
 * AWS nitro-enclave machine
 *
 * Copyright (c) 2024 Dorjoy Chowdhury <dorjoychy111@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"

#include "chardev/char.h"
#include "hw/core/sysbus.h"
#include "hw/core/eif.h"
#include "hw/i386/x86.h"
#include "hw/i386/microvm.h"
#include "hw/i386/nitro_enclave.h"
#include "hw/virtio/virtio-mmio.h"
#include "hw/virtio/virtio-nsm.h"
#include "hw/virtio/vhost-user-vsock.h"
#include "hw/virtio/virtio-vsock.h"
#include "system/hostmem.h"

static BusState *find_free_virtio_mmio_bus(void)
{
    BusChild *kid;
    BusState *bus = sysbus_get_default();

    QTAILQ_FOREACH(kid, &bus->children, sibling) {
        DeviceState *dev = kid->child;
        if (object_dynamic_cast(OBJECT(dev), TYPE_VIRTIO_MMIO)) {
            VirtIOMMIOProxy *mmio = VIRTIO_MMIO(OBJECT(dev));
            VirtioBusState *mmio_virtio_bus = &mmio->bus;
            BusState *mmio_bus = &mmio_virtio_bus->parent_obj;
            if (QTAILQ_EMPTY(&mmio_bus->children)) {
                return mmio_bus;
            }
        }
    }

    return NULL;
}

/*
 * The enclave talks to its parent over vsock, which can be served either by an
 * external vhost-user daemon ('vsock=<chardev>') or by QEMU's own virtio-vsock
 * device ('vsock-path=<host socket>').  The built-in device needs no daemon and
 * nothing from the host kernel, which is what makes it work on hosts without
 * AF_VSOCK.
 */
static void nitro_enclave_vsock_init(NitroEnclaveMachineState *nems)
{
    DeviceState *dev;
    BusState *bus;

    if (nems->vsock && nems->vsock_path) {
        error_report("'vsock' and 'vsock-path' are mutually exclusive: the "
                     "first uses an external vhost-user-vsock daemon, the "
                     "second QEMU's built-in virtio-vsock device");
        exit(1);
    }
    if (!nems->vsock && !nems->vsock_path) {
        error_report("A vsock device must be configured, either with the "
                     "'vsock' machine option (chardev id of a "
                     "vhost-user-vsock daemon) or with 'vsock-path' (host "
                     "socket path for the built-in virtio-vsock device)");
        exit(1);
    }

    bus = find_free_virtio_mmio_bus();
    if (!bus) {
        error_report("Failed to find bus for vsock device");
        exit(1);
    }

    if (nems->vsock_path) {
        dev = qdev_new(TYPE_VIRTIO_VSOCK);
        qdev_prop_set_uint64(dev, "guest-cid", nems->vsock_cid);
        qdev_prop_set_string(dev, "path", nems->vsock_path);
        if (nems->vsock_listen) {
            qdev_prop_set_string(dev, "forward-listen", nems->vsock_listen);
        }
    } else {
        Chardev *chardev = qemu_chr_find(nems->vsock);

        if (!chardev) {
            error_report("Failed to find chardev with id %s", nems->vsock);
            exit(1);
        }

        dev = qdev_new(TYPE_VHOST_USER_VSOCK);
        VHOST_USER_VSOCK(dev)->conf.chardev.chr = chardev;
    }

    qdev_realize_and_unref(dev, bus, &error_fatal);
}

static void virtio_nsm_init(NitroEnclaveMachineState *nems)
{
    DeviceState *dev = qdev_new(TYPE_VIRTIO_NSM);
    VirtIONSM *vnsm = VIRTIO_NSM(dev);
    BusState *bus = find_free_virtio_mmio_bus();

    if (!bus) {
        error_report("Failed to find bus for virtio-nsm device.");
        exit(1);
    }

    qdev_prop_set_string(dev, "module-id", nems->id);

    qdev_realize_and_unref(dev, bus, &error_fatal);
    nems->vnsm = vnsm;
}

static void nitro_enclave_devices_init(NitroEnclaveMachineState *nems)
{
    nitro_enclave_vsock_init(nems);
    virtio_nsm_init(nems);
}

static void nitro_enclave_machine_state_init(MachineState *machine)
{
    NitroEnclaveMachineClass *ne_class =
        NITRO_ENCLAVE_MACHINE_GET_CLASS(machine);
    NitroEnclaveMachineState *ne_state = NITRO_ENCLAVE_MACHINE(machine);

    ne_class->parent_init(machine);
    nitro_enclave_devices_init(ne_state);
}

static void nitro_enclave_machine_reset(MachineState *machine, ResetType type)
{
    NitroEnclaveMachineClass *ne_class =
        NITRO_ENCLAVE_MACHINE_GET_CLASS(machine);
    NitroEnclaveMachineState *ne_state = NITRO_ENCLAVE_MACHINE(machine);

    ne_class->parent_reset(machine, type);

    memset(ne_state->vnsm->pcrs, 0, sizeof(ne_state->vnsm->pcrs));

    /* PCR0 */
    ne_state->vnsm->extend_pcr(ne_state->vnsm, 0, ne_state->image_hash,
                               QCRYPTO_HASH_DIGEST_LEN_SHA384);
    /* PCR1 */
    ne_state->vnsm->extend_pcr(ne_state->vnsm, 1, ne_state->bootstrap_hash,
                               QCRYPTO_HASH_DIGEST_LEN_SHA384);
    /* PCR2 */
    ne_state->vnsm->extend_pcr(ne_state->vnsm, 2, ne_state->app_hash,
                               QCRYPTO_HASH_DIGEST_LEN_SHA384);
    /* PCR3 */
    if (ne_state->parent_role) {
        ne_state->vnsm->extend_pcr(ne_state->vnsm, 3,
                                   (uint8_t *) ne_state->parent_role,
                                   strlen(ne_state->parent_role));
    }
    /* PCR4 */
    if (ne_state->parent_id) {
        ne_state->vnsm->extend_pcr(ne_state->vnsm, 4,
                                   (uint8_t *) ne_state->parent_id,
                                   strlen(ne_state->parent_id));
    }
    /* PCR8 */
    if (ne_state->signature_found) {
        ne_state->vnsm->extend_pcr(ne_state->vnsm, 8,
                                   ne_state->fingerprint_hash,
                                   QCRYPTO_HASH_DIGEST_LEN_SHA384);
    }

    /* First 16 PCRs are locked from boot and reserved for nitro enclave */
    for (int i = 0; i < 16; ++i) {
        ne_state->vnsm->lock_pcr(ne_state->vnsm, i);
    }
}

static void nitro_enclave_machine_initfn(Object *obj)
{
    MicrovmMachineState *mms = MICROVM_MACHINE(obj);
    X86MachineState *x86ms = X86_MACHINE(obj);
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    nems->id = g_strdup("i-234-enc5678");
    /* Matches the CID used by the documented vhost-device-vsock recipe. */
    nems->vsock_cid = 4;

    /* AWS nitro enclaves have PCIE and ACPI disabled */
    mms->pcie = ON_OFF_AUTO_OFF;
    x86ms->acpi = ON_OFF_AUTO_OFF;
}

static void x86_load_eif(X86MachineState *x86ms, FWCfgState *fw_cfg,
                         int acpi_data_size)
{
    Error *err = NULL;
    char *eif_kernel, *eif_initrd, *eif_cmdline;
    MachineState *machine = MACHINE(x86ms);
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(x86ms);

    if (!read_eif_file(machine->kernel_filename, machine->initrd_filename,
                       &eif_kernel, &eif_initrd, &eif_cmdline,
                       nems->image_hash, nems->bootstrap_hash,
                       nems->app_hash, nems->fingerprint_hash,
                       &(nems->signature_found), &err)) {
        error_report_err(err);
        exit(1);
    }

    g_free(machine->kernel_filename);
    machine->kernel_filename = eif_kernel;
    g_free(machine->initrd_filename);
    machine->initrd_filename = eif_initrd;

    /*
     * If kernel cmdline argument was provided, let's concatenate it to the
     * extracted EIF kernel cmdline.
     */
    if (machine->kernel_cmdline != NULL) {
        char *cmd = g_strdup_printf("%s %s", eif_cmdline,
                                    machine->kernel_cmdline);
        g_free(eif_cmdline);
        g_free(machine->kernel_cmdline);
        machine->kernel_cmdline = cmd;
    } else {
        machine->kernel_cmdline = eif_cmdline;
    }

    x86_load_linux(x86ms, fw_cfg, 0);

    unlink(machine->kernel_filename);
    unlink(machine->initrd_filename);
}

static bool create_memfd_backend(MachineState *ms, const char *path,
                                 Error **errp)
{
    Object *obj;
    MachineClass *mc = MACHINE_GET_CLASS(ms);
    bool r = false;

    obj = object_new(TYPE_MEMORY_BACKEND_MEMFD);
    if (!object_property_set_int(obj, "size", ms->ram_size, errp)) {
        goto out;
    }
    object_property_add_child(object_get_objects_root(), mc->default_ram_id,
                              obj);

    if (!user_creatable_complete(USER_CREATABLE(obj), errp)) {
        goto out;
    }
    r = object_property_set_link(OBJECT(ms), "memory-backend", obj, errp);

out:
    object_unref(obj);
    return r;
}

static char *nitro_enclave_get_vsock_chardev_id(Object *obj, Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    return g_strdup(nems->vsock);
}

static void nitro_enclave_set_vsock_chardev_id(Object *obj, const char *value,
                                               Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->vsock);
    nems->vsock = g_strdup(value);
}

static char *nitro_enclave_get_vsock_path(Object *obj, Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    return g_strdup(nems->vsock_path);
}

static void nitro_enclave_set_vsock_path(Object *obj, const char *value,
                                         Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->vsock_path);
    nems->vsock_path = g_strdup(value);
}

static void nitro_enclave_get_vsock_cid(Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);
    uint32_t cid = nems->vsock_cid;

    visit_type_uint32(v, name, &cid, errp);
}

static void nitro_enclave_set_vsock_cid(Object *obj, Visitor *v,
                                        const char *name, void *opaque,
                                        Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);
    uint32_t cid;

    if (!visit_type_uint32(v, name, &cid, errp)) {
        return;
    }

    /* 0-2 are reserved: hypervisor, local and host. */
    if (cid <= 2) {
        error_setg(errp, "vsock-cid must be greater than 2");
        return;
    }

    nems->vsock_cid = cid;
}

static char *nitro_enclave_get_vsock_listen(Object *obj, Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    return g_strdup(nems->vsock_listen);
}

static void nitro_enclave_set_vsock_listen(Object *obj, const char *value,
                                           Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->vsock_listen);
    nems->vsock_listen = g_strdup(value);
}

static char *nitro_enclave_get_id(Object *obj, Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    return g_strdup(nems->id);
}

static void nitro_enclave_set_id(Object *obj, const char *value,
                                            Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->id);
    nems->id = g_strdup(value);
}

static char *nitro_enclave_get_parent_role(Object *obj, Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    return g_strdup(nems->parent_role);
}

static void nitro_enclave_set_parent_role(Object *obj, const char *value,
                                          Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->parent_role);
    nems->parent_role = g_strdup(value);
}

static char *nitro_enclave_get_parent_id(Object *obj, Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    return g_strdup(nems->parent_id);
}

static void nitro_enclave_set_parent_id(Object *obj, const char *value,
                                        Error **errp)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->parent_id);
    nems->parent_id = g_strdup(value);
}

static void nitro_enclave_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    MicrovmMachineClass *mmc = MICROVM_MACHINE_CLASS(oc);
    NitroEnclaveMachineClass *nemc = NITRO_ENCLAVE_MACHINE_CLASS(oc);

    mmc->x86_load_linux = x86_load_eif;

    mc->family = "nitro_enclave_i386";
    mc->desc = "AWS Nitro Enclave";

    nemc->parent_init = mc->init;
    mc->init = nitro_enclave_machine_state_init;

    nemc->parent_reset = mc->reset;
    mc->reset = nitro_enclave_machine_reset;

    mc->create_default_memdev = create_memfd_backend;

    object_class_property_add_str(oc, NITRO_ENCLAVE_VSOCK_CHARDEV_ID,
                                  nitro_enclave_get_vsock_chardev_id,
                                  nitro_enclave_set_vsock_chardev_id);
    object_class_property_set_description(oc, NITRO_ENCLAVE_VSOCK_CHARDEV_ID,
                                          "Set chardev id for vhost-user-vsock "
                                          "device");

    object_class_property_add_str(oc, NITRO_ENCLAVE_VSOCK_PATH,
                                  nitro_enclave_get_vsock_path,
                                  nitro_enclave_set_vsock_path);
    object_class_property_set_description(oc, NITRO_ENCLAVE_VSOCK_PATH,
                                          "Host socket path for the built-in "
                                          "virtio-vsock device (alternative "
                                          "to 'vsock')");

    object_class_property_add(oc, NITRO_ENCLAVE_VSOCK_CID, "uint32",
                              nitro_enclave_get_vsock_cid,
                              nitro_enclave_set_vsock_cid, NULL, NULL);
    object_class_property_set_description(oc, NITRO_ENCLAVE_VSOCK_CID,
                                          "CID of the enclave when using "
                                          "'vsock-path' (default 4)");

    object_class_property_add_str(oc, NITRO_ENCLAVE_VSOCK_LISTEN,
                                  nitro_enclave_get_vsock_listen,
                                  nitro_enclave_set_vsock_listen);
    object_class_property_set_description(oc, NITRO_ENCLAVE_VSOCK_LISTEN,
                                          "'+'-separated enclave ports to "
                                          "accept host connections on when "
                                          "using 'vsock-path'");

    object_class_property_add_str(oc, NITRO_ENCLAVE_ID, nitro_enclave_get_id,
                                  nitro_enclave_set_id);
    object_class_property_set_description(oc, NITRO_ENCLAVE_ID,
                                          "Set enclave identifier");

    object_class_property_add_str(oc, NITRO_ENCLAVE_PARENT_ROLE,
                                  nitro_enclave_get_parent_role,
                                  nitro_enclave_set_parent_role);
    object_class_property_set_description(oc, NITRO_ENCLAVE_PARENT_ROLE,
                                          "Set parent instance IAM role ARN");

    object_class_property_add_str(oc, NITRO_ENCLAVE_PARENT_ID,
                                  nitro_enclave_get_parent_id,
                                  nitro_enclave_set_parent_id);
    object_class_property_set_description(oc, NITRO_ENCLAVE_PARENT_ID,
                                          "Set parent instance identifier");
}

static void nitro_enclave_machine_finalize(Object *obj)
{
    NitroEnclaveMachineState *nems = NITRO_ENCLAVE_MACHINE(obj);

    g_free(nems->vsock);
    g_free(nems->vsock_path);
    g_free(nems->vsock_listen);
    g_free(nems->id);
    g_free(nems->parent_role);
    g_free(nems->parent_id);
}

static const TypeInfo nitro_enclave_machine_info = {
    .name          = TYPE_NITRO_ENCLAVE_MACHINE,
    .parent        = TYPE_MICROVM_MACHINE,
    .instance_size = sizeof(NitroEnclaveMachineState),
    .instance_init = nitro_enclave_machine_initfn,
    .instance_finalize = nitro_enclave_machine_finalize,
    .class_size    = sizeof(NitroEnclaveMachineClass),
    .class_init    = nitro_enclave_class_init,
};

static void nitro_enclave_machine_init(void)
{
    type_register_static(&nitro_enclave_machine_info);
}
type_init(nitro_enclave_machine_init);
