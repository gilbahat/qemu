/*
 * QEMU host memfd memory backend
 *
 * Copyright (C) 2018 Red Hat Inc
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "system/hostmem.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "migration/cpr.h"

OBJECT_DECLARE_SIMPLE_TYPE(HostMemoryBackendMemfd, MEMORY_BACKEND_MEMFD)


struct HostMemoryBackendMemfd {
    HostMemoryBackend parent_obj;

    bool hugetlb;
    uint64_t hugetlbsize;
    bool seal;
};

static bool
memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(backend);
    g_autofree char *name = host_memory_backend_get_name(backend);
    int fd = cpr_find_fd(name, 0);
    uint32_t ram_flags;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return false;
    }

    if (fd >= 0) {
        goto have_fd;
    }

    fd = qemu_memfd_create(TYPE_MEMORY_BACKEND_MEMFD, backend->size,
                           m->hugetlb, m->hugetlbsize, m->seal ?
                           F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL : 0,
                           NULL);
    if (fd == -1) {
        /*
         * memfd_create(2) is Linux-only. Fall back to an anonymous,
         * unlinked file, which is enough to hand a shareable fd to a
         * vhost-user backend (e.g. for the nitro-enclave machine on
         * macOS) even without memfd sealing support.
         */
        g_autofree char *tmpl = g_strdup_printf("%s/qemu-memfd-XXXXXX",
                                                g_get_tmp_dir());
        fd = mkstemp(tmpl);
        if (fd == -1) {
            error_setg_errno(errp, errno,
                             "failed to create memfd backend file");
            return false;
        }
        unlink(tmpl);
        if (ftruncate(fd, backend->size) == -1) {
            error_setg_errno(errp, errno,
                             "failed to resize memfd backend file");
            close(fd);
            return false;
        }
    }
    cpr_save_fd(name, 0, fd);

have_fd:
    backend->aligned = true;
    ram_flags = backend->share ? RAM_SHARED : RAM_PRIVATE;
    ram_flags |= backend->reserve ? 0 : RAM_NORESERVE;
    ram_flags |= backend->guest_memfd ? RAM_GUEST_MEMFD : 0;
    return memory_region_init_ram_from_fd(&backend->mr, OBJECT(backend), name,
                                          backend->size, ram_flags, fd, 0, errp);
}

static bool
memfd_backend_get_hugetlb(Object *o, Error **errp)
{
    return MEMORY_BACKEND_MEMFD(o)->hugetlb;
}

static void
memfd_backend_set_hugetlb(Object *o, bool value, Error **errp)
{
    MEMORY_BACKEND_MEMFD(o)->hugetlb = value;
}

static void
memfd_backend_set_hugetlbsize(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(obj);
    uint64_t value;

    if (host_memory_backend_mr_inited(MEMORY_BACKEND(obj))) {
        error_setg(errp, "cannot change property value");
        return;
    }

    if (!visit_type_size(v, name, &value, errp)) {
        return;
    }
    if (!value) {
        error_setg(errp, "Property '%s.%s' doesn't take value '%" PRIu64 "'",
                   object_get_typename(obj), name, value);
        return;
    }
    m->hugetlbsize = value;
}

static void
memfd_backend_get_hugetlbsize(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(obj);
    uint64_t value = m->hugetlbsize;

    visit_type_size(v, name, &value, errp);
}

static bool
memfd_backend_get_seal(Object *o, Error **errp)
{
    return MEMORY_BACKEND_MEMFD(o)->seal;
}

static void
memfd_backend_set_seal(Object *o, bool value, Error **errp)
{
    MEMORY_BACKEND_MEMFD(o)->seal = value;
}

static void
memfd_backend_instance_init(Object *obj)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(obj);

    /* default to sealed file */
    m->seal = true;
    MEMORY_BACKEND(m)->share = true;
}

static void
memfd_backend_class_init(ObjectClass *oc, const void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);

    bc->alloc = memfd_backend_memory_alloc;

    if (qemu_memfd_check(MFD_HUGETLB)) {
        object_class_property_add_bool(oc, "hugetlb",
                                       memfd_backend_get_hugetlb,
                                       memfd_backend_set_hugetlb);
        object_class_property_set_description(oc, "hugetlb",
                                              "Use huge pages");
        object_class_property_add(oc, "hugetlbsize", "int",
                                  memfd_backend_get_hugetlbsize,
                                  memfd_backend_set_hugetlbsize,
                                  NULL, NULL);
        object_class_property_set_description(oc, "hugetlbsize",
                                              "Huge pages size (ex: 2M, 1G)");
    }
    object_class_property_add_bool(oc, "seal",
                                   memfd_backend_get_seal,
                                   memfd_backend_set_seal);
    object_class_property_set_description(oc, "seal",
                                          "Seal growing & shrinking");
}

static const TypeInfo memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_MEMFD,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = memfd_backend_instance_init,
    .class_init = memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendMemfd),
};

static void register_types(void)
{
    /*
     * Always register: memfd_backend_memory_alloc() falls back to a plain
     * anonymous file when the host has no memfd_create(2) (e.g. macOS), so
     * this backend stays usable there, just without sealing. This is needed
     * by the nitro-enclave machine's default memory backend.
     */
    type_register_static(&memfd_backend_info);
}

type_init(register_types);
