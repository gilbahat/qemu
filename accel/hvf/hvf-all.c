/*
 * QEMU Hypervisor.framework support
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qapi/qapi-visit-common.h"
#include "accel/accel-ops.h"
#include "exec/cpu-common.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/hvf.h"
#include "system/hvf_int.h"
#include "hw/core/cpu.h"
#include "hw/core/boards.h"
#include "trace.h"

bool hvf_allowed;
bool hvf_kernel_irqchip;
bool hvf_nested_virt;
bool hvf_want_4k_ipa_granule;
static bool hvf_kernel_irqchip_override;
static uint64_t hvf_ipa_granule;
static HVFIpaDeniedFn *hvf_ipa_denied;

void hvf_nested_virt_enable(bool nested_virt)
{
    hvf_nested_virt = nested_virt;
}

void hvf_request_4k_ipa_granule(void)
{
    hvf_want_4k_ipa_granule = true;
}

uint64_t hvf_ipa_page_size(void)
{
    return hvf_ipa_granule ?: qemu_real_host_page_size();
}

void hvf_set_ipa_page_size(uint64_t size)
{
    hvf_ipa_granule = size;
}

bool hvf_ipa_granule_is_4k(void)
{
    return hvf_ipa_page_size() == 4 * KiB;
}

void hvf_set_ipa_denied_fn(HVFIpaDeniedFn *fn)
{
    hvf_ipa_denied = fn;
}

const char *hvf_return_string(hv_return_t ret)
{
    switch (ret) {
    case HV_SUCCESS:      return "HV_SUCCESS";
    case HV_ERROR:        return "HV_ERROR";
    case HV_BUSY:         return "HV_BUSY";
    case HV_BAD_ARGUMENT: return "HV_BAD_ARGUMENT";
    case HV_NO_RESOURCES: return "HV_NO_RESOURCES";
    case HV_NO_DEVICE:    return "HV_NO_DEVICE";
    case HV_UNSUPPORTED:  return "HV_UNSUPPORTED";
    case HV_DENIED:       return "HV_DENIED";
    default:              return "[unknown hv_return value]";
    }
}

void assert_hvf_ok_impl(hv_return_t ret, const char *file, unsigned int line,
                        const char *exp)
{
    if (ret == HV_SUCCESS) {
        return;
    }

    error_report("Error: %s = %s (0x%x, at %s:%u)",
        exp, hvf_return_string(ret), ret, file, line);

    abort();
}

/*
 * hv_vm_map(), hv_vm_unmap() and hv_vm_protect() all operate at the stage-2
 * granule: the host page size, unless a 4KiB granule was asked for and
 * granted (hvf_ipa_page_size()).  Sections which are not aligned to it are
 * therefore never mapped into the guest; accesses to them trap and are
 * emulated as MMIO.  Since they are never mapped, they must not be unmapped
 * or reprotected either: passing an unaligned range to the hypervisor returns
 * HV_BAD_ARGUMENT.
 */
static bool hvf_section_is_host_aligned(const MemoryRegionSection *section)
{
    uint64_t page_size = hvf_ipa_page_size();

    return QEMU_IS_ALIGNED(section->offset_within_address_space, page_size) &&
           QEMU_IS_ALIGNED(int128_get64(section->size), page_size);
}

static void do_hv_vm_protect(hwaddr start, size_t size,
                             hv_memory_flags_t flags)
{
    intptr_t page_mask = -(intptr_t)hvf_ipa_page_size();
    hv_return_t ret;

    trace_hvf_vm_protect(start, size, flags,
                         flags & HV_MEMORY_READ  ? 'R' : '-',
                         flags & HV_MEMORY_WRITE ? 'W' : '-',
                         flags & HV_MEMORY_EXEC  ? 'X' : '-');
    g_assert(!((uintptr_t)start & ~page_mask));
    g_assert(!(size & ~page_mask));

    ret = hv_vm_protect(start, size, flags);
    assert_hvf_ok(ret);
}

/*
 * Apply @flags to [start, start + size), except to pages the guest must not
 * reach at all (see hvf_set_ipa_denied_fn()), which get no access.  Every
 * path that widens a mapped page's permissions comes through here, so dirty
 * logging cannot hand a denied page back to the guest.  Runs of pages with
 * the same outcome are protected together.
 */
static void hvf_protect_range(hwaddr start, size_t size,
                              hv_memory_flags_t flags)
{
    uint64_t page_size = hvf_ipa_page_size();
    hwaddr run_start = start;
    hv_memory_flags_t run_flags = 0;
    hwaddr addr;

    if (!hvf_ipa_denied) {
        do_hv_vm_protect(start, size, flags);
        return;
    }

    for (addr = start; addr < start + size; addr += page_size) {
        hv_memory_flags_t f = hvf_ipa_denied(addr) ? 0 : flags;

        if (addr == start) {
            run_flags = f;
        } else if (f != run_flags) {
            do_hv_vm_protect(run_start, addr - run_start, run_flags);
            run_start = addr;
            run_flags = f;
        }
    }
    do_hv_vm_protect(run_start, start + size - run_start, run_flags);
}

void hvf_protect_clean_range(hwaddr addr, size_t size)
{
    hvf_protect_range(addr, size, HV_MEMORY_READ | HV_MEMORY_EXEC);
}

void hvf_unprotect_dirty_range(hwaddr addr, size_t size)
{
    hvf_protect_range(addr, size,
                      HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
}

/*
 * The flags a mapped page should have when nothing is denied: what
 * hvf_set_phys_mem() maps it with, less write while dirty logging has it
 * clean.  Returns false for an address that is not mapped at all.
 */
static bool hvf_mapped_page_flags(hwaddr ipa, hv_memory_flags_t *flags)
{
    uint64_t page_size = hvf_ipa_page_size();
    MemoryRegionSection section;
    MemoryRegion *mr;
    bool writable;

    /*
     * A page is only mapped if one RAM (or ROMD) region covers all of it:
     * hvf_set_phys_mem() skips sections that are not granule aligned.
     */
    section = memory_region_find(get_system_memory(), ipa, page_size);
    mr = section.mr;
    if (!mr) {
        return false;
    }
    if ((!memory_region_is_ram(mr) && !memory_region_is_romd(mr)) ||
        int128_get64(section.size) != page_size) {
        memory_region_unref(mr);
        return false;
    }
    writable = !mr->readonly && !mr->rom_device &&
               !memory_region_get_dirty_log_mask(mr);
    *flags = HV_MEMORY_READ | HV_MEMORY_EXEC | (writable ? HV_MEMORY_WRITE : 0);
    memory_region_unref(mr);
    return true;
}

void hvf_update_ipa_range(hwaddr start, hwaddr size)
{
    uint64_t page_size = hvf_ipa_page_size();
    hwaddr end, addr, run_start = 0;
    hv_memory_flags_t run_flags = 0;
    bool in_run = false;

    start = QEMU_ALIGN_DOWN(start, page_size);
    end = start + QEMU_ALIGN_UP(size, page_size);
    for (addr = start; addr < end; addr += page_size) {
        hv_memory_flags_t flags;
        bool mapped = hvf_mapped_page_flags(addr, &flags);

        if (mapped && hvf_ipa_denied && hvf_ipa_denied(addr)) {
            flags = 0;
        }
        /* One hv_vm_protect() per run of mapped pages with the same flags */
        if (in_run && (!mapped || flags != run_flags)) {
            do_hv_vm_protect(run_start, addr - run_start, run_flags);
            in_run = false;
        }
        if (mapped && !in_run) {
            run_start = addr;
            run_flags = flags;
            in_run = true;
        }
    }
    if (in_run) {
        do_hv_vm_protect(run_start, end - run_start, run_flags);
    }
}

static bool hvf_update_flat_range(Int128 start, Int128 len,
                                  const MemoryRegion *mr,
                                  hwaddr offset_in_region, void *opaque)
{
    if (memory_region_is_ram(mr)) {
        hvf_update_ipa_range(int128_get64(start), int128_get64(len));
    }
    return false;
}

void hvf_update_all_ipa(void)
{
    RCU_READ_LOCK_GUARD();
    flatview_for_each_range(address_space_to_flatview(&address_space_memory),
                            hvf_update_flat_range, NULL);
}

static void hvf_set_phys_mem(MemoryRegionSection *section, bool add)
{
    MemoryRegion *area = section->mr;
    bool writable = !area->readonly && !area->rom_device;
    hv_memory_flags_t flags;
    uint64_t gpa = section->offset_within_address_space;
    uint64_t size = int128_get64(section->size);
    hv_return_t ret;
    void *mem;

    if (!memory_region_is_ram(area)) {
        if (writable) {
            return;
        } else if (!memory_region_is_romd(area)) {
            /*
             * If the memory device is not in romd_mode, then we actually want
             * to remove the hvf memory slot so all accesses will trap.
             */
             add = false;
        }
    }

    if (!hvf_section_is_host_aligned(section)) {
        /*
         * Not host page aligned, so we can not map it as RAM.  It was never
         * mapped for exactly the same reason, so there is nothing to unmap
         * either: leave the hypervisor alone and let accesses trap.
         */
        return;
    }

    if (!add) {
        trace_hvf_vm_unmap(gpa, size);
        ret = hv_vm_unmap(gpa, size);
        assert_hvf_ok(ret);
        return;
    }

    flags = HV_MEMORY_READ | HV_MEMORY_EXEC | (writable ? HV_MEMORY_WRITE : 0);
    mem = memory_region_get_ram_ptr(area) + section->offset_within_region;

    trace_hvf_vm_map(gpa, size, mem, flags,
                     flags & HV_MEMORY_READ ?  'R' : '-',
                     flags & HV_MEMORY_WRITE ? 'W' : '-',
                     flags & HV_MEMORY_EXEC ?  'X' : '-');
    ret = hv_vm_map(mem, gpa, size, flags);
    assert_hvf_ok(ret);

    /* A new mapping starts out fully accessible; take denied pages back */
    if (hvf_ipa_denied) {
        hvf_protect_range(gpa, size, flags);
    }
}

static void hvf_log_start(MemoryListener *listener,
                          MemoryRegionSection *section, int old, int new)
{
    assert(new != 0);
    if (old == 0 && hvf_section_is_host_aligned(section)) {
        hvf_protect_clean_range(section->offset_within_address_space,
                                int128_get64(section->size));
    }
}

static void hvf_log_stop(MemoryListener *listener,
                         MemoryRegionSection *section, int old, int new)
{
    assert(old != 0);
    if (new == 0 && hvf_section_is_host_aligned(section)) {
        hvf_unprotect_dirty_range(section->offset_within_address_space,
                                  int128_get64(section->size));
    }
}

static void hvf_log_clear(MemoryListener *listener,
                          MemoryRegionSection *section)
{
    /*
     * The dirty page bits within section are being cleared.
     * Some number of those pages may have been dirtied and
     * the write permission enabled.  Reset the range read-only.
     */
    if (hvf_section_is_host_aligned(section)) {
        hvf_protect_clean_range(section->offset_within_address_space,
                                int128_get64(section->size));
    }
}

static void hvf_region_add(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    hvf_set_phys_mem(section, true);
}

static void hvf_region_del(MemoryListener *listener,
                           MemoryRegionSection *section)
{
    hvf_set_phys_mem(section, false);
}

static MemoryListener hvf_memory_listener = {
    .name = "hvf",
    .priority = MEMORY_LISTENER_PRIORITY_ACCEL,
    .region_add = hvf_region_add,
    .region_del = hvf_region_del,
    .log_start = hvf_log_start,
    .log_stop = hvf_log_stop,
    .log_clear = hvf_log_clear,
};

static int hvf_accel_init(AccelState *as, MachineState *ms)
{
    hv_return_t ret;
    HVFState *s = HVF_STATE(as);
    int pa_range = 36;
    MachineClass *mc = MACHINE_GET_CLASS(ms);


    if (mc->get_physical_address_range) {
        pa_range = mc->get_physical_address_range(ms,
            hvf_arch_get_default_ipa_bit_size(), hvf_arch_get_max_ipa_bit_size());
        if (pa_range < 0) {
            return -EINVAL;
        }
    }

    if (mc->get_kernel_irqchip_default) {
        bool kernel_irqchip_default = mc->get_kernel_irqchip_default(ms);
        if (!hvf_kernel_irqchip_override) {
            hvf_kernel_irqchip = kernel_irqchip_default;
        }
    }

    ret = hvf_arch_vm_create(ms, (uint32_t)pa_range);
    if (ret == HV_DENIED) {
        error_report("Could not access HVF. Is the executable signed"
                     " with com.apple.security.hypervisor entitlement?");
        exit(1);
    }
    assert_hvf_ok(ret);

    as->gdbstub.sstep_flags = SSTEP_ENABLE | SSTEP_NOIRQ;

    QTAILQ_INIT(&s->hvf_sw_breakpoints);

    hvf_state = s;
    memory_listener_register(&hvf_memory_listener, &address_space_memory);

    return hvf_arch_init();
}

static void hvf_set_kernel_irqchip(Object *obj, Visitor *v,
                                   const char *name, void *opaque,
                                   Error **errp)
{
    OnOffSplit mode;

    hvf_kernel_irqchip_override = true;
    if (!visit_type_OnOffSplit(v, name, &mode, errp)) {
        return;
    }

    switch (mode) {
    case ON_OFF_SPLIT_ON:
#ifdef HOST_X86_64
        /* macOS 12 onwards exposes an HVF virtual APIC. */
        error_setg(errp, "HVF: kernel irqchip is not currently implemented for x86.");
        break;
#else
        hvf_kernel_irqchip = true;
        break;
#endif

    case ON_OFF_SPLIT_OFF:
        hvf_kernel_irqchip = false;
        break;

    case ON_OFF_SPLIT_SPLIT:
        error_setg(errp, "HVF: split irqchip is not supported on HVF.");
        break;

    default:
        /*
         * The value was checked in visit_type_OnOffSplit() above. If
         * we get here, then something is wrong in QEMU.
         */
        abort();
    }
}

static void hvf_accel_class_init(ObjectClass *oc, const void *data)
{
    AccelClass *ac = ACCEL_CLASS(oc);
    ac->name = "HVF";
    ac->init_machine = hvf_accel_init;
    ac->allowed = &hvf_allowed;
    hvf_kernel_irqchip_override = false;
    hvf_kernel_irqchip = false;
    object_class_property_add(oc, "kernel-irqchip", "on|off|split",
        NULL, hvf_set_kernel_irqchip,
        NULL, NULL);
    object_class_property_set_description(oc, "kernel-irqchip",
        "Configure HVF irqchip");
}

static const TypeInfo hvf_accel_type = {
    .name = TYPE_HVF_ACCEL,
    .parent = TYPE_ACCEL,
    .instance_size = sizeof(HVFState),
    .class_init = hvf_accel_class_init,
};

static void hvf_type_init(void)
{
    type_register_static(&hvf_accel_type);
}

type_init(hvf_type_init);
