/*
 * QEMU Hypervisor.framework (HVF) support
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

/* header to be included in HVF-specific code */

#ifndef HVF_INT_H
#define HVF_INT_H

#include "qemu/queue.h"
#include "exec/vaddr.h"
#include "gdbstub/enums.h"
#include "qom/object.h"
#include "accel/accel-ops.h"

#ifdef __aarch64__
#include <Hypervisor/Hypervisor.h>
typedef hv_vcpu_t hvf_vcpuid;
#else
#include <Hypervisor/hv.h>
typedef hv_vcpuid_t hvf_vcpuid;
#endif

typedef struct hvf_vcpu_caps {
    uint64_t vmx_cap_pinbased;
    uint64_t vmx_cap_procbased;
    uint64_t vmx_cap_procbased2;
    uint64_t vmx_cap_entry;
    uint64_t vmx_cap_exit;
    uint64_t vmx_cap_preemption_timer;
} hvf_vcpu_caps;

struct HVFState {
    AccelState parent_obj;

    hvf_vcpu_caps *hvf_caps;
    uint64_t vtimer_offset;
    QTAILQ_HEAD(, hvf_sw_breakpoint) hvf_sw_breakpoints;
};
extern HVFState *hvf_state;

struct AccelCPUState {
    hvf_vcpuid fd;
#ifdef __aarch64__
    hv_vcpu_exit_t *exit;
    bool vtimer_masked;
    bool guest_debug_enabled;
    struct QEMUTimer *wfi_timer;
#endif
};

void assert_hvf_ok_impl(hv_return_t ret, const char *file, unsigned int line,
                        const char *exp);
#define assert_hvf_ok(EX) assert_hvf_ok_impl((EX), __FILE__, __LINE__, #EX)
const char *hvf_return_string(hv_return_t ret);
int hvf_arch_init(void);
hv_return_t hvf_arch_vm_create(MachineState *ms, uint32_t pa_range);
uint32_t hvf_arch_get_default_ipa_bit_size(void);
uint32_t hvf_arch_get_max_ipa_bit_size(void);
void hvf_kick_vcpu_thread(CPUState *cpu);

/* Must be called by the owning thread */
int hvf_arch_init_vcpu(CPUState *cpu);
/* Must be called by the owning thread */
void hvf_arch_vcpu_destroy(CPUState *cpu);
/* Must be called by the owning thread */
int hvf_arch_vcpu_exec(CPUState *);
/* Must be called by the owning thread */
int hvf_arch_put_registers(CPUState *);
/* Must be called by the owning thread */
int hvf_arch_get_registers(CPUState *);
/* Must be called by the owning thread */
void hvf_arch_update_guest_debug(CPUState *cpu);

void hvf_protect_clean_range(hwaddr addr, size_t size);
void hvf_unprotect_dirty_range(hwaddr addr, size_t size);

/* Set by hvf_request_4k_ipa_granule(); honoured by hvf_arch_vm_create() */
extern bool hvf_want_4k_ipa_granule;

/*
 * The stage-2 granule the VM was created with: the host page size unless
 * hvf_arch_vm_create() was granted a smaller one and recorded it here.
 */
uint64_t hvf_ipa_page_size(void);
void hvf_set_ipa_page_size(uint64_t size);

/**
 * HVFIpaDeniedFn: may the guest not reach @ipa at all?
 *
 * Optional, for guests whose own memory is partly off-limits to them, such as
 * an emulated CCA guest's protected pages after it has handed them back.
 * Denied pages are kept with no access in stage 2 whatever else wants them
 * mapped, so the guest takes a data abort on them.  Whoever changes the
 * answer calls hvf_update_ipa_range() for what changed.
 */
typedef bool HVFIpaDeniedFn(hwaddr ipa);
void hvf_set_ipa_denied_fn(HVFIpaDeniedFn *fn);

/* Recompute stage-2 permissions for a range, or for all mapped RAM */
void hvf_update_ipa_range(hwaddr start, hwaddr size);
void hvf_update_all_ipa(void);

struct hvf_sw_breakpoint {
    vaddr pc;
    vaddr saved_insn;
    int use_count;
    QTAILQ_ENTRY(hvf_sw_breakpoint) entry;
};

struct hvf_sw_breakpoint *hvf_find_sw_breakpoint(CPUState *cpu,
                                                 vaddr pc);
int hvf_sw_breakpoints_active(CPUState *cpu);

int hvf_arch_insert_sw_breakpoint(CPUState *cpu, struct hvf_sw_breakpoint *bp);
int hvf_arch_remove_sw_breakpoint(CPUState *cpu, struct hvf_sw_breakpoint *bp);
int hvf_arch_insert_gdbstub_hw_breakpoint(vaddr addr, vaddr len,
                                          GdbBreakpointType type);
int hvf_arch_remove_gdbstub_hw_breakpoint(vaddr addr, vaddr len,
                                          GdbBreakpointType type);
void hvf_arch_remove_all_gdbstub_hw_breakpoints(void);

/*
 * hvf_update_guest_debug:
 * @cs: CPUState for the CPU to update
 *
 * Update guest to enable or disable debugging. Per-arch specifics will be
 * handled by calling down to hvf_arch_update_guest_debug.
 */
void hvf_update_guest_debug(CPUState *cpu);

bool hvf_arch_cpu_realize(CPUState *cpu, Error **errp);
uint32_t hvf_arch_get_default_ipa_bit_size(void);
uint32_t hvf_arch_get_max_ipa_bit_size(void);

#endif
