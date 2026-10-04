/*
 * Emulated Arm CCA guest interface: TCG enforcement of page states.
 *
 * TCG asks arm_cca_ipa_permitted() from the page-table walker
 * (get_phys_addr_gpc), so a decision lives on in the softmmu TLB until it is
 * flushed.  That is all there is to do here.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "exec/cputlb.h"
#include "cpu.h"
#include "internals.h"

static void cca_tcg_ripas_changed(ARMCPU *cpu, uint64_t base, uint64_t top,
                                  bool restricted)
{
    /*
     * Handing a range back takes access away, so anything already cached for
     * it has to go.  A transition the other way only adds access and cannot
     * leave a stale entry behind, which is worth keeping in mind before making
     * this unconditional: a guest claiming memory does it a granule at a time.
     */
    if (restricted) {
        tlb_flush(CPU(cpu));
    }
}

static void cca_tcg_ripas_reloaded(void)
{
    /*
     * The page states just changed under every cached translation, so nothing
     * decided against the old ones may be reused.
     */
    tlb_flush_all_cpus_synced(first_cpu);
}

const ArmCcaAccelOps arm_cca_tcg_ops = {
    .ripas_changed = cca_tcg_ripas_changed,
    .ripas_reloaded = cca_tcg_ripas_reloaded,
};
