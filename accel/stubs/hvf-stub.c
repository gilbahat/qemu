/*
 * HVF stubs for QEMU
 *
 *  Copyright (c) Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "system/hvf.h"

bool hvf_allowed;
bool hvf_kernel_irqchip;
bool hvf_nested_virt;

void hvf_nested_virt_enable(bool nested_virt)
{
    /*
     * This is called unconditionally from hw/arm/virt.c
     * because we don't know if HVF is going to be used
     * as that step of initialisation happens later.
     * As such, do nothing here instead of marking as unreachable.
     */
}

void hvf_request_4k_ipa_granule(void)
{
    /* As above: called before anyone knows whether HVF will be used */
}

bool hvf_ipa_granule_is_4k(void)
{
    return false;
}
