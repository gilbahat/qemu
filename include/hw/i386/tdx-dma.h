/*
 * DMA filtering for the emulated TDX guest (TCG).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_I386_TDX_DMA_H
#define HW_I386_TDX_DMA_H

#include "hw/pci/pci.h"

/* Page granularity of the DMA filter's translations. */
#define TARGET_PAGE_MASK_TDX 0xfff

/**
 * tdx_dma_setup: restrict device DMA to guest-shared memory.
 * @bus: the root PCI bus, already created but with no devices on it yet.
 *
 * A no-op unless some already-realized CPU has x-tdx-guest=on.  Must be called
 * after the PCI bus exists and before any device is created, since devices
 * capture their DMA address space when they are realized.
 */
void tdx_dma_setup(PCIBus *bus);

/**
 * tdx_dma_arm: begin enforcing the shared-memory restriction on device DMA.
 *
 * Called from the TDCALL helper the first time the guest issues one, so that
 * TDX-unaware firmware on a -kernel boot is not caught by it.
 */
void tdx_dma_arm(void);

#endif /* HW_I386_TDX_DMA_H */
