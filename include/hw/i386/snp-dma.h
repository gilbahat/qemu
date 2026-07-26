/*
 * DMA filtering for the emulated AMD SEV-SNP guest (TCG).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_I386_SNP_DMA_H
#define HW_I386_SNP_DMA_H

#include "hw/pci/pci.h"

/* Page granularity of the DMA filter's translations. */
#define SNP_DMA_PAGE_MASK 0xfff

/**
 * snp_dma_setup: restrict device DMA to guest-shared memory.
 * @bus: the root PCI bus, already created but with no devices on it yet.
 *
 * A no-op unless some already-realized CPU has x-sev-snp-guest=on together with
 * page-state tracking (x-sev-snp-rmp), since without a page state there is
 * nothing to decide on.  Must be called after the PCI bus exists and before any
 * device is created, as devices capture their DMA address space at realize.
 */
void snp_dma_setup(PCIBus *bus);

/**
 * snp_dma_arm: begin enforcing the shared-memory restriction on device DMA.
 *
 * Called from the PVALIDATE helper the first time the guest issues one, so that
 * SNP-unaware firmware on a -kernel boot is not caught by it -- the same
 * arming rule as #VC reflection.
 */
void snp_dma_arm(void);

#endif /* HW_I386_SNP_DMA_H */
