/*
 * Device DMA for an emulated Arm CCA guest.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_CCA_DMA_H
#define HW_ARM_CCA_DMA_H

#include "hw/pci/pci.h"

/* x-cca-dma: which descriptor address a device is allowed to be given. */
#define CCA_DMA_PLAIN   0
#define CCA_DMA_BOTH    1

/**
 * cca_dma_setup: filter device DMA for an emulated CCA guest.
 * @bus: the PCI bus devices will attach to
 *
 * Does nothing unless some CPU has x-cca-guest set.  Must be called once the
 * bus exists and before any device is created, because a device captures its
 * DMA address space when it is realized.
 */
void cca_dma_setup(PCIBus *bus);

/**
 * cca_dma_arm: start judging device DMA.
 *
 * Called on the guest's first RSI call.  Before that the guest is firmware,
 * which loads over DMA and is not what this is meant to catch.
 */
void cca_dma_arm(void);

#endif /* HW_ARM_CCA_DMA_H */
