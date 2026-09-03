/*
 * Device DMA for an emulated Arm CCA guest.
 *
 * A device may only reach memory the Realm has handed back with
 * RSI_IPA_STATE_SET; its protected memory is not the host's to read.  Nothing
 * here enforces that in the sense of protecting anything -- there is no Realm
 * -- but refusing the accesses a real system would refuse is what makes a
 * guest that got it wrong say so, instead of working here and hanging on
 * hardware.
 *
 * The other half is which address a device should be given, and the two
 * launchers a Realm guest meets disagree.  kvmtool registers guest RAM once at
 * the protected IPA and hands that table to vhost, so a descriptor carrying
 * the alias resolves to nothing and the transfer silently does not happen.
 * QEMU as a Realm VMM adds an IOMMU region over the unprotected half and
 * retargets it, so either address works.  x-cca-dma picks which of the two a
 * guest is held to, because a guest tuned to one and run on the other is
 * exactly the bug this is here to catch.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio.h"
#include "system/memory.h"
#include "target/arm/cpu.h"
#include "target/arm/internals.h"
#include "exec/target_page.h"
#include "hw/arm/cca-dma.h"

#define TYPE_CCA_DMA_MEMORY_REGION "cca-dma-iommu-memory-region"

typedef struct CcaDmaState {
    IOMMUMemoryRegion iommu;
    AddressSpace as;
    ARMCPU *cpu;
    uint64_t shared_mask;
    bool armed;
    bool warned_alias;
    bool warned_protected;
} CcaDmaState;

static CcaDmaState *cca_dma_state;

void cca_dma_arm(void)
{
    if (cca_dma_state) {
        cca_dma_state->armed = true;
    }
}

static IOMMUTLBEntry cca_dma_translate(IOMMUMemoryRegion *iommu_mr, hwaddr addr,
                                       IOMMUAccessFlags flag, int iommu_idx)
{
    CcaDmaState *s = container_of(iommu_mr, CcaDmaState, iommu);
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = addr,
        .translated_addr = 0,
        .addr_mask = TARGET_PAGE_SIZE - 1,
        .perm = IOMMU_NONE,
    };
    bool aliased = !!(addr & s->shared_mask);
    hwaddr ipa = addr & ~s->shared_mask;

    /*
     * Until the guest has spoken RSI it is firmware, and firmware loading a
     * kernel over DMA is not the thing being judged.
     */
    if (!s->armed) {
        ret.translated_addr = ipa;
        ret.perm = IOMMU_RW;
        return ret;
    }

    if (aliased && s->cpu->cca_dma == CCA_DMA_PLAIN) {
        if (!s->warned_alias) {
            s->warned_alias = true;
            warn_report("cca: device DMA to 0x%" HWADDR_PRIx " denied: the "
                        "address carries the unprotected alias. A launcher "
                        "that registers Realm memory once at the protected "
                        "IPA -- kvmtool does -- resolves this to nothing and "
                        "moves no data. Pass x-cca-dma=both for a launcher "
                        "that accepts either.", addr);
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: DMA denied, 0x%" HWADDR_PRIx " carries the "
                      "unprotected alias\n", addr);
        return ret;
    }

    if (!arm_cca_gpa_is_shared(&s->cpu->env, ipa)) {
        if (!s->warned_protected) {
            s->warned_protected = true;
            warn_report("cca: device DMA to 0x%" HWADDR_PRIx " denied: the "
                        "Realm has not handed this page back with "
                        "RSI_IPA_STATE_SET, so on hardware the host cannot "
                        "read it at all.", addr);
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cca: DMA denied, the Realm still owns 0x%" HWADDR_PRIx
                      "\n", ipa);
        return ret;
    }

    ret.translated_addr = ipa;
    ret.perm = IOMMU_RW;
    return ret;
}

static AddressSpace *cca_dma_get_address_space(PCIBus *bus, void *opaque,
                                               int devfn)
{
    /*
     * One address space for every function: which pages a device may reach is
     * a property of the memory, not of which device is asking.
     */
    return &((CcaDmaState *)opaque)->as;
}

static const PCIIOMMUOps cca_dma_iommu_ops = {
    .get_address_space = cca_dma_get_address_space,
};

void cca_dma_setup(PCIBus *bus)
{
    ARMCPU *cpu = arm_cca_find_guest_cpu();
    CcaDmaState *s;

    if (!cpu || !bus) {
        return;
    }

    /*
     * Legacy virtio publishes a queue address as a 32-bit page frame number,
     * which cannot carry the alias bit, and cannot negotiate
     * VIRTIO_F_ACCESS_PLATFORM.  A Realm guest refuses such a device anyway;
     * refusing to create one says so earlier and more clearly.
     */
    object_register_sugar_prop(TYPE_VIRTIO_PCI, "disable-legacy", "on", true);
    object_register_sugar_prop(TYPE_VIRTIO_DEVICE, "iommu_platform", "on",
                               false);

    s = g_new0(CcaDmaState, 1);
    s->cpu = cpu;
    s->shared_mask = 1ULL << (cpu->cca_ipa_bits - 1);
    cca_dma_state = s;

    /* Wide enough to contain the alias, not just RAM. */
    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_CCA_DMA_MEMORY_REGION, OBJECT(bus),
                             "cca-dma", 1ULL << cpu->cca_ipa_bits);
    address_space_init(&s->as, MEMORY_REGION(&s->iommu), "cca-dma");
    pci_setup_iommu(bus, &cca_dma_iommu_ops, s);

    warn_report("cca: device DMA is restricted to pages the Realm has handed "
                "back with RSI_IPA_STATE_SET, addressed by their plain IPA%s. "
                "This is an emulation aid, not a security boundary.",
                cpu->cca_dma == CCA_DMA_BOTH ? " or their alias" : "");
}

static void cca_dma_memory_region_class_init(ObjectClass *klass,
                                             const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = cca_dma_translate;
}

static const TypeInfo cca_dma_memory_region_info = {
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .name = TYPE_CCA_DMA_MEMORY_REGION,
    .class_init = cca_dma_memory_region_class_init,
};

static void cca_dma_register_types(void)
{
    type_register_static(&cca_dma_memory_region_info);
}

type_init(cca_dma_register_types);
