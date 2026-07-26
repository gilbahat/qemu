/*
 * DMA filtering for the emulated AMD SEV-SNP guest (TCG).
 *
 * An SNP guest's private memory is not reachable by the host, so a device may
 * only DMA to pages the guest has moved to shared.  Unlike TDX, where shared
 * memory is a different *address* -- the SHARED alias, one GPA bit -- SNP
 * sharing is an attribute recorded in the RMP, so there is no address bit to
 * test.  The filter has to ask what state the page is in.
 *
 * That is why this could not exist before page-state tracking did: with nothing
 * recording which pages are shared, every answer would have been a guess.
 *
 * Without this the emulation certifies nothing on the device path: private and
 * shared are the same RAM under TCG, so a guest that never shares its virtio
 * rings works here and fails on hardware.  Denying the access loudly turns that
 * into an immediate, legible failure instead of silent ring corruption.
 *
 * This is a development aid, not a security boundary.  See
 * docs/system/i386/amd-sev-snp-tcg.rst.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "hw/i386/snp-dma.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-pci.h"
#include "system/memory.h"
#include "target/i386/cpu.h"
#include "target/i386/tcg/system/snp.h"

#define TYPE_SNP_DMA_MEMORY_REGION "snp-dma-iommu-memory-region"

typedef struct SnpDmaState {
    IOMMUMemoryRegion iommu;
    AddressSpace as;
    X86CPU *cpu;
    uint64_t cbit;
    bool warned;
    bool warned_cbit;
} SnpDmaState;

/*
 * Armed by the guest's first PVALIDATE, for the same reason #VC reflection is:
 * a direct -kernel boot runs SNP-unaware firmware as a loader shim, and that
 * firmware does DMA of its own long before the payload runs.  Denying it would
 * break the boot and bury the interesting failures in noise.
 */
static bool snp_dma_armed;

void snp_dma_arm(void)
{
    snp_dma_armed = true;
}

/*
 * Report the first denial in full and then stay quiet: a guest that has not
 * shared its rings generates one of these per descriptor fetch, and burying the
 * useful message under thousands of duplicates helps nobody.
 */
static void snp_dma_report_denied(SnpDmaState *s, hwaddr addr)
{
    if (!s->warned) {
        s->warned = true;
        warn_report("sev-snp: device DMA to GPA 0x%" HWADDR_PRIx " denied: the "
                    "guest has not shared this page. An SNP guest must move DMA "
                    "buffers to shared with a page-state change before a device "
                    "can reach them; on hardware the host cannot read "
                    "guest-private memory at all.", addr);
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "sev-snp: DMA denied, GPA 0x%" HWADDR_PRIx " is not shared\n",
                  addr);
}

/*
 * A DMA address is a plain GPA: the C-bit is a page-table attribute and has no
 * meaning to a device.  A guest that programs one into a descriptor has
 * confused the two, which is worth saying plainly -- the resulting address
 * would otherwise look like a wild pointer into high memory.
 */
static void snp_dma_report_cbit(SnpDmaState *s, hwaddr addr)
{
    if (!s->warned_cbit) {
        s->warned_cbit = true;
        warn_report("sev-snp: device DMA address 0x%" HWADDR_PRIx " has the "
                    "C-bit set. DMA addresses are plain guest physical "
                    "addresses; the C-bit belongs in page tables only.", addr);
    }
}

static IOMMUTLBEntry snp_dma_translate(IOMMUMemoryRegion *iommu_mr, hwaddr addr,
                                       IOMMUAccessFlags flag, int iommu_idx)
{
    SnpDmaState *s = container_of(iommu_mr, SnpDmaState, iommu);
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = addr & ~(hwaddr)SNP_DMA_PAGE_MASK,
        .translated_addr = addr & ~(hwaddr)SNP_DMA_PAGE_MASK,
        .addr_mask = SNP_DMA_PAGE_MASK,
        .perm = IOMMU_RW,
    };

    if (!snp_dma_armed) {
        /* Firmware, before the SNP payload has taken over: pass through. */
        return ret;
    }

    if (addr & s->cbit) {
        snp_dma_report_cbit(s, addr);
        ret.perm = IOMMU_NONE;
        return ret;
    }

    if (!snp_rmp_gpa_is_shared(&s->cpu->env, addr)) {
        snp_dma_report_denied(s, addr);
        ret.perm = IOMMU_NONE;
    }

    return ret;
}

static AddressSpace *snp_dma_get_address_space(PCIBus *bus, void *opaque,
                                               int devfn)
{
    SnpDmaState *s = opaque;

    /*
     * Every device shares one address space: the private/shared split is a
     * property of the guest's memory, not of which device is asking.
     */
    return &s->as;
}

static const PCIIOMMUOps snp_dma_iommu_ops = {
    .get_address_space = snp_dma_get_address_space,
};

static X86CPU *snp_dma_find_cpu(void)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        X86CPU *cpu = X86_CPU(cs);

        if (cpu->sev_snp_guest) {
            return cpu;
        }
    }
    return NULL;
}

void snp_dma_setup(PCIBus *bus)
{
    X86CPU *cpu = snp_dma_find_cpu();
    SnpDmaState *s;

    if (!cpu || !bus) {
        return;
    }

    /*
     * With no page-state tracking there is no shared/private distinction to
     * enforce, so the filter could only permit everything -- installing it
     * would cost a translation per access and decide nothing.  This is not
     * warned about: x-sev-snp-rmp=off means nothing is tracked, so nothing
     * being enforced is the definition of the mode rather than a surprise, and
     * the property already announces that on every start.  It is stated in
     * docs/system/i386/amd-sev-snp-tcg.rst instead.
     */
    if (cpu->sev_snp_rmp == SNP_RMP_OFF) {
        return;
    }

    /*
     * Confidential guests cannot use legacy virtio: it has no way to negotiate
     * VIRTIO_F_ACCESS_PLATFORM, so the guest driver would not know it has to
     * place buffers in shared memory at all.  This mirrors what
     * machine_run_board_init() does for a confidential-guest-support object,
     * which the CPU-property route does not reach.
     *
     * Registered here rather than later because devices have not been created
     * yet -- CPUs are realized before the PCI bus exists.
     */
    object_register_sugar_prop(TYPE_VIRTIO_PCI, "disable-legacy", "on", true);
    object_register_sugar_prop(TYPE_VIRTIO_DEVICE, "iommu_platform", "on",
                               false);

    s = g_new0(SnpDmaState, 1);
    s->cpu = cpu;
    s->cbit = 1ULL << cpu->sev_snp_cbitpos;

    /*
     * Spans the whole physical address space, so that an address with the C-bit
     * set still lands in the region and can be reported rather than aborting
     * somewhere less informative.  phys_bits is cbitpos + 1 by construction.
     */
    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_SNP_DMA_MEMORY_REGION, OBJECT(bus),
                             "snp-dma", 1ULL << cpu->phys_bits);
    address_space_init(&s->as, MEMORY_REGION(&s->iommu), "snp-dma");
    pci_setup_iommu(bus, &snp_dma_iommu_ops, s);

    warn_report("sev-snp: device DMA is restricted to guest-shared pages and "
                "legacy virtio is disabled. This is an emulation aid, not a "
                "security boundary.");
}

static void snp_dma_memory_region_class_init(ObjectClass *klass,
                                             const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = snp_dma_translate;
}

static const TypeInfo snp_dma_memory_region_info = {
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .name = TYPE_SNP_DMA_MEMORY_REGION,
    .class_init = snp_dma_memory_region_class_init,
};

static void snp_dma_register_types(void)
{
    type_register_static(&snp_dma_memory_region_info);
}

type_init(snp_dma_register_types);
