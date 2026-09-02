/*
 * DMA filtering for the emulated TDX guest (TCG).
 *
 * A TD's private memory is not reachable by the host, so a device may only DMA
 * to memory the guest has explicitly shared -- which a TD addresses through the
 * SHARED alias, i.e. with GPA bit (GPAW-1) set.  Model that by giving PCI
 * devices an address space that maps the shared alias and nothing else.
 *
 * Without this the emulation certifies nothing: private and shared are the same
 * RAM under TCG, so a guest that never shares its virtio rings works here and
 * fails on hardware.  Denying the access loudly turns that into an immediate,
 * legible failure.
 *
 * This is a development aid, not a security boundary.  See
 * docs/system/i386/tdx-tcg.rst.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "hw/i386/tdx-dma.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-pci.h"
#include "system/memory.h"
#include "target/i386/cpu.h"
#include "target/i386/tcg/system/tdx.h"

#define TYPE_TDX_DMA_MEMORY_REGION "tdx-dma-iommu-memory-region"

typedef struct TdxDmaState {
    IOMMUMemoryRegion iommu;
    AddressSpace as;
    X86CPU *cpu;
    uint64_t shared_mask;
    bool warned;
    bool warned_unconverted;
} TdxDmaState;

static TdxDmaState *tdx_dma_state;

/*
 * Armed by the guest's first TDCALL, for the same reason #VE reflection is: a
 * direct -kernel boot runs TDX-unaware firmware as a loader shim, and that
 * firmware does DMA of its own long before the TD payload runs.  Denying it
 * would break the boot and bury the interesting failures in noise.
 */
static bool tdx_dma_armed;

void tdx_dma_arm(void)
{
    tdx_dma_armed = true;
}

/*
 * Report the first denial in full and then stay quiet: a guest that has not
 * shared its rings generates one of these per descriptor fetch, and burying the
 * useful message under thousands of duplicates helps nobody.
 */
static void tdx_dma_report_denied(TdxDmaState *s, hwaddr addr)
{
    if (!s->warned) {
        s->warned = true;
        warn_report("tdx: device DMA to GPA 0x%" HWADDR_PRIx " denied: the "
                    "guest has not shared this memory. A TD must convert its "
                    "DMA buffers with TDVMCALL<MapGPA> (which names the alias, "
                    "GPA bit %d) and then give the device the plain GPA; on "
                    "hardware the host cannot read TD-private memory at all.",
                    addr, ctz64(s->shared_mask));
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "tdx: DMA denied, GPA 0x%" HWADDR_PRIx " is not shared\n",
                  addr);
}

static IOMMUTLBEntry tdx_dma_translate(IOMMUMemoryRegion *iommu_mr, hwaddr addr,
                                       IOMMUAccessFlags flag, int iommu_idx)
{
    TdxDmaState *s = container_of(iommu_mr, TdxDmaState, iommu);
    IOMMUTLBEntry ret = {
        .target_as = &address_space_memory,
        .iova = addr & ~(hwaddr)TARGET_PAGE_MASK_TDX,
        .translated_addr = 0,
        .addr_mask = TARGET_PAGE_MASK_TDX,
        .perm = IOMMU_NONE,
    };

    if (!tdx_dma_armed) {
        /* Firmware, before the TD payload has taken over: pass through. */
        ret.translated_addr = (addr & ~s->shared_mask) &
                              ~(hwaddr)TARGET_PAGE_MASK_TDX;
        ret.perm = IOMMU_RW;
    } else if (addr & s->shared_mask) {
        /*
         * The SHARED alias has no business in a DMA address.
         *
         * A TDVMCALL argument carries the bit, because that is how the call
         * tells the TDX module which alias it means.  Device DMA is not
         * relayed through the module: a VMM resolves the address itself,
         * against the ordinary guest memory map, and an address above RAM
         * resolves to nothing -- the descriptors are written, the device is
         * kicked, and no data moves.  Refusing it here is what makes that
         * visible, rather than leaving a guest to discover it on hardware as
         * a virtio device that negotiates and then hangs.
         */
        if (!s->warned_unconverted) {
            s->warned_unconverted = true;
            warn_report("tdx: device DMA to 0x%" HWADDR_PRIx " denied: the "
                        "address carries the SHARED alias. A TDVMCALL argument "
                        "names the alias; a DMA address does not -- on hardware "
                        "this resolves above RAM and silently transfers "
                        "nothing.", addr);
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "tdx: DMA denied, 0x%" HWADDR_PRIx " carries the SHARED "
                      "alias\n", addr);
    } else if (!tdx_sept_enabled(&s->cpu->env) ||
               tdx_sept_gpa_is_shared(&s->cpu->env,
                                      addr & ~(hwaddr)TARGET_PAGE_MASK_TDX)) {
        /*
         * A plain GPA over a page the TD converted with TDVMCALL<MapGPA>.
         * That is what a device is given and all it can reach: private pages
         * are behind guest_memfd on a real host and simply are not readable by
         * the VMM.  With no page-state model to ask, fall back to allowing it.
         */
        ret.translated_addr = addr & ~(hwaddr)TARGET_PAGE_MASK_TDX;
        ret.perm = IOMMU_RW;
    } else {
        tdx_dma_report_denied(s, addr);
    }

    return ret;
}

static AddressSpace *tdx_dma_get_address_space(PCIBus *bus, void *opaque,
                                               int devfn)
{
    TdxDmaState *s = opaque;

    /*
     * Every device shares one address space: in TDX the private/shared split
     * is a property of the guest's memory, not of which device is asking.
     */
    return &s->as;
}

static const PCIIOMMUOps tdx_dma_iommu_ops = {
    .get_address_space = tdx_dma_get_address_space,
};

/* The TDX CPU property is the single knob; find out whether it is set. */
static X86CPU *tdx_dma_find_cpu(void)
{
    CPUState *cs;

    CPU_FOREACH(cs) {
        X86CPU *cpu = X86_CPU(cs);

        if (cpu->tdx_guest) {
            return cpu;
        }
    }
    return NULL;
}

void tdx_dma_setup(PCIBus *bus)
{
    X86CPU *cpu = tdx_dma_find_cpu();
    TdxDmaState *s;

    if (!cpu || !bus) {
        return;
    }

    /*
     * Confidential guests cannot use legacy virtio: the legacy transport
     * publishes a queue address as a 32-bit page frame number, which tops out
     * at 2^44 and so cannot even express a SHARED alias address, and it has no
     * way to negotiate VIRTIO_F_ACCESS_PLATFORM.  This mirrors what
     * machine_run_board_init() does for a confidential-guest-support object,
     * which the CPU-property route does not reach.
     *
     * Registered here rather than later because devices have not been created
     * yet -- CPUs are realized before the PCI bus exists.
     */
    object_register_sugar_prop(TYPE_VIRTIO_PCI, "disable-legacy", "on", true);
    object_register_sugar_prop(TYPE_VIRTIO_DEVICE, "iommu_platform", "on",
                               false);

    s = g_new0(TdxDmaState, 1);
    s->cpu = cpu;
    s->shared_mask = 1ULL << (cpu->tdx_gpaw - 1);
    tdx_dma_state = s;

    /*
     * The region must be large enough to contain the shared alias, so it spans
     * the whole GPAW rather than just RAM.
     */
    memory_region_init_iommu(&s->iommu, sizeof(s->iommu),
                             TYPE_TDX_DMA_MEMORY_REGION, OBJECT(bus),
                             "tdx-dma", 1ULL << cpu->tdx_gpaw);
    address_space_init(&s->as, MEMORY_REGION(&s->iommu), "tdx-dma");
    pci_setup_iommu(bus, &tdx_dma_iommu_ops, s);

    warn_report("tdx: device DMA is restricted to pages the TD has converted "
                "with TDVMCALL<MapGPA> (the alias is GPA bit %d, which belongs "
                "in the call and not in a DMA address) and legacy virtio is "
                "disabled. This is an emulation aid, not a security boundary.",
                cpu->tdx_gpaw - 1);
}

static void tdx_dma_memory_region_class_init(ObjectClass *klass,
                                             const void *data)
{
    IOMMUMemoryRegionClass *imrc = IOMMU_MEMORY_REGION_CLASS(klass);

    imrc->translate = tdx_dma_translate;
}

static const TypeInfo tdx_dma_memory_region_info = {
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .name = TYPE_TDX_DMA_MEMORY_REGION,
    .class_init = tdx_dma_memory_region_class_init,
};

static void tdx_dma_register_types(void)
{
    type_register_static(&tdx_dma_memory_region_info);
}

type_init(tdx_dma_register_types);
