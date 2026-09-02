/*
 * Identity page tables with per-page C-bit control, for the emulated SEV-SNP
 * tests.
 *
 * PVALIDATE takes a linear address, so the walk decides which page it means
 * and, with it, whether the page is private.  On a mapping with C=0 it does
 * not return a status at all -- it raises #PF with the reserved bit set.  A
 * test that wants to validate a page therefore has to be able to map that one
 * page encrypted, and boot.S's tables cannot: they are 2MiB entries covering
 * everything, with no C-bit anywhere.
 *
 * So: a fresh identity map of the low 4GiB in 2MiB pages, except for the one
 * 2MiB region holding the pages under test, which is split to 4KiB so the
 * C-bit can be set one page at a time.  The tables themselves live in .bss and
 * stay shared, which is what lets the walk keep working while pages around
 * them become private.
 *
 * Include this once per test and call snp_tables_init() with an address in the
 * region to split, before the first PVALIDATE -- that is what arms #VC
 * reflection, and snp_cbit() needs a CPUID that would reflect afterwards.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SNP_PTES_H
#define SNP_PTES_H

#define SNP_PAGE_SIZE           4096UL
#define SNP_LARGE_PAGE_SIZE     (2UL * 1024 * 1024)

#define SNP_PTE_FLAGS           0x067   /* D | A | US | RW | P        */
#define SNP_PDE_LARGE_FLAGS     0x0e7   /* PS | D | A | US | RW | P   */
#define SNP_PDE_TABLE_FLAGS     0x007   /* US | RW | P                */

static unsigned long snp_pml4[512] __attribute__((aligned(4096)));
static unsigned long snp_pdp[512] __attribute__((aligned(4096)));
static unsigned long snp_pd[4][512] __attribute__((aligned(4096)));
static unsigned long snp_pt[512] __attribute__((aligned(4096)));
static unsigned long snp_split_base;

/*
 * Read once and cached.  Every CPUID reflects as #VC from the first PVALIDATE
 * onwards, and mapping a page happens well after that.  A real guest caches it
 * too, and has the sharper reason: the C-bit is what it needs in order to
 * reach a GHCB, so it cannot afford to need a GHCB to ask for it.
 */
static unsigned long snp_cbit_value;

static unsigned long snp_cbit(void)
{
    unsigned int a, b, c, d;

    if (snp_cbit_value) {
        return snp_cbit_value;
    }
    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(0x8000001F), "c"(0));
    snp_cbit_value = 1UL << (b & 0x3f);
    return snp_cbit_value;
}

static unsigned int snp_cbitpos(void)
{
    unsigned long bit = snp_cbit();
    unsigned int pos = 0;

    while (!(bit & 1UL)) {
        bit >>= 1;
        pos++;
    }
    return pos;
}

/* Build the tables and load them.  @split_addr picks the 2MiB region to split. */
static void snp_tables_init(unsigned long split_addr)
{
    unsigned long g, i;

    (void)snp_cbit();           /* before the first PVALIDATE arms reflection */

    for (i = 0; i < 512; i++) {
        snp_pml4[i] = 0;
        snp_pdp[i] = 0;
    }
    for (g = 0; g < 4; g++) {
        for (i = 0; i < 512; i++) {
            snp_pd[g][i] = (g << 30) | (i << 21) | SNP_PDE_LARGE_FLAGS;
        }
        snp_pdp[g] = (unsigned long)&snp_pd[g][0] | SNP_PDE_TABLE_FLAGS;
    }
    snp_pml4[0] = (unsigned long)snp_pdp | SNP_PDE_TABLE_FLAGS;

    snp_split_base = split_addr & ~(SNP_LARGE_PAGE_SIZE - 1);
    for (i = 0; i < 512; i++) {
        snp_pt[i] = (snp_split_base + i * SNP_PAGE_SIZE) | SNP_PTE_FLAGS;
    }
    snp_pd[snp_split_base >> 30][(snp_split_base >> 21) & 0x1ff] =
        (unsigned long)snp_pt | SNP_PDE_TABLE_FLAGS;

    __asm__ __volatile__("mov %0, %%cr3"
                         : : "r"((unsigned long)snp_pml4) : "memory");
}

static unsigned long *snp_pte_for(unsigned long va)
{
    return &snp_pt[(va - snp_split_base) / SNP_PAGE_SIZE];
}

static void snp_invlpg(unsigned long va)
{
    __asm__ __volatile__("invlpg (%0)" : : "r"(va) : "memory");
}

/* Map a page encrypted, and drop any translation cached for it. */
static void snp_map_private(unsigned long va)
{
    *snp_pte_for(va) |= snp_cbit();
    snp_invlpg(va);
}

/* And back, for a page being handed to a device. */
static void snp_map_shared(unsigned long va)
{
    *snp_pte_for(va) &= ~snp_cbit();
    snp_invlpg(va);
}

#endif /* SNP_PTES_H */
