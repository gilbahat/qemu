/*
 * Launch-image extents, for the emulated confidential-guest environments.
 *
 * The emulated TDX and SEV-SNP page-state models need to know which guest pages
 * are the launch image: those are the ones a real TD or SNP guest finds already
 * accepted or validated, and everything else it has to claim for itself before
 * use.  rom_ptr() answers that for images the loader placed as ROMs, but not
 * for the ``-kernel`` paths that publish the image through fw_cfg and let a DMA
 * option ROM copy it in from inside the guest: there is no ROM at the load
 * address, and the bytes do not reach guest memory until the guest has already
 * started running.
 *
 * A guest loaded that way cannot boot in strict mode and cannot fix it, because
 * the first checked access is the instruction fetch immediately after paging is
 * enabled -- it faults on the page it is fetching from, before any code of its
 * own could accept anything.  So the loaders record what they place here, at
 * load time, and the models consult it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i386/x86-launch-image.h"

/*
 * Fixed at 4KiB rather than taken from TARGET_PAGE_*: launch images on x86 are
 * placed at 4KiB granularity regardless of the mapping the guest later chooses,
 * and not depending on the target page definition keeps this unit-testable.
 */
#define LAUNCH_PAGE_SIZE  4096
#define LAUNCH_PAGE_MASK  (~(hwaddr)(LAUNCH_PAGE_SIZE - 1))

typedef struct LaunchExtent {
    hwaddr addr;
    size_t datasize;
    size_t totalsize;
    uint8_t *data;
} LaunchExtent;

static GArray *launch_extents;

void x86_launch_image_add(hwaddr addr, const void *data, size_t datasize,
                          size_t totalsize)
{
    LaunchExtent e = {
        .addr = addr,
        .datasize = data ? datasize : 0,
        .totalsize = totalsize,
        .data = (data && datasize) ? g_memdup2(data, datasize) : NULL,
    };

    if (!totalsize) {
        return;
    }
    if (!launch_extents) {
        launch_extents = g_array_new(false, false, sizeof(LaunchExtent));
    }
    g_array_append_val(launch_extents, e);
}

static const LaunchExtent *launch_find(hwaddr gpa)
{
    guint i;

    for (i = 0; launch_extents && i < launch_extents->len; i++) {
        const LaunchExtent *e =
            &g_array_index(launch_extents, LaunchExtent, i);

        if (gpa >= e->addr && gpa < e->addr + e->totalsize) {
            return e;
        }
    }
    return NULL;
}

bool x86_launch_image_contains(hwaddr gpa)
{
    return launch_find(gpa) != NULL;
}

hwaddr x86_launch_image_limit(void)
{
    hwaddr limit = 0;
    guint i;

    for (i = 0; launch_extents && i < launch_extents->len; i++) {
        const LaunchExtent *e =
            &g_array_index(launch_extents, LaunchExtent, i);

        limit = MAX(limit, e->addr + e->totalsize);
    }
    return limit;
}

bool x86_launch_image_page(hwaddr gpa, const void **data, size_t *valid)
{
    hwaddr page = gpa & LAUNCH_PAGE_MASK;
    const LaunchExtent *e = launch_find(page);
    hwaddr off;

    if (!e) {
        return false;
    }

    /*
     * A page can start inside the data and run past its end -- a segment with a
     * .bss tail does exactly that -- so report how much of it is real.  The
     * caller zero-fills the remainder, which is what the guest will see.
     */
    off = page - e->addr;
    if (!e->data || off >= e->datasize) {
        *data = NULL;
        *valid = 0;
        return true;
    }
    *data = e->data + off;
    *valid = MIN((size_t)LAUNCH_PAGE_SIZE, e->datasize - off);
    return true;
}
