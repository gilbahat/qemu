/*
 * Tests for the launch-image extent registry.
 *
 * The registry exists because a -kernel image published through fw_cfg and
 * copied in by a DMA option ROM is invisible to rom_ptr(): there is no ROM at
 * the load address, and the bytes are not in guest memory until the guest has
 * already started.  An emulated confidential guest loaded that way could not
 * boot in strict mode and could not fix it from inside, because the first
 * checked access is the fetch immediately after paging is enabled.
 *
 * The arithmetic worth testing is the partial page: a segment with a .bss tail
 * has a page that starts inside the real data and runs past its end, and the
 * remainder has to be reported as zero fill rather than read past the buffer.
 * Getting that wrong is how the measurement loops read off the end of a heap
 * allocation the first time round.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/i386/x86-launch-image.h"

#define IMG_BASE  0x100000
#define PAGE      4096

static void test_empty(void)
{
    const void *data;
    size_t valid;

    /* Nothing registered for this address: not part of any launch image. */
    g_assert_false(x86_launch_image_contains(0x900000));
    g_assert_false(x86_launch_image_page(0x900000, &data, &valid));
}

static void test_extent(void)
{
    /* 3 pages in guest memory, of which 1.5 pages are real data. */
    const size_t datasize = PAGE + PAGE / 2;
    const size_t totalsize = 3 * PAGE;
    g_autofree uint8_t *buf = g_malloc(datasize);
    const void *data;
    size_t valid;
    size_t i;

    for (i = 0; i < datasize; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }
    x86_launch_image_add(IMG_BASE, buf, datasize, totalsize);

    /* Every page of the region is part of the image, zero fill included. */
    g_assert_true(x86_launch_image_contains(IMG_BASE));
    g_assert_true(x86_launch_image_contains(IMG_BASE + 2 * PAGE + 17));
    g_assert_false(x86_launch_image_contains(IMG_BASE - 1));
    g_assert_false(x86_launch_image_contains(IMG_BASE + totalsize));

    /* First page: entirely real data. */
    g_assert_true(x86_launch_image_page(IMG_BASE, &data, &valid));
    g_assert_cmpuint(valid, ==, PAGE);
    g_assert_cmpmem(data, PAGE, buf, PAGE);

    /* Second page: half real, half zero fill -- the case that matters. */
    g_assert_true(x86_launch_image_page(IMG_BASE + PAGE, &data, &valid));
    g_assert_cmpuint(valid, ==, PAGE / 2);
    g_assert_cmpmem(data, PAGE / 2, buf + PAGE, PAGE / 2);

    /* Third page: past the data entirely, so no bytes and no pointer. */
    g_assert_true(x86_launch_image_page(IMG_BASE + 2 * PAGE, &data, &valid));
    g_assert_cmpuint(valid, ==, 0);
    g_assert_null(data);

    /* An offset within a page resolves to that page, not past it. */
    g_assert_true(x86_launch_image_page(IMG_BASE + PAGE + 8, &data, &valid));
    g_assert_cmpuint(valid, ==, PAGE / 2);
}

static void test_zero_fill_only(void)
{
    const void *data;
    size_t valid;

    /* A region with no backing data at all is still part of the image. */
    x86_launch_image_add(0x200000, NULL, 0, PAGE);
    g_assert_true(x86_launch_image_contains(0x200000));
    g_assert_true(x86_launch_image_page(0x200000, &data, &valid));
    g_assert_cmpuint(valid, ==, 0);
    g_assert_null(data);
}

static void test_zero_size_ignored(void)
{
    /* A zero-length region would otherwise make contains() match nothing. */
    x86_launch_image_add(0x300000, NULL, 0, 0);
    g_assert_false(x86_launch_image_contains(0x300000));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/x86-launch-image/empty", test_empty);
    g_test_add_func("/x86-launch-image/extent", test_extent);
    g_test_add_func("/x86-launch-image/zero-fill", test_zero_fill_only);
    g_test_add_func("/x86-launch-image/zero-size", test_zero_size_ignored);
    return g_test_run();
}
