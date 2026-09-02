/*
 * Launch-image extents, for the emulated confidential-guest environments.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_I386_X86_LAUNCH_IMAGE_H
#define HW_I386_X86_LAUNCH_IMAGE_H

#include "exec/hwaddr.h"

/**
 * x86_launch_image_add: record a region the loader places in guest memory.
 * @addr: guest physical address of the region.
 * @data: its contents, copied; may be NULL for a purely zero-filled region.
 * @datasize: bytes of @data that are real; the rest of @totalsize is zeros.
 * @totalsize: size of the region in guest memory.
 *
 * A confidential guest's memory is private and unusable until it has been
 * accepted or validated, with only the launch image exempt -- so the emulation
 * has to know what the launch image is.  ROM-backed loads can be found with
 * rom_ptr(), but the ``-kernel`` paths that hand the image to the guest through
 * fw_cfg and a DMA option ROM leave nothing for it to find, and the image is
 * not in memory until the guest itself has copied it.  Those loaders call this
 * instead, at load time, with what they are about to publish.
 *
 * The contents are copied because the caller usually passes ownership of its
 * buffer to fw_cfg immediately afterwards.
 */
void x86_launch_image_add(hwaddr addr, const void *data, size_t datasize,
                          size_t totalsize);

/**
 * x86_launch_image_contains: is this GPA part of the launch image?
 */
bool x86_launch_image_contains(hwaddr gpa);

/**
 * x86_launch_image_limit: one past the highest launch-image address, or 0.
 *
 * A caller walking guest pages to find the launch image needs somewhere to
 * stop.  RAM size is the obvious bound and the wrong one: a firmware launch
 * places its image in the window just below 4GiB, which is above RAM and would
 * be missed entirely.
 */
hwaddr x86_launch_image_limit(void);

/**
 * x86_launch_image_page: launch-image bytes for the page containing @gpa.
 * @data: set to the real bytes for that page, or NULL if the page is entirely
 *        zero fill.
 * @valid: set to how many bytes at @data are real; the rest of the page is zero
 *         on the guest side.
 *
 * Returns false if @gpa is not part of the launch image.  The bytes are the
 * emulator's own copy, so they reflect what was loaded regardless of what the
 * guest has since written -- which is what a measurement wants.
 */
bool x86_launch_image_page(hwaddr gpa, const void **data, size_t *valid);

#endif /* HW_I386_X86_LAUNCH_IMAGE_H */
