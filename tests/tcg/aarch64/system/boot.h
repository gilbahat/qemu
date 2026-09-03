/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *
 * Copyright (c) 2026 Linaro Ltd
 *
 */


/* Global variables exported in boot.S */
extern volatile uint64_t exception_fault_address; /* Updated by ISR */
extern volatile uint64_t exception_type_code; /* Updated by ISR */
extern uint64_t realms_gpt0[];
extern uint64_t realms_gpt1[];
/*
 * The level-2 table of the harness's identity map, covering the 1GB region the
 * test itself runs in, indexed by IA[29:21]. Exported so a test can install a
 * mapping of its own -- see cca-stage1.c, which needs one whose output address
 * is not the input address.
 */
extern uint64_t ttb_stage2[];
