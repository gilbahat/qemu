/*
 * x86_64 boot and support code
 *
 * Copyright 2019, 2024 Linaro
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * Unlike the i386 version we instead use Xen's PVHVM booting header
 * which should drop us automatically into 32 bit mode ready to go. I've
 * nabbed bits of the Linux kernel setup to achieve this.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

        .section .head

#define ELFNOTE_START(name, type, flags)	\
.pushsection .note.name, flags,@note	;	\
  .balign 4				;	\
  .long 2f - 1f		/* namesz */	;	\
  .long 4484f - 3f	/* descsz */	;	\
  .long type				;	\
1:.asciz #name				;	\
2:.balign 4				;	\
3:

#define ELFNOTE_END				\
4484:.balign 4				;	\
.popsection				;

#define ELFNOTE(name, type, desc)		\
	ELFNOTE_START(name, type, "")		\
		desc			;	\
	ELFNOTE_END

#define XEN_ELFNOTE_ENTRY          1
#define XEN_ELFNOTE_HYPERCALL_PAGE 2
#define XEN_ELFNOTE_VIRT_BASE      3
#define XEN_ELFNOTE_PADDR_OFFSET   4
#define XEN_ELFNOTE_PHYS32_ENTRY  18

#define __ASM_FORM(x)	x
#define __ASM_SEL(a,b)  __ASM_FORM(b)
#define _ASM_PTR	__ASM_SEL(.long, .quad)

	ELFNOTE(Xen, XEN_ELFNOTE_VIRT_BASE,      _ASM_PTR 0x100000)
	ELFNOTE(Xen, XEN_ELFNOTE_ENTRY,          _ASM_PTR _start)
	ELFNOTE(Xen, XEN_ELFNOTE_PHYS32_ENTRY,   _ASM_PTR _start)    /* entry == virtbase */
	ELFNOTE(Xen, XEN_ELFNOTE_PADDR_OFFSET,   _ASM_PTR 0)

       /*
	* Entry point for PVH guests.
	*
	* Xen ABI specifies the following register state when we come here:
	*
	* - `ebx`: contains the physical memory address where the loader has placed
	*          the boot start info structure.
	* - `cr0`: bit 0 (PE) must be set. All the other writable bits are cleared.
	* - `cr4`: all bits are cleared.
	* - `cs `: must be a 32-bit read/execute code segment with a base of ‘0’
	*          and a limit of ‘0xFFFFFFFF’. The selector value is unspecified.
	* - `ds`, `es`: must be a 32-bit read/write data segment with a base of
	*               ‘0’ and a limit of ‘0xFFFFFFFF’. The selector values are all
	*               unspecified.
	* - `tr`: must be a 32-bit TSS (active) with a base of '0' and a limit
	*         of '0x67'.
	* - `eflags`: bit 17 (VM) must be cleared. Bit 9 (IF) must be cleared.
	*             Bit 8 (TF) must be cleared. Other bits are all unspecified.
	*
	* All other processor registers and flag bits are unspecified. The OS is in
	* charge of setting up it's own stack, GDT and IDT.
	*/
        .code32
        .section .text

.global _start
_start:
	cld
        lgdt gdtr

        ljmp $0x8,$.Lloadcs
.Lloadcs:
        mov $0x10,%eax
        mov %eax,%ds
        mov %eax,%es
        mov %eax,%fs
        mov %eax,%gs
        mov %eax,%ss

	/* Enable PAE mode (bit 5). */
	mov %cr4, %eax
	btsl $5, %eax
	mov %eax, %cr4

#define MSR_EFER		0xc0000080 /* extended feature register */

	/* Enable Long mode. */
	mov $MSR_EFER, %ecx
	rdmsr
	btsl $8, %eax
	wrmsr

#ifdef SNP_CBIT_BOOT
	/*
	 * Adopt the SEV-SNP C-bit before paging comes on, the way SNP firmware
	 * does.  Guest RAM is private on an SNP machine, so a paged access with
	 * the bit clear is an RMP violation -- this has to happen before the
	 * first one.  Paging is still off here, so the tables can be patched in
	 * place without tripping the very check being set up.
	 *
	 * Inert on anything that is not an SNP guest, which is why plain boot.S
	 * can share this source: without the SNP bit nothing is written.
	 */
	mov $0x80000000, %eax
	cpuid
	cmp $0x8000001f, %eax
	jb .Lno_cbit
	mov $0x8000001f, %eax
	xor %ecx, %ecx
	cpuid
	bt $4, %eax			/* EAX[4]: SEV-SNP */
	jnc .Lno_cbit

	/*
	 * EBX[5:0] holds the C-bit position, which QEMU constrains to [32,51] --
	 * so it always lands in the upper half of the entry and one 32-bit store
	 * per entry is enough.
	 */
	and $0x3f, %ebx

	/*
	 * Keep it.  Every CPUID reflects as #VC from the first PVALIDATE
	 * onwards -- which this bootstrap is about to do -- so a payload that
	 * asks for the C-bit again faults, and faults before it has had a
	 * chance to install a handler.  Real firmware hands the position on for
	 * the same reason rather than making the payload re-derive it.
	 */
	mov %ebx, snp_cbit_pos

	sub $32, %ebx
	mov %ebx, %ecx
	mov $1, %esi
	shl %cl, %esi

	orl %esi, .Lpml4 + 4
	mov $.Lpdp, %edi
	mov $4, %ebx
7:	orl %esi, 4(%edi)
	add $8, %edi
	dec %ebx
	jnz 7b
	mov $.Lpd, %edi
	mov $(512 * 4), %ebx
8:	orl %esi, 4(%edi)
	add $8, %edi
	dec %ebx
	jnz 8b
.Lno_cbit:
#endif /* SNP_CBIT_BOOT */

	/* Enable paging */
	mov $.Lpml4, %ecx
	mov %ecx, %cr3

	mov %cr0, %eax
	btsl $31, %eax
	mov %eax, %cr0

	/* Jump to 64-bit mode. */
        lgdt gdtr64
        ljmp $0x8,$.Lenter64

        .code64
        .section .text
.Lenter64:


#ifdef TDX_ACCEPT_BOOT
	/*
	 * A TD's memory is private but *pending* until accepted, and .bss is
	 * not part of the launch image -- so the stack has to be accepted
	 * before use.  No page-table change is needed: a TD reaches private
	 * memory through the plain GPA, which this code already maps.
	 *
	 * Identified through CPUID leaf 0x21, "IntelTDX    ".  Inert on
	 * anything that is not a TD, which is why plain boot.S shares this
	 * source.
	 */
	mov $0x21, %eax
	xor %ecx, %ecx
	cpuid
	cmp $0x65746e49, %ebx			/* "Inte" */
	jne .Lno_accept
	cmp $0x5844546c, %edx			/* "lTDX" */
	jne .Lno_accept

	movq $__bss_st, %rbx
	andq $~0xfff, %rbx
6:	cmpq $__bss_en, %rbx
	jae .Lno_accept
	movq $6, %rax				/* TDG.MEM.PAGE.ACCEPT */
	movq %rbx, %rcx				/* GPA, level 0 (4KiB) */
	.byte 0x66, 0x0f, 0x01, 0xcc	/* tdcall */
	addq $0x1000, %rbx
	jmp 6b
.Lno_accept:
#endif /* TDX_ACCEPT_BOOT */

#ifdef SNP_CBIT_BOOT
	/*
	 * .bss is not part of the launch image, so on an SNP machine it is
	 * private but unvalidated -- touching it would raise #VC, and the stack
	 * lives here.  Validate it first, which is what a guest's own
	 * validation pass does.  No stack is used below, only PVALIDATE.
	 *
	 * PVALIDATE returns its status in RAX, so the cursor lives in RBX.
	 */
	mov $0x80000000, %eax
	cpuid
	cmp $0x8000001f, %eax
	jb .Lno_validate
	mov $0x8000001f, %eax
	xor %ecx, %ecx
	cpuid
	bt $4, %eax
	jnc .Lno_validate

	/*
	 * CR3 carries the C-bit too, and it could not be set earlier: CR3 was
	 * loaded from a 32-bit register, which cannot reach bit 32 or above.
	 */
	and $0x3f, %ebx
	mov %ebx, %ecx
	movq $1, %rsi
	shl %cl, %rsi
	mov %cr3, %rax
	or %rsi, %rax
	mov %rax, %cr3

	movq $__bss_st, %rbx
	andq $~0xfff, %rbx
9:	cmpq $__bss_en, %rbx
	jae .Lno_validate
	movq %rbx, %rax
	xorl %ecx, %ecx			/* 4KiB */
	movl $1, %edx			/* validate */
	.byte 0xf2, 0x0f, 0x01, 0xff	/* pvalidate */
	addq $0x1000, %rbx
	jmp 9b
.Lno_validate:
#endif /* SNP_CBIT_BOOT */

	// Setup stack ASAP
	movq $stack_end,%rsp

        /* don't worry about stack frame, assume everything is garbage when we return */
	call main

_exit:	/* output any non-zero result in eax to isa-debug-exit device */
        test %al, %al
        jz 1f
        out %ax, $0xf4

1:      /* QEMU ACPI poweroff */
	mov $0x604,%edx
	mov $0x2000,%eax
	out %ax,%dx
	hlt
	jmp 1b

        /*
         * Helper Functions
         *
         * x86_64 calling convention is rdi, rsi, rdx, rcx, r8, r9
         */

        /* Output a single character to serial port */
        .global __sys_outc
__sys_outc:
        pushq %rax
        mov %rax, %rdx
	out %al,$0xE9
        popq %rax
        ret

	/* Interrupt Descriptor Table */

        .section .data
	.globl snp_cbit_pos
	.align 4
snp_cbit_pos:
	.long 0

        .align 16

idt_00: .int 0, 0
idt_01: .int 0, 0
idt_02: .int 0, 0
idt_03: .int 0, 0
idt_04: .int 0, 0
idt_05: .int 0, 0
idt_06: .int 0, 0 /* intr_6_opcode, Invalid Opcode */
idt_07: .int 0, 0
idt_08: .int 0, 0
idt_09: .int 0, 0
idt_0A: .int 0, 0
idt_0B: .int 0, 0
idt_0C: .int 0, 0
idt_0D: .int 0, 0
idt_0E: .int 0, 0
idt_0F: .int 0, 0
idt_10: .int 0, 0
idt_11: .int 0, 0
idt_12: .int 0, 0
idt_13: .int 0, 0
idt_14: .int 0, 0
idt_15: .int 0, 0
idt_16: .int 0, 0
idt_17: .int 0, 0
idt_18: .int 0, 0
idt_19: .int 0, 0
idt_1A: .int 0, 0
idt_1B: .int 0, 0
idt_1C: .int 0, 0
idt_1D: .int 0, 0
idt_1E: .int 0, 0
idt_1F: .int 0, 0


	/*
	 * Global Descriptor Table (GDT)
	 *
	 * This describes various memory areas (segments) through
	 * segment descriptors. In 32 bit mode each segment each
	 * segment is associated with segment registers which are
	 * implicitly (or explicitly) referenced depending on the
	 * instruction. However in 64 bit mode selectors are flat and
	 * segmented addressing isn't used.
	 */
gdt:
        .short 0
gdtr:
        .short gdt_en - gdt - 1
        .int gdt

        // Code cs:
        .short 0xFFFF
        .short 0
        .byte 0
        .byte 0x9b
        .byte 0xCF
        .byte 0

        // Data  ds:, ss:, es:, fs:, and gs:
        .short 0xFFFF
        .short 0
        .byte 0
        .byte 0x93
        .byte 0xCF
        .byte 0
gdt_en:

gdt64:
        .short 0
gdtr64:
        .short gdt64_en - gdt64 - 1
        .int gdt64

        // Code
        .short 0xFFFF
        .short 0
        .byte 0
        .byte 0x9b
        .byte 0xAF
        .byte 0

        // Data
        .short 0xFFFF
        .short 0
        .byte 0
        .byte 0x93
        .byte 0xCF
        .byte 0
gdt64_en:

	.section .bss
        .align 16

stack: .space 65536
stack_end:

	.section .data

.align 4096
.Lpd:
i = 0
        .rept 512 * 4
        .quad 0x1e7 | (i << 21)
        i = i + 1
        .endr

.align 4096
.Lpdp:
        .quad .Lpd + 7 + 0 * 4096 /* 0-1 GB */
        .quad .Lpd + 7 + 1 * 4096 /* 1-2 GB */
        .quad .Lpd + 7 + 2 * 4096 /* 2-3 GB */
        .quad .Lpd + 7 + 3 * 4096 /* 3-4 GB */

.align 4096
.Lpml4:
        .quad .Lpdp + 7 /* 0-512 GB */
