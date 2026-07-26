Emulated Intel TDX guest (TCG)
==============================

.. warning::
   This is **not** Intel TDX. It is an emulation of the guest-visible TDX
   interface under TCG, intended for developing and testing TD guest software
   without TDX hardware. It provides **no confidentiality**, no memory
   encryption, no isolation from the host or from QEMU, no measured launch, and
   **no genuine attestation**. Any ``TDREPORT`` it produces is deliberately
   unauthenticated and must never be submitted to a quoting service or
   presented to a relying party. Do not rely on it for any security property.

For real TDX, which requires KVM and TDX-capable hardware, see
:doc:`tdx` and the ``tdx-guest`` object. The two are unrelated: this one is a
CPU property, is TCG-only, and enforces nothing.

The status of this support is experimental. It is enabled by the CPU property
``x-tdx-guest``, with the ``x-`` prefix present as a reminder of the
experimental status, and defaults off. The way it is enabled, and the
properties described here, may change or be removed in a future QEMU release
without notice or backward compatibility.

Usage
-----

.. parsed-literal::

  |qemu_system_x86| -accel tcg -cpu max,x-tdx-guest=on \\
                    -kernel td-payload.elf

The guest then sees:

* ``CPUID.0x21:0`` returning ``"IntelTDX    "`` in EBX:EDX:ECX, exactly as the
  TDX module reports it.
* The ``TDCALL`` instruction (``66 0F 01 CC``), which is ``#UD`` unless
  ``x-tdx-guest=on``, and is only available in 64-bit mode at CPL 0.

Implemented TDCALL leaves
-------------------------

``TDG.VP.VMCALL`` (0)
  The ``Instruction.IO`` (30), ``Instruction.CPUID`` (10),
  ``Instruction.RDMSR`` (31), ``Instruction.WRMSR`` (32) and
  ``Instruction.HLT`` (12) service routines are implemented, so a guest can
  handle a ``#VE`` by passing the exit reason it just read from
  ``TDG.VP.VEINFO.GET`` straight back as the sub-function. ``MapGPA`` converts
  a page between private and shared when ``x-tdx-sept`` is on, and validates its
  operands otherwise; a multi-page range converts its first page and returns
  ``RETRY`` with the next GPA. ``GetQuote`` is implemented; every other sub-function
  returns ``INVALID_OPERAND``.

  ``#VE.RequestMMIO`` (48) is also implemented, and is the counterpart of the
  ``#VE`` a TD takes on MMIO: R12 size, R13 direction, R14 GPA, R15 data for a
  write, with a read returning the value in R11.

  ``Instruction.HLT`` advances the guest RIP past the ``TDCALL`` before
  halting, as ``MWAIT`` does; without that the halt would resume by
  re-executing the instruction that caused it.

``TDG.VP.INFO`` (1)
  Reports GPAW from ``x-tdx-gpaw`` (default 48; real TDX uses 48 or 52),
  ATTRIBUTES from ``x-tdx-attributes``, and vCPU counts from the machine.

``TDG.MR.RTMR.EXTEND`` (2)
  ``RTMR[i] = SHA384(RTMR[i] || data)``, with the four RTMRs held per-TD.

``TDG.VP.VEINFO.GET`` (3)
  Returns the latched ``#VE`` information in registers. There is no VE-info
  page and no ``IA32_VE_INFO_ADDRESS`` MSR; those are plain-VMX constructs and
  a TD guest never uses them.

``TDG.MR.REPORT`` (4)
  Produces a structurally valid, deliberately unauthenticated ``TDREPORT``.

``TDG.MEM.PAGE.ACCEPT`` (6)
  Moves a page from private-pending to private-accepted when ``x-tdx-sept`` is
  on, reporting ``ALREADY_ACCEPTED`` for one that is, and refusing a shared page
  with ``PAGE_ATTR_CONFLICT``. Only 4KiB pages are modelled, so a 2MiB request
  is refused with ``PAGE_SIZE_MISMATCH``. Acceptance is per GPA and independent
  of how the page is mapped.

An unrecognised leaf returns ``TDX_OPERAND_INVALID``. It does **not** raise
``#UD``: that is what the TDX module does, and it matters because a guest may
issue its first TDCALL before installing an IDT, where a fault is a silent
triple fault.

Quoting
-------

``TDVMCALL<GetQuote>`` is implemented, because the *flow* is real porting work
even though the evidence cannot be. On hardware the VMM passes the TDREPORT to a
Quoting Enclave, which signs it with a key whose PCK certificate chains to
Intel's root; verification of the result needs that chain and therefore needs
hardware. Generating the request does not.

What a guest has to get right, and can now test:

* **The buffer must be shared.** ``R12`` carries a GPA that has to have the
  SHARED alias set *and* have been converted with ``TDVMCALL<MapGPA>``, and it
  has to be reached through that alias in the guest's own page tables. This is
  the first thing in a TD that needs a page-table entry it can change at run
  time, since nothing else about attestation touches shared memory.
* **It is asynchronous.** The call returns immediately with the buffer's status
  set to ``GET_QUOTE_IN_FLIGHT``; the guest polls until it changes. The emulated
  service answers after 100 virtual milliseconds.
* **The header contract** — version, ``in_len`` of a full ``TDREPORT``, and an
  ``out_len`` the service fills in, including when the buffer is too small.

The reply is a structurally correct DCAP Quote v4 with the TDX TEE type, whose
body carries the measurements and ``REPORTDATA`` from the report that was
submitted, so a guest can confirm the quote answers the question it asked.

Its signature is not a signature: like the ``REPORTMACSTRUCT`` MAC it is a fixed
marker, and the certification-data type is left at 0 rather than fabricating a
PCK chain. A DCAP verifier rejects it immediately, which is the correct outcome.
``SetupEventNotifyInterrupt`` is not implemented, so a guest must poll.

Why the report is not attestation
---------------------------------

The ``REPORTMACSTRUCT`` MAC is the fixed ASCII string
``QEMU-TCG-EMULATED-TDX-NOT-REAL!!`` rather than a keyed hash. Two reports over
different ``REPORTDATA`` therefore have byte-identical MACs, which any verifier
detects immediately. ``CPUSVN`` and ``TEE_TCB_INFO`` are likewise sentinels.
The hashes over ``TEE_TCB_INFO`` and ``TD_INFO`` are computed honestly so that
guest-side parsers can be developed, but nothing here carries trust, and there
is no quoting path at all.

``MRTD`` *is* a real measurement of the launch image -- see `The launch
measurement`_ -- but it is not the digest hardware would produce for the same
payload, so it is useful for checking a flow and useless for comparing against a
real TD.

Device I/O
----------

A TD's private memory is not reachable by the host, so a device may only DMA to
memory the guest has explicitly shared — which a TD addresses through the SHARED
alias, i.e. with GPA bit ``GPAW-1`` set. With ``x-tdx-guest`` off this is
moot, but with an emulated TD it is enforced: PCI devices are given an address
space that maps the shared alias and nothing else, and a DMA to any other
address is refused and logged under ``-d guest_errors``.

The alias is necessary but not sufficient. With ``x-tdx-sept`` on, the filter
also asks whether the page was ever converted, and refuses a DMA whose address
carries the SHARED bit for a page the TD never passed to
``TDVMCALL<MapGPA>``. Setting a bit is not the same as doing the work; on
hardware the shared mapping does not exist until the conversion is made. Without
that second check a guest could satisfy the emulation by decorating its
addresses.

Without that enforcement the emulation would certify nothing. Private and shared
are the same RAM under TCG, so a guest that never shares its virtio rings works
here and fails on hardware — the failure mode this whole model exists to catch.

**Legacy virtio is disabled** for an emulated TD, matching what QEMU already
does for a real confidential guest. The legacy transport publishes a queue
address as a 32-bit page frame number, so it tops out at 2\ :sup:`44` and cannot
express a SHARED alias address at all, and it has no way to negotiate
``VIRTIO_F_ACCESS_PLATFORM``. A TD guest must therefore use modern virtio 1.0:
the 64-bit ``queue_desc``/``queue_driver``/``queue_device`` registers reached
through the PCI capability structures, with ``VIRTIO_F_VERSION_1`` and
``VIRTIO_F_ACCESS_PLATFORM`` negotiated.

The order a guest meets these in is not the order they are listed. Device work
comes last, not first: a modern virtio device is configured through MMIO, and
MMIO is shared to a TD, so a BAR has to be mapped through the SHARED alias before
a driver can read a single register. Anything that touches a device is therefore
behind the memory work, not ahead of it.

The dependency order is: accept memory before using it, so the payload can run at
all; be able to set the alias bit on a mapping at runtime, so shared memory can
be reached; convert a region and allocate from it; and only then bring up a
device and bounce payloads through that region.

That does not require fine-grained page tables. Acceptance is per 4KiB GPA and is
independent of how the page is mapped -- 4KiB accepts under 2MiB mappings are
what ``tdx-strict`` does. And a 2MiB mapping can carry the alias bit for the
whole region, provided every 4KiB page within it has been converted, so a
2MiB-granular shared pool works with huge pages left in place. Only sharing at
4KiB granularity needs 4KiB tables.

Strict mode: reflecting #VE
---------------------------

By default nothing is reflected as ``#VE``, so a guest that performs port I/O,
MSR access, ``CPUID`` and ``HLT`` directly — as it would on a normal PC — runs
unchanged. That is useful for bring-up but tests very little, because a real TD
takes ``#VE`` on all of those and must service them through
``TDG.VP.VEINFO.GET`` and ``TDG.VP.VMCALL``.

Enabling reflection turns this into a conformance tool. Each class is
selectable so a port can be fixed one at a time:

``x-tdx-ve-io``, ``x-tdx-ve-msr``, ``x-tdx-ve-cpuid``, ``x-tdx-ve-hlt``, ``x-tdx-ve-mmio``
  Reflect that class. ``x-tdx-strict=on`` enables all five.

``x-tdx-ve-mmio`` matters for device work: modern virtio is driven entirely
through memory BARs, so once a guest moves off legacy virtio every config
access is MMIO. A TD maps device memory as shared and takes ``#VE`` on it,
reported as an EPT violation, and services it with ``TDVMCALL<#VE.RequestMMIO>``.
Reflection happens when a translation is installed rather than per instruction,
which is what hardware does: the guest learns that a physical address faulted,
not which instruction touched it.

Two carve-outs keep strict mode a useful signal rather than a brick wall, and
both match real TDX behaviour:

* MSRs used for ordinary long-mode and TLS setup — ``IA32_EFER``, ``FS_BASE``,
  ``GS_BASE``, ``KERNEL_GS_BASE``, ``TSC_AUX``, the SYSENTER and
  STAR/LSTAR/CSTAR/FMASK group — are handled natively and never reflected.
* ``CPUID`` leaf 0 and leaf ``0x21`` are always answered natively, otherwise a
  guest could not discover that it is a TD nor find the TDCALL interface with
  which to service the exception.

A ``#VE`` raised while the previous VE information has not yet been consumed by
``TDG.VP.VEINFO.GET`` is escalated to ``#DF``, as the TDX module does. Every
injection is logged under ``-d guest_errors``, so a guest with no handler leaves
a breadcrumb before it triple-faults.

When reflection starts
~~~~~~~~~~~~~~~~~~~~~~

Reflection is armed by the guest's **first TDCALL**, not from reset.

A real TD begins executing TDX-aware firmware at its reset vector. A direct
``-kernel`` boot instead runs the ordinary, TDX-unaware firmware as a loader
shim, and that firmware performs port I/O, ``CPUID`` and MSR access of its own
long before the payload runs — so reflecting from reset would fault inside the
firmware and never reach the guest under test. Treating the first TDCALL as
"the TD-aware code has taken over" scopes reflection to the payload. A guest
that never issues a TDCALL never sees ``#VE``.

Properties
----------

``x-tdx-guest=on|off``
  Enable the emulated TD guest environment. TCG and 64-bit only.

``x-tdx-gpaw=N``
  GPAW reported by ``TDG.VP.INFO``, in [32,52]; default 48. The SHARED GPA bit
  is bit ``N-1``. Above 52 the bit would leave ``PG_ADDRESS_MASK`` and could not
  appear in a page-table entry at all.

  Enabling ``x-tdx-guest`` also sets ``phys_bits`` to GPAW unless the user set it
  explicitly, in which case it must be at least GPAW. Without that invariant the
  SHARED bit falls inside the walker's reserved-bit mask, and a TD that maps
  shared memory takes a ``#PF`` on every access to it — which is to say it cannot
  use shared memory at all. It does mean a TD sees a different
  ``CPUID.0x80000008`` width than the same ``-cpu`` model without the property.

``x-tdx-sept=0|1|2``
  Page-state tracking: off, lazy or strict. See `Page state and the SHARED
  alias`_.

``x-tdx-attributes=N``
  TD ATTRIBUTES reported by ``TDG.VP.INFO``; default 0. The DEBUG bit (0) is
  rejected — a debuggable TD is not emulated.

``x-tdx-strict=on|off``, ``x-tdx-ve-io``, ``x-tdx-ve-msr``, ``x-tdx-ve-cpuid``, ``x-tdx-ve-hlt``
  Select which instruction classes are reflected as ``#VE``; see above.

Page state and the SHARED alias
-------------------------------

``x-tdx-sept`` turns on a Secure-EPT-lite: a per-page state of *shared*,
*private-pending* or *private-accepted*, moved by ``TDVMCALL<MapGPA>`` and
``TDG.MEM.PAGE.ACCEPT``, and checked on every page-table walk.

``x-tdx-sept=0`` (default)
  No tracking. ``MapGPA`` and ``PAGE.ACCEPT`` validate their operands and report
  success without recording anything. The SHARED alias still folds onto the
  underlying page, so a TD that uses it runs, but nothing is checked.

``x-tdx-sept=1`` (lazy)
  Pages start accepted, so a TD that has not adopted ``PAGE.ACCEPT`` runs
  unchanged, and enforcement applies only to pages it explicitly converts.

``x-tdx-sept=2`` (strict)
  Guest RAM starts private and pending, as the TDX module leaves it after
  ``TDH.MEM.PAGE.ADD``, with only the launch image accepted. A ``-kernel``
  payload's ``.bss`` is not part of that image and so starts pending, exactly as
  on hardware.

Lazy exists because enforcement is otherwise all-or-nothing: under strict, a TD
that never accepts its memory faults on its first use of the stack. That is the
truth and it is what a conformance run wants, but it leaves no way to adopt the
model a page at a time.

Two failures can arise, and unlike the SEV-SNP equivalent both go to the same
place — an EPT violation reported as ``#VE``, because that is what hardware does:

* A private access to a page the TD has not accepted. This is what tells a guest
  to issue ``TDG.MEM.PAGE.ACCEPT``.
* An alias that disagrees with the page's state: the SHARED alias on a page that
  was never converted, or the private alias on a page that was.

Both set bit 3 of the exit qualification, which is how hardware distinguishes a
mapping that is not present from an ordinary permission failure.

Because everything arrives as ``#VE``, a handler **must** consume the information
with ``TDG.VP.VEINFO.GET``. The next ``#VE`` cannot be delivered while the
previous one is still pending and ``#DF`` is injected instead, so a handler that
skips it survives exactly one fault. That is modelled here as well.

MMIO is always shared to a TD — there is no private device memory — so device
BARs must be mapped through the SHARED alias too. A TD that identity-maps its
BARs privately takes an EPT violation on the first register access.

Page-state changes flush the TLB when they remove access. Accepting only adds
access, and a pending page can have no cached entry because the fill that would
have created it faulted, so accepting needs no flush — which matters, as a TD
accepting 4 GiB performs a million of them.

The SHARED bit is stripped in all four page-table walkers: the TLB-fill one, the
debug one behind ``x``, gdb and ``cpu_memory_rw_debug()``, the one behind
``dump-guest-memory``, and the monitor's ``info mem``/``info tlb``.

The launch measurement
----------------------

MRTD was a constant zero until recently, which made the root of the measurement
chain a fixed value: a guest could not tell a correct measurement flow from no
flow, and the report could not change when the payload did.

Hardware builds MRTD from the ``TDH.MEM.PAGE.ADD`` and ``TDH.MR.EXTEND`` sequence
the VMM performs and seals it with ``TDH.MR.FINALIZE``. There is no such sequence
here, so the emulation hashes the launch image as loaded: SHA-384 over every page
belonging to a loaded image, each contributing its GPA followed by its contents,
in address order. The GPA makes it position-sensitive, as the hardware sequence
is.

It is therefore **not** the MRTD real hardware would report for the same payload
and must not be compared against one. What it is good for is that it is stable
across boots and changes when the payload changes. The emulated SEV-SNP launch
measurement uses the same construction.

It is computed at the transition to running, since ROMs reach guest memory in the
initial reset — after every machine-init-done notifier — and no vCPU has executed
by then. MRTD survives a reset, measuring an image a reset does not change; the
RTMRs do not, being runtime measurements.

Which pages *are* the launch image depends on how the payload was loaded, and
there are two answers. An image the loader placed as a ROM is found with
``rom_ptr()``. But ``-kernel`` does not always place one: a multiboot kernel that
sets ``MULTIBOOT_HEADER_HAS_ADDR``, and a Linux bzImage, are published through
fw_cfg and copied into guest memory by a DMA option ROM running *inside* the
guest. There is no ROM at the load address, and the bytes are not in memory until
the guest has already started, so those loaders record the extent at load time
and both models consult that as well.

Without it such a guest cannot boot in strict mode and cannot fix it from inside.
Everything before paging runs, because unpaged accesses are never walked; the
first checked access is the instruction fetch immediately after ``CR0.PG`` is
set, and it faults on the page it is fetching from. There is no window in which
guest code could accept anything, because ``TDCALL`` needs 64-bit mode, which
needs paging.

Not modelled
------------

Memory encryption and host/guest isolation of any kind; separate backing for the
private and shared aliases (``guest_memfd`` requires KVM, so both aliases are the
same RAM here and a conversion moves an attribute rather than any data — on
hardware it loses the page contents); SEPT page sizes, so a 2 MiB
``PAGE.ACCEPT`` is refused with ``PAGE_SIZE_MISMATCH``; multi-page ``MapGPA``
ranges, which convert their first page and return ``RETRY``; TDVF and the TD
reset vector; AP bring-up via ``TDG.VP.ENTER``; ``TDG.VP.CPUIDVE.SET``;
``TDG.SYS.*``; ``TDG.SERVTD.*``; and quoting.

Testing
-------

``tests/tcg/x86_64/system/`` contains five freestanding tests, run with
``make run-tcg-tests-x86_64-softmmu``:

``tdx``
  The interface surface: ``CPUID`` identification, ``TDG.VP.INFO``, the
  measurement calls, and the ``TDVMCALL`` service routines.

``tdx-attest``
  The attestation and quoting flow: that ``REPORTDATA`` comes back, that operand alignment is
  enforced, that MRTD is not zero, that extending an RTMR changes that register
  and no other and leaves MRTD alone, that the same data extended from the same
  state gives the same result and different data does not, and that two reports
  over identical inputs are identical. It also asserts what must *not* work: the
  ``REPORTMACSTRUCT`` MAC and the quote signature are the fixed not-real
  markers.

  The quoting half also covers what a guest must do to be answered at all: a
  buffer that is private, or that carries the alias without having been
  converted, or that is misaligned, is refused; a well-formed one comes back
  in flight and then completes, with the submitted MRTD and ``REPORTDATA``
  present in the quote body.

``tdx-sept``
  Page state, in lazy mode. Builds its own page tables so the SHARED alias can
  actually be mapped — which was impossible before the ``phys_bits`` invariant —
  and drives the state machine: converting a page and reaching it through the
  alias, the refusal to accept a shared page, an alias mismatch, and a pending
  page accepted on demand from the ``#VE`` handler. That handler is directed
  entirely by ``TDG.VP.VEINFO.GET`` with nothing arranged in advance.

``tdx-dma``
  Device DMA, driven through the ``edu`` test device's DMA engine, which calls
  ``pci_dma_read()`` on the guest's behalf — the same path a virtio ring fetch
  takes, with no driver needed. A converted page reads back correctly; a private
  page is refused; and so is a page whose address carries the SHARED alias but
  which was never converted.

``tdx-strict``
  The same faults with the TDX module's own defaults, and the answer to whether
  anything can survive strict mode. It links the ``TDX_ACCEPT_BOOT`` variant of
  ``boot.S``, which accepts ``.bss`` before the stack is used — the one thing TD
  firmware must do first. Reaching ``main()`` is the result; it then accepts RAM
  outside the launch image on demand.

  That bootstrap is a build-time variant rather than the default because
  accepting memory is wrong wherever it is not pending, and a TD has no way to
  tell which mode it is in — as on hardware, where the question does not arise.
  Without ``-DTDX_ACCEPT_BOOT`` the object is byte-identical to the one every
  other test links.
