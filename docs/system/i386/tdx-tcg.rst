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
  ``TDG.VP.VEINFO.GET`` straight back as the sub-function. ``MapGPA``
  succeeds as a validated no-op, since private and shared memory are the same
  RAM here. ``GetQuote`` is refused; every other sub-function returns
  ``INVALID_OPERAND``.

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
  Validated no-op; only 4KiB pages are modelled.

An unrecognised leaf returns ``TDX_OPERAND_INVALID``. It does **not** raise
``#UD``: that is what the TDX module does, and it matters because a guest may
issue its first TDCALL before installing an IDT, where a fault is a silent
triple fault.

Why the report is not attestation
---------------------------------

The ``REPORTMACSTRUCT`` MAC is the fixed ASCII string
``QEMU-TCG-EMULATED-TDX-NOT-REAL!!`` rather than a keyed hash. Two reports over
different ``REPORTDATA`` therefore have byte-identical MACs, which any verifier
detects immediately. ``CPUSVN`` and ``TEE_TCB_INFO`` are likewise sentinels.
The hashes over ``TEE_TCB_INFO`` and ``TD_INFO`` are computed honestly so that
guest-side parsers can be developed, but nothing here carries trust, and there
is no quoting path at all.

``MRTD`` is left zero: nothing was measured at launch. The payload is loaded
into ordinary RAM by the normal QEMU loader with no integrity domain, so a
plausible-looking MRTD would be actively misleading.

Device I/O
----------

A TD's private memory is not reachable by the host, so a device may only DMA to
memory the guest has explicitly shared — which a TD addresses through the SHARED
alias, i.e. with GPA bit ``GPAW-1`` set. With ``x-tdx-guest`` off this is
moot, but with an emulated TD it is enforced: PCI devices are given an address
space that maps the shared alias and nothing else, and a DMA to any other
address is refused and logged under ``-d guest_errors``.

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

In practice a guest being ported will meet these in order: its virtio probe
stops recognising the device (legacy is gone), then once it speaks modern virtio
its ring DMA is refused until the ring pages are shared and programmed at the
shared alias, then its payload buffers need to be bounced through shared memory
because the heap stays private.

Strict mode: reflecting #VE
---------------------------

By default nothing is reflected as ``#VE``, so a guest that performs port I/O,
MSR access, ``CPUID`` and ``HLT`` directly — as it would on a normal PC — runs
unchanged. That is useful for bring-up but tests very little, because a real TD
takes ``#VE`` on all of those and must service them through
``TDG.VP.VEINFO.GET`` and ``TDG.VP.VMCALL``.

Enabling reflection turns this into a conformance tool. Each class is
selectable so a port can be fixed one at a time:

``x-tdx-ve-io``, ``x-tdx-ve-msr``, ``x-tdx-ve-cpuid``, ``x-tdx-ve-hlt``
  Reflect that class. ``x-tdx-strict=on`` enables all four.

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
  GPAW reported by ``TDG.VP.INFO``, in [32,63]; default 48. The SHARED GPA bit
  is bit ``N-1``. TCG pins the physical address width to 40 bits, so with the
  default the SHARED bit lies above the addressable range and is masked off
  guest-supplied addresses rather than mapped.

``x-tdx-attributes=N``
  TD ATTRIBUTES reported by ``TDG.VP.INFO``; default 0. The DEBUG bit (0) is
  rejected — a debuggable TD is not emulated.

``x-tdx-strict=on|off``, ``x-tdx-ve-io``, ``x-tdx-ve-msr``, ``x-tdx-ve-cpuid``, ``x-tdx-ve-hlt``
  Select which instruction classes are reflected as ``#VE``; see above.

Not modelled
------------

Memory encryption and host/guest isolation of any kind; SEPT and private-memory
attributes (``guest_memfd`` requires KVM, so the TD uses plain RAM); TDVF and
the TD reset vector; AP bring-up via ``TDG.VP.ENTER``; MMIO reflection
(``EPT_VIOLATION``); ``TDG.VP.CPUIDVE.SET``; ``TDG.SYS.*``; ``TDG.SERVTD.*``;
and quoting.
