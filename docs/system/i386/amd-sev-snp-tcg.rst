Emulated AMD SEV-SNP guest (TCG)
================================

.. warning::
   This is **not** AMD SEV-SNP. It is an emulation of the guest-visible SEV-SNP
   interface under TCG, intended for developing and testing SNP guest software
   without SEV hardware. It provides **no memory encryption**, no RMP enforced
   by hardware, no isolation from the host or from QEMU, no measured launch, and
   **no attestation**. Do not rely on it for any security property.

For real SEV-SNP, which requires KVM and SEV-capable hardware, see
:doc:`amd-memory-encryption` and the ``sev-snp-guest`` object. The two are
unrelated: that one is a launch mechanism driven through the AMD-SP, this one is
a CPU property that models what the guest sees and enforces nothing.

The status of this support is experimental. It is enabled by the CPU property
``x-sev-snp-guest``, with the ``x-`` prefix present as a reminder of the
experimental status, and defaults off. The way it is enabled, and the properties
described here, may change or be removed in a future QEMU release without notice
or backward compatibility.

Usage
-----

.. parsed-literal::

  |qemu_system_x86| -accel tcg -cpu max,x-sev-snp-guest=on \\
                    -kernel snp-payload.elf

The guest then sees ``CPUID.0x8000001F`` reporting SEV, SEV-ES and SEV-SNP with
the C-bit position in EBX[5:0]; ``MSR_AMD64_SEV`` (SEV_STATUS), read-only;
``MSR_AMD64_SEV_ES_GHCB`` for the GHCB MSR protocol; ``VMGEXIT``; ``PVALIDATE``;
and ``#VC`` on the instruction classes hardware intercepts.

Reflection is faithful by default
---------------------------------

Unlike the TDX emulation, whose ``#VE`` classes are off until asked for, the
``#VC`` classes here are **on by default** and switched off individually:

``x-sev-snp-relax-io``, ``x-sev-snp-relax-msr``, ``x-sev-snp-relax-cpuid``, ``x-sev-snp-relax-hlt``
  Stop reflecting that class.

The polarity is deliberate. A real SNP guest takes ``#VC`` on all of them, and
unlike TDX there is no working baseline to preserve — a guest that has never run
under SNP is not going to boot regardless, so the default should describe
hardware rather than flatter the guest.

Two carve-outs keep this a usable signal rather than a brick wall, and both
match hardware. MSRs used for ordinary long-mode and TLS setup are handled
natively, as are the two SEV MSRs — reflecting the GHCB MSR would make the MSR
protocol recurse forever. ``CPUID`` leaves 0, ``0x80000000`` and ``0x8000001F``
always answer natively, or a guest could never discover it is an SNP guest, nor
read the C-bit it needs before it can map a GHCB.

When reflection starts
~~~~~~~~~~~~~~~~~~~~~~

Reflection is armed by the guest's first ``PVALIDATE``.

A direct ``-kernel`` boot runs ordinary, SNP-unaware firmware as a loader shim,
and that firmware performs port I/O and ``CPUID`` of its own long before the
payload runs — so reflecting from reset would fault inside the firmware and
never reach the guest under test. ``PVALIDATE`` is the natural trigger: it is an
SNP-only instruction, ``#UD`` everywhere else, needs no GHCB or handler to
execute, and is what a real SNP guest does first anyway. A guest that never
executes one never sees ``#VC``.

A ``#VC`` raised while the GHCB MSR still holds an unconsumed request escalates
to ``#DF``. That is not architectural — hardware relies on an IST stack and a
per-CPU GHCB backup — but servicing the second exception would clobber the
first's request, and silent corruption is the worst outcome for a development
tool. Every injection is logged under ``-d guest_errors``.

The GHCB
--------

Both protocols are implemented.

The **MSR protocol** on ``MSR_AMD64_SEV_ES_GHCB`` is the only channel before a
GHCB page exists: write a request, execute ``VMGEXIT``, read the response from
the same register. SEV information, CPUID, preferred GHCB GPA, register GHCB
GPA, page-state change, hypervisor features and termination are handled. The SEV
information response carries the C-bit position in bits [31:24], which is how a
guest learns it before it can run ``CPUID``. Termination stops the VM with the
guest's reason reported, rather than letting it reset into a loop.

The **page protocol** dispatches the NAE event named by ``SW_EXITCODE`` in a
registered GHCB: ``SVM_EXIT_IOIO``, ``SVM_EXIT_CPUID``, ``SVM_EXIT_MSR`` and
``SVM_EXIT_HLT``. Validity is enforced in both directions — an event whose
required inputs are not marked valid in the bitmap at offset 0x3F0 is refused,
and every field written has its valid bit set.

Properties
----------

``x-sev-snp-guest=on|off``
  Enable the emulated SNP guest environment. TCG and 64-bit only, and mutually
  exclusive with ``x-tdx-guest``.

``x-sev-snp-cbitpos=N``
  C-bit position, in [32,51]; default 51. Real hardware uses 47 or 51. Above 51
  the bit would leave ``PG_ADDRESS_MASK`` and collide with other page-table
  fields.

  Enabling the property also sets ``phys_bits`` to ``cbitpos + 1`` unless the
  user set it explicitly, in which case it must exceed the C-bit position. That
  invariant makes the C-bit the topmost physical address bit, so the page-table
  walker's reserved-bit mask never covers it and the walker needs no special
  case. It does mean an SNP guest sees a different ``CPUID.0x80000008`` width
  than the same ``-cpu`` model without the property.

``x-sev-snp-rmp=0|1|2``
  Page-state tracking: off, lazy or strict. See `Page state and the C-bit`_.

Page state and the C-bit
------------------------

``x-sev-snp-rmp`` turns on an RMP-lite: a per-page state of *shared*,
*private-unvalidated* or *private-validated*, moved by page-state changes and
``PVALIDATE``, and checked on every page-table walk.

``x-sev-snp-rmp=0`` (default)
  No tracking. ``PVALIDATE`` validates its operands and reports success, and
  page-state changes are accepted without effect. The C-bit is still stripped
  from page-table entries, so a guest that sets it runs, but nothing is checked.

``x-sev-snp-rmp=1`` (lazy)
  Pages start shared, so a guest that has not adopted the C-bit runs unchanged,
  and enforcement applies only to the pages it explicitly claims.

``x-sev-snp-rmp=2`` (strict)
  Guest RAM starts private, as it is on hardware after ``SNP_LAUNCH_UPDATE``,
  with only the launch image validated. A ``-kernel`` payload's ``.bss`` is not
  part of that image and so starts unvalidated, exactly as on hardware.

Lazy exists because enforcement is otherwise all-or-nothing: under strict, a
guest whose page tables carry no C-bit faults on its first instruction fetch.
That is the truth and it is what a conformance run wants, but it leaves no way
to adopt the C-bit a page at a time.

Two faults can arise, and they differ in where they go — as they do on hardware:

* Touching a **private-unvalidated** page raises ``#VC`` with ``SW_EXITCODE``
  ``0x404``, which is what tells a guest to ``PVALIDATE`` it. This is the case a
  guest is expected to handle.
* A **polarity mismatch** — the C-bit disagreeing with the page's state —
  terminates the guest with a log naming the GPA and both states. On hardware
  this is an ``#NPF`` to the hypervisor, which kills the VM; it is not
  guest-visible, so there is nothing to reflect.

Page-state changes flush the TLB only when they *remove* access. An unvalidated
page can have no cached entry, because the fill that would have created it
faulted, so ``PVALIDATE``-to-validated needs no flush — which matters, as a
guest validating 4 GiB of RAM performs a million of them.

The C-bit is stripped in both page-table walkers, the TLB-fill one and the debug
one behind ``x``, gdb and ``cpu_memory_rw_debug()``.

Device I/O
----------

An SNP guest's private memory is unreachable by the host, so a device may only
DMA to pages the guest has shared. When page-state tracking is on, device DMA is
filtered accordingly: a PCI device gets an address space whose translations
consult the page state, and an access to a page that is not shared is refused
and logged with its GPA.

Unlike TDX, where shared memory is a different *address* — one GPA bit, testable
without any state — SNP sharing is an RMP attribute, so there is nothing to test
but the state itself. That is why this needs ``x-sev-snp-rmp``; with tracking off
no filter is installed, and device DMA reaches everything. Nothing warns about
that, because with nothing tracked there is nothing to enforce, but it does mean
a guest that never shares its DMA buffers will work here and fail on hardware.

An address that arrives with the C-bit set is refused and called out
separately. DMA addresses are plain guest physical addresses; the C-bit is a
page-table attribute a device knows nothing about, and a descriptor containing
one is a guest bug that would otherwise look like a wild pointer into high
memory.

Enforcement is armed by the guest's first ``PVALIDATE``, the same trigger as
``#VC`` reflection and for the same reason: firmware on a ``-kernel`` boot does
DMA of its own long before the payload runs.

Enabling the filter also disables legacy virtio, which cannot negotiate
``VIRTIO_F_ACCESS_PLATFORM`` and so gives the guest driver no way to know its
buffers must be shared. This is what ``machine_run_board_init()`` does for a
``confidential-guest-support`` object, which the CPU-property route does not
reach.

Attestation
-----------

Not trustworthy, and it cannot be: there is no key. What is here is the *flow*,
because that is what a guest has to get right and it is checkable without a key.

``SNP_GUEST_REQUEST`` is implemented in full, including the AES-256-GCM sealing.
The guest reads a VMPCK from the secrets page, seals a ``MSG_REPORT_REQ`` with
the message header from offset 0x30 as additional authenticated data and the
sequence number as the nonce, and gets back a sealed ``MSG_REPORT_RSP``
containing an ``ATTESTATION_REPORT``. Get the key, the AAD, the sequence number
or the tag wrong and the request is refused with nothing returned — as on
hardware.

Doing that honestly needed an AEAD, which QEMU's crypto API does not provide, so
``target/i386/tcg/system/snp-gcm.c`` assembles AES-256-GCM from the AES block
cipher it does provide. It is checked against independently generated vectors in
``tests/unit/test-snp-gcm.c``. The alternative — accepting an unencrypted
payload — was rejected: a guest developed against that would skip the crypto
entirely and fail on hardware, which is the sort of false pass this emulation
exists to remove.

``x-sev-snp-secrets-gpa=N``
  Where to place the secrets page; 0 (the default) leaves it absent. On hardware
  the AMD-SP fills this page in and firmware tells the guest where it is, through
  metadata a ``-kernel`` boot has no equivalent of, so the address is agreed
  out-of-band here instead. It is rewritten on reset, as firmware would.

  **The VMPCKs in it are fixed, published constants.** They are not secret,
  cannot be, and a guest must never treat a key obtained this way as key
  material. What they are for is letting a guest exercise the real sealing path.

The report's ``MEASUREMENT`` is the launch measurement described below. Its
``REPORT_DATA`` is whatever the guest supplied, so a guest can bind a nonce and
check it came back.

Nothing here may be mistaken for evidence. The report's signature field is a
fixed marker rather than a signature, and ``SNP_EXT_GUEST_REQUEST`` — which
returns a certificate chain — is refused outright, because there is no chain
here that would not be a lie.

The launch measurement
----------------------

Hardware derives this from the ``SNP_LAUNCH_UPDATE`` sequence and seals it at
``SNP_LAUNCH_FINISH``. There is no such sequence here, so the emulation hashes
the launch image as loaded: SHA-384 over every page belonging to a loaded image,
each contributing its GPA followed by its contents, in address order. The GPA
makes it position-sensitive, which is the property the hardware sequence has.

It is therefore **not** the measurement real hardware would report for the same
payload and must not be compared against one. What it is good for is that it is
stable across boots and changes when the payload changes — so an attestation
flow can be tested against it. The emulated TDX MRTD uses the same construction.

It is computed at the transition to running: ROMs reach guest memory in the
initial reset, which happens after every machine-init-done notifier, and no vCPU
has executed yet — which is launch time.

Not modelled
------------

Memory encryption and isolation of any kind; RMP page sizes, so a 2 MiB
``PVALIDATE`` is refused with ``FAIL_SIZEMISMATCH``; ``RMPADJUST``,
``RMPQUERY``, ``PSMASH``; VMPLs and ``SNP_AP_CREATE``; MMIO reflection; string
I/O over the GHCB shared buffer; and any *trustworthy* attestation — there is no
signing key and no certificate chain, so the report is evidence of nothing.

Testing
-------

``tests/tcg/x86_64/system/`` contains nine freestanding tests, run with
``make run-tcg-tests-x86_64-softmmu``:

``sev-snp``
  Detection: the CPUID leaf, the reported C-bit and reduction, both MSRs, and
  the ``phys_bits`` invariant read back from inside the guest.

``sev-snp-vc``
  ``#VC`` reflection, with an IDT and a handler: that nothing reflects before
  arming, that each class arrives with the right ``SW_EXITCODE``, that the
  carve-outs stay native, and that a nested request escalates to ``#DF``.

``sev-snp-ghcb``
  The MSR protocol, cross-checking the C-bit against ``CPUID.0x8000001F`` and
  each CPUID register against the native instruction.

``sev-snp-nae``
  The page protocol, in the configuration a real guest runs in: reflection
  armed with no relaxations, and a ``#VC`` handler that services I/O through the
  GHCB. Its own output and its ACPI poweroff travel over the NAE path, so it
  could neither report nor exit if that path were broken.

``sev-snp-attest``
  The attestation flow, and the only test that carries its own AES-256-GCM: it
  seals its own request and opens the response, which is what makes it an
  interoperability check rather than the emulator agreeing with itself. It also
  asserts what must fail — a tampered tag, the wrong VMPCK, and the extended
  request.

``sev-snp-dma``
  Device DMA, driven through the ``edu`` test device's DMA engine — which calls
  ``pci_dma_read()`` on the guest's behalf, the same path a virtio ring fetch
  takes, without needing a driver. A shared page reads back correctly; the same
  device reading a page the guest kept private comes away with zeroes.

``sev-snp-rmp``
  Page-state tracking in lazy mode: that a shared page cannot be validated, that
  a claimed one can, that ``PVALIDATE`` reports no-change through CF, and that
  bad size and alignment are refused.

  Running that same binary with ``x-sev-snp-rmp=2`` checks the other half —
  strict mode terminates it on its first paged access, naming the GPA — but
  terminating is a pass there, so it is not in the automated set.

``sev-snp-cbit``
  The private side of the check. Builds its own page tables, maps two pages
  encrypted, and confirms that a validated page is usable with the C-bit set
  and that an unvalidated one raises ``#VC`` — which its handler resolves with
  ``PVALIDATE``, letting the faulting access retry. That retry also shows
  validation needs no TLB flush: if it did, and the flush were missing, the
  access would fault forever.

``sev-snp-strict``
  The same faults with hardware's own defaults, and the answer to whether
  anything can survive strict mode. It links the ``SNP_CBIT_BOOT`` variant of
  ``boot.S``, which sets the C-bit in the page tables before enabling paging,
  sets it in ``CR3`` once 64-bit mode makes bit 51 reachable, and validates
  ``.bss`` before the stack is used — the three things SNP firmware must do.
  Reaching ``main()`` is the result; it then validates RAM outside the launch
  image on demand, through ``#VC``.

  That bootstrap is a build-time variant rather than the default because
  adopting the C-bit is wrong wherever guest RAM is not private, and a guest has
  no way to tell which mode it is in — as on hardware, where the question does
  not arise. Without ``-DSNP_CBIT_BOOT`` the object is byte-identical to the
  one every other test links.
