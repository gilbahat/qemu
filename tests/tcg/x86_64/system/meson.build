tests = []

minilib_dir = meson.current_source_dir() / '..' / '..' / 'minilib'
minilib_printf = files(minilib_dir / 'printf.c')[0]
link_script = files('kernel.ld')[0]
boot = files('boot.S')[0]
cflags = ['-nostdlib',
          '-ffreestanding',
          '-Wa,--noexecstack',
          '-I', minilib_dir, minilib_printf, boot,
          '-Wl,-T', link_script,
          '-Wl,-melf_x86_64',
          '-Wl,--no-warn-rwx-segments',
          '-Wl,--build-id=none',
          '-lgcc']
qemu_def_args = ['-display', 'none',
                 '-device', 'isa-debugcon,chardev=stdio',
                 '-chardev', 'stdio,id=stdio',
                 '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x4',
                 '-kernel']

# Multi arch tests
multi_src = []
foreach t: tcg_tests['multiarch-softmmu']['tests']
  foreach src, setup: t
    new_cflags = cflags
    if fs.stem(src) == 'memory'
      new_cflags += '-DCHECK_UNALIGNED=1'
    endif
    if src not in multi_src
      setup += {'cflags': [new_cflags]}
      multi_src += src
    endif
    tests += {src: setup + {'qemu_args': qemu_def_args}}
  endforeach
endforeach

tests += {
  'patch-target.c': {
    'cflags': cflags,
    'qemu_args': qemu_def_args,
    'plugin_test': {
      'plugin': 'patch',
      'args': ['target=ffc0', 'patch=9090', 'use_hwaddr=true'],
    },
    'wrapper': [prog_check_plugin_output,
                find_program('./validate-patch.py')]
  }
}

# Emulated TDX and SEV-SNP guest interfaces.
#
# boot.S leaves SSE disabled (CR4.OSFXSR clear), so anything the compiler
# vectorises -- a struct initialiser is enough -- would #UD.  boot.S is built
# as part of each test, so a -D here selects its bootstrap for that test only.
cvm_cflags = cflags + ['-mgeneral-regs-only']

# TDX: sept=1 is page state in lazy mode (pages start accepted, so the test's
# own memory keeps working while the pages under test are converted); sept=2
# is strict (guest RAM private and pending, only the launch image accepted).
tdx_cpu = 'max,x-tdx-guest=on'
tdx_sept_cpu = tdx_cpu + ',x-tdx-sept=1'

# SEV-SNP: rmp=1 is RMP-lite in lazy mode (pages shared until claimed).  I/O is
# relaxed where the test has no GHCB to service it with: see sev-snp-vc.c.
snp_cpu = 'max,x-sev-snp-guest=on'
snp_rmp_cpu = snp_cpu + ',x-sev-snp-rmp=1,x-sev-snp-relax-io=on'

cvm_tests = {
  'tdx.c': {'cpu': tdx_cpu},
  # sept=1 so the quote buffer genuinely has to be converted before the quoting
  # service will look at it, which is the conformance point of GetQuote.
  'tdx-attest.c': {'cpu': tdx_sept_cpu},
  # I/O is relaxed because the first TDCALL arms reflection and this test's #VE
  # handler is for EPT violations, not for servicing I/O.
  'tdx-sept.c': {'cpu': tdx_sept_cpu},
  # Device DMA: the SHARED alias is necessary but not sufficient, so the filter
  # also asks whether the page was ever converted.  edu clamps DMA addresses to
  # its dma_mask, which defaults to 28 bits and would strip the SHARED alias
  # before the filter ever saw it.
  'tdx-dma.c': {'cpu': tdx_sept_cpu,
                'args': ['-device', 'edu,dma_mask=0xffffffffffff']},
  # Accepting .bss is wrong wherever guest memory is not pending, and a TD
  # cannot tell which it is in, so only this test gets the accept bootstrap.
  # Nothing boots here without it, which is what is being shown.
  'tdx-strict.c': {'cpu': tdx_cpu + ',x-tdx-sept=2',
                   'cflags': ['-DTDX_ACCEPT_BOOT']},
  'sev-snp.c': {'cpu': snp_cpu},
  # Attestation: the guest seals its own request with AES-256-GCM under a VMPCK
  # from the secrets page, so the emulator has to interoperate with an
  # independent implementation of the same construction.
  'sev-snp-attest.c': {'cpu': snp_cpu + ',x-sev-snp-secrets-gpa=0x4000000'},
  # A handler with no GHCB cannot service I/O, and both the test's output and
  # its exit are port I/O.
  'sev-snp-vc.c': {'cpu': snp_cpu + ',x-sev-snp-relax-io=on'},
  # Drives the GHCB MSR protocol without arming reflection, so its own output
  # still works; the protocol is what a guest needs before it can service #VC.
  'sev-snp-ghcb.c': {'cpu': snp_cpu},
  # Full strict I/O: the guest services its own port access through the GHCB,
  # so the test's output is itself proof the NAE path works.
  'sev-snp-nae.c': {'cpu': snp_cpu},
  # PVALIDATE arms reflection, and this test installs no handler.
  'sev-snp-rmp.c': {'cpu': snp_rmp_cpu},
  # Builds its own C-bit page tables and so reaches the private side of the
  # page-state check.  HLT is relaxed as well: boot.S halts on the way out,
  # after main() has returned, and a #VC there would be reported by a handler
  # whose job here is page faults.
  'sev-snp-cbit.c': {'cpu': snp_rmp_cpu + ',x-sev-snp-relax-hlt=on'},
  # Device DMA, driven through the edu device's DMA engine.  Needs page-state
  # tracking, since that is what the filter consults.
  'sev-snp-dma.c': {'cpu': snp_rmp_cpu, 'args': ['-device', 'edu']},
  # Adopting the C-bit is wrong in any configuration where guest RAM is not
  # private, and the guest has no way to tell, so only this test gets the
  # C-bit bootstrap.  Nothing boots here without it.
  'sev-snp-strict.c': {'cpu': snp_cpu + ',x-sev-snp-rmp=2,x-sev-snp-relax-io=on,x-sev-snp-relax-hlt=on',
                       'cflags': ['-DSNP_CBIT_BOOT']},
}

foreach src, t: cvm_tests
  tests += {
    src: {
      'cflags': cvm_cflags + t.get('cflags', []),
      'qemu_args': ['-cpu', t['cpu']] + t.get('args', []) + qemu_def_args,
    }
  }
endforeach

if 'qemu-system-x86_64' in emulators
  tcg_tests += {
    'x86_64-softmmu': {
      'cc': cc,
      'cc_alt': cc_alt + ['x86_64-elf-gcc'],
      'cc_dockerfile': cc_dockerfile,
      'folder': 'x86_64/system',
      'gdb_arch': 'x86_64',
      'qemu': emulators['qemu-system-x86_64'],
      'tests': tests,
    }
  }
endif
