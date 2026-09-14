# Default configuration for aarch64-softmmu

# We support all the 32 bit boards so need all their config
include ../arm-softmmu/default.mak

# These are selected by default when TCG is enabled, uncomment them to
# keep out of the build.
# CONFIG_XLNX_ZYNQMP_ARM=n
# CONFIG_XLNX_VERSAL=n
# CONFIG_SBSA_REF=n
# CONFIG_NPCM8XX=n
CONFIG_VMAPPLE=n

# Apple ParavirtualizedGraphics, off.
#
# Not a preference: on a host with only the Command Line Tools SDK, this
# cannot be linked at all. That SDK's ParavirtualizedGraphics.tbd declares
# targets x86_64, arm64e and arm64e.x1 -- no plain arm64-macos -- and does not
# export _PGNewDeviceWithDescriptor under any of them, so meson finds the
# framework, enables the device, and the link then fails on a symbol the stub
# never had. The result is that qemu-system-aarch64 cannot be built here at
# all, which has nothing to do with the device anybody actually wanted.
#
# Install the full Xcode SDK and this can come back.
CONFIG_MAC_PVG_PCI=n
CONFIG_MAC_PVG_MMIO=n
