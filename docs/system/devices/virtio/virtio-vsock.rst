..
   SPDX-License-Identifier: GPL-2.0-or-later

virtio-vsock
============

``virtio-vsock`` gives a guest an ``AF_VSOCK`` socket family for talking to the
host without a network. QEMU has three implementations of it, differing only in
who owns the virtqueues:

``vhost-vsock``
  The host kernel's ``/dev/vhost-vsock``. Fastest, Linux only, and the host end
  is the kernel's own vsock stack.

``vhost-user-vsock``
  An external daemon such as `vhost-device-vsock`_. Needs no host kernel
  support, but the daemon is a separate process to build, launch and keep alive.

``virtio-vsock``
  QEMU itself. Needs neither a host kernel driver nor a separate process, and is
  the only one of the three that works behind an address space that translates
  -- see `Confidential guests`_.

.. _vhost-device-vsock: https://github.com/rust-vmm/vhost-device/tree/main/vhost-device-vsock

The host end is a Unix socket, or a real ``AF_VSOCK`` socket where the platform
has one. Only ``SOCK_STREAM`` is implemented; ``VIRTIO_VSOCK_F_SEQPACKET`` is
not negotiated.

Usage
-----

::

  -device virtio-vsock-pci,guest-cid=4,path=/tmp/vsock.uds,forward-listen=9001+9002

On a machine without PCI, use ``virtio-vsock-device`` on a virtio-mmio bus
instead. The properties are the same for both:

``guest-cid=<n>`` (required)
  The guest's context ID. Must be greater than 2: 0, 1 and 2 are reserved for
  the hypervisor, the local CID and the host.

``path=<path>``
  Host Unix socket, using the Firecracker hybrid protocol described below.
  Mutually exclusive with ``forward-cid``; exactly one of the two is required.

``forward-cid=<cid>``
  Host ``AF_VSOCK`` CID to forward to instead. Requires an ``AF_VSOCK``-capable
  host; QEMU detects this at configure time (``linux/vm_sockets.h``), so on
  other platforms this fails with "socket family AF_VSOCK unsupported" no matter
  what the running host supports.

``forward-listen=<port>[+<port>...]``
  Ports the guest may be reached on from the host. Without this, connections can
  only be made guest to host.

The hybrid protocol
-------------------

With ``path=``, the host side speaks the same protocol as
``vhost-device-vsock --uds-path`` and Firecracker, so existing host tooling
works unchanged.

**Guest to host.** The device connects to ``path`` and sends a line naming the
port the guest asked for::

  CONNECT 9000\n

The host answers ``OK <port>\n`` to accept, or closes the socket to refuse, in
which case the guest's connect fails with ``ECONNREFUSED``. Everything after the
newline is the stream.

**Host to guest.** For each port in ``forward-listen`` the device listens on
``<path>_<port>``. Connecting to that socket opens a connection to the guest on
that port; there is no handshake line in this direction.

So a host program serving guest connections on port 9000 does::

  $ socat UNIX-LISTEN:/tmp/vsock.uds,fork EXEC:'sh -c "read line; echo OK 1234; cat"'

and one connecting to a guest listening on port 9001 does::

  $ socat - UNIX-CONNECT:/tmp/vsock.uds_9001

Flow control
------------

The device advertises a 64KiB receive window and honours the guest's. It stops
reading a host socket when the guest's window closes and resumes on
``VIRTIO_VSOCK_OP_CREDIT_UPDATE``, so a slow guest applies backpressure to the
host peer rather than causing unbounded buffering in QEMU. A guest that sends
more than the window it was granted has its connection reset.

Confidential guests
-------------------

This device owns its virtqueues, so descriptor fetches and buffer mappings go
through the device's own address space rather than a memory table shared with
another process. That is what makes it usable under QEMU's emulated TDX guest
(``x-tdx-guest=on``, see :doc:`../../i386/tdx-tcg`), where device DMA is filtered
through an IOMMU region that requires each page to carry the SHARED alias *and*
to have been converted with ``TDVMCALL<MapGPA>``.

An out-of-process backend cannot satisfy that. ``VHOST_USER_SET_MEM_TABLE``
hands the backend a flat list of mappable regions, which cannot express a
translation function whose answer depends on runtime conversion state. The
vhost-user IOTLB extension exists for exactly this, but it has to be implemented
on both sides, and ``vhost-device-vsock`` advertises neither
``VIRTIO_F_ACCESS_PLATFORM`` nor ``VHOST_USER_PROTOCOL_F_BACKEND_REQ``.

Limitations
-----------

* ``SOCK_SEQPACKET`` is not implemented.
* The device is unmigratable.
* One CID per device; there is no multi-guest multiplexing.
