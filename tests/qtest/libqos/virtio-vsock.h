/*
 * libqos driver framework for virtio-vsock
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#ifndef TESTS_LIBQOS_VIRTIO_VSOCK_H
#define TESTS_LIBQOS_VIRTIO_VSOCK_H

#include "qgraph.h"
#include "virtio.h"
#include "virtio-pci.h"

typedef struct QVirtioVsock QVirtioVsock;
typedef struct QVirtioVsockPCI QVirtioVsockPCI;
typedef struct QVirtioVsockDevice QVirtioVsockDevice;

/* rx, tx and event, in that order. */
#define QVIRTIO_VSOCK_NQUEUES 3

struct QVirtioVsock {
    QVirtioDevice *vdev;
    QVirtQueue *queues[QVIRTIO_VSOCK_NQUEUES];
};

struct QVirtioVsockPCI {
    QVirtioPCIDevice pci_vdev;
    QVirtioVsock vsock;
};

struct QVirtioVsockDevice {
    QOSGraphObject obj;
    QVirtioVsock vsock;
};

/* Guest port the device is told to forward host connections to. */
#define QVIRTIO_VSOCK_FORWARD_PORT 4321

/* Host-side socket path the device was configured with. */
const char *qvirtio_vsock_uds_path(void);

/*
 * Where the device listens for host-initiated connections to
 * QVIRTIO_VSOCK_FORWARD_PORT.  Unlike the path above, this one is bound by the
 * device, so a test connects to it rather than listening on it.
 */
const char *qvirtio_vsock_forward_path(void);

#endif
