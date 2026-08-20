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

#include "qemu/osdep.h"
#include "../libqtest.h"
#include "qemu/module.h"
#include "qgraph.h"
#include "virtio-vsock.h"
#include "standard-headers/linux/virtio_ids.h"

static QGuestAllocator *alloc;

/*
 * The device connects to this socket on demand, so the test only has to have
 * it listening before it makes the guest issue a connect.
 */
static char *uds_path;

/* Bound by the device, per forward-listen, as "<uds_path>_<port>". */
static char *forward_path;

const char *qvirtio_vsock_uds_path(void)
{
    return uds_path;
}

const char *qvirtio_vsock_forward_path(void)
{
    return forward_path;
}

static void virtio_vsock_cleanup(QVirtioVsock *interface)
{
    int i;

    for (i = 0; i < QVIRTIO_VSOCK_NQUEUES; i++) {
        qvirtqueue_cleanup(interface->vdev->bus, interface->queues[i], alloc);
    }
}

static void virtio_vsock_setup(QVirtioVsock *interface)
{
    QVirtioDevice *vdev = interface->vdev;
    uint64_t features;
    int i;

    features = qvirtio_get_features(vdev);
    features &= ~(QVIRTIO_F_BAD_FEATURE |
                  (1ull << VIRTIO_RING_F_INDIRECT_DESC) |
                  (1ull << VIRTIO_RING_F_EVENT_IDX));
    qvirtio_set_features(vdev, features);

    for (i = 0; i < QVIRTIO_VSOCK_NQUEUES; i++) {
        interface->queues[i] = qvirtqueue_setup(vdev, alloc, i);
    }
    qvirtio_set_driver_ok(vdev);
}

static void *qvirtio_vsock_get_driver(QVirtioVsock *v_vsock,
                                      const char *interface)
{
    if (!g_strcmp0(interface, "virtio-vsock")) {
        return v_vsock;
    }
    if (!g_strcmp0(interface, "virtio")) {
        return v_vsock->vdev;
    }

    fprintf(stderr, "%s not present in virtio-vsock-device\n", interface);
    g_assert_not_reached();
}

/* virtio-vsock-device */

static void qvirtio_vsock_device_destructor(QOSGraphObject *obj)
{
    QVirtioVsockDevice *v_vsock = (QVirtioVsockDevice *)obj;

    virtio_vsock_cleanup(&v_vsock->vsock);
}

static void qvirtio_vsock_device_start_hw(QOSGraphObject *obj)
{
    QVirtioVsockDevice *v_vsock = (QVirtioVsockDevice *)obj;

    virtio_vsock_setup(&v_vsock->vsock);
}

static void *qvirtio_vsock_device_get_driver(void *object,
                                             const char *interface)
{
    QVirtioVsockDevice *v_vsock = object;

    return qvirtio_vsock_get_driver(&v_vsock->vsock, interface);
}

static void *virtio_vsock_device_create(void *virtio_dev,
                                        QGuestAllocator *t_alloc,
                                        void *addr)
{
    QVirtioVsockDevice *dev = g_new0(QVirtioVsockDevice, 1);

    dev->vsock.vdev = virtio_dev;
    alloc = t_alloc;

    dev->obj.destructor = qvirtio_vsock_device_destructor;
    dev->obj.get_driver = qvirtio_vsock_device_get_driver;
    dev->obj.start_hw = qvirtio_vsock_device_start_hw;

    return &dev->obj;
}

/* virtio-vsock-pci */

static void qvirtio_vsock_pci_destructor(QOSGraphObject *obj)
{
    QVirtioVsockPCI *v_vsock = (QVirtioVsockPCI *)obj;

    virtio_vsock_cleanup(&v_vsock->vsock);
    qvirtio_pci_destructor(&v_vsock->pci_vdev.obj);
}

static void qvirtio_vsock_pci_start_hw(QOSGraphObject *obj)
{
    QVirtioVsockPCI *v_vsock = (QVirtioVsockPCI *)obj;

    qvirtio_pci_start_hw(&v_vsock->pci_vdev.obj);
    virtio_vsock_setup(&v_vsock->vsock);
}

static void *qvirtio_vsock_pci_get_driver(void *object, const char *interface)
{
    QVirtioVsockPCI *v_vsock = object;

    if (!g_strcmp0(interface, "pci-device")) {
        return v_vsock->pci_vdev.pdev;
    }
    return qvirtio_vsock_get_driver(&v_vsock->vsock, interface);
}

static void *virtio_vsock_pci_create(void *pci_bus, QGuestAllocator *t_alloc,
                                     void *addr)
{
    QVirtioVsockPCI *dev = g_new0(QVirtioVsockPCI, 1);
    QOSGraphObject *obj = &dev->pci_vdev.obj;

    virtio_pci_init(&dev->pci_vdev, pci_bus, addr);
    dev->vsock.vdev = &dev->pci_vdev.vdev;
    alloc = t_alloc;

    g_assert_cmphex(dev->vsock.vdev->device_type, ==, VIRTIO_ID_VSOCK);

    obj->destructor = qvirtio_vsock_pci_destructor;
    obj->start_hw = qvirtio_vsock_pci_start_hw;
    obj->get_driver = qvirtio_vsock_pci_get_driver;

    return obj;
}

static void virtio_vsock_register_nodes(void)
{
    QPCIAddress addr = {
        .devfn = QPCI_DEVFN(4, 0),
    };
    QOSGraphEdgeOptions opts = { };
    g_autofree char *device_opts = NULL;
    g_autofree char *pci_opts = NULL;

    uds_path = g_strdup_printf("%s/qtest-virtio-vsock-%d.sock",
                               g_get_tmp_dir(), getpid());
    forward_path = g_strdup_printf("%s_%d", uds_path,
                                   QVIRTIO_VSOCK_FORWARD_PORT);

    /*
     * Every node forwards a port, so the host-initiated path is configured
     * wherever the outbound one is.  It costs the other tests one unused
     * listening socket and means neither direction can be built without the
     * other being exercised.
     */
    device_opts = g_strdup_printf("guest-cid=3,path=%s,forward-listen=%d",
                                  uds_path, QVIRTIO_VSOCK_FORWARD_PORT);
    pci_opts = g_strdup_printf("guest-cid=3,path=%s,forward-listen=%d,addr=04.0",
                               uds_path, QVIRTIO_VSOCK_FORWARD_PORT);

    /* virtio-vsock-device */
    opts.extra_device_opts = device_opts;
    qos_node_create_driver("virtio-vsock-device", virtio_vsock_device_create);
    qos_node_consumes("virtio-vsock-device", "virtio-bus", &opts);
    qos_node_produces("virtio-vsock-device", "virtio-vsock");

    /* virtio-vsock-pci */
    opts.extra_device_opts = pci_opts;
    add_qpci_address(&opts, &addr);
    qos_node_create_driver("virtio-vsock-pci", virtio_vsock_pci_create);
    qos_node_consumes("virtio-vsock-pci", "pci-bus", &opts);
    qos_node_produces("virtio-vsock-pci", "virtio-vsock");
}

libqos_init(virtio_vsock_register_nodes);
