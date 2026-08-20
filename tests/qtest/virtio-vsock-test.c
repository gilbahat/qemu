/*
 * QTest testcase for the in-QEMU virtio-vsock device.
 *
 * Drives the rings directly and speaks the Firecracker hybrid protocol on the
 * host side, so a full connect / send / receive round trip is exercised
 * without needing a guest kernel.
 *
 * Copyright (c) 2026 Gil Bahat
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest-single.h"
#include "qemu/bswap.h"
#include "qemu/module.h"
#include "standard-headers/linux/virtio_vsock.h"
#include "libqos/qgraph.h"
#include "libqos/virtio-vsock.h"

#define TIMEOUT_US (30 * 1000 * 1000)

#define GUEST_CID 3
#define HOST_CID  2
#define GUEST_PORT 1234
#define HOST_PORT  5678

/* One header plus a page, which is what a Linux guest posts. */
#define RX_BUF_SIZE (sizeof(struct virtio_vsock_hdr) + 4096)

typedef struct {
    QVirtioDevice *vdev;
    QVirtQueue *rx;
    QVirtQueue *tx;
    QGuestAllocator *alloc;
    int listen_fd;
    int host_fd;                /* accepted connection, -1 until established */
    uint32_t fwd_cnt;           /* bytes we have consumed from the device */
    /*
     * Which ports this connection is between.  Fixed for a guest-initiated
     * call, but an inbound one is addressed to the forwarded listening port
     * and the device picks the host end, so both have to be discoverable.
     */
    uint32_t guest_port;
    uint32_t host_port;
    /* The CID the guest dials.  The device must answer from the same one. */
    uint64_t host_cid;
} VsockTest;

static void hdr_to_le(struct virtio_vsock_hdr *h)
{
    h->src_cid = cpu_to_le64(h->src_cid);
    h->dst_cid = cpu_to_le64(h->dst_cid);
    h->src_port = cpu_to_le32(h->src_port);
    h->dst_port = cpu_to_le32(h->dst_port);
    h->len = cpu_to_le32(h->len);
    h->type = cpu_to_le16(h->type);
    h->op = cpu_to_le16(h->op);
    h->flags = cpu_to_le32(h->flags);
    h->buf_alloc = cpu_to_le32(h->buf_alloc);
    h->fwd_cnt = cpu_to_le32(h->fwd_cnt);
}

static void hdr_from_le(struct virtio_vsock_hdr *h)
{
    h->src_cid = le64_to_cpu(h->src_cid);
    h->dst_cid = le64_to_cpu(h->dst_cid);
    h->src_port = le32_to_cpu(h->src_port);
    h->dst_port = le32_to_cpu(h->dst_port);
    h->len = le32_to_cpu(h->len);
    h->type = le16_to_cpu(h->type);
    h->op = le16_to_cpu(h->op);
    h->flags = le32_to_cpu(h->flags);
    h->buf_alloc = le32_to_cpu(h->buf_alloc);
    h->fwd_cnt = le32_to_cpu(h->fwd_cnt);
}

/* Put one packet on the tx queue, as the guest driver would. */
static void guest_send(VsockTest *t, uint16_t op, uint32_t flags,
                       const void *data, uint32_t len)
{
    QTestState *qts = global_qtest;
    struct virtio_vsock_hdr hdr = {
        .src_cid = GUEST_CID,
        .dst_cid = t->host_cid,
        .src_port = t->guest_port,
        .dst_port = t->host_port,
        .len = len,
        .type = VIRTIO_VSOCK_TYPE_STREAM,
        .op = op,
        .flags = flags,
        .buf_alloc = 64 * 1024,
        .fwd_cnt = t->fwd_cnt,
    };
    uint64_t addr;
    uint32_t head;

    hdr_to_le(&hdr);

    addr = guest_alloc(t->alloc, sizeof(hdr) + len);
    memwrite(addr, &hdr, sizeof(hdr));
    if (len) {
        memwrite(addr + sizeof(hdr), data, len);
    }

    head = qvirtqueue_add(qts, t->tx, addr, sizeof(hdr) + len, false, false);
    qvirtqueue_kick(qts, t->vdev, t->tx, head);
    qvirtio_wait_used_elem(qts, t->vdev, t->tx, head, NULL, TIMEOUT_US);

    guest_free(t->alloc, addr);
}

/*
 * Post one receive buffer and wait for the device to fill it.  Control packets
 * the test is not interested in (credit updates, mostly) are skipped, so a
 * caller can simply ask for the operation it expects next.
 */
static void guest_recv(VsockTest *t, uint16_t want_op,
                       struct virtio_vsock_hdr *hdr, void *data)
{
    QTestState *qts = global_qtest;
    int tries;

    for (tries = 0; tries < 16; tries++) {
        uint64_t addr = guest_alloc(t->alloc, RX_BUF_SIZE);
        uint32_t head;

        head = qvirtqueue_add(qts, t->rx, addr, RX_BUF_SIZE, true, false);
        qvirtqueue_kick(qts, t->vdev, t->rx, head);
        qvirtio_wait_used_elem(qts, t->vdev, t->rx, head, NULL, TIMEOUT_US);

        memread(addr, hdr, sizeof(*hdr));
        hdr_from_le(hdr);

        if (hdr->len && data) {
            memread(addr + sizeof(*hdr), data, hdr->len);
        }
        guest_free(t->alloc, addr);

        if (hdr->op == want_op) {
            t->fwd_cnt += hdr->len;
            return;
        }

        /* Anything else must at least be a well-formed control packet. */
        g_assert_cmpint(hdr->op, !=, VIRTIO_VSOCK_OP_RST);
        g_assert_cmpint(hdr->type, ==, VIRTIO_VSOCK_TYPE_STREAM);
    }

    g_assert_not_reached();
}

/* Read exactly @len bytes off the host socket. */
static void host_read(int fd, void *buf, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t ret = recv(fd, (char *)buf + done, len - done, 0);

        g_assert_cmpint(ret, >, 0);
        done += ret;
    }
}

/* Read one '\n'-terminated line, without reading past it. */
static char *host_read_line(int fd)
{
    GString *s = g_string_new(NULL);

    for (;;) {
        char c;

        host_read(fd, &c, 1);
        if (c == '\n') {
            break;
        }
        g_string_append_c(s, c);
        g_assert_cmpint(s->len, <, 64);
    }

    return g_string_free(s, FALSE);
}

static void vsock_test_init(VsockTest *t, QVirtioVsock *iface,
                            QGuestAllocator *alloc)
{
    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    const char *path = qvirtio_vsock_uds_path();

    t->vdev = iface->vdev;
    t->rx = iface->queues[0];
    t->tx = iface->queues[1];
    t->alloc = alloc;
    t->host_fd = -1;
    t->fwd_cnt = 0;
    t->guest_port = GUEST_PORT;
    t->host_port = HOST_PORT;
    t->host_cid = HOST_CID;

    g_assert_cmpint(strlen(path), <, sizeof(sun.sun_path));
    strcpy(sun.sun_path, path);
    unlink(path);

    t->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    g_assert_cmpint(t->listen_fd, >=, 0);
    g_assert_cmpint(bind(t->listen_fd, (struct sockaddr *)&sun, sizeof(sun)),
                    ==, 0);
    g_assert_cmpint(listen(t->listen_fd, 1), ==, 0);
}

static void vsock_test_cleanup(VsockTest *t)
{
    if (t->host_fd >= 0) {
        close(t->host_fd);
    }
    close(t->listen_fd);
    unlink(qvirtio_vsock_uds_path());
}

/*
 * Guest-initiated connect: OP_REQUEST must reach the host socket as a
 * "CONNECT <port>" line, and only once the host answers "OK" may the guest see
 * OP_RESPONSE.
 */
static void connect_and_transfer_test(void *obj, void *data,
                                      QGuestAllocator *alloc)
{
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    g_autofree char *line = NULL;
    char buf[64];
    VsockTest t;

    vsock_test_init(&t, iface, alloc);

    guest_send(&t, VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);

    t.host_fd = accept(t.listen_fd, NULL, NULL);
    g_assert_cmpint(t.host_fd, >=, 0);

    line = host_read_line(t.host_fd);
    g_assert_cmpstr(line, ==, "CONNECT " G_STRINGIFY(HOST_PORT));

    g_assert_cmpint(send(t.host_fd, "OK 9999\n", 8, 0), ==, 8);

    guest_recv(&t, VIRTIO_VSOCK_OP_RESPONSE, &hdr, NULL);
    g_assert_cmpint(hdr.src_cid, ==, HOST_CID);
    g_assert_cmpint(hdr.dst_cid, ==, GUEST_CID);
    g_assert_cmpint(hdr.src_port, ==, HOST_PORT);
    g_assert_cmpint(hdr.dst_port, ==, GUEST_PORT);
    g_assert_cmpint(hdr.buf_alloc, >, 0);

    /* Guest to host. */
    guest_send(&t, VIRTIO_VSOCK_OP_RW, 0, "PING", 4);
    host_read(t.host_fd, buf, 4);
    g_assert_cmpint(memcmp(buf, "PING", 4), ==, 0);

    /* Host to guest. */
    g_assert_cmpint(send(t.host_fd, "PONG", 4, 0), ==, 4);
    guest_recv(&t, VIRTIO_VSOCK_OP_RW, &hdr, buf);
    g_assert_cmpint(hdr.len, ==, 4);
    g_assert_cmpint(memcmp(buf, "PONG", 4), ==, 0);

    vsock_test_cleanup(&t);
}

/* A connect to a host that is not listening must come back as OP_RST. */
static void connect_refused_test(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    VsockTest t;

    vsock_test_init(&t, iface, alloc);

    /* Nothing is accepting, so the device's connect attempt cannot complete. */
    close(t.listen_fd);
    t.listen_fd = -1;
    unlink(qvirtio_vsock_uds_path());

    guest_send(&t, VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);
    guest_recv(&t, VIRTIO_VSOCK_OP_RST, &hdr, NULL);

    if (t.host_fd >= 0) {
        close(t.host_fd);
    }
}

/*
 * The host closing its end must be reported to the guest as a shutdown rather
 * than silently dropping the connection.
 */
static void host_close_test(void *obj, void *data, QGuestAllocator *alloc)
{
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    g_autofree char *line = NULL;
    VsockTest t;

    vsock_test_init(&t, iface, alloc);

    guest_send(&t, VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);
    t.host_fd = accept(t.listen_fd, NULL, NULL);
    g_assert_cmpint(t.host_fd, >=, 0);
    line = host_read_line(t.host_fd);
    g_assert_cmpstr(line, ==, "CONNECT " G_STRINGIFY(HOST_PORT));
    g_assert_cmpint(send(t.host_fd, "OK 9999\n", 8, 0), ==, 8);
    guest_recv(&t, VIRTIO_VSOCK_OP_RESPONSE, &hdr, NULL);

    close(t.host_fd);
    t.host_fd = -1;

    guest_recv(&t, VIRTIO_VSOCK_OP_SHUTDOWN, &hdr, NULL);
    g_assert_cmpint(hdr.flags & VIRTIO_VSOCK_SHUTDOWN_SEND, !=, 0);

    vsock_test_cleanup(&t);
}

/* Bring a connection up, leaving t->host_fd accepted and established. */
static void vsock_connect(VsockTest *t)
{
    struct virtio_vsock_hdr hdr;
    g_autofree char *line = NULL;

    guest_send(t, VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);
    t->host_fd = accept(t->listen_fd, NULL, NULL);
    g_assert_cmpint(t->host_fd, >=, 0);
    line = host_read_line(t->host_fd);
    g_assert_cmpstr(line, ==, "CONNECT " G_STRINGIFY(HOST_PORT));
    g_assert_cmpint(send(t->host_fd, "OK 9999\n", 8, 0), ==, 8);
    guest_recv(t, VIRTIO_VSOCK_OP_RESPONSE, &hdr, NULL);
}

/*
 * Push more than one receive window through the device.  This is the path that
 * splits a payload across several guest buffers and, once the window closes,
 * has to stop reading the host socket and resume when the guest grants credit
 * again -- so a stall here means the flow control is wrong, not merely slow.
 */
static void credit_window_test(void *obj, void *data, QGuestAllocator *alloc)
{
    const uint32_t total = 128 * 1024;
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    g_autofree uint8_t *src = NULL;
    uint32_t sent = 0, received = 0;
    char buf[4096];
    int guard;
    VsockTest t;

    vsock_test_init(&t, iface, alloc);
    vsock_connect(&t);

    src = g_malloc(total);
    for (uint32_t i = 0; i < total; i++) {
        src[i] = i & 0xff;
    }

    g_assert_true(qemu_set_blocking(t.host_fd, false, NULL));

    for (guard = 0; received < total; guard++) {
        /* The socket backs up once the device stops reading; that is fine. */
        while (sent < total) {
            ssize_t ret = send(t.host_fd, src + sent,
                               MIN(total - sent, 8192), 0);
            if (ret <= 0) {
                break;
            }
            sent += ret;
        }

        /* Returning credit is what lets the device resume reading. */
        guest_send(&t, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0, NULL, 0);

        guest_recv(&t, VIRTIO_VSOCK_OP_RW, &hdr, buf);
        g_assert_cmpint(hdr.len, >, 0);
        g_assert_cmpint(hdr.len, <=, sizeof(buf));
        g_assert_cmpint(memcmp(buf, src + received, hdr.len), ==, 0);
        received += hdr.len;

        g_assert_cmpint(guard, <, 1000);
    }

    g_assert_cmpint(received, ==, total);

    vsock_test_cleanup(&t);
}

/*
 * Host-initiated connect, via forward-listen.  The device must address the
 * REQUEST to the port the guest is listening on; the ephemeral port it picks
 * belongs to the host end of the call.
 *
 * Worth stating why this is asserted so precisely: a guest matches an inbound
 * REQUEST on dst_port, and one that finds no listener there drops the packet
 * rather than refusing it.  So getting these two round the wrong way does not
 * fail loudly -- the host sits connected to the socket and the guest sits
 * waiting to be called, with no error at either end.
 */
static void forward_listen_test(void *obj, void *data, QGuestAllocator *alloc)
{
    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    const char *path = qvirtio_vsock_forward_path();
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    char buf[64];
    VsockTest t;

    vsock_test_init(&t, iface, alloc);

    /* The device bound this when the guest set DRIVER_OK. */
    g_assert_cmpint(strlen(path), <, sizeof(sun.sun_path));
    strcpy(sun.sun_path, path);

    t.host_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    g_assert_cmpint(t.host_fd, >=, 0);
    g_assert_cmpint(connect(t.host_fd, (struct sockaddr *)&sun, sizeof(sun)),
                    ==, 0);

    guest_recv(&t, VIRTIO_VSOCK_OP_REQUEST, &hdr, NULL);
    g_assert_cmpint(hdr.src_cid, ==, HOST_CID);
    g_assert_cmpint(hdr.dst_cid, ==, GUEST_CID);
    g_assert_cmpint(hdr.dst_port, ==, QVIRTIO_VSOCK_FORWARD_PORT);
    g_assert_cmpint(hdr.src_port, !=, hdr.dst_port);
    g_assert_cmpint(hdr.buf_alloc, >, 0);

    t.guest_port = hdr.dst_port;
    t.host_port = hdr.src_port;

    /* Until this lands the device has no credit and must not read the host. */
    guest_send(&t, VIRTIO_VSOCK_OP_RESPONSE, 0, NULL, 0);

    /* Host to guest. */
    g_assert_cmpint(send(t.host_fd, "PING", 4, 0), ==, 4);
    guest_recv(&t, VIRTIO_VSOCK_OP_RW, &hdr, buf);
    g_assert_cmpint(hdr.len, ==, 4);
    g_assert_cmpint(memcmp(buf, "PING", 4), ==, 0);

    /* Guest to host. */
    guest_send(&t, VIRTIO_VSOCK_OP_RW, 0, "PONG", 4);
    host_read(t.host_fd, buf, 4);
    g_assert_cmpint(memcmp(buf, "PONG", 4), ==, 0);

    vsock_test_cleanup(&t);
    unlink(path);
}

/*
 * A guest matches a reply on the whole address, so the CID it dialled has to
 * come back as the CID the answer is from -- not whichever one the device
 * thinks of as its own.
 */
static void src_cid_echo_test(void *obj, void *data, QGuestAllocator *alloc)
{
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    g_autofree char *line = NULL;
    VsockTest t;

    vsock_test_init(&t, iface, alloc);
    t.host_cid = 42;

    guest_send(&t, VIRTIO_VSOCK_OP_REQUEST, 0, NULL, 0);
    t.host_fd = accept(t.listen_fd, NULL, NULL);
    g_assert_cmpint(t.host_fd, >=, 0);
    line = host_read_line(t.host_fd);
    g_assert_cmpstr(line, ==, "CONNECT " G_STRINGIFY(HOST_PORT));
    g_assert_cmpint(send(t.host_fd, "OK 9999\n", 8, 0), ==, 8);

    guest_recv(&t, VIRTIO_VSOCK_OP_RESPONSE, &hdr, NULL);
    g_assert_cmpint(hdr.src_cid, ==, 42);
    g_assert_cmpint(hdr.dst_cid, ==, GUEST_CID);

    vsock_test_cleanup(&t);
}

/*
 * A host that stops writing but keeps reading is half-closed, not closed: the
 * guest must be told to expect no more data without being told to stop sending
 * any, or a request/response peer that shuts down its write side after asking
 * would never hear the answer.
 */
static void host_half_close_test(void *obj, void *data,
                                 QGuestAllocator *alloc)
{
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    char buf[16];
    VsockTest t;

    vsock_test_init(&t, iface, alloc);
    vsock_connect(&t);

    g_assert_cmpint(shutdown(t.host_fd, SHUT_WR), ==, 0);

    guest_recv(&t, VIRTIO_VSOCK_OP_SHUTDOWN, &hdr, NULL);
    g_assert_cmpint(hdr.flags & VIRTIO_VSOCK_SHUTDOWN_SEND, !=, 0);
    g_assert_cmpint(hdr.flags & VIRTIO_VSOCK_SHUTDOWN_RCV, ==, 0);

    /* The guest's send direction must still work. */
    guest_send(&t, VIRTIO_VSOCK_OP_RW, 0, "LATE", 4);
    host_read(t.host_fd, buf, 4);
    g_assert_cmpint(memcmp(buf, "LATE", 4), ==, 0);

    vsock_test_cleanup(&t);
}

/*
 * Acknowledge host data only by piggybacking fwd_cnt on the guest's own writes,
 * never with an explicit CREDIT_UPDATE -- which is what Linux does when a
 * connection is busy in both directions. The device has to notice the window
 * reopening from any packet, so pushing more than one window through this way
 * must not stall.
 */
static void piggyback_credit_test(void *obj, void *data,
                                  QGuestAllocator *alloc)
{
    const uint32_t total = 96 * 1024;
    QVirtioVsock *iface = obj;
    struct virtio_vsock_hdr hdr;
    g_autofree uint8_t *src = NULL;
    uint32_t sent = 0, received = 0;
    char buf[4096];
    int guard;
    VsockTest t;

    vsock_test_init(&t, iface, alloc);
    vsock_connect(&t);

    src = g_malloc(total);
    for (uint32_t i = 0; i < total; i++) {
        src[i] = (i * 7) & 0xff;
    }

    g_assert_true(qemu_set_blocking(t.host_fd, false, NULL));

    for (guard = 0; received < total; guard++) {
        char ack;

        while (sent < total) {
            ssize_t ret = send(t.host_fd, src + sent,
                               MIN(total - sent, 8192), 0);
            if (ret <= 0) {
                break;
            }
            sent += ret;
        }

        /* The only credit the device ever gets is what this carries. */
        guest_send(&t, VIRTIO_VSOCK_OP_RW, 0, "a", 1);
        host_read(t.host_fd, &ack, 1);

        guest_recv(&t, VIRTIO_VSOCK_OP_RW, &hdr, buf);
        g_assert_cmpint(hdr.len, >, 0);
        g_assert_cmpint(hdr.len, <=, sizeof(buf));
        g_assert_cmpint(memcmp(buf, src + received, hdr.len), ==, 0);
        received += hdr.len;

        g_assert_cmpint(guard, <, 1000);
    }

    g_assert_cmpint(received, ==, total);

    vsock_test_cleanup(&t);
}

static void register_virtio_vsock_test(void)
{
    QOSGraphTestOptions opts = { };

    qos_add_test("src-cid-echo", "virtio-vsock", src_cid_echo_test, &opts);
    qos_add_test("host-half-close", "virtio-vsock", host_half_close_test,
                 &opts);
    qos_add_test("piggyback-credit", "virtio-vsock", piggyback_credit_test,
                 &opts);

    qos_add_test("connect-and-transfer", "virtio-vsock",
                 connect_and_transfer_test, &opts);
    qos_add_test("forward-listen", "virtio-vsock", forward_listen_test, &opts);
    qos_add_test("credit-window", "virtio-vsock", credit_window_test, &opts);
    qos_add_test("connect-refused", "virtio-vsock",
                 connect_refused_test, &opts);
    qos_add_test("host-close", "virtio-vsock", host_close_test, &opts);
}

libqos_init(register_virtio_vsock_test);
