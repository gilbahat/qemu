/*
 * In-QEMU virtio-vsock device.
 *
 * Unlike vhost-vsock and vhost-user-vsock, this device owns its virtqueues:
 * the rings are walked here, so every descriptor fetch and buffer mapping goes
 * through the device's own address space.  That is what makes it usable behind
 * an address space that translates -- notably the emulated-TDX DMA filter in
 * hw/i386/tdx-dma.c, which a vhost-user backend cannot work with because a
 * flat memory table cannot express a translate function whose answer depends on
 * runtime page-conversion state.
 *
 * The host side is either the Firecracker "hybrid vsock" AF_UNIX convention --
 * one listening socket, guest-initiated connections announced with
 * "CONNECT <port>\n" -- or real AF_VSOCK where the platform has it.  The
 * hybrid protocol is what vhost-device-vsock speaks with --uds-path, so
 * existing host tooling keeps working, and it needs nothing from the host
 * kernel, which is what makes this work on macOS.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/log.h"
#include "hw/core/qdev-properties.h"
#include "hw/virtio/virtio-access.h"
#include "hw/virtio/virtio-vsock.h"
#include "standard-headers/linux/virtio_ids.h"

/*
 * Ephemeral host-side ports handed to host-initiated connections.  The guest
 * end of such a call is the forwarded listening port and cannot be anything
 * else, so this names the other end.  Well above anything a peer is likely to
 * have bound.
 */
#define VIRTIO_VSOCK_EPHEMERAL_FIRST 0x40000000u

static void virtio_vsock_flush_rx(VirtIOVSock *s);
static void virtio_vsock_conn_flush_tx(VirtIOVSockConn *conn);
static void virtio_vsock_conn_close(VirtIOVSockConn *conn, bool send_rst);
static void virtio_vsock_conn_arm_read(VirtIOVSockConn *conn);

/* ------------------------------------------------------------------ */
/* Connection table                                                    */
/* ------------------------------------------------------------------ */

static uint64_t virtio_vsock_conn_key(uint32_t guest_port, uint32_t host_port)
{
    return ((uint64_t)guest_port << 32) | host_port;
}

/*
 * The CID we call ourselves when we are the one opening a connection.  For a
 * reply, prefer the CID the guest actually dialled -- see VirtIOVSockConn.
 */
static uint64_t virtio_vsock_host_cid(VirtIOVSock *s)
{
    return s->hybrid ? VIRTIO_VSOCK_HOST_CID : s->forward_cid;
}

static VirtIOVSockConn *virtio_vsock_conn_find(VirtIOVSock *s,
                                               uint32_t guest_port,
                                               uint32_t host_port)
{
    uint64_t key = virtio_vsock_conn_key(guest_port, host_port);

    return g_hash_table_lookup(s->conns, &key);
}

static void virtio_vsock_conn_free(gpointer opaque)
{
    VirtIOVSockConn *conn = opaque;

    if (conn->read_watch) {
        g_source_remove(conn->read_watch);
    }
    if (conn->write_watch) {
        g_source_remove(conn->write_watch);
    }
    if (conn->sioc) {
        qio_channel_close(QIO_CHANNEL(conn->sioc), NULL);
        object_unref(OBJECT(conn->sioc));
    }
    if (conn->tx_buf) {
        g_byte_array_free(conn->tx_buf, TRUE);
    }
    if (conn->reply) {
        g_string_free(conn->reply, TRUE);
    }
    g_free(conn);
}

static VirtIOVSockConn *virtio_vsock_conn_new(VirtIOVSock *s,
                                              uint32_t guest_port,
                                              uint32_t host_port,
                                              QIOChannelSocket *sioc)
{
    VirtIOVSockConn *conn = g_new0(VirtIOVSockConn, 1);
    uint64_t *key = g_new(uint64_t, 1);

    conn->vsock = s;
    conn->guest_port = guest_port;
    conn->host_port = host_port;
    conn->sioc = sioc;
    conn->tx_buf = g_byte_array_new();

    *key = virtio_vsock_conn_key(guest_port, host_port);
    g_hash_table_insert(s->conns, key, conn);

    return conn;
}

/*
 * How much more payload the guest has room for.  Everything we read from a
 * host socket is gated on this, which is what keeps the pending rx queue
 * bounded by the guest's own advertised buffer.
 */
static uint32_t virtio_vsock_conn_tx_window(VirtIOVSockConn *conn)
{
    uint32_t in_flight = conn->tx_cnt - conn->peer_fwd_cnt;

    if (in_flight >= conn->peer_buf_alloc) {
        return 0;
    }
    return conn->peer_buf_alloc - in_flight;
}

/* ------------------------------------------------------------------ */
/* Host -> guest: the rx virtqueue                                     */
/* ------------------------------------------------------------------ */

static void virtio_vsock_pkt_free(VirtIOVSockPkt *pkt)
{
    g_free(pkt->data);
    g_free(pkt);
}

/*
 * Queue one packet for the guest.  Delivery is deferred to
 * virtio_vsock_flush_rx() so that a caller never has to care whether the guest
 * has posted receive buffers; control packets must not be dropped just because
 * the ring happens to be empty.
 */
static void virtio_vsock_queue_pkt(VirtIOVSock *s, uint64_t src_cid,
                                   uint32_t guest_port, uint32_t host_port,
                                   uint16_t op, uint32_t flags,
                                   uint32_t fwd_cnt,
                                   const uint8_t *data, uint32_t len)
{
    VirtIOVSockPkt *pkt = g_new0(VirtIOVSockPkt, 1);

    pkt->hdr.src_cid = src_cid;
    pkt->hdr.dst_cid = s->guest_cid;
    pkt->hdr.src_port = host_port;
    pkt->hdr.dst_port = guest_port;
    pkt->hdr.type = VIRTIO_VSOCK_TYPE_STREAM;
    pkt->hdr.op = op;
    pkt->hdr.flags = flags;
    pkt->hdr.buf_alloc = VIRTIO_VSOCK_BUF_ALLOC;
    pkt->hdr.fwd_cnt = fwd_cnt;

    if (len) {
        pkt->data = g_memdup2(data, len);
        pkt->len = len;
    }

    QTAILQ_INSERT_TAIL(&s->rx_pending, pkt, next);
    virtio_vsock_flush_rx(s);
}

/*
 * Drain the pending queue into the rx virtqueue.  A data packet larger than
 * the buffer the guest posted is split across several descriptors -- vsock is
 * a byte stream, so that is transparent to the driver.
 */
static void virtio_vsock_flush_rx(VirtIOVSock *s)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    bool notify = false;

    if (!s->started || !virtio_queue_ready(s->recv_vq)) {
        return;
    }

    while (!QTAILQ_EMPTY(&s->rx_pending)) {
        VirtIOVSockPkt *pkt = QTAILQ_FIRST(&s->rx_pending);
        struct virtio_vsock_hdr hdr;
        VirtQueueElement *elem;
        uint32_t chunk;
        size_t cap;

        elem = virtqueue_pop(s->recv_vq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        if (elem->out_num) {
            virtio_error(vdev, "virtio-vsock: rx element has output buffers");
            virtqueue_detach_element(s->recv_vq, elem, 0);
            g_free(elem);
            return;
        }

        cap = iov_size(elem->in_sg, elem->in_num);
        if (cap < sizeof(hdr)) {
            virtio_error(vdev, "virtio-vsock: rx buffer smaller than header");
            virtqueue_detach_element(s->recv_vq, elem, 0);
            g_free(elem);
            return;
        }

        chunk = MIN(pkt->len - pkt->off, cap - sizeof(hdr));

        /*
         * A header-sized buffer cannot carry payload, so handing this packet to
         * it would consume the element without advancing pkt->off.  Give the
         * element back and wait for one with room rather than spending the ring
         * on empty packets.
         */
        if (chunk == 0 && pkt->len) {
            virtqueue_detach_element(s->recv_vq, elem, 0);
            g_free(elem);
            break;
        }

        hdr = pkt->hdr;
        hdr.src_cid = cpu_to_le64(hdr.src_cid);
        hdr.dst_cid = cpu_to_le64(hdr.dst_cid);
        hdr.src_port = cpu_to_le32(hdr.src_port);
        hdr.dst_port = cpu_to_le32(hdr.dst_port);
        hdr.len = cpu_to_le32(chunk);
        hdr.type = cpu_to_le16(hdr.type);
        hdr.op = cpu_to_le16(hdr.op);
        hdr.flags = cpu_to_le32(hdr.flags);
        hdr.buf_alloc = cpu_to_le32(hdr.buf_alloc);
        hdr.fwd_cnt = cpu_to_le32(hdr.fwd_cnt);

        iov_from_buf(elem->in_sg, elem->in_num, 0, &hdr, sizeof(hdr));
        if (chunk) {
            iov_from_buf(elem->in_sg, elem->in_num, sizeof(hdr),
                         pkt->data + pkt->off, chunk);
        }

        virtqueue_push(s->recv_vq, elem, sizeof(hdr) + chunk);
        g_free(elem);
        notify = true;

        pkt->off += chunk;
        if (pkt->off >= pkt->len) {
            QTAILQ_REMOVE(&s->rx_pending, pkt, next);
            virtio_vsock_pkt_free(pkt);
        }
    }

    if (notify) {
        virtio_notify(vdev, s->recv_vq);
    }
}

/* ------------------------------------------------------------------ */
/* Host socket I/O                                                     */
/* ------------------------------------------------------------------ */

static void virtio_vsock_conn_credit_update(VirtIOVSockConn *conn)
{
    conn->last_fwd_cnt = conn->fwd_cnt;
    virtio_vsock_queue_pkt(conn->vsock, conn->host_cid,
                           conn->guest_port, conn->host_port,
                           VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0,
                           conn->fwd_cnt, NULL, 0);
}

static gboolean virtio_vsock_conn_writable(QIOChannel *ioc, GIOCondition cond,
                                           void *opaque)
{
    VirtIOVSockConn *conn = opaque;

    conn->write_watch = 0;
    virtio_vsock_conn_flush_tx(conn);
    return G_SOURCE_REMOVE;
}

/*
 * Push buffered guest payload at the host socket.  fwd_cnt only advances for
 * bytes the socket actually accepted, so a blocked host end applies real
 * backpressure to the guest through the credit protocol rather than being
 * absorbed by an unbounded buffer here.
 */
static void virtio_vsock_conn_flush_tx(VirtIOVSockConn *conn)
{
    while (conn->tx_buf->len) {
        ssize_t ret = qio_channel_write(QIO_CHANNEL(conn->sioc),
                                        (const char *)conn->tx_buf->data,
                                        conn->tx_buf->len, NULL);

        if (ret == QIO_CHANNEL_ERR_BLOCK) {
            if (!conn->write_watch) {
                conn->write_watch = qio_channel_add_watch(
                    QIO_CHANNEL(conn->sioc), G_IO_OUT,
                    virtio_vsock_conn_writable, conn, NULL);
            }
            return;
        }
        if (ret <= 0) {
            virtio_vsock_conn_close(conn, true);
            return;
        }

        g_byte_array_remove_range(conn->tx_buf, 0, ret);
        conn->fwd_cnt += ret;
    }

    if (conn->write_watch) {
        g_source_remove(conn->write_watch);
        conn->write_watch = 0;
    }

    /*
     * Report progress on every drain rather than at some fraction of the
     * window.  A guest streaming to the host may never give us a packet to
     * piggyback fresh credit on, so withholding the update until a threshold
     * risks parking it at buf_alloc; an extra small packet is the cheaper
     * mistake.
     */
    if (conn->fwd_cnt != conn->last_fwd_cnt) {
        virtio_vsock_conn_credit_update(conn);
    }

    if (conn->guest_shutdown) {
        qio_channel_shutdown(QIO_CHANNEL(conn->sioc),
                             QIO_CHANNEL_SHUTDOWN_WRITE, NULL);
    }

    /*
     * The packet that brought this payload also carried the guest's fwd_cnt,
     * which may have reopened a window we had stopped reading on.  Re-arming
     * belongs here rather than at the OP_RW call site: the loop above can close
     * the connection, so this is the last point that is reached only when it
     * survived.
     */
    virtio_vsock_conn_arm_read(conn);
}

/*
 * Read the "OK <port>" line that answers our "CONNECT <port>".  One byte at a
 * time: the reply is followed immediately by stream data on the same socket,
 * so we must not read past the newline.
 */
static gboolean virtio_vsock_conn_handshake(VirtIOVSockConn *conn)
{
    VirtIOVSock *s = conn->vsock;

    for (;;) {
        char c;
        ssize_t ret = qio_channel_read(QIO_CHANNEL(conn->sioc), &c, 1, NULL);

        if (ret == QIO_CHANNEL_ERR_BLOCK) {
            return G_SOURCE_CONTINUE;
        }
        if (ret <= 0) {
            goto refused;
        }

        if (c == '\n') {
            break;
        }
        if (conn->reply->len > 64) {
            goto refused;
        }
        g_string_append_c(conn->reply, c);
    }

    if (!g_str_has_prefix(conn->reply->str, "OK")) {
        goto refused;
    }

    g_string_free(conn->reply, TRUE);
    conn->reply = NULL;
    conn->state = VIRTIO_VSOCK_CONN_ESTABLISHED;

    virtio_vsock_queue_pkt(s, conn->host_cid, conn->guest_port, conn->host_port,
                           VIRTIO_VSOCK_OP_RESPONSE, 0, conn->fwd_cnt, NULL, 0);
    return G_SOURCE_CONTINUE;

refused:
    conn->read_watch = 0;
    virtio_vsock_conn_close(conn, true);
    return G_SOURCE_REMOVE;
}

static gboolean virtio_vsock_conn_readable(QIOChannel *ioc, GIOCondition cond,
                                           void *opaque)
{
    VirtIOVSockConn *conn = opaque;
    VirtIOVSock *s = conn->vsock;
    g_autofree uint8_t *buf = NULL;
    uint32_t window;
    ssize_t ret;

    if (conn->state == VIRTIO_VSOCK_CONN_CONNECTING) {
        return virtio_vsock_conn_handshake(conn);
    }

    window = virtio_vsock_conn_tx_window(conn);
    if (!window) {
        /* Guest is out of buffer space; resume when it grants more credit. */
        conn->read_watch = 0;
        return G_SOURCE_REMOVE;
    }

    window = MIN(window, VIRTIO_VSOCK_MAX_PKT_BUF_SIZE);
    buf = g_malloc(window);

    ret = qio_channel_read(QIO_CHANNEL(conn->sioc), (char *)buf, window, NULL);
    if (ret == QIO_CHANNEL_ERR_BLOCK) {
        return G_SOURCE_CONTINUE;
    }
    if (ret < 0) {
        conn->read_watch = 0;
        virtio_vsock_conn_close(conn, true);
        return G_SOURCE_REMOVE;
    }
    if (ret == 0) {
        /*
         * Host end closed.  Tell the guest and keep the connection until it
         * acknowledges with RST or SHUTDOWN, so a close is not mistaken for a
         * lost connection.
         */
        conn->host_eof = true;
        conn->read_watch = 0;
        /*
         * SEND alone: the host will not send again, but it may still be
         * waiting to read.  Saying RCV too would tell the guest to stop
         * writing, and a peer that did shutdown(SHUT_WR) expecting a reply
         * would never get one.
         */
        virtio_vsock_queue_pkt(s, conn->host_cid, conn->guest_port,
                               conn->host_port, VIRTIO_VSOCK_OP_SHUTDOWN,
                               VIRTIO_VSOCK_SHUTDOWN_SEND,
                               conn->fwd_cnt, NULL, 0);
        return G_SOURCE_REMOVE;
    }

    conn->tx_cnt += ret;
    virtio_vsock_queue_pkt(s, conn->host_cid, conn->guest_port, conn->host_port,
                           VIRTIO_VSOCK_OP_RW, 0, conn->fwd_cnt, buf, ret);

    if (!virtio_vsock_conn_tx_window(conn)) {
        conn->read_watch = 0;
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static void virtio_vsock_conn_arm_read(VirtIOVSockConn *conn)
{
    if (conn->read_watch || conn->host_eof) {
        return;
    }
    switch (conn->state) {
    case VIRTIO_VSOCK_CONN_CONNECTING:
        /* Reading the handshake reply, which costs the guest no credit. */
        break;
    case VIRTIO_VSOCK_CONN_ESTABLISHED:
        if (!virtio_vsock_conn_tx_window(conn)) {
            return;
        }
        break;
    default:
        /*
         * Inbound connection the guest has not accepted yet: it has granted no
         * credit, so there is nowhere to put anything we might read.
         */
        return;
    }
    conn->read_watch = qio_channel_add_watch(QIO_CHANNEL(conn->sioc), G_IO_IN,
                                             virtio_vsock_conn_readable, conn,
                                             NULL);
}

static void virtio_vsock_conn_close(VirtIOVSockConn *conn, bool send_rst)
{
    VirtIOVSock *s = conn->vsock;
    uint64_t key = virtio_vsock_conn_key(conn->guest_port, conn->host_port);
    VirtIOVSockPkt *pkt, *tmp;

    /*
     * Drop anything still queued for this connection before the RST.  The
     * ports can be reused, and delivering a dead connection's payload after a
     * live one has taken the same pair would corrupt the new stream.
     */
    QTAILQ_FOREACH_SAFE(pkt, &s->rx_pending, next, tmp) {
        if (pkt->hdr.dst_port == conn->guest_port &&
            pkt->hdr.src_port == conn->host_port) {
            QTAILQ_REMOVE(&s->rx_pending, pkt, next);
            virtio_vsock_pkt_free(pkt);
        }
    }

    if (send_rst) {
        virtio_vsock_queue_pkt(s, conn->host_cid, conn->guest_port,
                               conn->host_port, VIRTIO_VSOCK_OP_RST, 0,
                               conn->fwd_cnt, NULL, 0);
    }
    g_hash_table_remove(s->conns, &key);
}

/* ------------------------------------------------------------------ */
/* Host address construction                                           */
/* ------------------------------------------------------------------ */

/*
 * Where the host end of a connection to @port lives.  In hybrid mode outbound
 * connections all go to the one socket (@port is announced in-band instead)
 * while inbound listeners get a per-port name; AF_VSOCK addresses the port
 * directly in both directions.
 */
static SocketAddress *virtio_vsock_host_addr(VirtIOVSock *s, uint32_t port,
                                             bool listen)
{
    SocketAddress *addr = g_new0(SocketAddress, 1);

    if (s->hybrid) {
        addr->type = SOCKET_ADDRESS_TYPE_UNIX;
        addr->u.q_unix.path = listen ?
            g_strdup_printf("%s_%u", s->path, port) : g_strdup(s->path);
    } else {
        addr->type = SOCKET_ADDRESS_TYPE_VSOCK;
        addr->u.vsock.cid = g_strdup_printf("%u", s->forward_cid);
        addr->u.vsock.port = g_strdup_printf("%u", port);
    }

    return addr;
}

/* ------------------------------------------------------------------ */
/* Guest -> host: the tx virtqueue                                     */
/* ------------------------------------------------------------------ */

/*
 * A connect in flight.  It outlives the connection it belongs to on purpose:
 * the guest can reset, or the device can be torn down, while the host end is
 * still being dialled.  So this holds a reference on the device and names the
 * connection by key rather than by pointer, and the completion tolerates
 * finding it gone.
 */
typedef struct VirtIOVSockConnectReq {
    VirtIOVSock *s;
    uint64_t key;
} VirtIOVSockConnectReq;

static void virtio_vsock_connect_done(QIOTask *task, gpointer opaque)
{
    VirtIOVSockConnectReq *req = opaque;
    VirtIOVSock *s = req->s;
    VirtIOVSockConn *conn = NULL;
    Error *err = NULL;

    if (s->conns) {
        conn = g_hash_table_lookup(s->conns, &req->key);
    }
    if (!conn || conn->state != VIRTIO_VSOCK_CONN_OPENING) {
        goto out;
    }

    if (qio_task_propagate_error(task, &err)) {
        warn_report_err(err);
        virtio_vsock_conn_close(conn, true);
        goto out;
    }

    if (s->hybrid) {
        g_autofree char *line =
            g_strdup_printf("CONNECT %u\n", conn->host_port);

        if (qio_channel_write_all(QIO_CHANNEL(conn->sioc), line, strlen(line),
                                  &err) < 0) {
            warn_report_err(err);
            virtio_vsock_conn_close(conn, true);
            goto out;
        }
        /* Wait for "OK <port>" before telling the guest it is connected. */
        conn->state = VIRTIO_VSOCK_CONN_CONNECTING;
        conn->reply = g_string_new(NULL);
    } else {
        conn->state = VIRTIO_VSOCK_CONN_ESTABLISHED;
        virtio_vsock_queue_pkt(s, conn->host_cid, conn->guest_port,
                               conn->host_port, VIRTIO_VSOCK_OP_RESPONSE, 0,
                               conn->fwd_cnt, NULL, 0);
    }

    qio_channel_set_blocking(QIO_CHANNEL(conn->sioc), false, NULL);
    virtio_vsock_conn_arm_read(conn);

out:
    object_unref(OBJECT(s));
    g_free(req);
}

/*
 * Guest asked to connect to @host_port.  The dial runs in the background: this
 * is called from the tx virtqueue handler with the BQL held, and a host end
 * that is slow to answer must not stop the whole machine.
 */
static void virtio_vsock_do_connect(VirtIOVSock *s,
                                    const struct virtio_vsock_hdr *hdr)
{
    g_autoptr(SocketAddress) addr = NULL;
    VirtIOVSockConnectReq *req;
    QIOChannelSocket *sioc;
    VirtIOVSockConn *conn;

    if (virtio_vsock_conn_find(s, hdr->src_port, hdr->dst_port)) {
        goto reject;
    }
    if (g_hash_table_size(s->conns) >= VIRTIO_VSOCK_MAX_CONNS) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-vsock: refusing connect, %u already open\n",
                      VIRTIO_VSOCK_MAX_CONNS);
        goto reject;
    }

    addr = virtio_vsock_host_addr(s, hdr->dst_port, false);
    sioc = qio_channel_socket_new();

    conn = virtio_vsock_conn_new(s, hdr->src_port, hdr->dst_port, sioc);
    conn->host_cid = hdr->dst_cid;
    conn->peer_buf_alloc = hdr->buf_alloc;
    conn->peer_fwd_cnt = hdr->fwd_cnt;
    conn->state = VIRTIO_VSOCK_CONN_OPENING;

    req = g_new0(VirtIOVSockConnectReq, 1);
    req->s = s;
    req->key = virtio_vsock_conn_key(conn->guest_port, conn->host_port);
    object_ref(OBJECT(s));

    qio_channel_socket_connect_async(sioc, addr, virtio_vsock_connect_done,
                                     req, NULL, NULL);
    return;

reject:
    virtio_vsock_queue_pkt(s, hdr->dst_cid, hdr->src_port, hdr->dst_port,
                           VIRTIO_VSOCK_OP_RST, 0, 0, NULL, 0);
}

static void virtio_vsock_handle_pkt(VirtIOVSock *s,
                                    const struct virtio_vsock_hdr *hdr,
                                    const uint8_t *data)
{
    VirtIOVSockConn *conn;

    if (hdr->op == VIRTIO_VSOCK_OP_REQUEST) {
        virtio_vsock_do_connect(s, hdr);
        return;
    }

    conn = virtio_vsock_conn_find(s, hdr->src_port, hdr->dst_port);
    if (!conn) {
        if (hdr->op != VIRTIO_VSOCK_OP_RST) {
            virtio_vsock_queue_pkt(s, hdr->dst_cid, hdr->src_port,
                                   hdr->dst_port, VIRTIO_VSOCK_OP_RST, 0, 0,
                                   NULL, 0);
        }
        return;
    }

    /* Every packet carries the peer's current credit state. */
    conn->peer_buf_alloc = hdr->buf_alloc;
    conn->peer_fwd_cnt = hdr->fwd_cnt;

    switch (hdr->op) {
    case VIRTIO_VSOCK_OP_RESPONSE:
        if (conn->state != VIRTIO_VSOCK_CONN_ACCEPTING) {
            virtio_vsock_conn_close(conn, true);
            return;
        }
        conn->state = VIRTIO_VSOCK_CONN_ESTABLISHED;
        conn->deadline = 0;
        break;

    case VIRTIO_VSOCK_OP_RW:
        if (conn->state != VIRTIO_VSOCK_CONN_ESTABLISHED) {
            virtio_vsock_conn_close(conn, true);
            return;
        }
        /*
         * We advertised VIRTIO_VSOCK_BUF_ALLOC; a guest that ignores it would
         * otherwise make our buffer grow without bound.
         */
        if (conn->tx_buf->len + hdr->len > VIRTIO_VSOCK_BUF_ALLOC) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "virtio-vsock: guest exceeded its send credit\n");
            virtio_vsock_conn_close(conn, true);
            return;
        }
        g_byte_array_append(conn->tx_buf, data, hdr->len);
        virtio_vsock_conn_flush_tx(conn);
        return;

    case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
        virtio_vsock_conn_credit_update(conn);
        break;

    case VIRTIO_VSOCK_OP_CREDIT_UPDATE:
        break;

    case VIRTIO_VSOCK_OP_SHUTDOWN:
        if (hdr->flags & VIRTIO_VSOCK_SHUTDOWN_SEND) {
            conn->guest_shutdown = true;
            if (!conn->tx_buf->len) {
                qio_channel_shutdown(QIO_CHANNEL(conn->sioc),
                                     QIO_CHANNEL_SHUTDOWN_WRITE, NULL);
            }
        }
        if ((hdr->flags & VIRTIO_VSOCK_SHUTDOWN_RCV) || conn->host_eof) {
            virtio_vsock_conn_close(conn, true);
            return;
        }
        break;

    case VIRTIO_VSOCK_OP_RST:
        virtio_vsock_conn_close(conn, false);
        return;

    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-vsock: unknown operation %u\n", hdr->op);
        virtio_vsock_conn_close(conn, true);
        return;
    }

    /* A credit grant may have reopened a window we had stopped reading on. */
    virtio_vsock_conn_arm_read(conn);
}

static void virtio_vsock_handle_tx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOVSock *s = VIRTIO_VSOCK(vdev);
    VirtQueueElement *elem;
    bool notify = false;

    if (!s->started) {
        return;
    }

    while ((elem = virtqueue_pop(vq, sizeof(VirtQueueElement)))) {
        struct virtio_vsock_hdr hdr;
        g_autofree uint8_t *data = NULL;
        size_t len;

        len = iov_size(elem->out_sg, elem->out_num);
        if (len < sizeof(hdr)) {
            virtio_error(vdev, "virtio-vsock: tx element shorter than header");
            goto err;
        }

        iov_to_buf(elem->out_sg, elem->out_num, 0, &hdr, sizeof(hdr));
        hdr.src_cid = le64_to_cpu(hdr.src_cid);
        hdr.dst_cid = le64_to_cpu(hdr.dst_cid);
        hdr.src_port = le32_to_cpu(hdr.src_port);
        hdr.dst_port = le32_to_cpu(hdr.dst_port);
        hdr.len = le32_to_cpu(hdr.len);
        hdr.type = le16_to_cpu(hdr.type);
        hdr.op = le16_to_cpu(hdr.op);
        hdr.flags = le32_to_cpu(hdr.flags);
        hdr.buf_alloc = le32_to_cpu(hdr.buf_alloc);
        hdr.fwd_cnt = le32_to_cpu(hdr.fwd_cnt);

        /*
         * Never trust a length from the ring.  This matters more than usual
         * here: behind a translating address space a denied DMA is bounce
         * buffered rather than failing, so a short or unmapped descriptor
         * arrives as plausible-looking zeroes instead of an error.
         */
        if (hdr.len > len - sizeof(hdr)) {
            virtio_error(vdev, "virtio-vsock: packet length %u exceeds buffer",
                         hdr.len);
            goto err;
        }

        if (hdr.type != VIRTIO_VSOCK_TYPE_STREAM) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "virtio-vsock: unsupported socket type %u\n",
                          hdr.type);
        } else {
            if (hdr.len) {
                data = g_malloc(hdr.len);
                iov_to_buf(elem->out_sg, elem->out_num, sizeof(hdr),
                           data, hdr.len);
            }
            virtio_vsock_handle_pkt(s, &hdr, data);
        }

        virtqueue_push(vq, elem, 0);
        g_free(elem);
        notify = true;
    }

    if (notify) {
        virtio_notify(vdev, vq);
    }
    return;

err:
    virtqueue_detach_element(vq, elem, 0);
    g_free(elem);
}

static void virtio_vsock_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOVSock *s = VIRTIO_VSOCK(vdev);
    GHashTableIter iter;
    gpointer conn;

    /* Fresh receive buffers: deliver what is waiting, then resume reading. */
    virtio_vsock_flush_rx(s);

    g_hash_table_iter_init(&iter, s->conns);
    while (g_hash_table_iter_next(&iter, NULL, &conn)) {
        virtio_vsock_conn_arm_read(conn);
    }
}

static void virtio_vsock_handle_event(VirtIODevice *vdev, VirtQueue *vq)
{
    /* The guest only supplies buffers here; we push events into them. */
}

/* ------------------------------------------------------------------ */
/* Host-initiated connections                                          */
/* ------------------------------------------------------------------ */

static void virtio_vsock_accept(QIONetListener *listener,
                                QIOChannelSocket *sioc, gpointer opaque)
{
    VirtIOVSockListener *l = opaque;
    VirtIOVSock *s = l->vsock;
    VirtIOVSockConn *conn;
    uint32_t host_port;

    if (!s->started) {
        qio_channel_close(QIO_CHANNEL(sioc), NULL);
        return;
    }

    if (g_hash_table_size(s->conns) >= VIRTIO_VSOCK_MAX_CONNS) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-vsock: refusing connection, %u already open\n",
                      VIRTIO_VSOCK_MAX_CONNS);
        qio_channel_close(QIO_CHANNEL(sioc), NULL);
        return;
    }

    /*
     * The ephemeral port belongs to the *host* end of an inbound call; the
     * guest end is the port it is listening on, and it has to be. A listening
     * guest matches an incoming REQUEST on dst_port, so naming the guest end
     * anything else addresses a port nobody is on -- and since a guest that
     * finds no listener just drops the packet, the call is never answered and
     * never refused either.
     */
    do {
        host_port = s->next_host_port++;
        if (s->next_host_port < VIRTIO_VSOCK_EPHEMERAL_FIRST) {
            s->next_host_port = VIRTIO_VSOCK_EPHEMERAL_FIRST;
        }
    } while (virtio_vsock_conn_find(s, l->port, host_port));

    object_ref(OBJECT(sioc));
    qio_channel_set_blocking(QIO_CHANNEL(sioc), false, NULL);

    conn = virtio_vsock_conn_new(s, l->port, host_port, sioc);
    conn->host_cid = virtio_vsock_host_cid(s);
    conn->state = VIRTIO_VSOCK_CONN_ACCEPTING;
    conn->deadline = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                     VIRTIO_VSOCK_ACCEPT_TIMEOUT_MS;
    timer_mod(s->accept_timer, conn->deadline);

    /*
     * No credit from the guest yet, so nothing may be read from the host end
     * until its OP_RESPONSE arrives with a buf_alloc.
     */
    virtio_vsock_queue_pkt(s, conn->host_cid, l->port, host_port,
                           VIRTIO_VSOCK_OP_REQUEST, 0, conn->fwd_cnt, NULL, 0);
}

/*
 * Reap inbound connections the guest never answered, and re-arm for the next
 * one still waiting.  One timer for all of them: these expire in the order they
 * were created, so the earliest outstanding deadline is the only one to hold.
 */
static void virtio_vsock_accept_expire(void *opaque)
{
    VirtIOVSock *s = opaque;
    int64_t now = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
    int64_t next = 0;
    GHashTableIter iter;
    g_autoptr(GPtrArray) expired = g_ptr_array_new();
    gpointer val;
    guint i;

    g_hash_table_iter_init(&iter, s->conns);
    while (g_hash_table_iter_next(&iter, NULL, &val)) {
        VirtIOVSockConn *conn = val;

        if (conn->state != VIRTIO_VSOCK_CONN_ACCEPTING || !conn->deadline) {
            continue;
        }
        if (conn->deadline <= now) {
            g_ptr_array_add(expired, conn);
        } else if (!next || conn->deadline < next) {
            next = conn->deadline;
        }
    }

    /* Collected first: closing mutates the table we were iterating. */
    for (i = 0; i < expired->len; i++) {
        VirtIOVSockConn *conn = g_ptr_array_index(expired, i);

        qemu_log_mask(LOG_GUEST_ERROR,
                      "virtio-vsock: no listener on guest port %u, giving up\n",
                      conn->guest_port);
        virtio_vsock_conn_close(conn, true);
    }

    if (next) {
        timer_mod(s->accept_timer, next);
    }
}

static bool virtio_vsock_listen(VirtIOVSock *s, Error **errp)
{
    g_auto(GStrv) ports = NULL;
    size_t i;

    if (!s->forward_listen || !*s->forward_listen) {
        return true;
    }

    ports = g_strsplit(s->forward_listen, "+", -1);
    s->nlisteners = g_strv_length(ports);
    s->listeners = g_new0(VirtIOVSockListener *, s->nlisteners);

    for (i = 0; i < s->nlisteners; i++) {
        g_autoptr(SocketAddress) addr = NULL;
        VirtIOVSockListener *l;
        uint64_t port;

        if (qemu_strtou64(ports[i], NULL, 10, &port) < 0 ||
            port == 0 || port > UINT32_MAX) {
            error_setg(errp, "virtio-vsock: invalid forward-listen port '%s'",
                       ports[i]);
            return false;
        }

        l = g_new0(VirtIOVSockListener, 1);
        l->vsock = s;
        l->port = port;
        l->listener = qio_net_listener_new();
        s->listeners[i] = l;

        qio_net_listener_set_name(l->listener, "virtio-vsock-listen");

        addr = virtio_vsock_host_addr(s, l->port, true);
        if (qio_net_listener_open_sync(l->listener, addr, 1, errp) < 0) {
            return false;
        }

        qio_net_listener_set_client_func(l->listener, virtio_vsock_accept,
                                         l, NULL);
    }

    return true;
}

static void virtio_vsock_unlisten(VirtIOVSock *s)
{
    size_t i;

    for (i = 0; i < s->nlisteners; i++) {
        VirtIOVSockListener *l = s->listeners[i];

        if (!l) {
            continue;
        }
        if (l->listener) {
            qio_net_listener_disconnect(l->listener);
            object_unref(OBJECT(l->listener));
        }
        g_free(l);
    }
    g_free(s->listeners);
    s->listeners = NULL;
    s->nlisteners = 0;
}

/* ------------------------------------------------------------------ */
/* Device model                                                        */
/* ------------------------------------------------------------------ */

static void virtio_vsock_drop_pending(VirtIOVSock *s)
{
    VirtIOVSockPkt *pkt, *tmp;

    QTAILQ_FOREACH_SAFE(pkt, &s->rx_pending, next, tmp) {
        QTAILQ_REMOVE(&s->rx_pending, pkt, next);
        virtio_vsock_pkt_free(pkt);
    }
}

static void virtio_vsock_stop(VirtIOVSock *s)
{
    if (!s->started) {
        return;
    }
    s->started = false;

    timer_del(s->accept_timer);
    virtio_vsock_unlisten(s);
    g_hash_table_remove_all(s->conns);
    virtio_vsock_drop_pending(s);
}

static int virtio_vsock_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIOVSock *s = VIRTIO_VSOCK(vdev);
    bool should_start = virtio_device_should_start(vdev, status);
    Error *err = NULL;

    if (should_start == s->started) {
        return 0;
    }

    if (!should_start) {
        virtio_vsock_stop(s);
        return 0;
    }

    s->started = true;
    if (!virtio_vsock_listen(s, &err)) {
        error_report_err(err);
        virtio_vsock_stop(s);
        return 0;
    }

    return 0;
}

static void virtio_vsock_reset(VirtIODevice *vdev)
{
    VirtIOVSock *s = VIRTIO_VSOCK(vdev);

    virtio_vsock_stop(s);
}

static void virtio_vsock_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOVSock *s = VIRTIO_VSOCK(vdev);
    struct virtio_vsock_config vsockcfg = {};

    virtio_stq_p(vdev, &vsockcfg.guest_cid, s->guest_cid);
    memcpy(config, &vsockcfg, sizeof(vsockcfg));
}

static uint64_t virtio_vsock_get_features(VirtIODevice *vdev,
                                          uint64_t features, Error **errp)
{
    /* SOCK_SEQPACKET is not implemented; STREAM only. */
    return features;
}

static void virtio_vsock_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOVSock *s = VIRTIO_VSOCK(dev);

    /* Refuse to use reserved CID numbers */
    if (s->guest_cid <= 2) {
        error_setg(errp, "guest-cid property must be greater than 2");
        return;
    }
    if (s->guest_cid > UINT32_MAX) {
        error_setg(errp, "guest-cid property must be a 32-bit number");
        return;
    }

    if (!s->path == !s->forward_cid) {
        error_setg(errp, "exactly one of 'path' (host AF_UNIX socket) and "
                         "'forward-cid' (host AF_VSOCK) must be set");
        return;
    }
    s->hybrid = s->path != NULL;

    virtio_init(vdev, VIRTIO_ID_VSOCK, sizeof(struct virtio_vsock_config));

    s->recv_vq = virtio_add_queue(vdev, VIRTIO_VSOCK_QUEUE_SIZE,
                                  virtio_vsock_handle_rx);
    s->trans_vq = virtio_add_queue(vdev, VIRTIO_VSOCK_QUEUE_SIZE,
                                   virtio_vsock_handle_tx);
    s->event_vq = virtio_add_queue(vdev, VIRTIO_VSOCK_QUEUE_SIZE,
                                   virtio_vsock_handle_event);

    s->conns = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                     g_free, virtio_vsock_conn_free);
    QTAILQ_INIT(&s->rx_pending);
    s->accept_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                   virtio_vsock_accept_expire, s);
    s->next_host_port = VIRTIO_VSOCK_EPHEMERAL_FIRST;
}

static void virtio_vsock_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOVSock *s = VIRTIO_VSOCK(dev);

    virtio_vsock_stop(s);
    timer_free(s->accept_timer);
    s->accept_timer = NULL;
    g_hash_table_unref(s->conns);
    s->conns = NULL;

    virtio_delete_queue(s->recv_vq);
    virtio_delete_queue(s->trans_vq);
    virtio_delete_queue(s->event_vq);
    virtio_cleanup(vdev);
}

static const VMStateDescription virtio_vsock_vmstate = {
    .name = "virtio-vsock",
    .unmigratable = 1,
};

static const Property virtio_vsock_properties[] = {
    DEFINE_PROP_UINT64("guest-cid", VirtIOVSock, guest_cid, 0),
    DEFINE_PROP_STRING("path", VirtIOVSock, path),
    DEFINE_PROP_UINT32("forward-cid", VirtIOVSock, forward_cid, 0),
    DEFINE_PROP_STRING("forward-listen", VirtIOVSock, forward_listen),
};

static void virtio_vsock_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_vsock_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->vmsd = &virtio_vsock_vmstate;

    vdc->realize = virtio_vsock_device_realize;
    vdc->unrealize = virtio_vsock_device_unrealize;
    vdc->get_features = virtio_vsock_get_features;
    vdc->get_config = virtio_vsock_get_config;
    vdc->set_status = virtio_vsock_set_status;
    vdc->reset = virtio_vsock_reset;
}

static const TypeInfo virtio_vsock_info = {
    .name = TYPE_VIRTIO_VSOCK,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOVSock),
    .class_init = virtio_vsock_class_init,
};

static void virtio_vsock_register_types(void)
{
    type_register_static(&virtio_vsock_info);
}

type_init(virtio_vsock_register_types)
