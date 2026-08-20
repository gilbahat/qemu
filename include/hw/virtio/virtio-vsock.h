/*
 * In-QEMU virtio-vsock device
 *
 * Copyright 2026 Gil Bahat
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#ifndef QEMU_VIRTIO_VSOCK_H
#define QEMU_VIRTIO_VSOCK_H

#include "standard-headers/linux/virtio_vsock.h"
#include "hw/virtio/virtio.h"
#include "io/channel-socket.h"
#include "io/net-listener.h"
#include "qapi/qapi-types-sockets.h"
#include "qom/object.h"

#define TYPE_VIRTIO_VSOCK "virtio-vsock-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOVSock, VIRTIO_VSOCK)

#define VIRTIO_VSOCK_QUEUE_SIZE 128

/*
 * Our receive window, advertised to the guest as buf_alloc.  It bounds both the
 * guest-to-host data we may have buffered for a blocked host socket and, via
 * the guest's own buf_alloc, the host-to-guest data we may have queued for the
 * rx virtqueue -- so the credit protocol is what keeps both directions from
 * growing without limit.
 */
#define VIRTIO_VSOCK_BUF_ALLOC (64 * 1024)

/* Largest payload we will put in a single packet handed to the guest. */
#define VIRTIO_VSOCK_MAX_PKT_BUF_SIZE (64 * 1024)

/* Host-side CID as seen by the guest.  VMADDR_CID_HOST. */
#define VIRTIO_VSOCK_HOST_CID 2

/*
 * How long an inbound connection may sit unanswered.  A guest with no listener
 * on the forwarded port drops the REQUEST rather than refusing it, so without a
 * deadline the connection and its host socket would live until device reset.
 */
#define VIRTIO_VSOCK_ACCEPT_TIMEOUT_MS 30000

/*
 * Ceiling on live connections.  Anyone who can reach the forwarded socket can
 * open these, and each one costs a host fd.
 */
#define VIRTIO_VSOCK_MAX_CONNS 1024

typedef enum {
    /* The host connect() is still in flight. */
    VIRTIO_VSOCK_CONN_OPENING,
    /*
     * Guest sent OP_REQUEST and we are waiting for the host end to come up:
     * in hybrid mode that means waiting for the "OK <port>" reply.
     */
    VIRTIO_VSOCK_CONN_CONNECTING,
    /* Host connected inbound; we sent OP_REQUEST, awaiting the guest reply. */
    VIRTIO_VSOCK_CONN_ACCEPTING,
    VIRTIO_VSOCK_CONN_ESTABLISHED,
} VirtIOVSockConnState;

typedef struct VirtIOVSockConn VirtIOVSockConn;

/* A packet queued for delivery to the guest through the rx virtqueue. */
typedef struct VirtIOVSockPkt {
    struct virtio_vsock_hdr hdr;    /* host byte order; converted on delivery */
    uint8_t *data;                  /* NULL for control packets */
    uint32_t len;
    uint32_t off;                   /* payload bytes already delivered */
    QTAILQ_ENTRY(VirtIOVSockPkt) next;
} VirtIOVSockPkt;

/* One host-side listener, bound to the guest port it forwards to. */
typedef struct VirtIOVSockListener {
    VirtIOVSock *vsock;
    uint32_t port;
    QIONetListener *listener;
} VirtIOVSockListener;

struct VirtIOVSockConn {
    VirtIOVSock *vsock;

    /* Ports as the guest sees them: guest_port is the guest end. */
    uint32_t guest_port;
    uint32_t host_port;

    /*
     * The CID the guest used for the host end.  Learned from the packet that
     * opened the connection rather than assumed, because a guest matches a
     * reply on the whole address: answer from a different CID than it dialled
     * and it will not recognise the connection it just opened.
     */
    uint64_t host_cid;

    QIOChannelSocket *sioc;
    guint read_watch;
    guint write_watch;

    VirtIOVSockConnState state;

    /* Host -> guest credit: peer_buf_alloc - (tx_cnt - peer_fwd_cnt). */
    uint32_t tx_cnt;
    uint32_t peer_buf_alloc;
    uint32_t peer_fwd_cnt;

    /* Guest -> host credit.  We advertise VIRTIO_VSOCK_BUF_ALLOC. */
    uint32_t fwd_cnt;
    uint32_t last_fwd_cnt;          /* fwd_cnt at our last credit update */

    /* Guest payload not yet accepted by the host socket. */
    GByteArray *tx_buf;

    /* Handshake reply accumulator, hybrid mode only. */
    GString *reply;

    bool guest_shutdown;            /* guest will send no more data */
    bool host_eof;                  /* host socket reached EOF */

    /* When an unanswered inbound connection gives up.  0 once established. */
    int64_t deadline;
};

struct VirtIOVSock {
    VirtIODevice parent_obj;

    VirtQueue *recv_vq;
    VirtQueue *trans_vq;
    VirtQueue *event_vq;

    /* Properties. */
    uint64_t guest_cid;
    char *path;                     /* hybrid AF_UNIX backend */
    uint32_t forward_cid;           /* AF_VSOCK backend */
    char *forward_listen;           /* '+'-separated host->guest ports */

    bool hybrid;                    /* path set: Firecracker hybrid protocol */
    bool started;

    GHashTable *conns;              /* key (guest_port << 32 | host_port) */
    QTAILQ_HEAD(, VirtIOVSockPkt) rx_pending;

    /* Reaps inbound connections the guest never answered. */
    QEMUTimer *accept_timer;

    /* Listeners for host-initiated connections, one per forwarded port. */
    struct VirtIOVSockListener **listeners;
    size_t nlisteners;

    /*
     * Ephemeral allocator for the host end of an inbound call. The guest end
     * of such a call is the forwarded listening port, never one of these.
     */
    uint32_t next_host_port;
};

#endif /* QEMU_VIRTIO_VSOCK_H */
