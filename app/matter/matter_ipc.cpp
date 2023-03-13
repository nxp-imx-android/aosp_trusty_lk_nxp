/*
 * Copyright 2023 The Android Open Source Project
 *
 * Copyright 2023 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <trusty_ipc.h>
#include <trusty_log.h>
#include <stdlib.h>
#include <string.h>
#include <lk/err_ptr.h>
#include <lk/macros.h>
#include <sys/mman.h>
#include <uapi/err.h>
#include <assert.h>

#include <matter_ipc.h>
#include <matter_defs.h>
#include <matter_messages.h>
#include <trusty_matter.h>

#define TLOG_TAG "matter"

using namespace matter;

static int wait_to_send(handle_t session, struct ipc_msg* msg) {
    int rc;
    struct uevent ev = UEVENT_INITIAL_VALUE(ev);

    rc = wait(session, &ev, INFINITE_TIME);
    if (rc < 0) {
        TLOGE("failed to wait for outgoing queue to free up\n");
        return rc;
    }

    if (ev.event & IPC_HANDLE_POLL_SEND_UNBLOCKED) {
        return send_msg(session, msg);
    }

    if (ev.event & IPC_HANDLE_POLL_MSG) {
        return ERR_BUSY;
    }

    if (ev.event & IPC_HANDLE_POLL_HUP) {
        return ERR_CHANNEL_CLOSED;
    }

    return rc;
}

static long send_response(handle_t chan,
                          uint32_t cmd,
                          uint8_t* out_buf,
                          uint32_t out_buf_size) {
    struct matter_message matter_msg;
    matter_msg.cmd = cmd | MATTER_RESP_BIT;
    struct iovec iov[2] = {{&matter_msg, sizeof(matter_msg)}, {nullptr, 0}};
    ipc_msg_t msg = {2, iov, 0, NULL};
    uint32_t msg_size;
    uint32_t bytes_remaining = out_buf_size;
    uint32_t bytes_sent = 0;
    uint32_t max_msg_size = MATTER_MAX_MSG_SIZE - 64;

    do {
        msg_size = MIN(max_msg_size, bytes_remaining);
        if (msg_size == bytes_remaining) {
            matter_msg.cmd = matter_msg.cmd | MATTER_STOP_BIT;
        }
        iov[1] = {out_buf + bytes_sent, msg_size};

        long rc = send_msg(chan, &msg);
        if (rc == ERR_NOT_ENOUGH_BUFFER) {
            rc = wait_to_send(chan, &msg);
        }

        // fatal error
        if (rc < 0) {
            TLOGE("failed (%ld) to send_msg for chan (%d)", rc, chan);
            return rc;
        }
        bytes_remaining -= msg_size;
        bytes_sent += msg_size;
    } while (bytes_remaining);

    return NO_ERROR;
}

static long send_error_response(handle_t chan,
                                uint32_t cmd,
                                matter_error_t err) {
    return send_response(chan, cmd, reinterpret_cast<uint8_t*>(&err),
                         sizeof(err));
}

/*
 * deseralize_request and serialize_request are used by the different
 * overloads of the do_dispatch template to handle the new API signatures
 * that matter is migrating to.
 */
template <typename Request>
static long deserialize_request(struct matter_message* msg,
                                uint32_t payload_size,
                                Request& req) {
    const uint8_t* payload = msg->payload;
    if (!req.Deserialize(&payload, msg->payload + payload_size))
        return ERR_NOT_VALID;

    return NO_ERROR;
}

template <typename Response>
static long serialize_response(Response& rsp,
                               matter::UniquePtr<uint8_t[]>* out,
                               uint32_t* out_size) {
    *out_size = rsp.SerializedSize();

    out->reset(new (std::nothrow) uint8_t[*out_size]);
    if (out->get() == NULL) {
        *out_size = 0;
        return ERR_NO_MEMORY;
    }

    rsp.Serialize(out->get(), out->get() + *out_size);

    return NO_ERROR;
}

TrustyMatter* device;

template <typename Matter, typename Request, typename Response>
static long do_dispatch(void (Matter::*operation)(const Request&, Response*),
                        struct matter_message* msg,
                        uint32_t payload_size,
                        matter::UniquePtr<uint8_t[]>* out,
                        uint32_t* out_size) {
    long err;
    Request req;

    err = deserialize_request(msg, payload_size, req);
    if (err != NO_ERROR)
        return err;

    Response rsp;
    (device->*operation)(req, &rsp);
    TLOGD("do_dispatch #1 err: %d\n", rsp.error);

    err = serialize_response(rsp, out, out_size);
    TLOGD("do_dispatch #1: serialized response, %d bytes\n", *out_size);
    if (err != NO_ERROR) {
        TLOGE("Error serializing response: %ld", err);
    }

    return err;
}

template <typename Matter, typename Request, typename Response>
static long do_dispatch(Response (Matter::*operation)(const Request&),
                        struct matter_message* msg,
                        uint32_t payload_size,
                        matter::UniquePtr<uint8_t[]>* out,
                        uint32_t* out_size) {
    long err;
    Request req;

    err = deserialize_request(msg, payload_size, req);
    if (err != NO_ERROR)
        return err;

    Response rsp = ((device->*operation)(req));
    TLOGD("do_dispatch #2 err: %d\n", rsp.error);

    err = serialize_response(rsp, out, out_size);
    TLOGD("do_dispatch #2: serialized response, %d bytes\n", *out_size);
    if (err != NO_ERROR) {
        TLOGE("Error serializing response: %d", err);
    }

    return err;
}

template <typename Matter, typename Response>
static long do_dispatch(Response (Matter::*operation)(),
                        struct matter_message* msg,
                        uint32_t payload_size,
                        matter::UniquePtr<uint8_t[]>* out,
                        uint32_t* out_size) {
    long err;
    Response rsp = ((device->*operation)());
    TLOGD("do_dispatch #3 err: %d\n", rsp.error);

    err = serialize_response(rsp, out, out_size);
    TLOGD("do_dispatch #3: serialized response, %d bytes\n", *out_size);
    if (err != NO_ERROR) {
        TLOGE("Error serializing response: %d", err);
    }

    return err;
}
static long message_dispatch(matter_message* msg,
                             uint32_t payload_size,
                             matter::UniquePtr<uint8_t[]>* out,
                             uint32_t* out_size) {
    switch (static_cast<matter_command>(msg->cmd)) {
    case MATTER_IMPORT_DAC:
        TLOGD("Dispatching MATTER_IMPORT_DAC, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ImportDACCert, msg, payload_size,
                           out, out_size);
    case MATTER_IMPORT_PAI:
        TLOGD("Dispatching MATTER_IMPORT_PAI, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ImportPAICert, msg, payload_size,
                           out, out_size);
    case MATTER_IMPORT_CD:
        TLOGD("Dispatching MATTER_IMPORT_CD, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ImportCDCert, msg, payload_size,
                           out, out_size);
    case MATTER_IMPORT_DAC_PRIKEY:
        TLOGD("Dispatching MATTER_IMPORT_DAC_PRIKEY, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ImportDACPriKey, msg, payload_size,
                           out, out_size);
    case MATTER_EXPORT_DAC:
        TLOGD("Dispatching MATTER_EXPORT_DAC, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ExportDACCert, msg, payload_size,
                           out, out_size);
    case MATTER_EXPORT_PAI:
        TLOGD("Dispatching MATTER_EXPORT_PAI, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ExportPAICert, msg, payload_size,
                           out, out_size);
    case MATTER_EXPORT_CD:
        TLOGD("Dispatching MATTER_EXPORT_CD, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::ExportCDCert, msg, payload_size,
                           out, out_size);
    case MATTER_SIGN_WITH_DAC_KEY:
        TLOGD("Dispatching MATTER_SIGN_WITH_DA_KEY, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::SignWithDACKey, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_INITIALIZE:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_INITIALIZE, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairInitialize, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_SERIALIZE:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_SERIALIZE, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairSerialize, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_DESERIALIZE:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_DESERIALIZE, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairDeserialize, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_DESTORY:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_DESTORY, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairDestory, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_ECSIGNMSG:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_ECSIGNMSG, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairECSignMsg, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_NEWCSR:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_NEWCSR, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairNewCSR, msg, payload_size,
                           out, out_size);
    case MATTER_P256_KEYPAIR_ECDH_DERIVE_SECRET:
        TLOGD("Dispatching MATTER_P256_KEYPAIR_ECDH_DERIVE_SECRET, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::P256KeypairECDH_Derive_secret, msg, payload_size,
                           out, out_size);
    case MATTER_HAS_OP_KEYPAIR_FOR_FABRIC:
        TLOGD("Dispatching MATTER_HAS_OP_KEYPAIR_FOR_FABRIC, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::HasOpKeypairForFabric, msg, payload_size,
                           out, out_size);
    case MATTER_COMMIT_OP_KEYPAIR_FOR_FABRIC:
        TLOGD("Dispatching MATTER_COMMIT_OP_KEYPAIR_FOR_FABRIC, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::CommitOpKeypairForFabric, msg, payload_size,
                           out, out_size);
    case MATTER_REMOVE_OP_KEYPAIR_FOR_FABRIC:
        TLOGD("Dispatching MATTER_REMOVE_OP_KEYPAIR_FOR_FABRIC, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::RemoveOpKeypairForFabric, msg, payload_size,
                           out, out_size);
    case MATTER_SIGN_WITH_STORED_OPKEY:
        TLOGD("Dispatching MATTER_SIGN_WITH_STORED_OPKEY, size: %d", payload_size);
        return do_dispatch(&TrustyMatter::SignWithStoredOpKey, msg, payload_size,
                           out, out_size);
    }

    TLOGE("Cannot dispatch unknown command %d", msg->cmd);
    return ERR_NOT_IMPLEMENTED;
}

static int matter_on_message(const struct tipc_port* port,
                                handle_t chan,
                                void* _ctx) {
    /* get message info */
    ipc_msg_info_t msg_inf;
    int rc = get_msg(chan, &msg_inf);
    if (rc == ERR_NO_MSG)
        return NO_ERROR; /* no new messages */

    // fatal error
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to get_msg for chan (%d), closing connection\n", rc,
              chan);
        return rc;
    }

    // allocate msg_buf, with one extra byte for null-terminator
    matter::UniquePtr<uint8_t[]> msg_buf(new (std::nothrow)
                                                    uint8_t[msg_inf.len + 1]);
    if (msg_buf.get() == nullptr) {
        return ERR_NO_MEMORY;
    }
    msg_buf[msg_inf.len] = 0;

    /* read msg content */
    struct iovec iov = {msg_buf.get(), msg_inf.len};
    ipc_msg_t msg = {1, &iov, 0, NULL};

    rc = read_msg(chan, msg_inf.id, 0, &msg);

    // retire the message (note msg_inf.id becomes invalid after put_msg)
    put_msg(chan, msg_inf.id);

    // fatal error
    if (rc < 0) {
        TLOGE("failed to read msg (%d)\n", rc);
        return rc;
    }
    TLOGD("Read %d-byte message\n", rc);

    if (((unsigned long)rc) < sizeof(matter_message)) {
        TLOGE("invalid message of size (%d)\n", rc);
        return ERR_NOT_VALID;
    }

    matter::UniquePtr<uint8_t[]> out_buf;
    uint32_t out_buf_size = 0;
    matter_message* in_msg =
            reinterpret_cast<matter_message*>(msg_buf.get());

    rc = message_dispatch( in_msg, msg_inf.len - sizeof(*in_msg), &out_buf,
                       &out_buf_size);
    if (rc < 0) {
        TLOGE("error handling message (%d)\n", rc);
        return send_error_response(chan, in_msg->cmd, MATTER_ERROR_UNKNOWN_ERROR);
    }

    TLOGD("Sending %d-byte response\n", out_buf_size);
    return send_response(chan, in_msg->cmd, out_buf.get(), out_buf_size);
}

static struct tipc_srv_ops ops = {
    .on_message = matter_on_message,
};

static struct tipc_port_acl acl = {
    .flags = IPC_PORT_ALLOW_NS_CONNECT,
};

static struct tipc_port port = {
    .name = MATTER_PORT_NAME,
    .msg_max_size = MATTER_MAX_MSG_SIZE,
    .msg_queue_len = 1,
    .acl = &acl,
};

int main(void) {
    int rc = 0;
    struct tipc_hset *hset;
    TLOGE("matter init.\n");

    device = new (std::nothrow) TrustyMatter();
    if (device->OPKeyInitialize()) {
        TLOGE("failed to initialize OPKeyPair!\n");
        return ERR_GENERIC;
    }

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("failed to create hset\n");
        return PTR_ERR(hset);
    }

    rc =  tipc_add_service(hset, &port, 1, 5, &ops);
    if (rc != NO_ERROR) {
        TLOGE("failed to add secureime service:%d\n", rc);
        return rc;
    }

    return tipc_run_event_loop(hset);
}
