#include "transfer_engine.h"
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uthash.h"

#define R101_SLICE_SIZE (64u * 1024u)
#define R101_SGES_PER_WR 16u
#define R101_QP_SEND_WRS 16u
#define R101_QP_RECV_WRS 16u
#define R101_MAX_CHAIN_WRS R101_QP_SEND_WRS

typedef struct r101_memory_exchange {
    uint64_t address;
    uint64_t length;
    uint32_t rkey;
} r101_memory_exchange;

typedef struct r101_local_buffer {
    uint32_t id;
    struct ibv_mr *mr;
    r101_memory_exchange exported;
    UT_hash_handle hh; /* makes this structure hashable */
} r101_local_buffer;

typedef struct r101_peer_exchange {
    uint16_t lid;
    uint32_t qpn;
    uint32_t psn;
    union ibv_gid gid;
} r101_peer_exchange;

typedef struct r101_remote_memory {
    uint32_t id;
    uint64_t address;
    uint64_t length;
    uint32_t rkey;
    UT_hash_handle hh; /* makes this structure hashable */
} r101_remote_memory;

typedef struct recv_entry {
    uint32_t batch_id;
    uint32_t index;
    uint64_t address;
    uint64_t length;
    struct recv_entry *next;
} recv_entry;

typedef struct r101_peer {
    uint32_t id;
    struct ibv_qp *qp;
    r101_peer_exchange exported;
    int connected;
    uint32_t send_capacity;
    uint32_t inflight;
    uint32_t recv_capacity;
    uint32_t recv_posted;
    recv_entry *recv_pending;
    recv_entry *recv_pending_tail;
    recv_entry *recv_active;
    recv_entry *recv_active_tail;
    r101_remote_memory *remote_mems; /* imported remote memories for this peer */
    UT_hash_handle hh;               /* makes this structure hashable */
} r101_peer;

typedef struct batch_result {
    uint32_t id;
    uint32_t count;
    r101_transfer_status *status;
    uint64_t *remaining;
    uint8_t *failed;
    r101_peer_handle *peers;
    UT_hash_handle hh; /* makes this structure hashable */
} batch_result;

typedef struct chain_wr {
    uint32_t index;
    uint32_t sges;
} chain_wr;

typedef struct posted_chain {
    uint32_t id;
    uint32_t batch_id;
    r101_peer_handle peer;
    uint32_t wr_count;
    chain_wr wrs[R101_MAX_CHAIN_WRS];
    UT_hash_handle hh; /* makes this structure hashable */
} posted_chain;

typedef struct pending_batch {
    batch_result *batch;
    r101_request *requests;
    uint32_t count;
    uint32_t index;
    uint64_t next_slice;
    int positioned;
    struct pending_batch *next;
} pending_batch;

/* Define struct r101_engine here to hold device resources, peers, MRs and tasks. */
typedef struct r101_engine {
    uint32_t port;
    uint32_t gid_index;
    enum ibv_mtu active_mtu;
    uint16_t lid;

    struct ibv_context *context;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_send_wr *chain_wrs;
    struct ibv_sge *chain_sges;

    r101_local_buffer *lbs;
    uint32_t buffer_count;
    uint32_t buffer_max_id;

    r101_peer *peers;
    uint32_t peer_count;
    uint32_t peer_max_id;

    uint32_t remote_mem_max_id;

    batch_result *batch_results;
    uint32_t batch_max_id;

    posted_chain *posted_chains;
    uint32_t chain_max_id;

    pending_batch *pending_head;
    pending_batch *pending_tail;

    pthread_t worker;
    pthread_mutex_t lock;
    int stop;
} r101_engine;

static int valid_array(const void *data, uint64_t count, size_t size, size_t alignment) {
    return data && count > 0 && count <= (uint64_t)PTRDIFF_MAX / size &&
           (uintptr_t)data % alignment == 0;
}

static int range_contains(uint64_t base, uint64_t size, uint64_t address, uint64_t length) {
    if (address < base)
        return 0;
    uint64_t offset = address - base;
    return offset <= size && length <= size - offset;
}

static r101_peer *find_peer(r101_engine *engine, uint64_t handle) {
    uint32_t id = (uint32_t)handle;
    r101_peer *peer;
    HASH_FIND_INT(engine->peers, &id, peer);
    return peer;
}

static r101_remote_memory *find_remote_memory(r101_peer *peer, uint64_t address, uint64_t length) {
    r101_remote_memory *rm, *tmp;
    HASH_ITER(hh, peer->remote_mems, rm, tmp) {
        if (range_contains(rm->address, rm->length, address, length))
            return rm;
    }
    return NULL;
}

static r101_local_buffer *
find_local_buffer(r101_engine *engine, uint64_t address, uint64_t length) {
    r101_local_buffer *lb, *tmp;
    HASH_ITER(hh, engine->lbs, lb, tmp) {
        if (range_contains(lb->exported.address, lb->exported.length, address, length))
            return lb;
    }
    return NULL;
}

static r101_result
validate_submission(r101_engine *engine, const r101_request *requests, uint64_t count) {
    for (uint64_t i = 0; i < count; ++i) {
        const r101_request *request = &requests[i];
        if (request->flags != 0 && request->flags != R101_INLINE)
            return R101_INVALID;
        if (request->flags == R101_INLINE && request->opcode != R101_WRITE &&
            request->opcode != R101_SEND && request->opcode != R101_WRITE_IMM)
            return R101_INVALID;
        if (request->opcode != R101_WRITE && request->opcode != R101_SEND &&
            request->opcode != R101_RECV && request->opcode != R101_WRITE_IMM) {
            switch (request->opcode) {
            case R101_READ:
            case R101_COMPARE_SWAP:
            case R101_FETCH_ADD:
                return R101_UNSUPPORTED;
            default:
                return R101_INVALID;
            }
        }
        r101_peer *peer = find_peer(engine, request->peer);
        if (!peer)
            return R101_INVALID;
        if (request->opcode != R101_RECV && !peer->connected)
            return R101_INVALID_STATE;
        if (request->length == 0)
            continue;
        int local_required = !(request->flags & R101_INLINE);
        if (local_required && !find_local_buffer(engine,
                                                 (uint64_t)(uintptr_t)request->local_address,
                                                 request->length))
            return R101_INVALID;
        if (request->opcode == R101_WRITE || request->opcode == R101_WRITE_IMM) {
            uint64_t remote = request->opcode == R101_WRITE
                                  ? request->args.rma.remote_address
                                  : request->args.write_imm.remote_address;
            if (!find_remote_memory(peer, remote, request->length))
                return R101_INVALID;
        }
    }
    return R101_OK;
}

static uint64_t request_slices_count(const r101_request *request) {
    switch (request->opcode) {
    case R101_WRITE:
        return request->length == 0 ? 0 : (request->length + R101_SLICE_SIZE - 1) / R101_SLICE_SIZE;
    case R101_WRITE_IMM:
        return request->length == 0 ? 1 : (request->length + R101_SLICE_SIZE - 1) / R101_SLICE_SIZE;
    case R101_SEND:
    case R101_RECV:
        return 1;
    default:
        return 0;
    }
}

static void complete_receive(r101_engine *engine, const struct ibv_wc *wc) {
    uint32_t batch_id = (uint32_t)(wc->wr_id >> 32);
    uint32_t index = (uint32_t)(wc->wr_id & 0xffffffffu);
    batch_result *bs;
    HASH_FIND_INT(engine->batch_results, &batch_id, bs);
    if (!bs || index >= bs->count || bs->remaining[index] == 0)
        return;
    r101_peer *peer = find_peer(engine, bs->peers[index]);
    if (peer) {
        recv_entry *prev = NULL;
        recv_entry *entry = peer->recv_active;
        while (entry && (entry->batch_id != batch_id || entry->index != index)) {
            prev = entry;
            entry = entry->next;
        }
        if (entry) {
            if (prev)
                prev->next = entry->next;
            else
                peer->recv_active = entry->next;
            if (peer->recv_active_tail == entry)
                peer->recv_active_tail = prev;
            free(entry);
        }
        if (peer->recv_posted > 0)
            --peer->recv_posted;
    }
    bs->remaining[index] = 0;
    if (wc->status != IBV_WC_SUCCESS) {
        bs->failed[index] = 1;
        bs->status[index].state = R101_FAILED;
        bs->status[index].error = R101_IO_ERROR;
        return;
    }
    r101_receive_result *receive = &bs->status[index].receive;
    if (wc->opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
        receive->kind = R101_RECV_WRITE_IMM;
        receive->immediate = ntohl(wc->imm_data);
        receive->length = 0;
    } else {
        receive->kind = R101_RECV_MESSAGE;
        receive->immediate = 0;
        receive->length = wc->byte_len;
    }
    bs->status[index].state = R101_COMPLETED;
    bs->status[index].error = R101_OK;
}

static void record_completion(r101_engine *engine, const struct ibv_wc *wc) {
    if (wc->opcode & IBV_WC_RECV) {
        complete_receive(engine, wc);
        return;
    }
    uint32_t chain_id = (uint32_t)(wc->wr_id >> 32);
    posted_chain *chain;
    HASH_FIND_INT(engine->posted_chains, &chain_id, chain);
    if (!chain)
        return;
    r101_peer *peer = find_peer(engine, chain->peer);
    if (peer)
        peer->inflight = peer->inflight >= chain->wr_count ? peer->inflight - chain->wr_count : 0;
    batch_result *bs;
    HASH_FIND_INT(engine->batch_results, &chain->batch_id, bs);
    if (bs) {
        int failed = wc->status != IBV_WC_SUCCESS;
        for (uint32_t w = 0; w < chain->wr_count; ++w) {
            uint32_t index = chain->wrs[w].index;
            uint32_t sges = chain->wrs[w].sges;
            if (index >= bs->count || bs->remaining[index] == 0)
                continue;
            if (failed)
                bs->failed[index] = 1;
            bs->remaining[index] = bs->remaining[index] > sges ? bs->remaining[index] - sges : 0;
            if (bs->remaining[index] == 0) {
                bs->status[index].state = bs->failed[index] ? R101_FAILED : R101_COMPLETED;
                bs->status[index].error = bs->failed[index] ? R101_IO_ERROR : R101_OK;
            }
        }
    }
    HASH_DEL(engine->posted_chains, chain);
    free(chain);
}

static void fill_slice_sges(struct ibv_sge *group,
                            uint64_t first_slice,
                            uint64_t count,
                            uint64_t length,
                            uint64_t local,
                            uint32_t lkey) {
    for (uint64_t k = 0; k < count; ++k) {
        uint64_t offset = (first_slice + k) * R101_SLICE_SIZE;
        uint64_t chunk = length - offset;
        if (chunk > R101_SLICE_SIZE)
            chunk = R101_SLICE_SIZE;
        group[k].addr = local + offset;
        group[k].length = (uint32_t)chunk;
        group[k].lkey = lkey;
    }
}

static uint32_t append_send_wr(struct ibv_send_wr *wrs,
                               struct ibv_sge *sges,
                               uint32_t built,
                               uint32_t index,
                               const r101_request *request,
                               uint32_t lkey,
                               posted_chain *chain) {
    struct ibv_send_wr *wr = &wrs[built];
    memset(wr, 0, sizeof(*wr));
    wr->opcode = IBV_WR_SEND;
    if (request->length > 0) {
        struct ibv_sge *sge = &sges[(size_t)built * R101_SGES_PER_WR];
        sge->addr = (uint64_t)(uintptr_t)request->local_address;
        sge->length = (uint32_t)request->length;
        sge->lkey = lkey;
        wr->sg_list = sge;
        wr->num_sge = 1;
    }
    if (request->flags & R101_INLINE)
        wr->send_flags |= IBV_SEND_INLINE;
    chain->wrs[built].index = index;
    chain->wrs[built].sges = 1;
    return built + 1;
}

static uint32_t append_write_imm_wr(struct ibv_send_wr *wrs,
                                    uint32_t built,
                                    uint32_t index,
                                    const r101_request *request,
                                    uint32_t rkey,
                                    posted_chain *chain) {
    struct ibv_send_wr *wr = &wrs[built];
    memset(wr, 0, sizeof(*wr));
    wr->opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
    wr->imm_data = htonl(request->args.write_imm.immediate);
    wr->wr.rdma.remote_addr = request->args.write_imm.remote_address;
    wr->wr.rdma.rkey = rkey;
    chain->wrs[built].index = index;
    chain->wrs[built].sges = 1;
    return built + 1;
}

static void fill_slice_wr(struct ibv_send_wr *wr,
                          struct ibv_sge *group,
                          const r101_request *request,
                          uint64_t first_slice,
                          uint64_t count,
                          uint64_t total,
                          uint64_t remote,
                          uint32_t rkey,
                          int with_imm) {
    memset(wr, 0, sizeof(*wr));
    wr->opcode = IBV_WR_RDMA_WRITE;
    wr->sg_list = group;
    wr->num_sge = (int)count;
    wr->wr.rdma.remote_addr = remote + first_slice * R101_SLICE_SIZE;
    wr->wr.rdma.rkey = rkey;
    if (with_imm && first_slice + count == total) {
        wr->opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
        wr->imm_data = htonl(request->args.write_imm.immediate);
    }
    if (request->flags & R101_INLINE)
        wr->send_flags |= IBV_SEND_INLINE;
}

static uint32_t append_rma_wrs(struct ibv_send_wr *wrs,
                               struct ibv_sge *sges,
                               uint32_t built,
                               uint32_t budget,
                               uint32_t index,
                               uint64_t *next_slice,
                               const r101_request *request,
                               uint32_t lkey,
                               uint32_t rkey,
                               posted_chain *chain) {
    int with_imm = request->opcode == R101_WRITE_IMM;
    if (request->length == 0) {
        if (!with_imm || *next_slice > 0)
            return built;
        *next_slice = 1;
        return append_write_imm_wr(wrs, built, index, request, rkey, chain);
    }

    uint64_t total = (request->length + R101_SLICE_SIZE - 1) / R101_SLICE_SIZE;
    uint64_t remote =
        with_imm ? request->args.write_imm.remote_address : request->args.rma.remote_address;
    uint64_t local = (uint64_t)(uintptr_t)request->local_address;
    while (*next_slice < total && built < budget) {
        uint64_t count = total - *next_slice;
        if (count > R101_SGES_PER_WR)
            count = R101_SGES_PER_WR;
        struct ibv_sge *group = &sges[(size_t)built * R101_SGES_PER_WR];
        fill_slice_sges(group, *next_slice, count, request->length, local, lkey);
        fill_slice_wr(
            &wrs[built], group, request, *next_slice, count, total, remote, rkey, with_imm);
        chain->wrs[built].index = index;
        chain->wrs[built].sges = (uint32_t)count;
        ++built;
        *next_slice += count;
    }
    return built;
}

static uint32_t ensure_slices(struct ibv_send_wr *wrs,
                              struct ibv_sge *sges,
                              uint32_t built,
                              uint32_t budget,
                              uint32_t index,
                              uint64_t *next_slice,
                              const r101_request *request,
                              uint32_t lkey,
                              uint32_t rkey,
                              posted_chain *chain) {
    if (built >= budget)
        return built;
    if (request->opcode == R101_SEND) {
        if (*next_slice > 0)
            return built;
        built = append_send_wr(wrs, sges, built, index, request, lkey, chain);
        *next_slice = 1;
        return built;
    }
    return append_rma_wrs(wrs, sges, built, budget, index, next_slice, request, lkey, rkey, chain);
}

static void fail_task(batch_result *bs, uint32_t index, r101_result error) {
    if (bs->remaining[index] == 0)
        return;
    bs->remaining[index] = 0;
    bs->failed[index] = 1;
    bs->status[index].state = R101_FAILED;
    bs->status[index].error = error;
}

static void free_recv_list(recv_entry *head) {
    while (head) {
        recv_entry *next = head->next;
        free(head);
        head = next;
    }
}

static void cancel_recv_list(r101_engine *engine, recv_entry *head, r101_result error) {
    while (head) {
        recv_entry *next = head->next;
        batch_result *bs;
        uint32_t batch_id = head->batch_id;
        HASH_FIND_INT(engine->batch_results, &batch_id, bs);
        if (bs && head->index < bs->count)
            fail_task(bs, head->index, error);
        free(head);
        head = next;
    }
}

static void enqueue_receive(r101_engine *engine, pending_batch *pending, uint32_t index) {
    const r101_request *request = &pending->requests[index];
    r101_peer *peer = find_peer(engine, request->peer);
    if (!peer) {
        fail_task(pending->batch, index, R101_CANCELED);
        return;
    }
    recv_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        fail_task(pending->batch, index, R101_NO_MEMORY);
        return;
    }
    entry->batch_id = pending->batch->id;
    entry->index = index;
    entry->address = (uint64_t)(uintptr_t)request->local_address;
    entry->length = request->length;
    if (peer->recv_pending_tail)
        peer->recv_pending_tail->next = entry;
    else
        peer->recv_pending = entry;
    peer->recv_pending_tail = entry;
}

static void post_receives(r101_engine *engine) {
    r101_peer *peer, *tmp;
    HASH_ITER(hh, engine->peers, peer, tmp) {
        while (peer->recv_pending && peer->recv_posted < peer->recv_capacity) {
            recv_entry *entry = peer->recv_pending;
            peer->recv_pending = entry->next;
            if (!peer->recv_pending)
                peer->recv_pending_tail = NULL;

            struct ibv_sge sge;
            struct ibv_recv_wr wr;
            memset(&sge, 0, sizeof(sge));
            memset(&wr, 0, sizeof(wr));
            wr.wr_id = ((uint64_t)entry->batch_id << 32) | entry->index;
            int failed = 0;
            if (entry->length > 0) {
                r101_local_buffer *lb = find_local_buffer(engine, entry->address, entry->length);
                if (!lb) {
                    failed = 1;
                } else {
                    sge.addr = entry->address;
                    sge.length = (uint32_t)entry->length;
                    sge.lkey = lb->mr->lkey;
                    wr.sg_list = &sge;
                    wr.num_sge = 1;
                }
            }
            if (!failed) {
                struct ibv_recv_wr *bad = NULL;
                if (ibv_post_recv(peer->qp, &wr, &bad) != 0)
                    failed = 1;
            }
            if (failed) {
                batch_result *bs;
                uint32_t batch_id = entry->batch_id;
                HASH_FIND_INT(engine->batch_results, &batch_id, bs);
                if (bs && entry->index < bs->count)
                    fail_task(bs, entry->index, R101_INVALID_STATE);
                free(entry);
                continue;
            }
            ++peer->recv_posted;
            entry->next = NULL;
            if (peer->recv_active_tail)
                peer->recv_active_tail->next = entry;
            else
                peer->recv_active = entry;
            peer->recv_active_tail = entry;
        }
    }
}

static void pop_pending(r101_engine *engine, pending_batch *pending) {
    engine->pending_head = pending->next;
    if (!engine->pending_head)
        engine->pending_tail = NULL;
    free(pending->requests);
    free(pending);
}

static void fail_pending(r101_engine *engine, pending_batch *pending, r101_result error) {
    batch_result *bs = pending->batch;
    for (uint32_t i = 0; i < bs->count; ++i)
        fail_task(bs, i, error);
    pop_pending(engine, pending);
}

static int position_pending(r101_engine *engine, pending_batch *pending) {
    if (pending->positioned)
        return pending->index < pending->count;
    while (pending->index < pending->count) {
        const r101_request *request = &pending->requests[pending->index];
        if (request->opcode == R101_RECV) {
            enqueue_receive(engine, pending, pending->index);
            post_receives(engine);
            ++pending->index;
            pending->next_slice = 0;
            continue;
        }
        if (pending->next_slice < request_slices_count(request))
            break;
        ++pending->index;
        pending->next_slice = 0;
    }
    pending->positioned = 1;
    return pending->index < pending->count;
}

static int lookup_request(r101_engine *engine,
                          r101_peer *peer,
                          const r101_request *request,
                          uint32_t *lkey,
                          uint32_t *rkey) {
    *lkey = 0;
    *rkey = 0;
    int inline_source = (request->flags & R101_INLINE) != 0;
    if (request->length > 0 && !inline_source) {
        r101_local_buffer *lb =
            find_local_buffer(engine, (uint64_t)(uintptr_t)request->local_address, request->length);
        if (!lb)
            return 0;
        *lkey = lb->mr->lkey;
    }
    if (request->length > 0 &&
        (request->opcode == R101_WRITE || request->opcode == R101_WRITE_IMM)) {
        uint64_t remote = request->opcode == R101_WRITE ? request->args.rma.remote_address
                                                        : request->args.write_imm.remote_address;
        r101_remote_memory *rm = find_remote_memory(peer, remote, request->length);
        if (!rm)
            return 0;
        *rkey = rm->rkey;
    }
    return 1;
}

static uint32_t build_chain(r101_engine *engine,
                            pending_batch *pending,
                            posted_chain *chain,
                            uint32_t *index,
                            uint64_t *next_slice,
                            uint32_t capacity,
                            r101_peer_handle first_peer,
                            r101_peer *peer) {
    uint32_t built = 0;
    while (built < capacity && *index < pending->count) {
        const r101_request *request = &pending->requests[*index];
        if (request->opcode == R101_RECV) {
            enqueue_receive(engine, pending, *index);
            post_receives(engine);
            ++*index;
            *next_slice = 0;
            continue;
        }
        uint64_t total = request_slices_count(request);
        if (*next_slice >= total) {
            ++*index;
            *next_slice = 0;
            continue;
        }
        if (request->peer != first_peer)
            break;

        uint32_t lkey = 0;
        uint32_t rkey = 0;
        if (!lookup_request(engine, peer, request, &lkey, &rkey)) {
            pending->batch->remaining[*index] -= total - *next_slice;
            fail_task(pending->batch, *index, R101_INVALID_STATE);
            ++*index;
            *next_slice = 0;
            continue;
        }

        built = ensure_slices(engine->chain_wrs,
                              engine->chain_sges,
                              built,
                              capacity,
                              *index,
                              next_slice,
                              request,
                              lkey,
                              rkey,
                              chain);
        if (*next_slice >= total) {
            ++*index;
            *next_slice = 0;
        }
    }
    return built;
}

static int post_chain(r101_engine *engine,
                      pending_batch *pending,
                      posted_chain *chain,
                      r101_peer *peer,
                      r101_peer_handle first_peer,
                      uint32_t built) {
    chain->id = ++engine->chain_max_id;
    for (uint32_t w = 0; w < built; ++w) {
        engine->chain_wrs[w].wr_id = ((uint64_t)chain->id << 32) | w;
        engine->chain_wrs[w].next = w + 1 < built ? &engine->chain_wrs[w + 1] : NULL;
    }
    engine->chain_wrs[built - 1].send_flags |= IBV_SEND_SIGNALED;

    struct ibv_send_wr *bad = NULL;
    if (ibv_post_send(peer->qp, &engine->chain_wrs[0], &bad) != 0) {
        free(chain);
        fail_pending(engine, pending, R101_IO_ERROR);
        return 0;
    }

    chain->batch_id = pending->batch->id;
    chain->peer = first_peer;
    chain->wr_count = built;
    HASH_ADD_INT(engine->posted_chains, id, chain);
    peer->inflight += built;
    return 1;
}

static void post_pending(r101_engine *engine) {
    while (engine->pending_head) { // poll request from the list
        pending_batch *pending = engine->pending_head;

        if (!position_pending(engine, pending)) {
            pop_pending(engine, pending);
            continue;
        }

        uint32_t first = pending->index;
        r101_peer_handle first_peer = pending->requests[first].peer;
        r101_peer *peer = find_peer(engine, first_peer);
        if (!peer || !peer->connected) {
            fail_task(pending->batch, first, R101_INVALID_STATE);
            ++pending->index;
            pending->next_slice = 0;
            pending->positioned = 0;
            continue;
        }

        uint64_t capacity =
            peer->send_capacity > peer->inflight ? peer->send_capacity - peer->inflight : 0;
        if (capacity == 0)
            return;
        if (capacity > R101_MAX_CHAIN_WRS)
            capacity = R101_MAX_CHAIN_WRS;

        posted_chain *chain = calloc(1, sizeof(*chain));
        if (!chain) {
            fail_pending(engine, pending, R101_NO_MEMORY);
            continue;
        }

        uint32_t index = pending->index;
        uint64_t next_slice = pending->next_slice;
        uint32_t built = build_chain(
            engine, pending, chain, &index, &next_slice, (uint32_t)capacity, first_peer, peer);
        if (built == 0) {
            free(chain);
            pending->index = index;
            pending->next_slice = next_slice;
            pending->positioned = 0;
            continue;
        }
        if (!post_chain(engine, pending, chain, peer, first_peer, built))
            continue;

        pending->index = index;
        pending->next_slice = next_slice;
        pending->positioned = 0;
    }
}
static void *poll_worker(void *arg) {
    r101_engine *engine = arg;
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000};
    for (;;) {
        pthread_mutex_lock(&engine->lock);
        if (engine->stop) {
            pthread_mutex_unlock(&engine->lock);
            break;
        }
        post_receives(engine);
        post_pending(engine);
        struct ibv_wc wc[16];
        int n = ibv_poll_cq(engine->cq, 16, wc);
        for (int i = 0; i < n; ++i)
            record_completion(engine, &wc[i]);
        pthread_mutex_unlock(&engine->lock);
        if (n <= 0)
            nanosleep(&delay, NULL);
    }
    return NULL;
}

r101_result open_device(const char *name, struct ibv_context **ctx_out) {
    int num_devices = 0;
    struct ibv_device **devices = ibv_get_device_list(&num_devices);
    if (!devices)
        return R101_INVALID;
    if (num_devices == 0)
        return R101_UNSUPPORTED;

    struct ibv_device *chosen = NULL;
    for (int i = 0; i < num_devices; ++i) {
        const char *dev_name = ibv_get_device_name(devices[i]);
        if (!name || strcmp(name, dev_name) == 0) {
            chosen = devices[i];
            break;
        }
    }
    if (!chosen)
        return R101_INVALID;

    struct ibv_context *ctx = ibv_open_device(chosen);
    ibv_free_device_list(devices);
    if (!ctx)
        return R101_IO_ERROR;
    *ctx_out = ctx;
    return R101_OK;
}

r101_result r101_create_engine(const r101_config *config, r101_engine **engine) {
    if (!engine)
        return R101_INVALID;
    *engine = NULL;
    if (!config || config->abi_version != R101_ABI_VERSION)
        return R101_INVALID;
    /* Create an engine with device resources and a background worker.
     * Copy retained config strings and release partial resources on failure. */

    r101_engine *e = calloc(1, sizeof(*e));
    if (!e)
        return R101_NO_MEMORY;

    e->buffer_count = 0;
    e->buffer_max_id = 0;
    e->peer_max_id = 0;
    e->batch_max_id = 0;

    int rc = open_device(config->device, &(e->context));
    if (rc != R101_OK) {
        free(e);
        return R101_INVALID;
    }

    e->pd = ibv_alloc_pd(e->context);
    if (!e->pd) {
        ibv_close_device(e->context);
        free(e);
        return R101_INVALID;
    }

    e->cq = ibv_create_cq(e->context, 1024, NULL, NULL, 0);
    if (!e->cq) {
        ibv_dealloc_pd(e->pd);
        ibv_close_device(e->context);
        free(e);
        return R101_INVALID;
    }

    e->port = config->port;
    e->gid_index = config->gid_index;

    struct ibv_port_attr port_attr;
    if (ibv_query_port(e->context, e->port, &port_attr) != 0) {
        ibv_destroy_cq(e->cq);
        ibv_dealloc_pd(e->pd);
        ibv_close_device(e->context);
        free(e);
        return R101_IO_ERROR;
    }
    e->active_mtu = port_attr.active_mtu;
    e->lid = port_attr.lid;

    e->chain_wrs = calloc(R101_MAX_CHAIN_WRS, sizeof(*e->chain_wrs));
    e->chain_sges = calloc((size_t)R101_MAX_CHAIN_WRS * R101_SGES_PER_WR, sizeof(*e->chain_sges));
    if (!e->chain_wrs || !e->chain_sges) {
        free(e->chain_wrs);
        free(e->chain_sges);
        ibv_destroy_cq(e->cq);
        ibv_dealloc_pd(e->pd);
        ibv_close_device(e->context);
        free(e);
        return R101_NO_MEMORY;
    }

    if (pthread_mutex_init(&e->lock, NULL) != 0) {
        free(e->chain_wrs);
        free(e->chain_sges);
        ibv_destroy_cq(e->cq);
        ibv_dealloc_pd(e->pd);
        ibv_close_device(e->context);
        free(e);
        return R101_NO_MEMORY;
    }
    if (pthread_create(&e->worker, NULL, poll_worker, e) != 0) {
        pthread_mutex_destroy(&e->lock);
        free(e->chain_wrs);
        free(e->chain_sges);
        ibv_destroy_cq(e->cq);
        ibv_dealloc_pd(e->pd);
        ibv_close_device(e->context);
        free(e);
        return R101_NO_MEMORY;
    }

    *engine = e;
    return R101_OK;
}

r101_result r101_destroy_engine(r101_engine *engine) {
    if (!engine)
        return R101_INVALID;

    pthread_mutex_lock(&engine->lock);
    engine->stop = 1;
    pthread_mutex_unlock(&engine->lock);
    pthread_join(engine->worker, NULL);
    pthread_mutex_destroy(&engine->lock);

    r101_peer *pm, *tmp1;
    HASH_ITER(hh, engine->peers, pm, tmp1) {
        ibv_destroy_qp(pm->qp);
        free_recv_list(pm->recv_pending);
        free_recv_list(pm->recv_active);
        r101_remote_memory *rm, *tmp3;
        HASH_ITER(hh, pm->remote_mems, rm, tmp3) {
            HASH_DEL(pm->remote_mems, rm);
            free(rm);
        }
        HASH_DEL(engine->peers, pm);
        free(pm);
    }

    r101_local_buffer *lbm, *tmp2;
    HASH_ITER(hh, engine->lbs, lbm, tmp2) {
        ibv_dereg_mr(lbm->mr);
        HASH_DEL(engine->lbs, lbm);
        free(lbm);
    }

    pending_batch *pending = engine->pending_head;
    while (pending) {
        pending_batch *next = pending->next;
        free(pending->requests);
        free(pending);
        pending = next;
    }
    engine->pending_head = NULL;
    engine->pending_tail = NULL;

    batch_result *bs, *tmp4;
    HASH_ITER(hh, engine->batch_results, bs, tmp4) {
        HASH_DEL(engine->batch_results, bs);
        free(bs->status);
        free(bs->remaining);
        free(bs->failed);
        free(bs->peers);
        free(bs);
    }

    posted_chain *chain, *tmp5;
    HASH_ITER(hh, engine->posted_chains, chain, tmp5) {
        HASH_DEL(engine->posted_chains, chain);
        free(chain);
    }

    if (engine->cq != NULL) {
        ibv_destroy_cq(engine->cq);
        engine->cq = NULL;
    }

    if (engine->pd != NULL) {
        ibv_dealloc_pd(engine->pd);
        engine->pd = NULL;
    }

    if (engine->context) {
        ibv_close_device(engine->context);
        engine->context = NULL;
    }

    free(engine->chain_wrs);
    free(engine->chain_sges);
    free(engine);
    return R101_OK;
}

r101_result r101_register_local_memory(r101_engine *engine,
                                       void *address,
                                       uint64_t length,
                                       r101_access_flags access,
                                       r101_local_memory_handle *memory,
                                       const void **metadata,
                                       uint64_t *metadata_size) {
    if (!memory || !metadata || !metadata_size)
        return R101_INVALID;
    *memory = 0;
    *metadata = NULL;
    *metadata_size = 0;
    const r101_access_flags known =
        R101_LOCAL_WRITE | R101_REMOTE_WRITE | R101_REMOTE_READ | R101_REMOTE_ATOMIC;
    if (!engine || !valid_array(address, length, 1, 1) || (access & ~known))
        return R101_INVALID;
    /* Register application memory and export its handle and stable metadata. */

    r101_local_buffer *lbm = calloc(1, sizeof(*lbm));
    if (!lbm) {
        return R101_NO_MEMORY;
    }
    lbm->mr = ibv_reg_mr(engine->pd, address, length, access);
    if (!lbm->mr) {
        free(lbm);
        return R101_NO_MEMORY;
    }
    lbm->exported.address = (uint64_t)(uintptr_t)address;
    lbm->exported.length = length;
    lbm->exported.rkey = lbm->mr->rkey;

    pthread_mutex_lock(&engine->lock);
    uint64_t id = ++engine->buffer_max_id;
    lbm->id = id;
    HASH_ADD_INT(engine->lbs, id, lbm);
    ++engine->buffer_count;
    pthread_mutex_unlock(&engine->lock);

    *memory = id;
    *metadata = &lbm->exported;
    *metadata_size = sizeof(r101_memory_exchange);

    return R101_OK;
}

r101_result r101_deregister_local_memory(r101_engine *engine, r101_local_memory_handle memory) {
    if (!engine || !memory)
        return R101_INVALID;
    /* Deregister local memory without freeing the application's buffer. Return BUSY while
     * accepted tasks use it. */

    uint64_t id = memory;
    r101_local_buffer *lbm;
    pthread_mutex_lock(&engine->lock);
    HASH_FIND_INT(engine->lbs, &id, lbm);
    if (lbm) {
        HASH_DEL(engine->lbs, lbm);
        --engine->buffer_count;
    }
    pthread_mutex_unlock(&engine->lock);
    if (lbm) {
        ibv_dereg_mr(lbm->mr);
        free(lbm);
    }

    return R101_OK;
}

r101_result r101_import_remote_memory(r101_engine *engine,
                                      r101_peer_handle peer,
                                      const void *metadata,
                                      uint64_t metadata_size,
                                      r101_remote_memory_handle *remote_memory) {
    if (!remote_memory)
        return R101_INVALID;
    *remote_memory = 0;
    if (!engine || !peer || !metadata || metadata_size != sizeof(r101_memory_exchange))
        return R101_INVALID;
    /* Import a connected peer's memory registration and return a local handle.
     * Reuse identical live imports; reject conflicting overlapping regions. */

    r101_memory_exchange *info = (r101_memory_exchange *)metadata;

    uint32_t pid = (uint32_t)peer;
    pthread_mutex_lock(&engine->lock);
    r101_peer *pm;
    HASH_FIND_INT(engine->peers, &pid, pm);
    if (!pm) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID;
    }
    if (!pm->connected) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID_STATE;
    }

    r101_remote_memory *rm, *tmp;
    HASH_ITER(hh, pm->remote_mems, rm, tmp) {
        if (rm->address == info->address && rm->length == info->length && rm->rkey == info->rkey) {
            *remote_memory = rm->id;
            pthread_mutex_unlock(&engine->lock);
            return R101_OK;
        }
        if (rm->address < info->address + info->length &&
            info->address < rm->address + rm->length) {
            pthread_mutex_unlock(&engine->lock);
            return R101_INVALID;
        }
    }

    r101_remote_memory *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        pthread_mutex_unlock(&engine->lock);
        return R101_NO_MEMORY;
    }
    entry->address = info->address;
    entry->length = info->length;
    entry->rkey = info->rkey;
    uint32_t handle = ++engine->remote_mem_max_id;
    entry->id = handle;
    HASH_ADD_INT(pm->remote_mems, id, entry);
    pthread_mutex_unlock(&engine->lock);

    *remote_memory = handle;
    return R101_OK;
}

r101_result r101_remove_remote_memory(r101_engine *engine,
                                      r101_remote_memory_handle remote_memory) {
    if (!engine || !remote_memory)
        return R101_INVALID;
    /* Remove the imported descriptor unless an accepted task still uses it. */

    uint32_t id = (uint32_t)remote_memory;
    pthread_mutex_lock(&engine->lock);
    r101_peer *pm, *tmp;
    HASH_ITER(hh, engine->peers, pm, tmp) {
        r101_remote_memory *rm;
        HASH_FIND_INT(pm->remote_mems, &id, rm);
        if (rm) {
            HASH_DEL(pm->remote_mems, rm);
            free(rm);
            pthread_mutex_unlock(&engine->lock);
            return R101_OK;
        }
    }
    pthread_mutex_unlock(&engine->lock);

    return R101_INVALID;
}

r101_result r101_create_peer(r101_engine *engine,
                             r101_peer_handle *peer,
                             const void **metadata,
                             uint64_t *metadata_size) {
    if (!peer || !metadata || !metadata_size)
        return R101_INVALID;
    *peer = 0;
    *metadata = NULL;
    *metadata_size = 0;
    if (!engine)
        return R101_INVALID;
    /* Create a local peer and export its connection metadata.
     * The RC QP starts in INIT; roll back the creation on failure. */

    r101_peer *pm = calloc(1, sizeof(*pm));
    if (!pm) {
        return R101_NO_MEMORY;
    }

    struct ibv_qp_init_attr qp_init;
    memset(&qp_init, 0, sizeof(qp_init));
    qp_init.send_cq = engine->cq;
    qp_init.recv_cq = engine->cq;
    qp_init.qp_type = IBV_QPT_RC;
    qp_init.cap.max_send_wr = R101_QP_SEND_WRS;
    qp_init.cap.max_recv_wr = R101_QP_RECV_WRS;
    qp_init.cap.max_send_sge = R101_SGES_PER_WR;
    qp_init.cap.max_recv_sge = R101_SGES_PER_WR;
    qp_init.cap.max_inline_data = 256;

    pm->qp = ibv_create_qp(engine->pd, &qp_init);
    if (!pm->qp) {
        free(pm);
        return R101_IO_ERROR;
    }
    pm->send_capacity = qp_init.cap.max_send_wr;
    pm->recv_capacity = qp_init.cap.max_recv_wr;

    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = engine->port;
    attr.qp_access_flags =
        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;

    int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    if (ibv_modify_qp(pm->qp, &attr, flags) != 0) {
        ibv_destroy_qp(pm->qp);
        free(pm);
        return R101_IO_ERROR;
    }

    pm->exported.qpn = pm->qp->qp_num;
    pm->exported.psn = (uint32_t)(rand() & 0xffffff);
    if (ibv_query_gid(engine->context, engine->port, engine->gid_index, &pm->exported.gid) != 0) {
        ibv_destroy_qp(pm->qp);
        free(pm);
        return R101_IO_ERROR;
    }

    pm->exported.lid = engine->lid;

    pthread_mutex_lock(&engine->lock);
    uint64_t id = ++engine->peer_max_id;
    pm->id = id;
    HASH_ADD_INT(engine->peers, id, pm);
    ++engine->peer_count;
    pthread_mutex_unlock(&engine->lock);

    *peer = id;
    *metadata = &pm->exported;
    *metadata_size = sizeof(r101_peer_exchange);

    return R101_OK;
}

static inline enum ibv_mtu choose_mtu(enum ibv_mtu active_mtu) {
    return active_mtu < IBV_MTU_1024 ? active_mtu : IBV_MTU_1024;
}

static int gid_is_zero(union ibv_gid gid) {
    static const union ibv_gid zero;
    return memcmp(&gid, &zero, sizeof(gid)) == 0;
}

r101_result r101_connect_peer(r101_engine *engine,
                              r101_peer_handle peer,
                              const void *metadata,
                              uint64_t metadata_size) {
    if (!engine || !peer || !metadata || metadata_size != sizeof(r101_peer_exchange))
        return R101_INVALID;
    /* Complete the local side of a connection using the remote peer's metadata.
     * Copy retained fields and move the QP to RTR/RTS. */

    const r101_peer_exchange *remote = (const r101_peer_exchange *)metadata;

    uint64_t id = peer;
    pthread_mutex_lock(&engine->lock);
    r101_peer *lpm;
    HASH_FIND_INT(engine->peers, &id, lpm);
    if (!lpm) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID;
    }
    if (lpm->connected) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID_STATE;
    }

    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = choose_mtu(engine->active_mtu);
    attr.dest_qp_num = remote->qpn;
    attr.rq_psn = remote->psn;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 16;
    attr.ah_attr.dlid = remote->lid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = engine->port;
    if (!gid_is_zero(remote->gid)) {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.grh.dgid = remote->gid;
        attr.ah_attr.grh.sgid_index = engine->gid_index;
        attr.ah_attr.grh.hop_limit = 1;
    }

    int flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    if (ibv_modify_qp(lpm->qp, &attr, flags) != 0) {
        pthread_mutex_unlock(&engine->lock);
        return R101_IO_ERROR;
    }

    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = lpm->exported.psn;
    attr.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
            IBV_QP_MAX_QP_RD_ATOMIC;
    if (ibv_modify_qp(lpm->qp, &attr, flags) != 0) {
        pthread_mutex_unlock(&engine->lock);
        return R101_IO_ERROR;
    }

    lpm->connected = 1;
    pthread_mutex_unlock(&engine->lock);

    return R101_OK;
}

r101_result r101_destroy_peer(r101_engine *engine, r101_peer_handle h) {
    if (!engine || !h)
        return R101_INVALID;

    /* Destroy this peer and its imports after stopping its work and handling completions. */
    pthread_mutex_lock(&engine->lock);
    uint64_t id = (uint64_t)h;
    r101_peer *peer;
    HASH_FIND_INT(engine->peers, &id, peer);
    if (!peer) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID;
    }

    cancel_recv_list(engine, peer->recv_pending, R101_CANCELED);
    cancel_recv_list(engine, peer->recv_active, R101_CANCELED);
    peer->recv_pending = peer->recv_pending_tail = NULL;
    peer->recv_active = peer->recv_active_tail = NULL;
    peer->recv_posted = 0;

    for (pending_batch *item = engine->pending_head; item; item = item->next) {
        batch_result *bs = item->batch;
        for (uint32_t i = 0; i < item->count; ++i) {
            if ((uint32_t)item->requests[i].peer == id && bs->remaining[i] > 0)
                fail_task(bs, i, R101_CANCELED);
        }
    }

    if (peer->qp) {
        ibv_destroy_qp(peer->qp);
        peer->qp = NULL;
    }
    r101_remote_memory *rm, *tmp;
    HASH_ITER(hh, peer->remote_mems, rm, tmp) {
        HASH_DEL(peer->remote_mems, rm);
        free(rm);
    }

    HASH_DEL(engine->peers, peer);
    free(peer);
    --engine->peer_count;
    pthread_mutex_unlock(&engine->lock);
    return R101_OK;
}

r101_result r101_submit_transfer(r101_engine *engine,
                                 const r101_request *requests,
                                 uint64_t count,
                                 r101_batch_handle *batch) {
    if (!batch)
        return R101_INVALID;
    *batch = 0;
    if (!engine || !valid_array(requests, count, sizeof(*requests), _Alignof(r101_request)))
        return R101_INVALID;

    r101_result rc = validate_submission(engine, requests, count);
    if (rc != R101_OK)
        return rc;

    /* Submit requests as a new batch for background execution and return its nonzero handle.
     * Copy the descriptors and accept the whole batch or none; buffers remain application-owned. */
    batch_result *bs = calloc(1, sizeof(*bs));
    pending_batch *pending = calloc(1, sizeof(*pending));
    if (!bs || !pending) {
        free(bs);
        free(pending);
        return R101_NO_MEMORY;
    }
    bs->count = (uint32_t)count;
    bs->status = calloc(count, sizeof(*bs->status));
    bs->remaining = calloc(count, sizeof(*bs->remaining));
    bs->failed = calloc(count, sizeof(*bs->failed));
    bs->peers = calloc(count, sizeof(*bs->peers));
    pending->count = (uint32_t)count;
    pending->requests = calloc(count, sizeof(*pending->requests));
    if (!bs->status || !bs->remaining || !bs->failed || !bs->peers || !pending->requests) {
        free(bs->status);
        free(bs->remaining);
        free(bs->failed);
        free(bs->peers);
        free(pending->requests);
        free(bs);
        free(pending);
        return R101_NO_MEMORY;
    }
    memcpy(pending->requests, requests, count * sizeof(*requests));
    pending->batch = bs;
    for (uint64_t i = 0; i < count; ++i) {
        bs->peers[i] = pending->requests[i].peer;
        bs->remaining[i] = request_slices_count(&pending->requests[i]);
        if (bs->remaining[i] == 0)
            bs->status[i].state = R101_COMPLETED;
    }

    pthread_mutex_lock(&engine->lock);
    bs->id = ++engine->batch_max_id;
    HASH_ADD_INT(engine->batch_results, id, bs);
    // add the batch to pending list
    if (engine->pending_tail)
        engine->pending_tail->next = pending;
    else
        engine->pending_head = pending;
    engine->pending_tail = pending;
    pthread_mutex_unlock(&engine->lock);

    *batch = bs->id;
    return R101_OK;
}

r101_result r101_get_transfer_statuses(r101_engine *engine,
                                       r101_batch_handle batch,
                                       r101_transfer_status *statuses,
                                       uint64_t count) {
    if (!engine || !batch ||
        !valid_array(statuses, count, sizeof(*statuses), _Alignof(r101_transfer_status)))
        return R101_INVALID;
    /* Read every task's current status in submission order without advancing transfers.
     * The output count must equal the batch size; failure leaves outputs unchanged. */
    uint32_t id = batch;
    batch_result *bs;
    pthread_mutex_lock(&engine->lock);
    HASH_FIND_INT(engine->batch_results, &id, bs);
    if (!bs || count != bs->count) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID;
    }

    memcpy(statuses, bs->status, count * sizeof(r101_transfer_status));
    pthread_mutex_unlock(&engine->lock);

    return R101_OK;
}

r101_result r101_free_batch(r101_engine *engine, r101_batch_handle batch) {
    if (!engine || !batch)
        return R101_INVALID;
    /* Free terminal task records; return BUSY while any task remains pending. */

    uint32_t id = batch;
    batch_result *bs;
    pthread_mutex_lock(&engine->lock);
    HASH_FIND_INT(engine->batch_results, &id, bs);
    if (!bs) {
        pthread_mutex_unlock(&engine->lock);
        return R101_INVALID;
    }
    for (uint64_t i = 0; i < bs->count; ++i) {
        if (bs->status[i].state == R101_PENDING) {
            pthread_mutex_unlock(&engine->lock);
            return R101_BUSY;
        }
    }

    HASH_DEL(engine->batch_results, bs);
    pthread_mutex_unlock(&engine->lock);
    free(bs->status);
    free(bs->remaining);
    free(bs->failed);
    free(bs->peers);
    free(bs);

    return R101_OK;
}
