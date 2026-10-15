#include "transfer_engine.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"

typedef struct r101_memory_info {
    uint64_t address;
    uint64_t length;
    uint32_t rkey;
} r101_memory_info;

typedef struct r101_local_buffer_metadata {
    uint32_t id;
    struct ibv_mr *mr;
    r101_memory_info exported;
    UT_hash_handle hh; /* makes this structure hashable */
} r101_local_buffer_metadata;

typedef struct r101_peer_info {
    uint16_t lid;
    uint32_t qpn;
    uint32_t psn;
    union ibv_gid gid;
} r101_peer_info;

typedef struct r101_local_peer_metadata {
    uint32_t id;
    struct ibv_qp *qp;
    r101_peer_info exported;
    UT_hash_handle hh; /* makes this structure hashable */
} r101_local_peer_metadata;

/* Define struct r101_engine here to hold device resources, peers, MRs and tasks. */
typedef struct r101_engine {
    uint32_t port;
    uint32_t gid_index;
    enum ibv_mtu active_mtu;
    uint16_t lid;
    struct ibv_context *context;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    r101_local_buffer_metadata *lbms;
    uint32_t lbm_count;
    uint32_t lbm_max_id;
    r101_local_peer_metadata *pms;
    uint32_t pm_count;
    uint32_t pm_max_id;
} r101_engine;

static int valid_array(const void *data, uint64_t count, size_t size, size_t alignment) {
    return data && count > 0 && count <= (uint64_t)PTRDIFF_MAX / size &&
           (uintptr_t)data % alignment == 0;
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

    e->lbm_count = 0;
    e->lbm_max_id = 0;
    e->pm_max_id = 0;

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

    *engine = e;
    return R101_OK;
}

r101_result r101_destroy_engine(r101_engine *engine) {
    if (!engine)
        return R101_INVALID;

    r101_local_peer_metadata *pm, *tmp1;
    HASH_ITER(hh, engine->pms, pm, tmp1) {
        ibv_destroy_qp(pm->qp);
        HASH_DEL(engine->pms, pm);
        free(pm);
    }

    r101_local_buffer_metadata *lbm, *tmp2;
    HASH_ITER(hh, engine->lbms, lbm, tmp2) {
        ibv_dereg_mr(lbm->mr);
        HASH_DEL(engine->lbms, lbm);
        free(lbm);
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

    r101_local_buffer_metadata *lbm = calloc(1, sizeof(*lbm));
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

    uint64_t id = ++engine->lbm_max_id;
    lbm->id = id;
    HASH_ADD_INT(engine->lbms, id, lbm);

    *memory = id;
    engine->lbm_count++;
    *metadata = &lbm->exported;
    *metadata_size = sizeof(r101_memory_info);

    return R101_OK;
}

r101_result r101_deregister_local_memory(r101_engine *engine, r101_local_memory_handle memory) {
    if (!engine || !memory)
        return R101_INVALID;
    /* Deregister local memory without freeing the application's buffer. Return BUSY while
     * accepted tasks use it. */

    uint64_t id = memory;
    r101_local_buffer_metadata *lbm;
    HASH_FIND_INT(engine->lbms, &id, lbm);
    if (lbm) {
        ibv_dereg_mr(lbm->mr);
        HASH_DEL(engine->lbms, lbm);
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
    if (!engine || !peer || !valid_array(metadata, metadata_size, 1, 1))
        return R101_INVALID;
    /* Import a connected peer's memory registration and return a local handle.
     * Reuse identical live imports; reject conflicting overlapping regions. */
    return R101_UNIMPLEMENTED;
}

r101_result r101_remove_remote_memory(r101_engine *engine,
                                      r101_remote_memory_handle remote_memory) {
    if (!engine || !remote_memory)
        return R101_INVALID;
    /* Remove the imported descriptor unless an accepted task still uses it. */
    return R101_UNIMPLEMENTED;
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

    r101_local_peer_metadata *pm = calloc(1, sizeof(*pm));
    if (!pm) {
        return R101_NO_MEMORY;
    }

    struct ibv_qp_init_attr qp_init;
    memset(&qp_init, 0, sizeof(qp_init));
    qp_init.send_cq = engine->cq;
    qp_init.recv_cq = engine->cq;
    qp_init.qp_type = IBV_QPT_RC;
    qp_init.cap.max_send_wr = 16;
    qp_init.cap.max_recv_wr = 16;
    qp_init.cap.max_send_sge = 16;
    qp_init.cap.max_recv_sge = 16;

    pm->qp = ibv_create_qp(engine->pd, &qp_init);
    if (!pm->qp) {
        free(pm);
        return R101_IO_ERROR;
    }

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

    uint64_t id = ++engine->pm_max_id;
    pm->id = id;
    HASH_ADD_INT(engine->pms, id, pm);

    *peer = id;
    engine->pm_count++;
    *metadata = &pm->exported;
    *metadata_size = sizeof(r101_peer_info);

    return R101_OK;
}

static enum ibv_mtu choose_mtu(enum ibv_mtu active_mtu) {
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
    if (!engine || !peer || !valid_array(metadata, metadata_size, 1, 1))
        return R101_INVALID;
    /* Complete the local side of a connection using the remote peer's metadata.
     * Copy retained fields and move the QP to RTR/RTS. */

    r101_peer_info *remote = (r101_peer_info *)metadata;

    uint64_t id = peer;
    r101_local_peer_metadata *lpm;
    HASH_FIND_INT(engine->pms, &id, lpm);
    if (!lpm) {
        return R101_INVALID;
    }

    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = choose_mtu(engine->active_mtu);
    attr.dest_qp_num = remote->qpn;
    attr.rq_psn = remote->psn;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
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
    if (ibv_modify_qp(lpm->qp, &attr, flags) != 0)
        return R101_IO_ERROR;

    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = lpm->exported.psn;
    attr.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN |
            IBV_QP_MAX_QP_RD_ATOMIC;
    if (ibv_modify_qp(lpm->qp, &attr, flags) != 0)
        return R101_IO_ERROR;

    return R101_OK;
}

r101_result r101_destroy_peer(r101_engine *engine, r101_peer_handle peer) {
    if (!engine || !peer)
        return R101_INVALID;
    /* Destroy this peer and its imports after stopping its work and handling completions. */
    return R101_UNIMPLEMENTED;
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
    for (uint64_t i = 0; i < count; ++i) {
        const r101_request *request = &requests[i];
        if (request->flags != 0 && request->flags != R101_INLINE)
            return R101_INVALID;
        if (request->flags == R101_INLINE && request->opcode != R101_WRITE &&
            request->opcode != R101_SEND && request->opcode != R101_WRITE_IMM)
            return R101_INVALID;
        switch (request->opcode) {
        case R101_WRITE:
        case R101_READ:
        case R101_SEND:
        case R101_RECV:
        case R101_WRITE_IMM:
        case R101_COMPARE_SWAP:
        case R101_FETCH_ADD:
            break;
        default:
            return R101_INVALID;
        }
    }
    /* Submit requests as a new batch for background execution and return its nonzero handle.
     * Copy the descriptors and accept the whole batch or none; buffers remain application-owned. */
    return R101_UNIMPLEMENTED;
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
    return R101_UNIMPLEMENTED;
}

r101_result r101_free_batch(r101_engine *engine, r101_batch_handle batch) {
    if (!engine || !batch)
        return R101_INVALID;
    /* Free terminal task records; return BUSY while any task remains pending. */
    return R101_UNIMPLEMENTED;
}
