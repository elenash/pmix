/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2014-2015 Intel, Inc.  All rights reserved.
 * Copyright (c) 2014      Research Organization for Information Science
 *                         and Technology (RIST). All rights reserved.
 * Copyright (c) 2014      Artem Y. Polyakov <artpol84@gmail.com>.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include <private/autogen/config.h>
#include <pmix/rename.h>
#include <private/types.h>
#include <private/pmix_stdint.h>

#include <pmix.h>

#include "src/include/pmix_globals.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include PMIX_EVENT_HEADER

#include "src/class/pmix_list.h"
#include "src/buffer_ops/buffer_ops.h"
#include "src/util/argv.h"
#include "src/util/error.h"
#include "src/util/output.h"
#include "src/util/progress_threads.h"
#include "src/usock/usock.h"
#include "src/sec/pmix_sec.h"

#include "pmix_client_ops.h"

static void wait_cbfunc(struct pmix_peer_t *pr, pmix_usock_hdr_t *hdr,
                        pmix_buffer_t *buf, void *cbdata);
static void op_cbfunc(int status, void *cbdata);
static void wait_lookup_cbfunc(struct pmix_peer_t *pr, pmix_usock_hdr_t *hdr,
                               pmix_buffer_t *buf, void *cbdata);
static void lookup_cbfunc(int status, pmix_pdata_t pdata[], size_t ndata,
                          void *cbdata);

int PMIx_Publish(pmix_data_range_t scope,
                 pmix_persistence_t persist,
                 const pmix_info_t info[],
                 size_t ninfo)
{
    int rc;
    pmix_cb_t *cb;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: publish called");
    
    if (pmix_client_globals.init_cntr <= 0) {
        return PMIX_ERR_INIT;
    }

    /* if we aren't connected, don't attempt to send */
    if (!pmix_globals.connected) {
        return PMIX_ERR_UNREACH;
    }

    /* create a callback object to let us know when it is done */
    cb = PMIX_NEW(pmix_cb_t);
    cb->active = true;

    if (PMIX_SUCCESS != (rc = PMIx_Publish_nb(scope, persist, info, ninfo, op_cbfunc, cb))) {
        PMIX_RELEASE(cb);
        return rc;
    }

    /* wait for the server to ack our request */
    PMIX_WAIT_FOR_COMPLETION(cb->active);
    rc = cb->status;
    PMIX_RELEASE(cb);
    
    return rc;
}

int PMIx_Publish_nb(pmix_data_range_t scope,
                    pmix_persistence_t persist,
                    const pmix_info_t info[],
                    size_t ninfo,
                    pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    pmix_buffer_t *msg;
    pmix_cmd_t cmd = PMIX_PUBLISHNB_CMD;
    int rc;
    pmix_cb_t *cb;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: publish called");
    
    if (pmix_client_globals.init_cntr <= 0) {
        return PMIX_ERR_INIT;
    }

    /* if we aren't connected, don't attempt to send */
    if (!pmix_globals.connected) {
        return PMIX_ERR_UNREACH;
    }

    /* check for bozo cases */
    if (NULL == info) {
        /* nothing to publish */
        return PMIX_ERR_BAD_PARAM;
    }
    
    /* create the publish cmd */
    msg = PMIX_NEW(pmix_buffer_t);
    /* pack the cmd */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &cmd, 1, PMIX_CMD))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the data range */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &scope, 1, PMIX_DATA_RANGE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the persistence */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &persist, 1, PMIX_PERSIST))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the info keys that were given */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &ninfo, 1, PMIX_SIZE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, info, ninfo, PMIX_INFO))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    
    /* create a callback object as we need to pass it to the
     * recv routine so we know which callback to use when
     * the return message is recvd */
    cb = PMIX_NEW(pmix_cb_t);
    cb->op_cbfunc = cbfunc;
    cb->cbdata = cbdata;
    cb->active = true;

    /* push the message into our event base to send to the server */
    PMIX_ACTIVATE_SEND_RECV(&pmix_client_globals.myserver, msg, wait_cbfunc, cb);

    return PMIX_SUCCESS;
}

int PMIx_Lookup(pmix_data_range_t scope,
                pmix_pdata_t pdata[], size_t ndata)
{
    int rc;
    pmix_cb_t *cb;
    char **keys = NULL;
    size_t i;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: lookup called");

    /* bozo protection */
    if (NULL == pdata) {
        return PMIX_ERR_BAD_PARAM;
    }

    /* transfer the info keys to the keys argv array */
    for (i=0; i < ndata; i++) {
        if ('\0' != pdata[i].key[0]) {
            pmix_argv_append_nosize(&keys, pdata[i].key);
        }
    }
    
    /* create a callback object as we need to pass it to the
     * recv routine so we know which callback to use when
     * the return message is recvd */
    cb = PMIX_NEW(pmix_cb_t);
    cb->cbdata = (void*)pdata;
    cb->nvals = ndata;
    cb->active = true;

    if (PMIX_SUCCESS != (rc = PMIx_Lookup_nb(scope, false, keys, lookup_cbfunc, cb))) {
        PMIX_RELEASE(cb);
        pmix_argv_free(keys);
        return rc;
    }

    /* wait for the server to ack our request */
    PMIX_WAIT_FOR_COMPLETION(cb->active);

    /* the data has been stored in the info array by lookup_cbfunc, so
     * nothing more for us to do */
    rc = cb->status;
    PMIX_RELEASE(cb);
    return rc;
}

int PMIx_Lookup_nb(pmix_data_range_t scope, int wait, char **keys,
                   pmix_lookup_cbfunc_t cbfunc, void *cbdata)
{
    pmix_buffer_t *msg;
    pmix_cmd_t cmd = PMIX_LOOKUPNB_CMD;
    int rc;
    pmix_cb_t *cb;
    size_t nkeys;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: lookup called");
    
    if (pmix_client_globals.init_cntr <= 0) {
        return PMIX_ERR_INIT;
    }

    /* check for bozo cases */
    if (NULL == keys) {
        return PMIX_ERR_BAD_PARAM;
    }
    
    /* create the lookup cmd */
    msg = PMIX_NEW(pmix_buffer_t);
    /* pack the cmd */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &cmd, 1, PMIX_CMD))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the scope */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &scope, 1, PMIX_DATA_RANGE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the wait flag */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &wait, 1, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the keys */
    nkeys = pmix_argv_count(keys);
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &nkeys, 1, PMIX_SIZE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    if (0 < nkeys) {
        if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, keys, nkeys, PMIX_STRING))) {
            PMIX_ERROR_LOG(rc);
            PMIX_RELEASE(msg);
            return rc;
        }
    }
    
    /* create a callback object as we need to pass it to the
     * recv routine so we know which callback to use when
     * the return message is recvd */
    cb = PMIX_NEW(pmix_cb_t);
    cb->lookup_cbfunc = cbfunc;
    cb->cbdata = cbdata;

    /* push the message into our event base to send to the server */
    PMIX_ACTIVATE_SEND_RECV(&pmix_client_globals.myserver, msg, wait_lookup_cbfunc, cb);

    return PMIX_SUCCESS;
}

int PMIx_Unpublish(pmix_data_range_t scope, char **keys)
{
    int rc;
    pmix_cb_t *cb;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: unpublish called");
    
    /* create a callback object as we need to pass it to the
     * recv routine so we know which callback to use when
     * the return message is recvd */
    cb = PMIX_NEW(pmix_cb_t);
    cb->active = true;

    /* push the message into our event base to send to the server */
    if (PMIX_SUCCESS != (rc = PMIx_Unpublish_nb(scope, keys, op_cbfunc, cb))) {
        PMIX_RELEASE(cb);
        return rc;
    }

    /* wait for the server to ack our request */
    PMIX_WAIT_FOR_COMPLETION(cb->active);
    rc = cb->status;
    PMIX_RELEASE(cb);
    
    return rc;
}

int PMIx_Unpublish_nb(pmix_data_range_t scope, char **keys,
                      pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    pmix_buffer_t *msg;
    pmix_cmd_t cmd = PMIX_UNPUBLISHNB_CMD;
    int rc;
    pmix_cb_t *cb;
    size_t i, j;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: unpublish called");
    
    if (pmix_client_globals.init_cntr <= 0) {
        return PMIX_ERR_INIT;
    }

    /* create the unpublish cmd */
    msg = PMIX_NEW(pmix_buffer_t);
    /* pack the cmd */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &cmd, 1, PMIX_CMD))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the scope */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &scope, 1, PMIX_DATA_RANGE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    /* pack the number of keys */
    i = pmix_argv_count(keys);
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &i, 1, PMIX_SIZE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return rc;
    }
    if (0 < i) {
        for (j=0; j < i; j++) {
            if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &keys[j], 1, PMIX_STRING))) {
                PMIX_ERROR_LOG(rc);
                PMIX_RELEASE(msg);
                return rc;
            }
        }
    }

    /* create a callback object */
    cb = PMIX_NEW(pmix_cb_t);
    cb->op_cbfunc = cbfunc;
    cb->cbdata = cbdata;
    cb->active = true;

    /* push the message into our event base to send to the server */
    PMIX_ACTIVATE_SEND_RECV(&pmix_client_globals.myserver, msg, wait_cbfunc, cb);

    return PMIX_SUCCESS;
}

static void wait_cbfunc(struct pmix_peer_t *pr, pmix_usock_hdr_t *hdr,
                        pmix_buffer_t *buf, void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;
    int rc, ret;
    int32_t cnt;

    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix:client recv callback activated with %d bytes",
                        (NULL == buf) ? -1 : (int)buf->bytes_used);

    /* unpack the returned status */
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &ret, &cnt, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        ret = rc;
    }
    if (NULL != cb->op_cbfunc) {
        cb->op_cbfunc(ret, cb->cbdata);
    }
    PMIX_RELEASE(cb);
}

static void op_cbfunc(int status, void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;

    cb->status = status;
    cb->active = false;
}

static void wait_lookup_cbfunc(struct pmix_peer_t *pr, pmix_usock_hdr_t *hdr,
                               pmix_buffer_t *buf, void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;
    int rc, ret;
    int32_t cnt;
    pmix_pdata_t *pdata;
    size_t ndata;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix:client recv callback activated with %d bytes",
                        (NULL == buf) ? -1 : (int)buf->bytes_used);

    if (NULL == cb->lookup_cbfunc) {
        /* nothing we can do with this */
        PMIX_RELEASE(cb);
        return;
    }

    /* set the defaults */
    pdata = NULL;
    ndata = 0;
    
    /* unpack the returned status */
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &ret, &cnt, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        ret = rc;
    }
    if (PMIX_SUCCESS != ret) {
        if (NULL != cb->lookup_cbfunc) {
            cb->lookup_cbfunc(ret, NULL, 0, cb->cbdata);
        }
        PMIX_RELEASE(cb);
        return;
    }
    
    /* unpack the number of returned values */
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &ndata, &cnt, PMIX_SIZE))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(cb);
        return;
    }
    if (0 < ndata) {
        /* create the array storage */
        PMIX_PDATA_CREATE(pdata, ndata);
        cnt = ndata;
        /* unpack the returned values into the pdata array */
        if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, pdata, &cnt, PMIX_PDATA))) {
            PMIX_ERROR_LOG(rc);
            goto cleanup;
        }
    }

    if (NULL != cb->lookup_cbfunc) {
        cb->lookup_cbfunc(rc, pdata, ndata, cb->cbdata);
    }

 cleanup:
    /* cleanup */
    PMIX_PDATA_FREE(pdata, ndata);
    
    PMIX_RELEASE(cb);
}

static void lookup_cbfunc(int status, pmix_pdata_t pdata[], size_t ndata,
                          void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;
    pmix_pdata_t *tgt = (pmix_pdata_t*)cb->cbdata;
    size_t i, j;
    
    /* find the matching key in the provided info array - error if not found */
    for (i=0; i < ndata; i++) {
        for (j=0; j < cb->nvals; j++) {
            if (0 == strcmp(pdata[i].key, tgt[j].key)) {
                /* transfer the publishing proc id */
                (void)strncpy(tgt[j].proc.nspace, pdata[i].proc.nspace, PMIX_MAX_NSLEN);
                tgt[j].proc.rank = pdata[i].proc.rank;
                /* transfer the value to the pmix_info_t */
                pmix_value_xfer(&tgt[j].value, &pdata[i].value);
                break;
            }
        }
    }
    cb->active = false;
}
