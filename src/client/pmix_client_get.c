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
#include "src/util/hash.h"
#include "src/util/output.h"
#include "src/util/progress_threads.h"
#include "src/usock/usock.h"
#include "src/sec/pmix_sec.h"

#include "pmix_client_ops.h"

static pmix_buffer_t* pack_get(const char nspace[], int rank,
                               const char key[], pmix_cmd_t cmd);
static void getnb_cbfunc(struct pmix_peer_t *pr, pmix_usock_hdr_t *hdr,
                         pmix_buffer_t *buf, void *cbdata);
static void getnb_shortcut(int fd, short flags, void *cbdata);
static void value_cbfunc(int status, pmix_value_t *kv, void *cbdata);

int PMIx_Get(const char nspace[], int rank,
             const char key[], pmix_value_t **val)
{
    pmix_cb_t *cb;
    int rc;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: getting value for proc %s:%d key %s",
                        (NULL == nspace) ? "NULL" : nspace, rank,
                        (NULL == key) ? "NULL" : key);

    if (pmix_client_globals.init_cntr <= 0) {
        return PMIX_ERR_INIT;
    }

    /* if we aren't connected, don't attempt to send */
    if (!pmix_globals.connected) {
        return PMIX_ERR_UNREACH;
    }

    /* create a callback object as we need to pass it to the
     * recv routine so we know which callback to use when
     * the return message is recvd */
    cb = PMIX_NEW(pmix_cb_t);
    cb->active = true;

    if (PMIX_SUCCESS != (rc = PMIx_Get_nb(nspace, rank, key, value_cbfunc, cb))) {
        PMIX_RELEASE(cb);
        *val = NULL;
        return rc;
    }
    
    /* wait for the data to return */
    PMIX_WAIT_FOR_COMPLETION(cb->active);
    rc = cb->status;
    *val = cb->value;
    PMIX_RELEASE(cb);

    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix:client get completed");
    return rc;
}

int PMIx_Get_nb(const char *nspace, int rank,
                const char *key,
                pmix_value_cbfunc_t cbfunc, void *cbdata)
{
    pmix_value_t *val;
    pmix_buffer_t *msg;
    pmix_cb_t *cb;
    int rc;
    char *nm;
    pmix_nsrec_t *ns, *nptr;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: get_nb value for proc %s:%d key %s",
                        (NULL == nspace) ? "NULL" : nspace, rank,
                        (NULL == key) ? "NULL" : key);
    
    if (pmix_client_globals.init_cntr <= 0) {
        return PMIX_ERR_INIT;
    }

    /* if we aren't connected, don't attempt to send */
    if (!pmix_globals.connected) {
        return PMIX_ERR_UNREACH;
    }

    /* protect against bozo input */
    if (NULL == key) {
        return PMIX_ERR_BAD_PARAM;
    }
    
    /* if the nspace is NULL, then the caller is referencing
     * our own nspace */
    if (NULL == nspace) {
        nm = pmix_globals.nspace;
    } else {
        nm = (char*)nspace;
    }

    /* find the nspace object */
    nptr = NULL;
    PMIX_LIST_FOREACH(ns, &pmix_client_globals.nspaces, pmix_nsrec_t) {
        if (0 == strcmp(nm, ns->nspace)) {
            nptr = ns;
            break;
        }
    }
    if (NULL == nptr) {
        /* we are asking for info about a new nspace - give us
         * a chance to learn about it from the server. If the
         * server has never heard of it, the server will return
         * an error */
         nptr = PMIX_NEW(pmix_nsrec_t);
         (void)strncpy(nptr->nspace, nm, PMIX_MAX_NSLEN);
         pmix_list_append(&pmix_client_globals.nspaces, &nptr->super);
         /* there is no point in looking for data in this nspace
          * object, so let's just go generate the request */
         goto request;
    }

    /* the requested data could be in the job-data table, so let's
     * just check there first.  */
    PMIX_VALUE_CREATE(val, 1);
    if (PMIX_SUCCESS == (rc = pmix_hash_fetch(&nptr->data, PMIX_RANK_WILDCARD, key, &val))) {
        /* found it - return it via appropriate channel */
        cb = PMIX_NEW(pmix_cb_t);
        (void)strncpy(cb->nspace, nm, PMIX_MAX_NSLEN);
        cb->rank = rank;
        cb->key = strdup(key);
        cb->value_cbfunc = cbfunc;
        cb->cbdata = cbdata;
        /* pack the return data so the unpack routine can get it */
        if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(&cb->data, val, 1, PMIX_VALUE))) {
            PMIX_ERROR_LOG(rc);
        }
        /* cleanup */
        if (NULL != val) {
            PMIX_VALUE_RELEASE(val);
        }
        /* activate the event */
        event_assign(&(cb->ev), pmix_globals.evbase, -1,
                     EV_WRITE, getnb_shortcut, cb);
        event_active(&(cb->ev), EV_WRITE, 1);
        return PMIX_SUCCESS;
    }
    if (PMIX_RANK_WILDCARD == rank) {
        /* can't be anywhere else */
        return PMIX_ERR_NOT_FOUND;
    }

    /* it could still be in the job-data table, only stored under its own
     * rank and not WILDCARD - e.g., this is true of data returned about
     * ourselves during startup */
    if (PMIX_SUCCESS == (rc = pmix_hash_fetch(&nptr->data, rank, key, &val))) {
        /* found it - return it via appropriate channel */
        cb = PMIX_NEW(pmix_cb_t);
        (void)strncpy(cb->nspace, nm, PMIX_MAX_NSLEN);
        cb->rank = rank;
        cb->key = strdup(key);
        cb->value_cbfunc = cbfunc;
        cb->cbdata = cbdata;
        /* pack the return data so the unpack routine can get it */
        if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(&cb->data, val, 1, PMIX_VALUE))) {
            PMIX_ERROR_LOG(rc);
        }
        /* cleanup */
        if (NULL != val) {
            PMIX_VALUE_RELEASE(val);
        }
        /* activate the event */
        event_assign(&(cb->ev), pmix_globals.evbase, -1,
                     EV_WRITE, getnb_shortcut, cb);
        event_active(&(cb->ev), EV_WRITE, 1);
        return PMIX_SUCCESS;
    }

    /* not finding it is not an error - it could be in the
     * modex hash table, so check it */
    if (PMIX_SUCCESS == (rc = sm_data_fetch( nm,  rank, key, &val))) {
//    if (PMIX_SUCCESS == (rc = pmix_hash_fetch(&nptr->modex, rank, key, &val))) {
        pmix_output_verbose(2, pmix_globals.debug_output,
                            "pmix: value retrieved from dstore");
        /* need to push this into the event library to ensure
         * the callback occurs within an event */
        cb = PMIX_NEW(pmix_cb_t);
        (void)strncpy(cb->nspace, nm, PMIX_MAX_NSLEN);
        cb->rank = rank;
        cb->key = strdup(key);
        cb->value_cbfunc = cbfunc;
        cb->cbdata = cbdata;
        /* pack the return data so the unpack routine can get it */
        if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(&cb->data, val, 1, PMIX_VALUE))) {
            PMIX_ERROR_LOG(rc);
        }
        /* cleanup */
        if (NULL != val) {
            PMIX_VALUE_RELEASE(val);
        }
        /* activate the event */
        event_assign(&(cb->ev), pmix_globals.evbase, -1,
                     EV_WRITE, getnb_shortcut, cb);
        event_active(&(cb->ev), EV_WRITE, 1);
        return PMIX_SUCCESS;
    } else if (PMIX_ERR_NOT_FOUND == rc) {
        /* we have the modex data from this proc, but didn't find the key
         * the user requested. At this time, there is no way for the
         * key to eventually be found, so all we can do is return
         * the error */
        return rc;
    }

  request:
    /* if we got here, then we don't have the data for this proc - see if
     * we already have a request in place with the server for data from
     * this nspace:rank. If we do, then no need to ask again as the
     * request will return _all_ data from that proc */
    PMIX_LIST_FOREACH(cb, &pmix_client_globals.pending_requests, pmix_cb_t) {
        if (0 == strncmp(nm, cb->nspace, PMIX_MAX_NSLEN) && cb->rank == rank) {
            /* we do have a pending request, but we still need to track this
             * outstanding request so we can satisfy it once the data is returned */
            cb = PMIX_NEW(pmix_cb_t);
            (void)strncpy(cb->nspace, nm, PMIX_MAX_NSLEN);
            cb->rank = rank;
            cb->key = strdup(key);
            cb->value_cbfunc = cbfunc;
            cb->cbdata = cbdata;
            pmix_list_append(&pmix_client_globals.pending_requests, &cb->super);
            return PMIX_SUCCESS;
        }
    }

    /* we don't have a pending request, so let's create one */
    if (NULL == (msg = pack_get(nm, rank, key, PMIX_GETNB_CMD))) {
        return PMIX_ERROR;
    }
    
    /* create a callback object as we need to pass it to the
     * recv routine so we know which callback to use when
     * the return message is recvd */
    cb = PMIX_NEW(pmix_cb_t);
    (void)strncpy(cb->nspace, nm, PMIX_MAX_NSLEN);
    cb->rank = rank;
    cb->key = strdup(key);
    cb->value_cbfunc = cbfunc;
    cb->cbdata = cbdata;
    pmix_list_append(&pmix_client_globals.pending_requests, &cb->super);
    
    /* push the message into our event base to send to the server */
    PMIX_ACTIVATE_SEND_RECV(&pmix_client_globals.myserver, msg, getnb_cbfunc, cb);

    return PMIX_SUCCESS;
}

static void value_cbfunc(int status, pmix_value_t *kv, void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;

    cb->status = status;
    if (PMIX_SUCCESS == status) {
        pmix_bfrop.copy((void**)&cb->value, kv, PMIX_VALUE);
    }
    cb->active = false;
}

static pmix_buffer_t* pack_get(const char nspace[], int rank,
                               const char key[], pmix_cmd_t cmd)
{
    pmix_buffer_t *msg;
    int rc;
    
    /* nope - see if we can get it */
    msg = PMIX_NEW(pmix_buffer_t);
    /* pack the get cmd */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &cmd, 1, PMIX_CMD))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return NULL;
    }
    /* pack the request information - we'll get the entire blob
     * for this proc, so we don't need to pass the key */
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &nspace, 1, PMIX_STRING))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return NULL;
    }
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(msg, &rank, 1, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        PMIX_RELEASE(msg);
        return NULL;
    }
    return msg;
}

static void getnb_cbfunc(struct pmix_peer_t *pr, pmix_usock_hdr_t *hdr,
                         pmix_buffer_t *buf, void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;
    pmix_cb_t *cb2;
    int rc, ret;
    pmix_value_t *val = NULL;
    int32_t cnt;
    pmix_buffer_t *bptr;
    pmix_kval_t *kp;
    pmix_nsrec_t *ns, *nptr;
    int rank;
    
    pmix_output_verbose(2, pmix_globals.debug_output,
                        "pmix: get_nb callback recvd");

    if (NULL == cb) {
        /* nothing we can do */
        PMIX_ERROR_LOG(PMIX_ERR_BAD_PARAM);
        return;
    }
    // cache the rank
    rank = cb->rank;
    
    /* unpack the status */
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &ret, &cnt, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        return;
    }

    /* look up the nspace object for this proc */
    nptr = NULL;
    PMIX_LIST_FOREACH(ns, &pmix_client_globals.nspaces, pmix_nsrec_t) {
        if (0 == strcmp(cb->nspace, ns->nspace)) {
            nptr = ns;
            break;
        }
    }
    if (NULL == nptr) {
        /* new nspace - setup a record for it */
        nptr = PMIX_NEW(pmix_nsrec_t);
        (void)strncpy(nptr->nspace, cb->nspace, PMIX_MAX_NSLEN);
        pmix_list_append(&pmix_client_globals.nspaces, &nptr->super);
    }

    if (PMIX_SUCCESS != ret) {
        goto done;
    }

    /* we received the entire blob for this process, so
     * unpack and store it in the modex - this could consist
     * of buffers from multiple scopes */
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: look for data in sm for %s:%d key %s", __FILE__, __LINE__, __func__, cb->nspace, cb->rank, cb->key));
    PMIX_VALUE_CREATE(val, 1);
    rc = sm_data_fetch( cb->nspace,  cb->rank, cb->key, &val);
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: data fetch rc %d for %s:%d key %s val->type = %d", __FILE__, __LINE__, __func__, rc, cb->nspace, cb->rank, cb->key, val->type));

    if (PMIX_SUCCESS != rc) {
        PMIX_VALUE_RELEASE(val);
        val = NULL;
    }

    /*kp = PMIX_NEW(pmix_kval_t);
    kp->key = strdup(cb->key);
    rc = pmix_bfrop.copy((void**)&(kp->value), val, PMIX_VALUE);
    if (PMIX_SUCCESS != (rc = pmix_hash_store(&nptr->modex, cb->rank, kp))) {
        PMIX_ERROR_LOG(rc);
    }
    PMIX_RELEASE(kp);*/

#if 0
    /* unpack the nspace */
    char *unpacked_nspace;
    int unpacked_rank;
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &unpacked_nspace, &cnt, PMIX_STRING))) {
        PMIX_ERROR_LOG(rc);
        return;
    }
    /* unpack the rank */
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &unpacked_rank, &cnt, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        return;
    }
    cnt = 1;
    while (PMIX_SUCCESS == (rc = pmix_bfrop.unpack(buf, &bptr, &cnt, PMIX_BUFFER))) {
        cnt = 1;
        kp = PMIX_NEW(pmix_kval_t);
        while (PMIX_SUCCESS == (rc = pmix_bfrop.unpack(bptr, kp, &cnt, PMIX_KVAL))) {
            pmix_output_verbose(2, pmix_globals.debug_output,
                                "pmix: unpacked key %s", kp->key);
            if (PMIX_SUCCESS != (rc = pmix_hash_store(&nptr->modex, cb->rank, kp))) {
                PMIX_ERROR_LOG(rc);
            }
            if (NULL != cb->key && 0 == strcmp(cb->key, kp->key)) {
                pmix_output_verbose(2, pmix_globals.debug_output,
                                    "pmix: found requested value");
                if (PMIX_SUCCESS != (rc = pmix_bfrop.copy((void**)&val, kp->value, PMIX_VALUE))) {
                    PMIX_ERROR_LOG(rc);
                    PMIX_RELEASE(kp);
                    val = NULL;
                    goto done;
                }
            }
            PMIX_RELEASE(kp); // maintain acctg - hash_store does a retain
            cnt = 1;
            kp = PMIX_NEW(pmix_kval_t);
        }
        cnt = 1;
        PMIX_RELEASE(kp);
        PMIX_RELEASE(bptr);  // free's the data region
        if (PMIX_ERR_UNPACK_READ_PAST_END_OF_BUFFER != rc) {
            PMIX_ERROR_LOG(rc);
            break;
        }
    }
    if (PMIX_ERR_UNPACK_READ_PAST_END_OF_BUFFER != rc) {
        PMIX_ERROR_LOG(rc);
    } else {
        rc = PMIX_SUCCESS;
    }
#endif
 done:
    /* if a callback was provided, execute it */
    if (NULL != cb && NULL != cb->value_cbfunc) {
        if (NULL == val) {
            rc = PMIX_ERR_NOT_FOUND;
        }
        cb->value_cbfunc(rc, val, cb->cbdata);
    }
    if (NULL != val) {
        PMIX_VALUE_RELEASE(val);
    }
    /* we obviously processed this one, so remove it from the
     * list of pending requests */
    pmix_list_remove_item(&pmix_client_globals.pending_requests, &cb->super);
    PMIX_RELEASE(cb);

    /* now search any pending requests to see if they can be met */
    PMIX_LIST_FOREACH_SAFE(cb, cb2, &pmix_client_globals.pending_requests, pmix_cb_t) {
        if (0 == strncmp(nptr->nspace, cb->nspace, PMIX_MAX_NSLEN) && cb->rank == rank) {
           /* we have the data - see if we can find the key */
            //val = NULL;
            //rc = pmix_hash_fetch(&nptr->modex, rank, cb->key, &val);
            PMIX_VALUE_CREATE(val, 1);
            rc = sm_data_fetch( cb->nspace,  rank, cb->key, &val);
            cb->value_cbfunc(rc, val, cb->cbdata);
            if (NULL != val) {
                PMIX_VALUE_RELEASE(val);
            }
            pmix_list_remove_item(&pmix_client_globals.pending_requests, &cb->super);
            PMIX_RELEASE(cb);
        }
    }
}

static void getnb_shortcut(int fd, short flags, void *cbdata)
{
    pmix_cb_t *cb = (pmix_cb_t*)cbdata;
    pmix_value_t val;
    int rc;
    int32_t m;

    pmix_output_verbose(2, pmix_globals.debug_output,
                        "getnb_shortcut called with %s cbfunc",
                        (NULL == cb->value_cbfunc) ? "NULL" : "NON-NULL");

    PMIX_VALUE_CONSTRUCT(&val);
    if (NULL != cb->value_cbfunc) {
        m=1;
        rc = pmix_bfrop.unpack(&cb->data, &val, &m, PMIX_VALUE);
        cb->value_cbfunc(rc, &val, cb->cbdata);
    }
    PMIX_VALUE_DESTRUCT(&val);
    PMIX_RELEASE(cb);
}
