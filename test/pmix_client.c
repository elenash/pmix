/*
 * Copyright (c) 2004-2010 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2011 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2006-2013 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2009-2012 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011      Oak Ridge National Labs.  All rights reserved.
 * Copyright (c) 2013-2015 Intel, Inc.  All rights reserved.
 * Copyright (c) 2015      Mellanox Technologies, Inc.  All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 *
 */
#include <private/autogen/config.h>
#include <pmix.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "src/class/pmix_object.h"
#include "src/buffer_ops/types.h"
#include "test_common.h"
#include "test_fence.h"
#include "test_publish.h"
#include "test_spawn.h"
#include "test_cd.h"
#include "test_resolve_peers.h"

int main(int argc, char **argv)
{
    char nspace[PMIX_MAX_NSLEN+1];
    int rank;
    int rc;
    pmix_value_t value;
    pmix_value_t *val = &value;
    test_params params;
    INIT_TEST_PARAMS(params);

    parse_cmd(argc, argv, &params);

    // We don't know rank at this place!
    TEST_VERBOSE(("Client ns %s rank %d: Start", params.nspace, params.rank));

    /* handle early-fail test case */
    if (1 == params.early_fail && 0 == params.rank) {
        exit(0);
    }

    /* init us */
    if (PMIX_SUCCESS != (rc = PMIx_Init(nspace, &rank))) {
        TEST_ERROR(("Client ns %s rank %d: PMIx_Init failed: %d", params.nspace, rank, rc));
        FREE_TEST_PARAMS(params);
        exit(0);
    }

    if (rank != params.rank) {
        TEST_ERROR(("Client ns %s Rank returned in PMIx_Init %d does not match to rank from command line %d.", params.nspace, rank, params.rank));
        FREE_TEST_PARAMS(params);
        exit(0);
    }
    if ( NULL != params.prefix && -1 != params.ns_id) {
        TEST_SET_FILE(params.prefix, params.ns_id, rank);
    }
    TEST_VERBOSE((" Client ns %s rank %d: PMIx_Init success", params.nspace, rank));

    if (PMIX_SUCCESS != (rc = PMIx_Get(nspace, rank,PMIX_UNIV_SIZE,&val))) {
        TEST_ERROR(("rank %d: PMIx_Get universe size failed: %d", rank, rc));
        FREE_TEST_PARAMS(params);
        exit(0);
    }
    if (NULL == val) {
        TEST_ERROR(("rank %d: PMIx_Get universe size returned NULL value", rank));
        FREE_TEST_PARAMS(params);
        exit(0);
    }
    if (val->type != PMIX_UINT32 || val->data.uint32 != (uint32_t)params.ns_size ) {
        TEST_ERROR(("rank %d: Universe size value or type mismatch,"
                    " want %d(%d) get %d(%d)",
                    rank, params.ns_size, PMIX_UINT32,
                    val->data.integer, val->type));
        FREE_TEST_PARAMS(params);
        exit(0);
    }

    TEST_VERBOSE(("rank %d: Universe size check: PASSED", rank));

    if( NULL != params.nspace && 0 != strcmp(nspace, params.nspace) ) {
        TEST_ERROR(("rank %d: Bad nspace!", rank));
        FREE_TEST_PARAMS(params);
        exit(0);
    }

    if (NULL != params.fences) {
        rc = test_fence(params, params.nspace, rank);
        if (PMIX_SUCCESS != rc) {
            FREE_TEST_PARAMS(params);
            TEST_ERROR(("%s:%d Fence test failed: %d", params.nspace, rank, rc));
            exit(0);
        }
    }

    if (0 != params.test_job_fence) {
        rc = test_job_fence(params, params.nspace, rank);
        if (PMIX_SUCCESS != rc) {
            FREE_TEST_PARAMS(params);
            TEST_ERROR(("%s:%d Job fence test failed: %d", params.nspace, rank, rc));
            exit(0);
        }
    }

    if (0 != params.test_publish) {
        rc = test_publish_lookup(params.nspace, rank);
        if (PMIX_SUCCESS != rc) {
            FREE_TEST_PARAMS(params);
            TEST_ERROR(("%s:%d Publish/Lookup test failed: %d", params.nspace, rank, rc));
            exit(0);
        }
    }

    if (0 != params.test_spawn) {
        rc = test_spawn(params.nspace, rank);
        if (PMIX_SUCCESS != rc) {
            FREE_TEST_PARAMS(params);
            TEST_ERROR(("%s:%d Spawn test failed: %d", params.nspace, rank, rc));
            exit(0);
        }
    }

    if (0 != params.test_connect) {
        rc = test_connect_disconnect(params.nspace, rank);
        if (PMIX_SUCCESS != rc) {
            FREE_TEST_PARAMS(params);
            TEST_ERROR(("%s:%d Connect/Disconnect test failed: %d", params.nspace, rank, rc));
            exit(0);
        }
    }

    if (0 != params.test_resolve_peers) {
        rc = test_resolve_peers(params.nspace, rank, params);
        if (PMIX_SUCCESS != rc) {
            FREE_TEST_PARAMS(params);
            TEST_ERROR(("%s:%d Resolve peers test failed: %d", params.nspace, rank, rc));
            exit(0);
        }
    }

    TEST_VERBOSE(("Client ns %s rank %d: PASSED", params.nspace, rank));

    /* finalize us */
    TEST_VERBOSE(("Client ns %s rank %d: Finalizing", params.nspace, rank));
    if (PMIX_SUCCESS != (rc = PMIx_Finalize())) {
        TEST_ERROR(("Client ns %s rank %d:PMIx_Finalize failed: %d", params.nspace, rank, rc));
    } else {
        TEST_VERBOSE(("Client ns %s rank %d:PMIx_Finalize successfully completed", params.nspace, rank));
    }

    TEST_OUTPUT_CLEAR(("OK\n"));
    TEST_CLOSE_FILE();
    FREE_TEST_PARAMS(params);
    exit(0);
}
