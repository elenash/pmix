/*
 * Copyright (c) 2015      Mellanox Technologies, Inc.
 *                         All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "src/class/pmix_list.h"
#include "src/util/error.h"

#include "src/class/pmix_shared_memory.h"
#include "src/buffer_ops/types.h"

#define INITIAL_SEG_SIZE 4096
#define NS_META_SEG_SIZE (1<<22)
#define NS_DATA_SEG_SIZE (1<<22)

typedef enum {
    INITIAL_SEGMENT,
    NS_META_SEGMENT,
    NS_DATA_SEGMENT
} segment_type;

/* initial segment format:
 * size_t num_elems;
 * int full; //indicate to client that it needs to attach to the next segment
 * ns_seg_info_t ns_seg_info[max_ns_num];
 */

typedef struct {
    char ns_name[PMIX_MAX_NSLEN+1];
    size_t num_meta_seg;/* read by clients to attach to this number of segments. */
    size_t num_data_seg;
} ns_seg_info_t;

/* meta segment format:
 * size_t num_elems;
 * rank_meta_info meta_info[max_meta_elems];
 */

typedef struct {
    size_t rank;
    size_t offset;
    size_t count;
} rank_meta_info;

/* this structs are used to store information about
 * shared segments addresses locally at each process,
 * so they are common for different types of segments
 * and don't have a specific content (namespace's info,
 * rank's meta info, ranks's data). */

typedef struct seg_desc_t seg_desc_t;
struct seg_desc_t {
    segment_type type;
    pmix_sm_seg_t seg_info;
    uint32_t id;
    seg_desc_t *next;
};

typedef struct {
    pmix_list_item_t super;
    char ns_name[PMIX_MAX_NSLEN+1];
    size_t num_meta_seg;
    size_t num_data_seg;
    seg_desc_t *meta_seg;
    seg_desc_t *data_seg;
} ns_track_elem_t;
PMIX_CLASS_DECLARATION(ns_track_elem_t);

int sm_dstore_open(int is_cli);
int sm_dstore_close();
int sm_data_store(pmix_buffer_t *buf);
int sm_data_fetch(char *nspace, int rank, char *key, pmix_value_t **kvs);
