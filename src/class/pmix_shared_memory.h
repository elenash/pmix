#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <private/autogen/config.h>
#include "pmix/pmix_common.h"

typedef struct pmix_sm_seg_t {
    /* pid of the shared memory segment creator */
    pid_t seg_cpid;
    /* state flags */
//    opal_shmem_ds_flag_t flags;
    /* ds id */
    int seg_id;
    /* size of shared memory segment */
    size_t seg_size;
    /* base address of shared memory segment */
    unsigned char *seg_base_addr;
    char seg_name[PMIX_PATH_MAX];
} pmix_sm_seg_t;

int segment_create(pmix_sm_seg_t *sm_seg, char *file_name, size_t size);
int segment_attach(pmix_sm_seg_t *sm_seg);
int segment_detach(pmix_sm_seg_t *sm_seg);
int segment_unlink(pmix_sm_seg_t *sm_seg);
