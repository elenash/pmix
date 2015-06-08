#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "pmix_shared_memory.h"

#define PMIX_SHMEM_DS_ID_INVALID -1

static inline void
shmem_ds_reset(pmix_sm_seg_t *sm_seg)
{
    sm_seg->seg_cpid = 0;
    //OPAL_SHMEM_DS_RESET_FLAGS(ds_buf);
    sm_seg->seg_id = PMIX_SHMEM_DS_ID_INVALID;
    sm_seg->seg_size = 0;
    memset(sm_seg->seg_name, '\0', PMIX_PATH_MAX);
    sm_seg->seg_base_addr = (unsigned char *)MAP_FAILED;
}

/* ////////////////////////////////////////////////////////////////////////// */
int segment_create(pmix_sm_seg_t *sm_seg, char *file_name, size_t size)
{
    int rc;
    void *seg_addr;
    pid_t my_pid = getpid();
    rc = PMIX_SUCCESS;
    shmem_ds_reset(sm_seg);
    /* enough space is available, so create the segment */
    if (-1 == (sm_seg->seg_id = open(file_name, O_CREAT | O_RDWR, 0600))) {
        fprintf(stderr, "sys call open(2) fail\n");
        rc = PMIX_ERROR;
        goto out;
    }
    /* size backing file - note the use of real_size here */
    if (0 != ftruncate(sm_seg->seg_id, size)) {
        fprintf(stderr, "sys call ftruncate(2) fail\n");
        rc = PMIX_ERROR;
        goto out;
    }
    if (MAP_FAILED == (seg_addr = mmap(NULL, size,
                                       PROT_READ | PROT_WRITE, MAP_SHARED,
                                       sm_seg->seg_id, 0))) {
        fprintf(stderr, "sys call mmap(2) fail\n");
        rc = PMIX_ERROR;
        goto out;
    }
    sm_seg->seg_cpid = my_pid;
    sm_seg->seg_size = size;
    sm_seg->seg_base_addr = (unsigned char *)seg_addr;
    (void)strncpy(sm_seg->seg_name, file_name, PMIX_PATH_MAX - 1);

out:
    if (-1 != sm_seg->seg_id) {
        if (0 != close(sm_seg->seg_id)) {
            fprintf(stderr, "sys call close(2) fail\n");
            rc = PMIX_ERROR;
         }
     }
    /* an error occured, so invalidate the shmem object and munmap if needed */
    if (PMIX_SUCCESS != rc) {
        if (MAP_FAILED != seg_addr) {
            munmap((void *)seg_addr, size);
        }
        shmem_ds_reset(sm_seg);
    }
    return rc;
}

int segment_attach(pmix_sm_seg_t *sm_seg)
{
//    pid_t my_pid = getpid();

//    if (my_pid != sm_seg->seg_cpid) {
        if (-1 == (sm_seg->seg_id = open(sm_seg->seg_name, O_RDWR))) {
            return PMIX_ERROR;
        }
        if (MAP_FAILED == (sm_seg->seg_base_addr = (unsigned char *)
                              mmap(NULL, sm_seg->seg_size,
                                   PROT_READ | PROT_WRITE, MAP_SHARED,
                                   sm_seg->seg_id, 0))) {
            /* mmap failed, so close the file and return NULL - no error check
             * here because we are already in an error path...
             */
            fprintf(stderr, "sys call mmap(2) fail\n");
            close(sm_seg->seg_id);
            return PMIX_ERROR;
        }
        /* all is well */
        /* if close fails here, that's okay.  just let the user know and
         * continue.  if we got this far, open and mmap were successful...
         */
        if (0 != close(sm_seg->seg_id)) {
            fprintf(stderr, "sys call close(2) fail\n");
        }
//    }
    /* else i was the segment creator. */
    //return sm_seg->seg_base_addr;
    sm_seg->seg_cpid = 0;/* FIXME */
    return PMIX_SUCCESS;
}

int segment_detach(pmix_sm_seg_t *sm_seg)
{
    int rc = PMIX_SUCCESS;

    if (0 != munmap((void *)sm_seg->seg_base_addr, sm_seg->seg_size)) {
        fprintf(stderr, "sys call munmap(2) fail\n");
        rc = PMIX_ERROR;
    }
    /* reset the contents of the pmix_sm_seg_t associated with this
     * shared memory segment.
     */
    shmem_ds_reset(sm_seg);
    return rc;
}

int segment_unlink(pmix_sm_seg_t *sm_seg)
{
    if (-1 == unlink(sm_seg->seg_name)) {
        fprintf(stderr, "sys call unlink(2) fail\n");
        return PMIX_ERROR;
    }

    /* don't completely reset the pmix_sm_seg_t.  in particular, only reset
     * the id and flip the invalid bit.  size and name values will remain valid
     * across unlinks. other information stored in flags will remain untouched.
     */
    sm_seg->seg_id = PMIX_SHMEM_DS_ID_INVALID;
    /* note: this is only chaning the valid bit to 0. */
//    OPAL_SHMEM_DS_INVALIDATE(sm_seg);
    return PMIX_SUCCESS;
}
