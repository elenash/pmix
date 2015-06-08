#include "src/class/pmix_list.h"
#include "src/util/error.h"

#include "src/class/pmix_shared_memory.h"

#define NUM_META_ELEMS 10
#define NUM_NS 10

typedef struct {
    char ns_name[PMIX_MAX_NSLEN+1];
//    pmix_sm_seg_t meta_seg_info;//?
//    pmix_sm_seg_t data_seg_info;//? maybe just seg_name or nothing, or id seg in list
    size_t num_meta_seg;/* read by clients to attach to this number of segments. */
    size_t num_data_seg;
    size_t meta_segsize;/*if it is based on number of processes in namespace, it will be different among namespaces, but same for all meta segments for this nspace. */
    size_t data_segsize;/*if it is based on number of processes in namespace, it will be different among namespaces, but same for all data segments for this nspace. */
} ns_seg_info_t;

typedef struct {
    size_t rank;
    //pmix_sm_seg_t seg_info;
    size_t offset;
    size_t count;
} rank_meta_info;

typedef struct {
    size_t num_elems;
    rank_meta_info meta_info[NUM_META_ELEMS];
//    pmix_sm_seg_t next_segment;
} ns_meta_segment;

typedef struct {
    char key[PMIX_MAX_KEYLEN+1];
//    buffer;
//    pmix_sm_seg_t next_segment;
} ns_data_segment;

#define NS_DATA_SEG_SIZE 10000

typedef struct {
    size_t num_elems;
    ns_seg_info_t ns_seg_info[NUM_NS];
    int full;/* if 1, then additional segment is created. */
} global_segment;

typedef struct pmix_sm_segment_t pmix_sm_segment_t;

struct pmix_sm_segment_t {
    pmix_list_item_t super;
    pmix_sm_seg_t seg_info;
    int attached;
    void *addr;
    size_t offset;
    pmix_sm_segment_t *next;
};
PMIX_CLASS_DECLARATION(pmix_sm_segment_t);



typedef enum {
    INITIAL_SEGMENT,
    NS_META_SEGMENT,
    NS_DATA_SEGMENT
} segment_type;

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
