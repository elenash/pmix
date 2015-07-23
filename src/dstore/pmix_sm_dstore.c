#include "pmix_sm_dstore.h"
#include "src/buffer_ops/buffer_ops.h"
#include "src/util/pmix_environ.h"

static void delete_sm_desc(seg_desc_t *desc)
{
    seg_desc_t *tmp;
    /* free all global segments */
    while (NULL != desc) {
        tmp = desc->next;
        /* detach & unlink from current desc */
        if (desc->seg_info.seg_cpid == getpid()) {
            segment_unlink(&desc->seg_info);
        }
        segment_detach(&desc->seg_info);
        /* FIXME return status? */
        free(desc);
        desc = tmp;
    }
}

static void ncon(ns_track_elem_t *p) {
    p->meta_seg = NULL;
    p->data_seg = NULL;
    p->num_meta_seg = 0;
    p->num_data_seg = 0;
}

static void ndes(ns_track_elem_t *p) {
    delete_sm_desc(p->meta_seg);
    delete_sm_desc(p->data_seg);
}

PMIX_CLASS_INSTANCE(ns_track_elem_t,
                    pmix_list_item_t,
                    ncon, ndes);

static int is_client;

static seg_desc_t *create_new_segment(segment_type type, char *nsname, uint32_t id);
static seg_desc_t *attach_new_segment(segment_type type, char *nsname, uint32_t id);
static int update_ns_elem(ns_track_elem_t *ns_elem, ns_seg_info_t *info);
static int put_ns_info_to_initial_segment(const char *nspace, pmix_sm_seg_t *metaseg, pmix_sm_seg_t *dataseg);
static ns_seg_info_t *get_ns_info_from_initial_segment(const char *nspace);
static ns_track_elem_t *get_track_elem_for_namespace(char *nspace);
static rank_meta_info *get_rank_meta_info(int rank, seg_desc_t *segdesc);

seg_desc_t *global_sm_seg_first, *global_sm_seg_last;
static pmix_list_t namespace_info_list;
static char *tmp_dir = NULL;
static size_t initial_segment_size;
static size_t max_ns_num;
static size_t meta_segment_size;
static size_t max_meta_elems;
static size_t data_segment_size;

static void set_constants_from_env()
{
    char *str;
    if( NULL != (str = getenv("INITIAL_SEG_SIZE")) ) {
        initial_segment_size = strtol(str, NULL, 10);
    } else {
        initial_segment_size = INITIAL_SEG_SIZE;
    }
    if( NULL != (str = getenv("NS_META_SEG_SIZE")) ) {
        meta_segment_size = strtol(str, NULL, 10);
    } else {
        meta_segment_size = NS_META_SEG_SIZE;
    }
    if( NULL != (str = getenv("NS_DATA_SEG_SIZE")) ) {
        data_segment_size = strtol(str, NULL, 10);
    } else {
        data_segment_size = NS_DATA_SEG_SIZE;
    }
}

int sm_dstore_open(int is_cli)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    int rc;
    seg_desc_t *seg;
    PMIX_CONSTRUCT(&namespace_info_list, pmix_list_t);
    global_sm_seg_first = NULL;
    global_sm_seg_last = NULL;
    is_client = is_cli;
    tmp_dir = strdup(pmix_tmp_directory());
    set_constants_from_env();
    max_ns_num = (initial_segment_size - sizeof(size_t) - sizeof(int))/sizeof(ns_seg_info_t);
    max_meta_elems = (meta_segment_size - sizeof(size_t))/sizeof(rank_meta_info);

    if (0 == is_client) {
        seg = create_new_segment(INITIAL_SEGMENT, NULL, 0);
    } else {
        seg = attach_new_segment(INITIAL_SEGMENT, NULL, 0);
    }
    if (NULL != seg) {
        global_sm_seg_first = seg;
        global_sm_seg_last = global_sm_seg_first;
        return PMIX_SUCCESS;
    }
    return PMIX_ERROR;
}

int sm_dstore_close()
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    delete_sm_desc(global_sm_seg_first);
    PMIX_LIST_DESTRUCT(&namespace_info_list);
    if (NULL != tmp_dir) {
        free(tmp_dir);
    }
    return PMIX_SUCCESS;
}

static seg_desc_t *create_new_segment(segment_type type, char *nsname, uint32_t id)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: segment type %d, nspace %s, id %u", __FILE__, __LINE__, __func__, type, nsname, id));
    int rc;
    char file_name[PMIX_PATH_MAX];
    size_t size;
    seg_desc_t *new_seg = NULL;
    switch (type) {
        case INITIAL_SEGMENT:
            size = initial_segment_size;
            snprintf(file_name, PMIX_PATH_MAX, "%s/initial-pmix_shared-segment-%u", tmp_dir, id);
            break;
        case NS_META_SEGMENT:
            size = meta_segment_size;
            snprintf(file_name, PMIX_PATH_MAX, "%s/smseg-%s-%u", tmp_dir, nsname, id);
            break;
        case NS_DATA_SEGMENT:
            size = data_segment_size;
            snprintf(file_name, PMIX_PATH_MAX, "%s/smdataseg-%s-%d", tmp_dir, nsname, id);
            break;
        default:
            PMIX_ERROR_LOG(rc);
            return NULL;
    }
    new_seg = (seg_desc_t*)malloc(sizeof(seg_desc_t));
    new_seg->id = id;
    new_seg->next = NULL;
    new_seg->type = type;
    rc = segment_create(&new_seg->seg_info, file_name, size);
    if (PMIX_SUCCESS != rc) {
        free(new_seg);
        new_seg = NULL;
        PMIX_ERROR_LOG(rc);
    }
    memset(new_seg->seg_info.seg_base_addr, 0, size);
    return new_seg;
}

static seg_desc_t *attach_new_segment(segment_type type, char *nsname, uint32_t id)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: segment type %d, nspace %s, id %u", __FILE__, __LINE__, __func__, type, nsname, id));
    int rc;
    seg_desc_t *new_seg = NULL;
    new_seg = (seg_desc_t*)malloc(sizeof(seg_desc_t));
    new_seg->id = id;
    new_seg->next = NULL;
    new_seg->type = type;
    switch (type) {
        case INITIAL_SEGMENT:
            new_seg->seg_info.seg_size = initial_segment_size;
            snprintf(new_seg->seg_info.seg_name, PMIX_PATH_MAX, "%s/initial-pmix_shared-segment-%u", tmp_dir, id);
            break;
        case NS_META_SEGMENT:
            new_seg->seg_info.seg_size = meta_segment_size;
            snprintf(new_seg->seg_info.seg_name, PMIX_PATH_MAX, "%s/smseg-%s-%u", tmp_dir, nsname, id);
            break;
        case NS_DATA_SEGMENT:
            new_seg->seg_info.seg_size = data_segment_size;
            snprintf(new_seg->seg_info.seg_name, PMIX_PATH_MAX, "%s/smdataseg-%s-%d", tmp_dir, nsname, id);
            break;
        default:
            PMIX_ERROR_LOG(rc);
            return NULL;
    }
    rc = segment_attach(&new_seg->seg_info);
    if (PMIX_SUCCESS != rc) {
        free(new_seg);
        new_seg = NULL;
        PMIX_ERROR_LOG(rc);
    }
    return new_seg;
}

static int update_ns_elem(ns_track_elem_t *ns_elem, ns_seg_info_t *info)
{
    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    seg_desc_t *seg, *tmp = NULL;
    size_t i, offs;

    tmp = ns_elem->meta_seg;
    if (NULL != tmp) {
        while(NULL != tmp->next) {
            tmp = tmp->next;
        }
    }

    for (i = ns_elem->num_meta_seg; i < info->num_meta_seg; i++) {
        if (0 == is_client) {
            seg = create_new_segment(NS_META_SEGMENT, info->ns_name, i);
        } else {
            seg = attach_new_segment(NS_META_SEGMENT, info->ns_name, i);
        }
        if (NULL == seg) {
            PMIX_ERROR_LOG(PMIX_ERROR);
            return PMIX_ERROR;
        }
        if (NULL == tmp) {
            ns_elem->meta_seg = seg;
        } else {
            tmp->next = seg;
        }
        tmp = seg;
        ns_elem->num_meta_seg++;
    }
  
    tmp = ns_elem->data_seg;
    if (NULL != tmp) {
        while(NULL != tmp->next) {
            tmp = tmp->next;
        }
    }
    for (i = ns_elem->num_data_seg; i < info->num_data_seg; i++) {
        if (0 == is_client) {
            seg = create_new_segment(NS_DATA_SEGMENT, info->ns_name, i);
            offs = sizeof(size_t);//shift on offset field itself
            memcpy(seg->seg_info.seg_base_addr, &offs, sizeof(size_t));
        } else {
            seg = attach_new_segment(NS_DATA_SEGMENT, info->ns_name, i);
        }
        if (NULL == seg) {
            PMIX_ERROR_LOG(PMIX_ERROR);
            return PMIX_ERROR;
        }
        if (NULL == tmp) {
            ns_elem->data_seg = seg;
        } else {
            tmp->next = seg;
        }
        tmp = seg;
        ns_elem->num_data_seg++;
    }

    return PMIX_SUCCESS;
}

static seg_desc_t *extend_segment(seg_desc_t *segdesc, char *nspace)
{
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    seg_desc_t *tmp, *seg;
    /* find last segment */
    tmp = segdesc;
    while (NULL != tmp->next) {
        tmp = tmp->next;
    }
    /* create another segment, the old one is full. */
    seg = create_new_segment(segdesc->type, nspace, tmp->id+1);
    if (NULL == seg) {
        PMIX_ERROR_LOG(PMIX_ERROR);
        return NULL;
    }

    tmp->next = seg;

    return seg;
}

static int put_ns_info_to_initial_segment(const char *nspace, pmix_sm_seg_t *metaseg, pmix_sm_seg_t *dataseg)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    ns_seg_info_t elem;
    size_t num_elems;
    num_elems = *((size_t*)(global_sm_seg_last->seg_info.seg_base_addr));
    seg_desc_t *last_seg = global_sm_seg_last;

    if (max_ns_num == num_elems) {
        if (NULL == (last_seg = extend_segment(last_seg, NULL))) {
            PMIX_ERROR_LOG(PMIX_ERROR);
            return PMIX_ERROR;
        }
        /* mark previous segment as full */
        int full = 1;
        memcpy((uint8_t*)(global_sm_seg_last->seg_info.seg_base_addr + sizeof(size_t)), &full, sizeof(int));
        global_sm_seg_last = last_seg;
        memset(global_sm_seg_last->seg_info.seg_base_addr, 0, initial_segment_size);
    }
    strncpy(elem.ns_name, nspace, PMIX_MAX_NSLEN);
    elem.num_meta_seg = 1;
    elem.num_data_seg = 1;
    elem.meta_segsize = meta_segment_size;
    elem.data_segsize = data_segment_size;
    memcpy((uint8_t*)(global_sm_seg_last->seg_info.seg_base_addr) + sizeof(size_t) + sizeof(int) + num_elems * sizeof(ns_seg_info_t), &elem, sizeof(ns_seg_info_t));
    num_elems++;
    memcpy((uint8_t*)(global_sm_seg_last->seg_info.seg_base_addr), &num_elems, sizeof(size_t));
    return PMIX_SUCCESS;
}

/* clients should sync local info with information from initial segment regularly */
static void update_initial_segment_info()
{
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    size_t i;
    seg_desc_t *tmp;
    tmp = global_sm_seg_first;
    /* go through all global segments */
    do {
        /* check if current segment was marked as full but no more next segment is in the chain */
        if (NULL == tmp->next && 1 == *((int*)((uint8_t*)(tmp->seg_info.seg_base_addr) + sizeof(size_t)))) {
            tmp->next = attach_new_segment(INITIAL_SEGMENT, NULL, tmp->id+1);
        }
        tmp = tmp->next;
    }
    while (NULL != tmp);
}

/* this function will be used by clients to get ns data from the initial segment and add them to the tracker list */
static ns_seg_info_t *get_ns_info_from_initial_segment(const char *nspace)
{
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    int rc;
    size_t i;
    seg_desc_t *tmp;
    ns_seg_info_t *elem, *cur_elem;
    elem = NULL;
    size_t num_elems;

    tmp = global_sm_seg_first;

    rc = 1;
    /* go through all global segments */
    do {
        num_elems = *((size_t*)(tmp->seg_info.seg_base_addr));
        for (i = 0; i < num_elems; i++) {
            cur_elem = (ns_seg_info_t*)((uint8_t*)(tmp->seg_info.seg_base_addr) + sizeof(size_t) + sizeof(int) + i * sizeof(ns_seg_info_t));
            if (0 == (rc = strncmp(cur_elem->ns_name, nspace, strlen(nspace)))) {
                break;
            }
        }
        if (0 == rc) {
            elem = cur_elem;
            //fprintf(stderr, "get_ns_info_from_initial_segment ret %s:%lu\n", elem->ns_name, elem->num_meta_seg);
            break;
        }
        tmp = tmp->next;
    }
    while (NULL != tmp);
    return elem;
}

static ns_track_elem_t *get_track_elem_for_namespace(char *nspace)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: nspace %s", __FILE__, __LINE__, __func__, nspace));
    int rc;
    ns_track_elem_t *new_elem = NULL;

    /* check if this namespace is already being tracked to avoid duplicating data. */
    PMIX_LIST_FOREACH(new_elem, &namespace_info_list, ns_track_elem_t) {
        if (0 == strncmp(nspace, new_elem->ns_name, PMIX_MAX_NSLEN+1)) {
            /* data for this namespace should be already stored in shared memory region. */
            /* so go and just put new data. */
            PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                        "%s:%d:%s: found nspace %s in the track list", __FILE__, __LINE__, __func__, nspace));
            return new_elem;
        }
    }

    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: create new object for nspace %s", __FILE__, __LINE__, __func__, nspace));
    /* create shared memory regions for this namespace and store its info locally
     * to operate with address and detach/unlink afterwards. */
    new_elem = PMIX_NEW(ns_track_elem_t);
    strncpy(new_elem->ns_name, nspace, PMIX_MAX_NSLEN);

    pmix_list_append(&namespace_info_list, &new_elem->super);

    return new_elem;
}

static rank_meta_info *get_rank_meta_info(int rank, seg_desc_t *segdesc)
{
    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    size_t i;
    rank_meta_info *elem = NULL;
    seg_desc_t *tmp = segdesc;
    size_t num_elems;
    rank_meta_info *cur_elem;
    /* go through all existing meta segments for this namespace */
    do {
        num_elems = *((size_t*)(tmp->seg_info.seg_base_addr));
        for (i = 0; i < num_elems; i++) {
            cur_elem = (rank_meta_info*)((uint8_t*)(tmp->seg_info.seg_base_addr) + sizeof(size_t) + i * sizeof(rank_meta_info));
            if (rank == cur_elem->rank) {
                elem = cur_elem;
                break;
            }
        }
        tmp = tmp->next;
    }
    while (NULL != tmp && NULL == elem);
    return elem;
}

static uint8_t *get_data_region_by_offset(seg_desc_t *segdesc, size_t offset)
{
    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                         "%s:%d:%s", __FILE__, __LINE__, __func__));
    seg_desc_t *tmp = segdesc;
    size_t rel_offset = offset;
    uint8_t *dataaddr = NULL;
    /* go through all existing data segments for this namespace */
    do {
        if (rel_offset >= data_segment_size) {
            rel_offset -= data_segment_size;
        } else {
            dataaddr = tmp->seg_info.seg_base_addr + rel_offset;
        }
        tmp = tmp->next;
    }
    while (NULL != tmp && NULL == dataaddr);
    return dataaddr;
}

static int update_rank_meta_info(ns_track_elem_t *ns_info, rank_meta_info *rinfo)
{
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s: nspace %s, add rank %d offset %lu count %lu meta info", __FILE__, __LINE__, __func__, ns_info->ns_name, rinfo->rank, rinfo->offset, rinfo->count));
    /* it's claimed that there is still no meta info for this rank stored,
     * so look for the last existing meta segment. */
    seg_desc_t *tmp;
    size_t num_elems;
    rank_meta_info *cur_elem;
    tmp = ns_info->meta_seg;
    while (NULL != tmp->next) {
        tmp = tmp->next;
    }
    num_elems = *((size_t*)(tmp->seg_info.seg_base_addr));
    if (max_meta_elems <= num_elems) {
        PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                    "%s:%d:%s: extend meta segment for nspace %s", __FILE__, __LINE__, __func__, ns_info->ns_name));
        /* extend meta segment, so create a new one */
        tmp = extend_segment(tmp, ns_info->ns_name);
        if (NULL == tmp) {
            PMIX_ERROR_LOG(PMIX_ERROR);
            return PMIX_ERROR;
        }
        ns_info->num_meta_seg++;
        memset(tmp->seg_info.seg_base_addr, 0, sizeof(rank_meta_info));
        /* update_ns_info_in_initial_segment */
        ns_seg_info_t *elem = get_ns_info_from_initial_segment(ns_info->ns_name);
        if (ns_info->num_meta_seg != elem->num_meta_seg) {
            //elem->num_meta_seg++;
            elem->num_meta_seg = ns_info->num_meta_seg;
        }
        num_elems = 0;
    }
    cur_elem = (rank_meta_info*)((uint8_t*)(tmp->seg_info.seg_base_addr) + sizeof(size_t) + num_elems * sizeof(rank_meta_info));
    memcpy(cur_elem, rinfo, sizeof(rank_meta_info));
    num_elems++;
    memcpy(tmp->seg_info.seg_base_addr, &num_elems, sizeof(size_t));
    return PMIX_SUCCESS;
}

#define EXT_SLOT_SIZE (PMIX_MAX_KEYLEN + 2*sizeof(size_t)) /* in ext slot new offset will be stored in case if new data were added for the same process during next commit */


/* FIXME Added flag argument to indicate if we cam here when we first put data for rank or replace already existing data.
 * If we don't have enough space in the current segment, we allocate a new one and store new offset at the ext slot
 * at the end of previous segment. But if we replace existing data, we would store ext slot twice and corrupt memory, so
 * to avoid it, we don't store ext slot here in the case. */
static size_t put_data_to_the_end(ns_track_elem_t *ns_info, seg_desc_t *dataseg, char *key, void *buffer, size_t size, int flag)
{
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s: key %s", __FILE__, __LINE__, __func__, key));
    /* TODO check if size of blob <= data_segment_size */
    size_t offset;
    seg_desc_t *tmp;
    tmp = dataseg;
    int id = 0;
    size_t sz, global_offset, data_ended, new_offset, add_space;
    /* first find the last data segment */
    while (NULL != tmp->next) {
        tmp = tmp->next;
        id++;
    }
    offset = *((size_t*)(tmp->seg_info.seg_base_addr));
    /* We should provide additional space at the end of segment to place EXTENSION_SLOT to have an ability to enlarge data for this rank.
     * But in case if this function was called with EXTENSION_SLOT key we don't do it, just place this data to the provided slot. */
    add_space = EXT_SLOT_SIZE;
    if (!strncmp(key, "EXTENSION_SLOT", PMIX_MAX_KEYLEN)) {
        add_space = 0;
    }
    if (offset + PMIX_MAX_KEYLEN + sizeof(size_t) + size + add_space > data_segment_size)  {
        /* store new offset to the extension slot here */
        id++;
        if (flag) {
            new_offset = id * data_segment_size + sizeof(size_t);
            sz = sizeof(size_t);
            strncpy((uint8_t*)(tmp->seg_info.seg_base_addr) + offset, "EXTENSION_SLOT", PMIX_MAX_KEYLEN);
            memcpy((uint8_t*)tmp->seg_info.seg_base_addr + offset + PMIX_MAX_KEYLEN, &sz, sizeof(size_t));
            memcpy((uint8_t*)tmp->seg_info.seg_base_addr + offset + PMIX_MAX_KEYLEN + sizeof(size_t), &new_offset, sizeof(size_t));
        }
        /* create a new data segment. */
        tmp = extend_segment(tmp, ns_info->ns_name);
        if (NULL == tmp) {
            PMIX_ERROR_LOG(PMIX_ERROR);
            return PMIX_ERROR;
        }
        ns_info->num_data_seg++;
        /* update_ns_info_in_initial_segment */
        ns_seg_info_t *elem = get_ns_info_from_initial_segment(ns_info->ns_name);
        elem->num_data_seg++;

        offset = sizeof(size_t);
    }
    strncpy((uint8_t*)(tmp->seg_info.seg_base_addr) + offset, key, PMIX_MAX_KEYLEN);
    sz = size;
    memcpy((uint8_t*)tmp->seg_info.seg_base_addr + offset + PMIX_MAX_KEYLEN, &sz, sizeof(size_t));
    memcpy((uint8_t*)tmp->seg_info.seg_base_addr + offset + PMIX_MAX_KEYLEN + sizeof(size_t), buffer, size);

    /* update offset at the beginning of current segment */
    data_ended = offset + PMIX_MAX_KEYLEN + sizeof(size_t) + size;
    memcpy(tmp->seg_info.seg_base_addr, &data_ended, sizeof(size_t));
    global_offset = offset + id * data_segment_size;
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s: key %s, rel start offset %lu, rel end offset %lu, abs shift %lu size %lu", __FILE__, __LINE__, __func__, key, offset, data_ended, id * data_segment_size, size));
    return global_offset;
}

static int pmix_sm_store(ns_track_elem_t *ns_info, int rank, pmix_kval_t *kval, rank_meta_info **rinfo, int replace_flag)
{
    PMIX_OUTPUT_VERBOSE((2, pmix_globals.debug_output,
                         "%s:%d:%s: for rank %d, replace flag %d", __FILE__, __LINE__, __func__, rank, replace_flag));
    size_t offset, size, kval_cnt;
    pmix_buffer_t *buffer;
    int rc;
    seg_desc_t *datadesc;
    size_t update_ext_slot = 0;
    uint8_t *addr;
    
    datadesc = ns_info->data_seg;    
    /* pack value to the buffer */
    buffer = PMIX_NEW(pmix_buffer_t);
    if (PMIX_SUCCESS != (rc = pmix_bfrop.pack(buffer, kval->value, 1, PMIX_VALUE))) {
        PMIX_RELEASE(buffer);
        PMIX_ERROR_LOG(rc);
        return rc;
    }
    size = buffer->bytes_used;

    if (0 == replace_flag) {
        /* there is no data blob for this rank yet, so add it. */
        offset = put_data_to_the_end(ns_info, datadesc, kval->key, buffer->base_ptr, size, 1);
        if (NULL == *rinfo) {
            *rinfo = (rank_meta_info*)malloc(sizeof(rank_meta_info));
            (*rinfo)->rank = rank;
            (*rinfo)->offset = offset;
            (*rinfo)->count = 0;
        }
        (*rinfo)->count++;
    } else if (NULL != *rinfo) {
        /* there is data blob for this rank */
        addr = get_data_region_by_offset(datadesc, (*rinfo)->offset);
        if (NULL == addr) {
            PMIX_RELEASE(buffer);
            PMIX_ERROR_LOG(PMIX_ERROR);
            return rc;
        }
        /* go through previous data region and find key matches.
         * If one is found, then mark this kval as invalidated.
         * Then put a new empty offset to the next extension slot,
         * and add new kval by this offset. 
         * no need to update meta info, it's still the same. */
    //size_t ofs= (*rinfo)->offset;
        kval_cnt = (*rinfo)->count + 1;
        while (0 < kval_cnt) {
            /* data is stored in the following format:
             * key[PMIX_MAX_KEYLEN]
             * size_t size
             * byte buffer containing pmix_value, should be loaded to pmix_buffer_t and unpacked.
             * next kval pair
             * .....
             * extension slot which has key = EXTENSION_SLOT and a size_t value for offset to next data address for this process.
             */
            if (0 == strncmp(addr, "EXTENSION_SLOT", PMIX_MAX_KEYLEN)) {
                offset = *(size_t *)(addr + PMIX_MAX_KEYLEN + sizeof(size_t));
                if (0 < offset) {
                    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                                "%s:%d:%s: for rank %d, replace flag %d EXTENSION_SLOT is filled with %lu value", __FILE__, __LINE__, __func__, rank, replace_flag, offset));
                    addr = get_data_region_by_offset(datadesc, offset);
                    if (NULL == addr) {
                        PMIX_RELEASE(buffer);
                        PMIX_ERROR_LOG(PMIX_ERROR);
                        return rc;
                    }
       //             ofs = offset;
                } else {
                    if (0 == update_ext_slot) {
                        /* add to the end */
                        offset = put_data_to_the_end(ns_info, datadesc, kval->key, buffer->base_ptr, size, 0);
                        PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                                    "%s:%d:%s: for rank %d, replace flag %d item not found ext slot empty, put key %s to the end", __FILE__, __LINE__, __func__, rank, replace_flag, kval->key));
                        size_t tmp = 0.0;
                        put_data_to_the_end(ns_info, datadesc, "EXTENSION_SLOT", (void*)&tmp, sizeof(size_t), 1);
                        (*rinfo)->count++;
                        update_ext_slot = offset;
                    }
                    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                                "%s:%d:%s: for rank %d, replace flag %d EXTENSION_SLOT should be filled with offset %lu value", __FILE__, __LINE__, __func__, rank, replace_flag, update_ext_slot));
                    memcpy(addr+PMIX_MAX_KEYLEN + sizeof(size_t), &update_ext_slot, sizeof(size_t));
                    break;
                }
            } else if (0 == strncmp(addr, kval->key, PMIX_MAX_KEYLEN)) {
                PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                            "%s:%d:%s: for rank %d, replace flag %d found target key %s", __FILE__, __LINE__, __func__, rank, replace_flag, kval->key));
                /* target key is found, compare value sizes */
                size_t cur_size = *(size_t *)(addr + PMIX_MAX_KEYLEN);
                if (cur_size != size) {
                //if (1) {
                    /* invalidate current value and store another one at the end of data region. */
                    strncpy(addr, "INVALIDATED", PMIX_MAX_KEYLEN);
                    /* add to the end */
                    offset = put_data_to_the_end(ns_info, datadesc, kval->key, buffer->base_ptr, size, 1);
                    size_t tmp = 0.0;
                    put_data_to_the_end(ns_info, datadesc, "EXTENSION_SLOT", (void*)&tmp, sizeof(size_t), 1);
                    (*rinfo)->count++;
                    /* find next ext slot and put new offset to it */
                    update_ext_slot = offset;
                    addr += PMIX_MAX_KEYLEN + sizeof(size_t) + cur_size;
    //                ofs += PMIX_MAX_KEYLEN + sizeof(size_t) + cur_size;
                    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                                "%s:%d:%s: for rank %d, replace flag %d mark key %s regions as invalidated. put new data by offset %lu", __FILE__, __LINE__, __func__, rank, replace_flag, kval->key, update_ext_slot));
                } else {
                    PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                                "%s:%d:%s: for rank %d, replace flag %d replace data for key %s in place", __FILE__, __LINE__, __func__, rank, replace_flag, kval->key));
                    /* replace old data with new one. */
                    addr += PMIX_MAX_KEYLEN;
                    memcpy(addr, &size, sizeof(size_t));
                    addr += sizeof(size_t);
                    memset(addr, 0, cur_size);
                    memcpy(addr, buffer->base_ptr, size);
                    addr += cur_size;
                    break;
                }
            } else {
                char ckey[PMIX_MAX_KEYLEN];
                strncpy(ckey, addr, PMIX_MAX_KEYLEN);
                PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                            "%s:%d:%s: for rank %d, replace flag %d skip %s key, look for %s key", __FILE__, __LINE__, __func__, rank, replace_flag, ckey, kval->key));
                /* key == "INVALIDATED" or key is real but different from target one. */
                /*skip it */
                if (strncmp("INVALIDATED", ckey, PMIX_MAX_KEYLEN)) {
                    kval_cnt--;
                }
                size_t size = *(size_t *)(addr + PMIX_MAX_KEYLEN);
                addr += PMIX_MAX_KEYLEN + sizeof(size_t) + size;
    //            ofs += PMIX_MAX_KEYLEN + sizeof(size_t) + size;
            }
        }
    }
    buffer->base_ptr = NULL;
    buffer->bytes_used = 0;
    PMIX_RELEASE(buffer);
    return rc;
}

static int store_data_for_rank(ns_track_elem_t *ns_info, int rank, pmix_buffer_t *buf)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: for rank %d", __FILE__, __LINE__, __func__, rank));
    int rc;
    int32_t cnt;
    
    pmix_buffer_t *bptr;
    pmix_kval_t *kp;
    seg_desc_t *metadesc, *datadesc;
    
    rank_meta_info *rinfo = NULL;
    size_t num_elems;
    int replace_flag;

    metadesc = ns_info->meta_seg;    
    datadesc = ns_info->data_seg;    
    
    if (NULL == datadesc || NULL == metadesc) {
        PMIX_ERROR_LOG(PMIX_ERR_BAD_PARAM);
        return PMIX_ERROR;
    }
    
    num_elems = *((size_t*)(metadesc->seg_info.seg_base_addr));
    replace_flag = 0;
    if (0 < num_elems) {
        /* go through all elements in meta segment and look for target rank. */
        rinfo = get_rank_meta_info(rank, metadesc);
        if (NULL != rinfo) {
            replace_flag = 1;
        }
    }
    /* incoming buffer may contain several inner buffers for different scopes,
     * so unpack these buffers, and then unpack kvals from each modex buffer,
     * storing them in the shared memory dstore.
     */
    cnt = 1;
    while (PMIX_SUCCESS == (rc = pmix_bfrop.unpack(buf, &bptr, &cnt, PMIX_BUFFER))) {
        cnt = 1;
        kp = PMIX_NEW(pmix_kval_t);
        while (PMIX_SUCCESS == (rc = pmix_bfrop.unpack(bptr, kp, &cnt, PMIX_KVAL))) {
            pmix_output_verbose(2, pmix_globals.debug_output,
                                "pmix: unpacked key %s", kp->key);
            if (PMIX_SUCCESS != (rc = pmix_sm_store(ns_info, rank, kp, &rinfo, replace_flag))) {
                PMIX_ERROR_LOG(rc);
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

    /* reserve space for EXTENSION slot  TODO*/
    size_t tmp = 0.0, tmp2;
    tmp2 = put_data_to_the_end(ns_info, ns_info->data_seg, "EXTENSION_SLOT", (void*)&tmp, sizeof(size_t), 1);

    /* if this is the first data posted for this rank, then
     * update meta info for it */
    if (0 == replace_flag) {
        update_rank_meta_info(ns_info, rinfo);
        if (NULL != rinfo) {
            free(rinfo);
        }
    }

    return rc;
}

int sm_data_store(pmix_buffer_t *buf)
{
    int rc;
    size_t i;
    ns_track_elem_t *elem;
    char *nspace;
    int rank;
    int cnt;
    ns_seg_info_t ns_info;

    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &nspace, &cnt, PMIX_STRING))) {
        PMIX_ERROR_LOG(rc);
        return rc;
    }
    /* unpack the rank */
    cnt = 1;
    if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(buf, &rank, &cnt, PMIX_INT))) {
        PMIX_ERROR_LOG(rc);
        return rc;
    }
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: for %s:%d", __FILE__, __LINE__, __func__, nspace, rank));

    /* first of all look for this namespace in the local track list,
     * if it is there, then shared memory segments for it are created,
     * we might need just extend them by creating new segments and put
     * their info as a last element, and updating the tracker consequently.
     * If current namespace doesn't exist in the local track list, then
     * create all necessary shared memory segments for it, put info about it
     * to the initial shared segment and append it to the local track list. */ 

    elem = get_track_elem_for_namespace(nspace);
    if (NULL == elem) {
        PMIX_ERROR_LOG(PMIX_ERROR);
        return PMIX_ERROR;
    }

    /* if elem was just created, need to create corresponding meta and data segments and update elem's fields */
    if (NULL == elem->meta_seg || NULL == elem->data_seg) {
        strncpy(ns_info.ns_name, nspace, PMIX_MAX_NSLEN);
        ns_info.num_meta_seg = 1;
        ns_info.num_data_seg = 1;
        ns_info.meta_segsize = meta_segment_size;
        ns_info.data_segsize = data_segment_size;
        rc = update_ns_elem(elem, &ns_info);
        if (PMIX_SUCCESS != rc || NULL == elem->meta_seg || NULL == elem->data_seg) {
            PMIX_ERROR_LOG(rc);
            return PMIX_ERROR;
        }

        /* zero created shared memory segments for this namespace */
        memset(elem->meta_seg->seg_info.seg_base_addr, 0, meta_segment_size);
        memset(elem->data_seg->seg_info.seg_base_addr, 0, data_segment_size);

        /* put ns's shared segments info to the global meta segment. */
        rc = put_ns_info_to_initial_segment(nspace, &elem->meta_seg->seg_info, &elem->data_seg->seg_info);
        if (PMIX_SUCCESS != rc) {
            PMIX_ERROR_LOG(rc);
            return rc;
        }
    }

    /* now we know info about meta segment for this namespace. If meta segment
     * is not empty, then we look for data for the target rank. If they present, replace it. */
    rc = store_data_for_rank(elem, rank, buf);
    return rc;
}

int sm_data_fetch(char *nspace, int rank, char *key, pmix_value_t **kvs)
{
    PMIX_OUTPUT_VERBOSE((1, pmix_globals.debug_output,
                         "%s:%d:%s: for %s:%d look for key %s", __FILE__, __LINE__, __func__, nspace, rank, key));
    ns_seg_info_t *ns_info = NULL;
    int rc;
    ns_track_elem_t *elem;
    rank_meta_info *rinfo = NULL;
    size_t num_elems, kval_cnt, i;
    seg_desc_t *meta_seg, *data_seg;
    uint8_t *addr;

    /* first of all look for this namespace in the initial segment,
     * if it is there, get numbers of meta & data segments and
     * compare these numbers with the number of trackable meta & data
     * segments for this namespace in the local track list.
     * If the first number exceeds the last, or the local track list
     * doesn't track current namespace yet, then we update it (attach
     * to additional segments).
     * Then we just look for the rank blob in the shared meta segment,
     * which address we get from the local track list.
     */

    /* get information about shared segments per this namespace from the initial segment. */
    /* probably need to get just nspace from the initial segment, based on it we can generate file name to attach. */
    /* first update local information about initial segments. they can be extended, so then we need to attach to new segments. */
    update_initial_segment_info();

    ns_info = get_ns_info_from_initial_segment(nspace);
    if (NULL == ns_info) {
        /* no data for this namespace is found in the shared memory. */
        PMIX_ERROR_LOG(PMIX_ERROR);
        return PMIX_ERROR;
    }

    elem = get_track_elem_for_namespace(nspace);
    if (NULL == elem) {
        PMIX_ERROR_LOG(PMIX_ERROR);
        return PMIX_ERROR;
    }
    /* need to update tracker:
     * attach to shared memory regions for this namespace and store its info locally
     * to operate with address and detach/unlink afterwards. */
    rc = update_ns_elem(elem, ns_info);
    if (PMIX_SUCCESS != rc) {
        PMIX_ERROR_LOG(PMIX_ERROR);
        return PMIX_ERROR;
    }

    /* now we know info about meta segment for this namespace. */
    meta_seg = elem->meta_seg;
    data_seg = elem->data_seg;
    num_elems = *((size_t*)(meta_seg->seg_info.seg_base_addr));
    //fprintf(stderr,  "<client>meta_seg %x, dataseg %x num_elems in meta seg %d rank %d\n", meta_seg, data_seg, num_elems, rank);
    if (0 == num_elems) {
        /* no data for this rank is found in the shared memory. */
        PMIX_OUTPUT_VERBOSE((0, pmix_globals.debug_output,
                    "%s:%d:%s:  no data for this rank is found in the shared memory. rank %d", __FILE__, __LINE__, __func__, rank));
        return PMIX_ERROR;
    } else {
        /* go through all elements and look for target rank. */
        rinfo = get_rank_meta_info(rank, meta_seg);
    }
    if (NULL == rinfo) {
        PMIX_OUTPUT_VERBOSE((0, pmix_globals.debug_output,
                    "%s:%d:%s:  no data for this rank is found in the shared memory. rank %d", __FILE__, __LINE__, __func__, rank));
        /* no data for this rank is found in the shared memory. */
        return PMIX_ERROR;
    }
    //fprintf(stderr, "<client> get_data_region_by_offset found rank %d meta info count = %lu, offset = %lu rank %d\n", rank, rinfo->count, rinfo->offset, rank);
    addr = get_data_region_by_offset(data_seg, rinfo->offset);
    if (NULL == addr) {
        PMIX_ERROR_LOG(PMIX_ERROR);
        return PMIX_ERROR;
    }
    kval_cnt = rinfo->count;
    pmix_buffer_t buffer;
    pmix_value_t val;
    rc = PMIX_ERROR;
    
    //size_t ofs = rinfo->offset;
    while (0 < kval_cnt) {
        /* data is stored in the following format:
         * key[PMIX_MAX_KEYLEN]
         * size_t size
         * byte buffer containing pmix_value, should be loaded to pmix_buffer_t and unpacked.
         * next kval pair
         * .....
         * EXTENSION slot which has key = EXTENSION_SLOT and a size_t value for offset to next data address for this process.
         */
        if (0 == strncmp(addr, "INVALIDATED", PMIX_MAX_KEYLEN)) {
            PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                        "%s:%d:%s: for rank %s:%d, skip INVALIDATED region", __FILE__, __LINE__, __func__, nspace, rank));
            /*skip it */
            size_t size = *(size_t *)(addr + PMIX_MAX_KEYLEN);
            addr += PMIX_MAX_KEYLEN + sizeof(size_t) + size;
   //         ofs += PMIX_MAX_KEYLEN + sizeof(size_t) + size;
        } else if (0 == strncmp(addr, "EXTENSION_SLOT", PMIX_MAX_KEYLEN)) {
            size_t offset = *(size_t *)(addr + PMIX_MAX_KEYLEN + sizeof(size_t));
            PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                        "%s:%d:%s: for rank %s:%d, reached EXTENSION_SLOT with %lu value", __FILE__, __LINE__, __func__, nspace, rank, offset));
            if (0 < offset) {
                addr = get_data_region_by_offset(data_seg, offset);
                if (NULL == addr) {
                    /* report problem and return */
                    PMIX_ERROR_LOG(PMIX_ERROR);
                    return PMIX_ERROR;
                }
   //             fprintf(stderr, "   <client> data fetch switch to next data offset %lu\n", offset);
   //             ofs = offset;
            } else {
                /* no more data for this rank */
                PMIX_OUTPUT_VERBOSE((0, pmix_globals.debug_output,
                            "%s:%d:%s:  no more data for this rank is found in the shared memory. rank %d key %s not found", __FILE__, __LINE__, __func__, rank, key));
                break;
            }
        } else if (0 == strncmp(addr, key, PMIX_MAX_KEYLEN)) {
            PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                        "%s:%d:%s: for rank %s:%d, found target key %s", __FILE__, __LINE__, __func__, nspace, rank, key));
            /* target key is found, get value */
            size_t size = *(size_t *)(addr + PMIX_MAX_KEYLEN);
            addr += PMIX_MAX_KEYLEN + sizeof(size_t);
            PMIX_CONSTRUCT(&buffer, pmix_buffer_t);
            PMIX_LOAD_BUFFER(&buffer, addr, size);
            int cnt = 1;
            /* unpack value for this key from the buffer. */
            PMIX_VALUE_CONSTRUCT(&val);
            if (PMIX_SUCCESS != (rc = pmix_bfrop.unpack(&buffer, &val, &cnt, PMIX_VALUE))) {
                PMIX_ERROR_LOG(rc);
                PMIX_DESTRUCT(&buffer);
                PMIX_VALUE_DESTRUCT(&val);
                return rc;
            }
            buffer.base_ptr = NULL;
            buffer.bytes_used = 0;
            PMIX_DESTRUCT(&buffer);
            //*kvs = &val;
            rc = pmix_bfrop.copy((void**)kvs, &val, PMIX_VALUE);
            rc = PMIX_SUCCESS;
            break;
        } else {
            char ckey[PMIX_MAX_KEYLEN];
            strncpy(ckey, addr, PMIX_MAX_KEYLEN);
            size_t size = *(size_t *)(addr + PMIX_MAX_KEYLEN);
            PMIX_OUTPUT_VERBOSE((10, pmix_globals.debug_output,
                        "%s:%d:%s: for rank %s:%d, skip key %s look for key %s", __FILE__, __LINE__, __func__, nspace, rank, ckey, key));
            addr += PMIX_MAX_KEYLEN + sizeof(size_t) + size;
     //       ofs += PMIX_MAX_KEYLEN + sizeof(size_t) + size;
            kval_cnt--;
        }
        rinfo->count++;
    }
    return rc;
}
