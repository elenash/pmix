/* include/pmix/pmix_common.h.  Generated from pmix_common.h.in by configure.  */
/*
 * Copyright (c) 2013-2014 Intel, Inc. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer listed
 *   in this license in the documentation and/or other materials
 *   provided with the distribution.
 *
 * - Neither the name of the copyright holders nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * The copyright holders provide no reassurances that the source code
 * provided does not infringe any patent, copyright, or any other
 * intellectual property rights of third parties.  The copyright holders
 * disclaim any liability to any recipient for claims brought against
 * recipient by any third party for infringement of that parties
 * intellectual property rights.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * $COPYRIGHT$
 * 
 * Additional copyrights may follow
 * 
 * $HEADER$
 */

#ifndef PMIx_COMMON_H
#define PMIx_COMMON_H

#include <pmix/autogen/pmix_config.h>
#include <pmix/rename.h>

#include <stdint.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h> /* for struct timeval */
#endif

#ifndef PMIX_CONFIG_H

/* ensure we have the version info available for external users */
/* #undef PMIX_MAJOR_VERSION */
/* #undef PMIX_MINOR_VERSION */
/* #undef PMIX_RELEASE_VERSION */

#endif

/* #undef BEGIN_C_DECLS */
/* #undef END_C_DECLS */
#if defined(c_plusplus) || defined(__cplusplus)
# define BEGIN_C_DECLS extern "C" {
# define END_C_DECLS }
#else
#define BEGIN_C_DECLS          /* empty */
#define END_C_DECLS            /* empty */
#endif

BEGIN_C_DECLS

/****  PMIX CONSTANTS    ****/

/* define maximum value and key sizes */
#define PMIX_MAX_NSLEN     255
#define PMIX_MAX_VALLEN   1023
#define PMIX_MAX_KEYLEN    511

/* define a *wildcard* value for requests involving rank */
#define PMIX_RANK_WILDCARD -1

/* define a set of "standard" PMIx attributes that can
 * be queried. Implementations (and users) are free to extend as
 * desired, so the get functions need to be capable
 * of handling the "not found" condition. Note that these
 * are attributes of the system and the job as opposed to
 * values the application (or underlying MPI library)
 * might choose to expose - i.e., they are values provided
 * by the resource manager as opposed to the application. Thus,
 * these keys are RESERVED */
#define PMIX_ATTR_UNDEF      NULL

/* general proc-level attributes */
#define PMIX_CREDENTIAL            "pmix.cred"         // (char*) security credential assigned to proc
#define PMIX_SPAWNED               "pmix.spawned"      // (bool) true if this proc resulted from a call to PMIx_Spawn

/* scratch directory locations for use by applications */
#define PMIX_TMPDIR                "pmix.tmpdir"       // (char*) top-level tmp dir assigned to session

/* information about relative ranks as assigned by the RM */
#define PMIX_JOBID                 "pmix.jobid"        // (char*) jobid assigned by scheduler
#define PMIX_APPNUM                "pmix.appnum"       // (uint32_t) app number within the job
#define PMIX_RANK                  "pmix.rank"         // (uint32_t) process rank within the job
#define PMIX_GLOBAL_RANK           "pmix.grank"        // (uint32_t) rank spanning across all jobs in this session
#define PMIX_APP_RANK              "pmix.apprank"      // (uint32_t) rank within this app
#define PMIX_NPROC_OFFSET          "pmix.offset"       // (uint32_t) starting global rank of this job
#define PMIX_LOCAL_RANK            "pmix.lrank"        // (uint16_t) rank on this node within this job
#define PMIX_NODE_RANK             "pmix.nrank"        // (uint16_t) rank on this node spanning all jobs
#define PMIX_LOCALLDR              "pmix.lldr"         // (uint64_t) opal_identifier of lowest rank on this node within this job
#define PMIX_APPLDR                "pmix.aldr"         // (uint32_t) lowest rank in this app within this job

/* proc location-related info */
#define PMIX_CPUSET                "pmix.cpuset"       // (char*) hwloc bitmap applied to proc upon launch
/* For PMIX_HOSTNAME, three use-cases exist for PMIx_Get:
 *
 * (a) Specifying a namespace with PMIX_RANK_WILDCARD will return
 *     a comma-delimited list of nodes that host procs in that namespace
 *
 * (b) Passing a NULL namespace will return a comma-delimited list of all
 *     nodes known to this session, regardless of whether or not they
 *     currently host procs. The rank argument in PMIx_Get is ignored
 *     for this use-case
 *
 * (c) Specifying a namespace and a rank will return the name of the
 *     host this proc is on
 */
#define PMIX_HOSTNAME              "pmix.hname"        // (char*) see above comment
#define PMIX_LOCAL_PEERS           "pmix.lpeers"       // (char*) comma-delimited string of ranks on this node within the specified nspace
#define PMIX_LOCAL_CPUSETS         "pmix.lcpus"        // (char*) colon-delimited cpusets of local peers within the specified nspace

/* size info */
#define PMIX_UNIV_SIZE             "pmix.univ.size"    // (uint32_t) #procs in this nspace
#define PMIX_JOB_SIZE              "pmix.job.size"     // (uint32_t) #procs in this job
#define PMIX_LOCAL_SIZE            "pmix.local.size"   // (uint32_t) #procs in this job on this node
#define PMIX_NODE_SIZE             "pmix.node.size"    // (uint32_t) #procs across all jobs on this node
#define PMIX_MAX_PROCS             "pmix.max.size"     // (uint32_t) max #procs for this job

/* topology info */
#define PMIX_NET_TOPO              "pmix.ntopo"        // (char*) xml-representation of network topology
#define PMIX_LOCAL_TOPO            "pmix.ltopo"        // (char*) xml-representation of local node topology
#define PMIX_NODE_LIST             "pmix.nlist"        // (char*) comma-delimited list of nodes running procs for this job

/* fault tolerance-related info */
#define PMIX_TERMINATE_SESSION     "pmix.term.sess"    // (bool) RM intends to terminate session
#define PMIX_TERMINATE_JOB         "pmix.term.job"     // (bool) RM intends to terminate this job
#define PMIX_TERMINATE_NODE        "pmix.term.node"    // (bool) RM intends to terminate all procs on this node
#define PMIX_TERMINATE_PROC        "pmix.term.proc"    // (bool) RM intends to terminate just this process
#define PMIX_ERROR_ACTION_TIMEOUT  "pmix.err.timeout"  // (int) time in sec before RM will execute error response


/* attributes used by host server to pass data to the server convenience library - the
 * data will then be parsed and provided to the local clients */
#define PMIX_PROC_DATA             "pmix.pdata"        // (pmix_value_array_t) starts with rank, then contains more data
#define PMIX_NODE_MAP              "pmix.nmap"         // (char*) regex of nodes containing procs for this job
#define PMIX_PROC_MAP              "pmix.pmap"         // (char*) regex describing procs on each node within this job

/* attributes used internally to communicate data from the server to the client */
#define PMIX_PROC_BLOB             "pmix.pblob"        // (pmix_byte_object_t) packed blob of process data
#define PMIX_MAP_BLOB              "pmix.mblob"        // (pmix_byte_object_t) packed blob of process location


/****    PMIX ERROR CONSTANTS    ****/
/* PMIx errors are always negative, with 0 reserved for success */
#define PMIX_ERROR_MIN  -41  // set equal to number of non-zero entries in enum

typedef enum {
    PMIX_ERR_UNPACK_READ_PAST_END_OF_BUFFER = PMIX_ERROR_MIN,
    PMIX_ERR_COMM_FAILURE,
    PMIX_ERR_NOT_IMPLEMENTED,
    PMIX_ERR_NOT_SUPPORTED,
    PMIX_ERR_NOT_FOUND,
    PMIX_ERR_SERVER_NOT_AVAIL,
    PMIX_ERR_INVALID_NAMESPACE,
    PMIX_ERR_INVALID_SIZE,
    PMIX_ERR_INVALID_KEYVALP,
    PMIX_ERR_INVALID_NUM_PARSED,

    PMIX_ERR_INVALID_ARGS,
    PMIX_ERR_INVALID_NUM_ARGS,
    PMIX_ERR_INVALID_LENGTH,
    PMIX_ERR_INVALID_VAL_LENGTH,
    PMIX_ERR_INVALID_VAL,
    PMIX_ERR_INVALID_KEY_LENGTH,
    PMIX_ERR_INVALID_KEY,
    PMIX_ERR_INVALID_ARG,
    PMIX_ERR_NOMEM,
    PMIX_ERR_INIT,

    PMIX_ERR_DATA_VALUE_NOT_FOUND,
    PMIX_ERR_OUT_OF_RESOURCE,
    PMIX_ERR_RESOURCE_BUSY,
    PMIX_ERR_BAD_PARAM,
    PMIX_ERR_IN_ERRNO,
    PMIX_ERR_UNREACH,
    PMIX_ERR_TIMEOUT,
    PMIX_ERR_NO_PERMISSIONS,
    PMIX_ERR_PACK_MISMATCH,
    PMIX_ERR_PACK_FAILURE,
    
    PMIX_ERR_UNPACK_FAILURE,
    PMIX_ERR_UNPACK_INADEQUATE_SPACE,
    PMIX_ERR_TYPE_MISMATCH,
    PMIX_ERR_PROC_ENTRY_NOT_FOUND,
    PMIX_ERR_UNKNOWN_DATA_TYPE,
    PMIX_ERR_WOULD_BLOCK,
    PMIX_ERR_READY_FOR_HANDSHAKE,
    PMIX_ERR_HANDSHAKE_FAILED,
    PMIX_ERR_INVALID_CRED,
    PMIX_EXISTS,
    
    PMIX_ERROR,
    PMIX_SUCCESS
} pmix_status_t;


/****    PMIX DATA TYPES    ****/
typedef enum {
    PMIX_UNDEF = 0,
    PMIX_BYTE,           // a byte of data
    PMIX_STRING,         // NULL-terminated string
    PMIX_SIZE,           // size_t
    PMIX_PID,            // OS-pid

    PMIX_INT,
    PMIX_INT8,
    PMIX_INT16,
    PMIX_INT32,
    PMIX_INT64,

    PMIX_UINT,
    PMIX_UINT8,
    PMIX_UINT16,
    PMIX_UINT32,
    PMIX_UINT64,

    PMIX_FLOAT,
    PMIX_DOUBLE,

    PMIX_TIMEVAL,
    PMIX_TIME,

    PMIX_HWLOC_TOPO,
    PMIX_VALUE,
    PMIX_INFO_ARRAY,
    PMIX_PROC,
    PMIX_APP,
    PMIX_INFO,
    PMIX_PDATA,
    PMIX_BUFFER,
    PMIX_BYTE_OBJECT,
    PMIX_KVAL,
    PMIX_MODEX,
    PMIX_PERSIST
} pmix_data_type_t;

/* define a scope for data "put" by PMI per the following:
 *
 * PMI_LOCAL - the data is intended only for other application
 *             processes on the same node. Data marked in this way
 *             will not be included in data packages sent to remote requestors
 * PMI_REMOTE - the data is intended solely for applications processes on
 *              remote nodes. Data marked in this way will not be shared with
 *              other processes on the same node
 * PMI_GLOBAL - the data is to be shared with all other requesting processes,
 *              regardless of location
 */
#define PMIX_SCOPE PMIX_UINT32
typedef enum {
    PMIX_SCOPE_UNDEF = 0,
    PMIX_INTERNAL,        // data used internally only
    PMIX_LOCAL,           // share to procs also on this node
    PMIX_REMOTE,          // share with procs not on this node
    PMIX_GLOBAL,          // share with all procs (local + remote)
    PMIX_NAMESPACE,       // used by Publish to indicate data is available to nspace only
    PMIX_UNIVERSAL,       // used by Publish to indicate data available to all
    PMIX_USER             // used by Publish to indicate data available to all user-owned nspaces
} pmix_scope_t; 

/* define a "persistence" policy for data published by
 * clients to the "global" nspace */
typedef enum {
    PMIX_PERSIST_INDEF = 0,   // retain until specifically deleted
    PMIX_PERSIST_PROC,        // retain until publishing process terminates
    PMIX_PERSIST_APP,         // retain until application terminates
    PMIX_PERSIST_SESSION      // retain until session/allocation terminates
} pmix_persistence_t;


/****    PMIX BYTE OBJECT    ****/
typedef struct {
    char *bytes;
    size_t size;
} pmix_byte_object_t;


/****    PMIX PROC OBJECT    ****/
typedef struct {
    char nspace[PMIX_MAX_NSLEN+1];
    int rank;
} pmix_proc_t;
#define PMIX_PROC_CREATE(m, n)                                  \
    do {                                                        \
        (m) = (pmix_proc_t*)malloc((n) * sizeof(pmix_proc_t));  \
        memset((m), 0, (n) * sizeof(pmix_proc_t));              \
    } while(0);

#define PMIX_PROC_RELEASE(m)                    \
    do {                                        \
        PMIX_PROC_FREE((m));                    \
    } while(0);

#define PMIX_PROC_CONSTRUCT(m)                  \
    do {                                        \
        memset((m), 0, sizeof(pmix_proc_t));    \
    } while(0);

#define PMIX_PROC_DESTRUCT(m)

#define PMIX_PROC_FREE(m, n)                    \
    do {                                        \
        if (NULL != (m)) {                      \
            free((m));                          \
        }                                       \
    } while(0);



/****    PMIX VALUE STRUCT    ****/
struct pmix_info_t;

typedef struct {
    size_t size;
    struct pmix_info_t *array;
} pmix_info_array_t;
/* NOTE: operations can supply a collection of values under
 * a single key by passing a pmix_value_t containing an
 * array of type PMIX_INFO_ARRAY, with each array element
 * containing its own pmix_info_t object */

typedef struct {
    pmix_data_type_t type;
    union {
        uint8_t byte;
        char *string;
        size_t size;
        pid_t pid;
        int integer;
        int8_t int8;
        int16_t int16;
        int32_t int32;
        int64_t int64;
        unsigned int uint;
        uint8_t uint8;
        uint16_t uint16;
        uint32_t uint32;
        uint64_t uint64;
        float fval;
        double dval;
        struct timeval tv;
        pmix_info_array_t array;
        pmix_byte_object_t bo;
    } data;
} pmix_value_t;
/* allocate and initialize a specified number of value structs */
#define PMIX_VALUE_CREATE(m, n)                                         \
    do {                                                                \
        int _ii;                                                        \
        (m) = (pmix_value_t*)malloc((n) * sizeof(pmix_value_t));        \
        memset((m), 0, (n) * sizeof(pmix_value_t));                     \
        for (_ii=0; _ii < (int)(n); _ii++) {                            \
            (m)[_ii].type = PMIX_UNDEF;                                 \
        }                                                               \
    } while(0);

/* release a single pmix_value_t struct, including its data */
#define PMIX_VALUE_RELEASE(m)                                           \
    do {                                                                \
        PMIX_VALUE_DESTRUCT((m));                                       \
        free((m));                                                      \
    } while(0);

/* initialize a single value struct */
#define PMIX_VALUE_CONSTRUCT(m)                 \
    do {                                        \
        memset((m), 0, sizeof(pmix_value_t));   \
        (m)->type = PMIX_UNDEF;                 \
    } while(0);

/* release the memory in the value struct data field */
#define PMIX_VALUE_DESTRUCT(m)                                          \
    do {                                                                \
        if (PMIX_STRING == (m)->type && NULL != (m)->data.string) {     \
            free((m)->data.string);                                     \
        }                                                               \
    } while(0);

#define PMIX_VALUE_FREE(m, n)                           \
    do {                                                \
        size_t _s;                                      \
        if (NULL != (m)) {                              \
            for (_s=0; _s < (n); _s++) {                \
                PMIX_VALUE_DESTRUCT(&((m)[_s]));        \
            }                                           \
            free((m));                                  \
        }                                               \
    } while(0);


/****    PMIX INFO STRUCT    ****/
typedef struct {
    char key[PMIX_MAX_KEYLEN+1];  // ensure room for the NULL terminator
    pmix_value_t value;
} pmix_info_t;

/* utility macros for working with pmix_info_t structs */
#define PMIX_INFO_CREATE(m, n)                                  \
    do {                                                        \
        (m) = (pmix_info_t*)malloc((n) * sizeof(pmix_info_t));  \
        memset((m), 0, (n) * sizeof(pmix_info_t));              \
    } while(0);

#define PMIX_INFO_RELEASE(m)                    \
    do {                                        \
        PMIX_VALUE_DESTRUCT(&(m)->value);       \
        free((m));                              \
    } while(0);

#define PMIX_INFO_CONSTRUCT(m)                  \
    do {                                        \
        memset((m), 0, sizeof(pmix_info_t));    \
        (m)->value.type = PMIX_UNDEF;           \
    } while(0);

#define PMIX_INFO_DESTRUCT(m) \
    do {                                        \
        PMIX_VALUE_DESTRUCT(&(m)->value);       \
    } while(0);

#define PMIX_INFO_FREE(m, n)                    \
    do {                                        \
        size_t _s;                              \
        if (NULL != (m)) {                      \
            for (_s=0; _s < (n); _s++) {        \
                PMIX_INFO_DESTRUCT(&((m)[_s])); \
            }                                   \
            free((m));                          \
        }                                       \
    } while(0);

#define PMIX_INFO_LOAD(m, k, v, t)                      \
    do {                                                \
    if (NULL != (m)) {                                  \
        (void)strncpy((m)->key, (k), PMIX_MAX_KEYLEN);  \
        pmix_value_load(&((m)->value), (v), (t));       \
    } while(0);


/****    PMIX LOOKUP RETURN STRUCT    ****/
typedef struct {
    pmix_proc_t proc;
    char key[PMIX_MAX_KEYLEN+1];  // ensure room for the NULL terminator
    pmix_value_t value;
} pmix_pdata_t;

/* utility macros for working with pmix_pdata_t structs */
#define PMIX_PDATA_CREATE(m, n)                                         \
    do {                                                                \
        (m) = (pmix_pdata_t*)malloc((n) * sizeof(pmix_pdata_t));        \
        memset((m), 0, (n) * sizeof(pmix_pdata_t));                     \
    } while(0);

#define PMIX_PDATA_RELEASE(m)                   \
    do {                                        \
        PMIX_VALUE_DESTRUCT(&(m)->value);       \
        free((m));                              \
    } while(0);

#define PMIX_PDATA_CONSTRUCT(m)                 \
    do {                                        \
        memset((m), 0, sizeof(pmix_pdata_t));   \
        (m)->value.type = PMIX_UNDEF;           \
    } while(0);

#define PMIX_PDATA_DESTRUCT(m)                  \
    do {                                        \
        PMIX_VALUE_DESTRUCT(&(m)->value);       \
    } while(0);

#define PMIX_PDATA_FREE(m, n)                           \
    do {                                                \
        size_t _s;                                      \
        if (NULL != (m)) {                              \
            for (_s=0; _s < (n); _s++) {                \
                PMIX_PDATA_DESTRUCT(&((m)[_s]));        \
            }                                           \
            free((m));                                  \
        }                                               \
    } while(0);

#define PMIX_PDATA_LOAD(m, p, k, v, t)                                  \
    do {                                                                \
    if (NULL != (m)) {                                                  \
        (void)strncpy((m)->proc.nspace, (p)->nspace, PMIX_MAX_NSLEN);   \
        (m)->proc.rank = (p)->rank;                                     \
        (void)strncpy((m)->key, (k), PMIX_MAX_KEYLEN);                  \
        pmix_value_load(&((m)->value), (v), (t));                       \
    } while(0);


/****    PMIX APP STRUCT    ****/
typedef struct {
    char *cmd;
    int argc;
    char **argv;
    char **env;
    int maxprocs;
    pmix_info_t *info;
    size_t ninfo;
} pmix_app_t;
/* utility macros for working with pmix_app_t structs */
#define PMIX_APP_CREATE(m, n)                                   \
    do {                                                        \
        (m) = (pmix_app_t*)malloc((n) * sizeof(pmix_app_t));    \
        memset((m), 0, (n) * sizeof(pmix_app_t));               \
    } while(0);

#define PMIX_APP_RELEASE(m)                     \
    do {                                        \
        PMIX_APP_DESTRUCT((m));                 \
        free((m));                              \
    } while(0);

#define PMIX_APP_CONSTRUCT(m)                   \
    do {                                        \
        memset((m), 0, sizeof(pmix_app_t));     \
    } while(0);

#define PMIX_APP_DESTRUCT(m)                                    \
    do {                                                        \
        size_t _ii;                                             \
        if (NULL != (m)->cmd) {                                 \
            free((m)->cmd);                                     \
        }                                                       \
        if (NULL != (m)->argv) {                                \
            for (_ii=0; NULL != (m)->argv[_ii]; _ii++) {        \
                free((m)->argv[_ii]);                           \
            }                                                   \
            free((m)->argv);                                    \
        }                                                       \
        if (NULL != (m)->env) {                                 \
            for (_ii=0; NULL != (m)->env[_ii]; _ii++) {         \
                free((m)->env[_ii]);                            \
            }                                                   \
            free((m)->env);                                     \
        }                                                       \
        if (NULL != (m)->info) {                                \
            for (_ii=0; _ii < (m)->ninfo; _ii++) {              \
                PMIX_INFO_DESTRUCT(&(m)->info[_ii]);            \
            }                                                   \
        }                                                       \
    } while(0);    

#define PMIX_APP_FREE(m, n)                     \
    do {                                        \
        size_t _s;                              \
        if (NULL != (m)) {                      \
            for (_s=0; _s < (n); _s++) {        \
                PMIX_APP_DESTRUCT(&((m)[_s]));  \
            }                                   \
            free((m));                          \
        }                                       \
    } while(0);

/****    PMIX MODEX STRUCT    ****/
typedef struct {
    char nspace[PMIX_MAX_NSLEN+1];
    int rank;
    uint8_t *blob;
    size_t size;
} pmix_modex_data_t;
/* utility macros for working with pmix_modex_t structs */
#define PMIX_MODEX_CREATE(m, n)                                         \
    do {                                                                \
        (m) = (pmix_modex_data_t*)malloc((n) * sizeof(pmix_modex_data_t)); \
        memset((m), 0, (n) * sizeof(pmix_modex_data_t));                \
    } while(0);

#define PMIX_MODEX_RELEASE(m)                   \
    do {                                        \
        PMIX_MODEX_DESTRUCT((m));               \
        free((m));                              \
    } while(0);

#define PMIX_MODEX_CONSTRUCT(m)                         \
    do {                                                \
        memset((m), 0, sizeof(pmix_modex_data_t));      \
    } while(0);

#define PMIX_MODEX_DESTRUCT(m)                  \
    do {                                        \
        if (NULL != (m)->blob) {                \
            free((m)->blob);                    \
        }                                       \
    } while(0);

#define PMIX_MODEX_FREE(m, n)                           \
    do {                                                \
        size_t _s;                                      \
        if (NULL != (m)) {                              \
            for (_s=0; _s < (n); _s++) {                \
                PMIX_MODEX_DESTRUCT(&((m)[_s]));        \
            }                                           \
            free((m));                                  \
        }                                               \
    } while(0);


/****    CALLBACK FUNCTIONS FOR NON-BLOCKING OPERATIONS    ****/

/* define a callback function that is solely used by servers, and
 * not clients, to return modex data in response to "fence" and "get"
 * operations. The returned blob contains the data collected from each
 * server participating in the operation. */
typedef void (*pmix_modex_cbfunc_t)(pmix_status_t status,
                                    const char *data, size_t ndata,
                                    void *cbdata);

/* define a callback function for calls to PMIx_Spawn_nb - the function
 * will be called upon completion of the spawn command. The status
 * will indicate whether or not the spawn succeeded. The nspace
 * of the spawned processes will be returned, along with any provided
 * callback data. Note that the returned nspace value will be
 * released by the library upon return from the callback function, so
 * the receiver must copy it if it needs to be retained */
typedef void (*pmix_spawn_cbfunc_t)(pmix_status_t status,
                                    char nspace[], void *cbdata);

/* define a callback for common operations that simply return
 * a status. Examples include the non-blocking versions of
 * Fence, Connect, and Disconnect */
typedef void (*pmix_op_cbfunc_t)(pmix_status_t status, void *cbdata);

/* define a callback function for calls to PMIx_Lookup_nb - the
 * function will be called upon completion of the command with the
 * status indicating the success of failure of the request. Any
 * retrieved data will be returned in an array of pmix_pdata_t structs.
 * The nspace/rank of the process that provided each data element is
 * also returned.
 *
 * Note that these structures will be released upon return from
 * the callback function, so the receiver must copy/protect the
 * data prior to returning if it needs to be retained */

typedef void (*pmix_lookup_cbfunc_t)(pmix_status_t status,
                                     pmix_pdata_t data[], size_t ndata,
                                     void *cbdata);

/* define a callback function for the errhandler. Upon receipt of an
 * error notification, PMIx will execute the specified notification
 * callback function, providing:
 *
 * status - the error that occurred
 * procs -  the nspace and ranks of the affected processes. A NULL
 *          value indicates that the error occurred in the PMIx
 *          client library within this process itself
 * nprocs - the number of procs in the provided array
 * info - any additional info provided regarding the error.
 * ninfo - the number of info objects in the provided array
 *
 * Note that different resource managers may provide differing levels
 * of support for error notification to application processes. Thus, the
 * info array may be NULL or may contain detailed information of the error.
 * It is the responsibility of the application to parse any provided info array
 * for defined key-values if it so desires.
 *
 * Possible uses of the pmix_info_t object include:
 *
 * - for the RM to alert the process as to planned actions, such as
 *   to abort the session, in response to the reported error
 *
 * - provide a timeout for alternative action to occur, such as for
 *   the application to request an alternate response to the error
 *
 * For example, the RM might alert the application to the failure of
 * a node that resulted in termination of several processes, and indicate
 * that the overall session will be aborted unless the application
 * requests an alternative behavior in the next 5 seconds. The application
 * then has time to respond with a checkpoint request, or a request to
 * recover from the failure by obtaining replacement nodes and restarting
 * from some earlier checkpoint.
 *
 * Support for these options is left to the discretion of the host RM. Info
 * keys are included in the common definions above, but also may be augmented
 * on a per-RM basis.
 *
 * On the server side, the notification function is used to inform the host
 * server of a detected error in the PMIx subsystem and/or client */
typedef void (*pmix_notification_fn_t)(pmix_status_t status,
                                       pmix_proc_t procs[], size_t nprocs,
                                       pmix_info_t info[], size_t ninfo);

/* define a callback function for calls to PMIx_Get_nb. The status
 * indicates if the requested data was found or not - a pointer to the
 * pmix_value_t structure containing the found data is returned. The
 * pointer will be NULL if the requested data was not found. */ 
typedef void (*pmix_value_cbfunc_t)(pmix_status_t status,
                                    pmix_value_t *kv, void *cbdata);

/****    COMMON SUPPORT FUNCTIONS    ****/
/* Register an errhandler to report errors. Two types of errors
 * will be reported:
 *
 * (a) those that occur within the client library, but are not
 *     reportable via the API itself (e.g., loss of connection to
 *     the server). These errors typically occur during behind-the-scenes
 *     non-blocking operations.
 *
 * (b) job-related errors such as the failure of another process in
 *     the job or in any connected job, impending failure of hardware
 *     within the job's usage footprint, etc.
 *
 * See pmix_common.h for a description of the notification function */
void PMIx_Register_errhandler(pmix_notification_fn_t errhandler);

/* deregister the errhandler */
void PMIx_Deregister_errhandler(void);

/* Provide a string representation of a pmix_status_t value. Note
 * that the provided string is statically defined and must NOT be
 * free'd */
const char* PMIx_Error_string(pmix_status_t status);

/* Get the PMIx version string. Note that the provided string is
 * statically defined and must NOT be free'd  */
const char* PMIx_Get_version(void);


/* Key-Value pair management macros */
// TODO: add all possible types/fields here.

#define PMIX_VAL_FIELD_int(x) ((x)->data.integer)
#define PMIX_VAL_FIELD_uint32_t(x) ((x)->data.uint32)
#define PMIX_VAL_FIELD_uint16_t(x) ((x)->data.uint16)
#define PMIX_VAL_FIELD_string(x) ((x)->data.string)
#define PMIX_VAL_FIELD_float(x) ((x)->data.fval)

#define PMIX_VAL_TYPE_int    PMIX_INT
#define PMIX_VAL_TYPE_uint32_t PMIX_UINT32
#define PMIX_VAL_TYPE_uint16_t PMIX_UINT16
#define PMIX_VAL_TYPE_string PMIX_STRING
#define PMIX_VAL_TYPE_float  PMIX_FLOAT

#define PMIX_VAL_set_assign(_v, _field, _val )   \
    do {                                                            \
        (_v)->type = PMIX_VAL_TYPE_ ## _field;                      \
        PMIX_VAL_FIELD_ ## _field((_v)) = _val;                     \
    } while(0);

#define PMIX_VAL_set_strdup(_v, _field, _val )       \
    do {                                                                \
        (_v)->type = PMIX_VAL_TYPE_ ## _field;                          \
        PMIX_VAL_FIELD_ ## _field((_v)) = strdup(_val);                 \
    } while(0);

#define PMIX_VAL_SET_int     PMIX_VAL_set_assign
#define PMIX_VAL_SET_uint32_t  PMIX_VAL_set_assign
#define PMIX_VAL_SET_uint16_t  PMIX_VAL_set_assign
#define PMIX_VAL_SET_string  PMIX_VAL_set_strdup
#define PMIX_VAL_SET_float   PMIX_VAL_set_assign

#define PMIX_VAL_SET(_v, _field, _val )   \
    PMIX_VAL_SET_ ## _field(_v, _field, _val)

#define PMIX_VAL_cmp_val(_val1, _val2)      ((_val1) != (_val2))
#define PMIX_VAL_cmp_float(_val1, _val2)    (abs((_val1) - (_val2)) > 0.000001)
#define PMIX_VAL_cmp_ptr(_val1, _val2)      strncmp(_val1, _val2, strlen(_val1)+1)

#define PMIX_VAL_CMP_int     PMIX_VAL_cmp_val
#define PMIX_VAL_CMP_uint32_t     PMIX_VAL_cmp_val
#define PMIX_VAL_CMP_uint16_t     PMIX_VAL_cmp_val
#define PMIX_VAL_CMP_float     PMIX_VAL_cmp_float
#define PMIX_VAL_CMP_string     PMIX_VAL_cmp_ptr

#define PMIX_VAL_CMP(_field, _val1, _val2) \
    PMIX_VAL_CMP_ ## _field(_val1, _val2)

#define PMIX_VAL_FREE(_v) \
     PMIx_free_value_data(_v)

END_C_DECLS
#endif
