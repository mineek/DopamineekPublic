//#import <os/atomic_private.h>
//#import <libjailbreak.h>
//#import <physrw.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/primitives_IOSurface.h>
#import <libjailbreak/physrw_pte.h>
#import <libjailbreak/physrw.h>
#import <libjailbreak/translation.h>
#import <libjailbreak/kernel.h>
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/trustcache.h>
#import <libjailbreak/kalloc_pt.h>
#import <libjailbreak/jbserver_boomerang.h>
#import <libjailbreak/signatures.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/kcall_arm64.h>
#import <sys/event.h>

#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))

#define NULLVP NULL
#define XNU_PTRAUTH_SIGNED_PTR(A)
#define MNTK_SYSTEM             0x00000040
#define MNTK_VIRTUALDEV         0x00200000
#define VROOT           0x000001
#define VSYSTEM         0x000004
#define VMOUNT          0x000080
#define VMOUNTEDHERE   0x40000000
#define VNODE_REF_FORCE 0x1

#define v_mountedhere   v_un.vu_mountedhere
#define v_socket        v_un.vu_socket
#define v_specinfo      v_un.vu_specinfo
#define v_fifoinfo      v_un.vu_fifoinfo
#define v_ubcinfo       v_un.vu_ubcinfo
#define v_rdev v_specinfo->si_rdev

#define panic(...) do { printf(__VA_ARGS__); printf("\n"); abort(); } while (0)
#define vnode_lock_convert(v)   lck_mtx_convert_spin(&(v)->v_lock)

const off_t
  off_p_pfd = 0xf8,
  off_fd_cdir = 0x20,
  off_fg_data = 0x38,
  off_fp_glob = 0x10;

LIST_HEAD(buflists, buf);
typedef int kauth_action_t;
typedef uint32_t vfs_switch_root_flags_t;
typedef uintptr_t __smrq_link_t;
typedef uint64_t lck_mtx_t[2];
typedef uint32_t  pending_io_t;
typedef int64_t daddr64_t;

dev_t *rootdev_p;
vnode_t *rootvnode_p, *rootvp_p;

enum vtype      {
	/* 0 */
	VNON,
	/* 1 - 5 */
	VREG, VDIR, VBLK, VCHR, VLNK,
	/* 6 - 10 */
	VSOCK, VFIFO, VBAD, VSTR, VCPLX
};

typedef struct {
	uintptr_t               opaque[2] __kernel_data_semantics;
} lck_rw_t;

struct smrq_link {
	__smrq_link_t           next;
	__smrq_link_t          *prev;
};

TAILQ_HEAD(vnodelst, vnode);
struct mount {
	TAILQ_ENTRY(mount)      mnt_list;                   /* mount list */
	int32_t                 mnt_count;                  /* reference on the mount */
	lck_mtx_t               mnt_mlock;                  /* mutex that protects mount point */
	const struct vfsops     * XNU_PTRAUTH_SIGNED_PTR("mount.vfsops") mnt_op;        /* operations on fs */
	struct vfstable         * XNU_PTRAUTH_SIGNED_PTR("mount.mnt_vtable") mnt_vtable;        /* configuration info */
	struct vnode            * XNU_PTRAUTH_SIGNED_PTR("mount.mnt_vnodecovered") mnt_vnodecovered;    /* vnode we mounted on */
	struct vnodelst         mnt_vnodelist;              /* list of vnodes this mount */
	struct vnodelst         mnt_workerqueue;            /* list of vnodes this mount */
	struct vnodelst         mnt_newvnodes;              /* list of vnodes this mount */
	uint32_t                mnt_flag;                   /* flags */
	uint32_t                mnt_kern_flag;              /* kernel only flags.  NOTE: See mnt_supl_kern_flags below! */
	uint32_t                mnt_compound_ops;           /* Available compound operations */
	uint32_t                mnt_lflag;                  /* mount life cycle flags */
	uint32_t                mnt_maxsymlinklen;          /* max size of short symlink */
	struct vfsstatfs        mnt_vfsstat;                /* cache of filesystem stats */
	qaddr_t                 mnt_data;                   /* private data */
	/* Cached values of the IO constraints for the device */
	uint32_t                mnt_maxreadcnt;             /* Max. byte count for read */
	uint32_t                mnt_maxwritecnt;            /* Max. byte count for write */
	uint32_t                mnt_segreadcnt;             /* Max. segment count for read */
	uint32_t                mnt_segwritecnt;            /* Max. segment count for write */
	uint32_t                mnt_maxsegreadsize;         /* Max. segment read size  */
	uint32_t                mnt_maxsegwritesize;        /* Max. segment write size */
	uint32_t                mnt_alignmentmask;          /* Mask of bits that aren't addressable via DMA */
	uint32_t                mnt_devblocksize;           /* the underlying device block size */
	uint32_t                mnt_ioqueue_depth;          /* the maxiumum number of commands a device can accept */
	uint32_t                mnt_ioscale;                /* scale the various throttles/limits imposed on the amount of I/O in flight */
	uint32_t                mnt_ioflags;                /* flags for  underlying device */
	uint32_t                mnt_minsaturationbytecount; /* if non-zero, mininum amount of writes (in bytes) needed to max out throughput */
	pending_io_t            mnt_pending_write_size __attribute__((aligned(sizeof(pending_io_t))));  /* byte count of pending writes */
	pending_io_t            mnt_pending_read_size  __attribute__((aligned(sizeof(pending_io_t))));  /* byte count of pending reads */
	struct timeval          mnt_last_write_issued_timestamp;
	struct timeval          mnt_last_write_completed_timestamp;
	int64_t                 mnt_max_swappin_available;

	lck_rw_t                mnt_rwlock;                 /* mutex readwrite lock */
	lck_mtx_t               mnt_renamelock;             /* mutex that serializes renames that change shape of tree */
	vnode_t                 mnt_devvp;                  /* the device mounted on for local file systems */
	uint32_t                mnt_devbsdunit;             /* the BSD unit number of the device */
	uint64_t                mnt_throttle_mask;          /* the throttle mask of what devices will be affected by I/O from this mnt */
	void                    *mnt_throttle_info;         /* used by the throttle code */
	int32_t                 mnt_crossref;               /* refernces to cover lookups  crossing into mp */
	int32_t                 mnt_iterref;                /* refernces to cover iterations; drained makes it -ve  */
   //...
};

struct  namecache {
	TAILQ_ENTRY(namecache)  nc_entry;       /* chain of all entries */
	TAILQ_ENTRY(namecache)  nc_child;       /* chain of ncp's that are children of a vp */
	union {
		LIST_ENTRY(namecache)  nc_link; /* chain of ncp's that 'name' a vp */
		TAILQ_ENTRY(namecache) nc_negentry; /* chain of ncp's that 'name' a vp */
	} nc_un;
	struct smrq_link        nc_hash;        /* hash chain */
	uint32_t                nc_vid;         /* vid for nc_vp */
	uint32_t                nc_counter;     /* flags */
	vnode_t                 nc_dvp;         /* vnode of parent of name */
	vnode_t                 nc_vp;          /* vnode the name refers to */
	unsigned int            nc_hashval;     /* hashval of stringname */
	const char              *nc_name;       /* pointer to segment name in string cache */
};

struct specinfo {
	struct  vnode **si_hashchain;
	struct  vnode *si_specnext;
	long    si_flags;
	dev_t   si_rdev;
	int32_t si_opencount;
	daddr_t si_size;                /* device block size in bytes */
	daddr64_t       si_lastr;       /* last read blkno (read-ahead) */
	u_int64_t       si_devsize;     /* actual device size in bytes */

	u_int8_t        si_initted;
	u_int8_t        si_throttleable;
	u_int16_t       si_isssd;
	u_int32_t       si_devbsdunit;
	u_int64_t       si_throttle_mask;
	thread_t        si_mountingowner;
};

struct vnode {
    lck_mtx_t v_lock;
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;         /* vnodes for mount point */
    TAILQ_HEAD(, namecache) v_ncchildren;   /* name cache entries that regard us as their parent */
    LIST_HEAD(, namecache) v_nclinks;       /* name cache entries that name this vnode */
    uint64_t v_defer_reclaimlist;
    uint32_t v_listflag;
    uint32_t v_flag;
    uint16_t v_lflag;
    uint8_t v_iterblkflags;
    uint8_t v_references;
    int32_t v_kusecount;
    int32_t v_usecount;
    int32_t v_iocount;
    uint64_t v_owner;
    uint16_t v_type;
    uint16_t v_tag;
    uint32_t v_id;
    union {
        mount_t vu_mountedhere;
        uint64_t vu_socket;
        struct specinfo *vu_specinfo;
        uint64_t vu_fifoinfo;
        uint64_t vu_ubcinfo;
    } v_un;
    struct buflists v_cleanblkhd;
    struct buflists v_dirtyblkhd;
    struct klist v_knotes;
    kauth_cred_t    /* XNU_PTRAUTH_SIGNED_PTR("vnode.v_cred")*/ v_cred;
    kauth_action_t  v_authorized_actions;
    int             v_cred_timestamp;
    int             v_nc_generation;
    int32_t         v_numoutput;
    int32_t         v_writecount;
    uint32_t        v_holdcount;
    const char *v_name;
    vnode_t /* XNU_PTRAUTH_SIGNED_PTR("vnode.v_parent") */ v_parent;
    struct lockf *v_lockf;
    int(**v_op)(void *);
    mount_t /* XNU_PTRAUTH_SIGNED_PTR("vnode.v_mount") */ v_mount;
    void *v_data;              
};
typedef struct vnode * vnode_t;

extern TAILQ_HEAD(mntlist, mount) mountlist;
