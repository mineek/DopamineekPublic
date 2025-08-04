//
//  DOFakeFS.m
//  Dopamine
//
//  Created by Mineek on 22/07/2024.
//

#import <Foundation/Foundation.h>
#import "DOJailbreaker.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOUIManager.h"
#import <sys/stat.h>
#import <compression.h>
#import <xpf/xpf.h>
#import <dlfcn.h>
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
#import <CoreServices/LSApplicationProxy.h>
#import <sys/utsname.h>
#import "spawn.h"
#import "DOMineek.h"
#import <sys/mount.h>
#import "structs.h"
#import "mount_args.h"

uint64_t vfs_context_kernel(void) {
    return gSystemInfo.kernelConstant.slide + ADDR_vfs_context_kernel;
}

uint64_t vnode_lookup(const char *path, int flags, vnode_t *vnode, uint64_t vfs_context) {
    uint64_t vnode_lookup = gSystemInfo.kernelConstant.slide + ADDR_vnode_lookup;
    uint64_t out;
    uint64_t out_vnode_mem;
    kalloc(&out_vnode_mem, sizeof(uint64_t));
    uint64_t path_kernel;
    kalloc(&path_kernel, strlen(path) + 1);
    kwritebuf(path_kernel, path, strlen(path));
    out = kcallmineek(vnode_lookup, (uint64_t)path_kernel, flags, out_vnode_mem, vfs_context, 0, 0, 0);
    *vnode = (vnode_t)kread64(out_vnode_mem);
    return out;
}

uint64_t vnode_lookupat(const char *path, int flags, vnode_t *vnode, uint64_t ctx, uint64_t start_dvp) {
    uint64_t vnode_lookupat = gSystemInfo.kernelConstant.slide + ADDR_vnode_lookupat;
    uint64_t out;
    uint64_t out_vnode_mem;
    kalloc(&out_vnode_mem, sizeof(uint64_t));
    uint64_t path_kernel;
    kalloc(&path_kernel, strlen(path) + 1);
    kwritebuf(path_kernel, path, strlen(path));
    out = kcallmineek(vnode_lookupat, (uint64_t)path_kernel, flags, out_vnode_mem, ctx, start_dvp, 0, 0);
    *vnode = (vnode_t)kread64(out_vnode_mem);
    kfree(out_vnode_mem, sizeof(uint64_t));
    return out;
}

uint64_t vnode_vtype(vnode_t vnode) {
//    printf("0x%llx\n", (uint64_t)vnode);
//    printf("0x%llx\n", (uint64_t)&vnode->v_type);
//    sleep(1);
    return kread64((uint64_t)&vnode->v_type);
}

uint64_t vnode_ref_ext(vnode_t vp, int fmode, int flags) {
    uint64_t vnode_ref_ext = gSystemInfo.kernelConstant.slide + ADDR_vnode_ref_ext;
    uint64_t out;
    out = kcallmineek(vnode_ref_ext, (uint64_t)vp, fmode, flags, 0, 0, 0, 0);
    return out;
}

#define rootvnode_addr (gSystemInfo.kernelConstant.slide + ADDR_rootvnode_addr)
#define rootvp_addr (gSystemInfo.kernelConstant.slide + ADDR_rootvp_addr)
#define rootdev_addr (gSystemInfo.kernelConstant.slide + ADDR_rootdev_addr)

void set_rootvnode(uint64_t new_rootvnode) {
    printf("Setting rootvnode to 0x%llx\n", new_rootvnode);
    uint64_t new_mount = kread64(new_rootvnode + 0xd8);
    uint64_t new_devvp = kread64(new_mount + 0x980);
//    uint64_t old_rootvnode = kread_ptr(rootvnode_addr);

    kwrite32(new_rootvnode + 0x54, kread32(new_rootvnode + 0x54) | 0x1); // VROOT
    kwrite64(rootvp_addr, new_devvp); // rootvp
    kwrite64(rootvnode_addr, new_rootvnode); // rootvnode
    kwrite64(proc_find(0) + 0x120, new_rootvnode); // fd_fd_cdir

    kwrite32(rootdev_addr, kread32(kread_ptr(new_devvp + 0x78) + 0x18));
}

void vfs_setmntsystem(mount_t mp) {
    kwrite32((uint64_t)mp + 0x74, kread32((uint64_t)mp + 0x74) | 0x40);
}

uint64_t vnode_put(vnode_t vp) {
    uint64_t vnode_put = gSystemInfo.kernelConstant.slide + ADDR_vnode_put;
    uint64_t out;
    out = kcallmineek(vnode_put, (uint64_t)vp, 0, 0, 0, 0, 0, 0);
    return out;
}

uint64_t vnode_rele(vnode_t vp) {
    uint64_t vnode_rele = gSystemInfo.kernelConstant.slide + ADDR_vnode_rele;
    uint64_t out;
    out = kcallmineek(vnode_rele, (uint64_t)vp, 0, 0, 0, 0, 0, 0);
    return out;
}

uint64_t
verify_incoming_rootfs(vnode_t incoming_rootvnodep, uint64_t ctx,
    vfs_switch_root_flags_t flags)
{
    mount_t mp;
//    vnode_t tdp;
    vnode_t incoming_rootvnode_with_iocount = incoming_rootvnodep;
    vnode_t incoming_rootvnode_with_usecount = NULLVP;
    uint64_t error = 0;
    
//    if (vnode_vtype(incoming_rootvnode_with_iocount) != VDIR) {
//        printf("Incoming rootfs path not a directory\n");
//        sleep(1);
//        error = ENOTDIR;
//        goto done;
//    }
    
//    printf("found 3\n");
//    sleep(1);
    
    /*
     * Before we call VFS_ROOT, we have to let go of the iocount already
     * acquired, but before doing that get a usecount.
     */
    vnode_ref_ext(incoming_rootvnode_with_iocount, 0, VNODE_REF_FORCE);
//    printf("found 4\n");
//    sleep(1);
    incoming_rootvnode_with_usecount = incoming_rootvnode_with_iocount;
//    printf("found 5\n");
//    sleep(1);
    // if ((mp = incoming_rootvnode_with_usecount->v_mount)) {
    mp = (mount_t)kread64((uint64_t)incoming_rootvnode_with_usecount + 0xd8);
//    printf("found 6\n");
//    sleep(1);
    if (mp) {
        printf("mp: 0x%llx\n", (uint64_t)mp);
        //        mp->mnt_crossref++;
        kwrite32((uint64_t)&mp->mnt_crossref, kread32((uint64_t)&mp->mnt_crossref) + 1);
        //        vnode_unlock(incoming_rootvnode_with_usecount);
//        printf("found 7\n");
//        sleep(1);
    } else {
        //        vnode_unlock(incoming_rootvnode_with_usecount);
        printf("Incoming rootfs root vnode does not have associated mount\n");
        error = ENOTDIR;
        goto done;
    }
    
    vnode_put(incoming_rootvnode_with_iocount);
//    printf("found 8\n");
//    sleep(1);
    incoming_rootvnode_with_iocount = NULLVP;
    
    //    error = VFS_ROOT(mp, &tdp, ctx);
    
    out:
//    vnode_lock(incoming_rootvnode_with_usecount);
//    mp->mnt_crossref--;
    kwrite32((uint64_t)&mp->mnt_crossref, kread32((uint64_t)&mp->mnt_crossref) - 1);
//    printf("found 10\n");
//    sleep(1);
    // if (mp->mnt_crossref < 0) {
    if (kread32((uint64_t)&mp->mnt_crossref) < 0) {
        panic("mount cross refs -ve");
    }
//    printf("found 9\n");
//    sleep(1);
//    vnode_unlock(incoming_rootvnode_with_usecount);
    
done:
    if (incoming_rootvnode_with_usecount) {
        vnode_rele(incoming_rootvnode_with_usecount);
        incoming_rootvnode_with_usecount = NULLVP;
    }
    
    if (error && incoming_rootvnode_with_iocount) {
        vnode_put(incoming_rootvnode_with_iocount);
        incoming_rootvnode_with_iocount = NULLVP;
    }
    
//    *incoming_rootvnodep = incoming_rootvnode_with_iocount;
    printf("err: %llx\n", error);
    return error;
}

uint64_t
vfs_switch_root(const char *incoming_vol_old_path,
    const char *outgoing_vol_new_path,
    vfs_switch_root_flags_t flags)
{
    // grumble grumble
#define countof(x) (sizeof(x) / sizeof(x[0]))
    
    struct preserved_mount {
        vnode_t pm_rootvnode;
        mount_t pm_mount;
        vnode_t pm_new_covered_vp;
        vnode_t pm_old_covered_vp;
        const char *pm_path;
    };
    
    uint64_t ctx = vfs_context_kernel();
    vnode_t incoming_rootvnode = NULLVP;
    vnode_t outgoing_vol_new_covered_vp = NULLVP;
    vnode_t incoming_vol_old_covered_vp = NULLVP;
    mount_t outgoing = NULL;
    mount_t incoming = NULL;
    
    struct preserved_mount devfs = { 0, 0, 0, 0, "dev" };
    struct preserved_mount preboot = { 0, 0, 0, 0, "private/preboot" };
    // struct preserved_mount developer = { 0, 0, 0, 0, "Developer" };
    struct preserved_mount var = { 0, 0, 0, 0, "var" };
    struct preserved_mount msu = { 0, 0, 0, 0, "private/var/MobileSoftwareUpdate" };
    struct preserved_mount baseband = { 0, 0, 0, 0, "private/var/wireless/baseband_data" };
    struct preserved_mount hardware = { 0, 0, 0, 0, "private/var/hardware" };
    struct preserved_mount xarts = { 0, 0, 0, 0, "private/xarts" };
    struct preserved_mount factorydata = { 0, 0, 0, 0, "System/Library/Caches/com.apple.factorydata" };
    //struct preserved_mount usr_lib = { 0, 0, 0, 0, "usr/lib" };
    
    // only on iPhone X, uncomment and add if u have an iphone x.
    // struct preserved_mount referenceframes = {0,0,0,0, "/System/Library/Pearl/ReferenceFrames"};
    
    struct preserved_mount *preserved[8];
    preserved[0] = &devfs;
    preserved[1] = &preboot;
    preserved[2] = &var;
    preserved[3] = &msu;
    preserved[4] = &baseband;
    preserved[5] = &hardware;
    preserved[6] = &xarts;
    preserved[7] = &factorydata;
    // preserved[8] = &referenceframes;
    
    uint64_t error;
    
    printf("%s : shuffling mount points : %s <-> / <-> %s\n", __FUNCTION__, incoming_vol_old_path, outgoing_vol_new_path);
    
    if (outgoing_vol_new_path[0] == '/') {
        // I should have written this to be more helpful and just advance the pointer forward past the slash
        printf("Do not use a leading slash in outgoing_vol_new_path\n");
        return EINVAL;
    }
    
    //    sleep(1);
    
    // Set incoming_rootvnode.
    // Find the vnode representing the mountpoint of the new root
    // filesystem. That will be the new root directory.
    error = vnode_lookup(incoming_vol_old_path, 0, &incoming_rootvnode, ctx);
    if (error) {
        printf("Incoming rootfs root vnode not found\n");
        error = ENOENT;
        goto done;
    }
    
//    printf("found 1\n");
//    printf("0x%llx\n", (uint64_t)incoming_rootvnode);
//    printf("0x%llx\n", (uint64_t)&incoming_rootvnode);
//    printf("0x%llx\n", (uint64_t)&incoming_rootvnode->v_flag);
//    printf("0x%llx\n", (uint64_t)&incoming_rootvnode->v_type);
    //    sleep(1);
    
    /*
     * This function drops the icoount and sets the vnode to NULL on error.
     */
    error = verify_incoming_rootfs(incoming_rootvnode, ctx, flags);
    if (error) {
        goto done;
    }
    
//    printf("found 2\n");
    //    sleep(1);
    
    /*
     * Set outgoing_vol_new_covered_vp.
     * Find the vnode representing the future mountpoint of the old
     * root filesystem, inside the directory incoming_rootvnode.
     * Right now it's at "/incoming_vol_old_path/outgoing_vol_new_path".
     * soon it will become "/oldrootfs_path_after", which will be covered.
     */
    error = vnode_lookupat(outgoing_vol_new_path, 0, &outgoing_vol_new_covered_vp, ctx, (uint64_t)incoming_rootvnode);
    if (error) {
        printf("Outgoing rootfs path not found, abandoning / switch, error = %llx\n", error);
        error = ENOENT;
        goto done;
    }
    
    /*
     * Find the preserved mounts - see if they are mounted. Get their root
     * vnode if they are. If they aren't, leave rootvnode NULL which will
     * be the signal to ignore this mount later on.
     *
     * Also get preserved mounts' new_covered_vp.
     * Find the node representing the folder "dev" inside the directory newrootvnode.
     * Right now it's at "/incoming_vol_old_path/dev".
     * Soon it will become /dev, which will be covered by the devfs mountpoint.
     */
    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        
        error = vnode_lookupat(pmi->pm_path, 0, &pmi->pm_rootvnode, ctx, kread_ptr(rootvnode_addr));
        if (error) {
            printf("skipping preserved mountpoint because not found or error: %llx: %s\n", error, pmi->pm_path);
            // not fatal. try the next one in the list.
            continue;
        }
//        printf("found frcoal\n");
        
        error = vnode_lookupat(pmi->pm_path, 0, &pmi->pm_new_covered_vp, ctx, (uint64_t)incoming_rootvnode);
        if (error) {
            printf("preserved new mount directory not found or error: %llx: %s\n", error, pmi->pm_path);
            error = ENOENT;
            goto done;
        }

        printf("will preserve mountpoint across pivot: /%s\n", pmi->pm_path);
    }
    
    /*
     * --
     * At this point, everything has been prepared and all error conditions
     * have been checked. We check everything we can before this point;
     * from now on we start making destructive changes, and we can't stop
     * until we reach the end.
     * ----
     */
    
    /* this usecount is transferred to the mnt_vnodecovered */
    vnode_ref_ext(outgoing_vol_new_covered_vp, 0, VNODE_REF_FORCE);
    /* this usecount is transferred to set_rootvnode */
    vnode_ref_ext(incoming_rootvnode, 0, VNODE_REF_FORCE);
    
    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == NULLVP) {
            continue;
        }
        
        /* this usecount is transferred to the mnt_vnodecovered */
        vnode_ref_ext(pmi->pm_new_covered_vp, 0, VNODE_REF_FORCE);
        
        /* The new_covered_vp is a mountpoint from now on. */
        //        vnode_lock_spin(pmi->pm_new_covered_vp);
        kwrite32((uint64_t)&pmi->pm_new_covered_vp->v_flag, kread32((uint64_t)&pmi->pm_new_covered_vp->v_flag) | VMOUNTEDHERE);
    }
    
    kwrite32((uint64_t)&outgoing_vol_new_covered_vp->v_flag, kread32((uint64_t)&outgoing_vol_new_covered_vp->v_flag) | VMOUNTEDHERE);
    
    /*
     * Identify the mount_ts of the mounted filesystems that are being
     * manipulated: outgoing rootfs, incoming rootfs, and the preserved
     * mounts.
     */
    outgoing = (mount_t)kread64((uint64_t)kread_ptr(rootvnode_addr) + 0xd8);
    incoming = (mount_t)kread64((uint64_t)incoming_rootvnode + 0xd8);
    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == NULLVP) {
            continue;
        }
        
        pmi->pm_mount = (mount_t)kread64((uint64_t)pmi->pm_rootvnode + 0xd8);
    }
    
    /* Setup incoming as the new rootfs */
    incoming_vol_old_covered_vp = (vnode_t)kread64((uint64_t)incoming + 0x38);
    kwrite64((uint64_t)incoming + 0x38, 0);
    char incoming_mntonname[0x400];
    kreadbuf((uint64_t)incoming + 0xe4, incoming_mntonname, 0x400);
//    printf("incoming_mntonname: %s\n", incoming_mntonname);
    kwritebuf((uint64_t)incoming + 0xe4, "/", 0x400);
    kwrite32((uint64_t)&incoming->mnt_flag, kread32((uint64_t)&incoming->mnt_flag) | MNT_ROOTFS);
    
    /*
     * The preserved mountpoints will now be moved to
     * incoming_rootnode/pm_path, and then by the end of the function,
     * since incoming_rootnode is going to /, the preserved mounts
     * will be end up back at /pm_path
     */
    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == NULLVP) {
            continue;
        }
        
        pmi->pm_old_covered_vp = (vnode_t)kread64((uint64_t)&pmi->pm_mount->mnt_vnodecovered);
        kwrite64((uint64_t)&pmi->pm_mount->mnt_vnodecovered, (uint64_t)pmi->pm_new_covered_vp);
        kwrite64((uint64_t)&pmi->pm_new_covered_vp->v_mountedhere, (uint64_t)pmi->pm_mount);
        kwrite32((uint64_t)&pmi->pm_new_covered_vp->v_flag, kread32((uint64_t)&pmi->pm_new_covered_vp->v_flag) | VMOUNTEDHERE);
    }
    
    /*
     * The old root volume now covers outgoing_vol_new_covered_vp
     * on the new root volume. Remove the ROOTFS marker.
     * Now it is to be found at outgoing_vol_new_path
     */
    kwrite64((uint64_t)&outgoing->mnt_vnodecovered, (uint64_t)outgoing_vol_new_covered_vp);
    char outgoing_vol_new_path_buf[MAXPATHLEN];
    kreadbuf((uint64_t)outgoing + 0xe4, &outgoing_vol_new_path_buf, MAXPATHLEN);
//    printf("outgoing_mntonname: %s\n", outgoing_vol_new_path_buf);
    kwritebuf((uint64_t)outgoing + 0xe4, outgoing_vol_new_path, MAXPATHLEN);
    kwrite32((uint64_t)&outgoing->mnt_flag, kread32((uint64_t)&outgoing->mnt_flag) & ~MNT_ROOTFS);
    kwrite64((uint64_t)&outgoing_vol_new_covered_vp->v_mountedhere, (uint64_t)outgoing);
    
    vfs_setmntsystem(outgoing);
    
    kwrite32((uint64_t)&incoming_vol_old_covered_vp->v_flag, kread32((uint64_t)&incoming_vol_old_covered_vp->v_flag) & ~VMOUNT);
    kwrite64((uint64_t)&incoming_vol_old_covered_vp->v_mountedhere, 0);
    
    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == NULLVP) {
            continue;
        }
        
        kwrite32((uint64_t)&pmi->pm_old_covered_vp->v_flag, kread32((uint64_t)&pmi->pm_old_covered_vp->v_flag) & ~VMOUNTEDHERE);
        kwrite64((uint64_t)&pmi->pm_old_covered_vp->v_mountedhere, 0);
    }
    
    set_rootvnode((uint64_t)incoming_rootvnode);
    printf("set!\n");
    
    error = 0;
    
done:
   for (size_t i = 0; i < countof(preserved); i++) {
       struct preserved_mount *pmi = preserved[i];
       
       if (pmi->pm_rootvnode) {
           vnode_put(pmi->pm_rootvnode);
       }
       if (pmi->pm_new_covered_vp) {
           vnode_put(pmi->pm_new_covered_vp);
       }
       if (pmi->pm_old_covered_vp) {
           vnode_rele(pmi->pm_old_covered_vp);
       }
   }
   
   if (outgoing_vol_new_covered_vp) {
       vnode_put(outgoing_vol_new_covered_vp);
   }
   
   if (incoming_vol_old_covered_vp) {
       vnode_rele(incoming_vol_old_covered_vp);
   }
   
//   if (incoming_rootvnode) {
//       vnode_put(incoming_rootvnode);
//   }
    
    printf("%s : done shuffling mount points with error: %llx\n", __FUNCTION__, error);
    return error;
}

void execute_unsandboxed(void (^block)(void)) {
    uint64_t kernproc = proc_find(0);
    uint64_t kern_ucred = proc_ucred(kernproc);
    uint64_t proc = proc_find(getpid());
    uint64_t orig_ucred = proc_ucred(proc);
    if (gSystemInfo.kernelStruct.proc_ro.exists) {
        uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
        kwrite64(proc_ro + koffsetof(proc_ro, ucred), kern_ucred);
    }
    else {
        kwrite_ptr(proc + koffsetof(proc, ucred), kern_ucred, 0x84E8);
    }

    uint64_t our_label = kread_ptr(orig_ucred + koffsetof(ucred, label));
    uint64_t our_slot = mac_label_get(our_label, 0);
    mac_label_set(kread_ptr(kern_ucred + koffsetof(ucred, label)), 0, our_slot);

    block();

    if (gSystemInfo.kernelStruct.proc_ro.exists) {
        uint64_t proc_ro = kread_ptr(proc + koffsetof(proc, proc_ro));
        kwrite64(proc_ro + koffsetof(proc_ro, ucred), orig_ucred);
    } else {
        kwrite_ptr(proc + koffsetof(proc, ucred), orig_ucred, 0x84E8);
    }
    mac_label_set(kread_ptr(kern_ucred + koffsetof(ucred, label)), 0, -1);
}

int mount_unsandboxed(const char *type, const char *dir, int flags, void *data) {
    __block int r = 0;
    execute_unsandboxed(^{
        r = mount(type, dir, flags, data);
    });
    return r;
}

int unmount_unsandboxed(const char *dir, int type) {
    __block int r = 0;
    execute_unsandboxed(^{
        r = unmount(dir, type);
    });
    return r;
}

int mount_apfs(const char *dir, int flags, char *device) {
    apfs_mount_args_t args = { device, flags, APFS_MOUNT_FILESYSTEM , 0, 0, { "" }, NULL, 0, 0, NULL, 0, 0, 0, 0, 0, 0 };
    return mount_unsandboxed("apfs", dir, flags, &args);
}

void enter_fakefs(void) {
    printf("Mounting fakefs\n");
#ifdef iOS15
    if (access("/dev/disk0s1s8", 0) != 0xffffffff) {
        printf("Found /dev/disk0s1s8\n");
    } else {
        printf("Did not found /dev/disk0s1s8\n");
    }
#else
    if (access("/dev/disk1s8", 0) != 0xffffffff) {
        printf("Found /dev/disk1s8\n");
    } else {
        printf("Did not found /dev/disk1s8\n");
    }
#endif
    if ((access("/private/var/mnt", 0) == 0xffffffff && mkdir("/private/var/mnt", 0x1ff) == 0xffffffff)) {
        printf("mkdir /private/var/mnt failed\n");
    }
    if (access("/private/var/mnt/fake", 0) == 0xffffffff) {
        if (mkdir("/private/var/mnt/fake", 0x1ff) != 0xffffffff) {
            printf("mkdir /private/var/mnt/fake failed\n");
        }
    }
//#ifdef iOS15
//    //    int r = exec_cmd("/sbin/mount_apfs", "/dev/disk0s1s8", "/private/var/mnt/fake", 0, 0);
//#else
////        int r = exec_cmd("/sbin/mount_apfs", "/dev/disk1s8", "/private/var/mnt/fake", 0, 0);
//#endif
////        if (r != 0) {
////            printf("Failed to mount fakefs\n");
////        }
#ifdef iOS15
    if (mount_apfs("/private/var/mnt/fake", 0, "/dev/disk0s1s8") != 0) {
        printf("Mount / failed: %d\n", errno);
    }
#else
    if (mount_apfs("/private/var/mnt/fake", 0, "/dev/disk1s8") != 0) {
        printf("Mount / failed: %d\n", errno);
    }
#endif
    printf("Mounted rootfs\n");
//    sleep(1);
    
    printf("Switching to fakefs\n");
    vfs_switch_root("/private/var/mnt/fake", "cores", 0);

    NSArray *slashContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/" error:nil];
    printf("Contents of /:\n");
    for (NSString *slashContent in slashContents) {
        printf(" - %s\n", slashContent.UTF8String);
    }

    NSArray *usr_libContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/usr/lib" error:nil];
    printf("Contents of /usr/lib:\n");
    for (NSString *usr_libContent in usr_libContents) {
        printf(" - %s\n", usr_libContent.UTF8String);
    }
    
    NSArray *var_mntContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/private/var/mnt/fake" error:nil];
    printf("Contents of /private/var/mnt/fake:\n");
    for (NSString *var_mntContent in var_mntContents) {
        printf(" - %s\n", var_mntContent.UTF8String);
    }

    NSArray *cores_contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/cores" error:nil];
    printf("Contents of /cores:\n");
    for (NSString *cores_content in cores_contents) {
        printf(" - %s\n", cores_content.UTF8String);
    }

//    int r = exec_cmd("/sbin/mount", NULL, NULL, 0, 0);
////    r = exec_cmd("/sbin/mount", NULL, NULL, 0, 0);
//    if (r != 0) {
//        printf("Failed to exec /sbin/mount\n");
//    }
}
