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

uint64_t vfs_context_kernel(void) {
    return gSystemInfo.kernelConstant.slide + ADDR_vfs_context_kernel;
}

uint64_t vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {
    uint64_t vnode_lookup = gSystemInfo.kernelConstant.slide + ADDR_vnode_lookup;
    uint64_t out;
    uint64_t out_vnode_mem;
    kalloc(&out_vnode_mem, sizeof(uint64_t));
    uint64_t path_kernel;
    kalloc(&path_kernel, strlen(path) + 1);
    kwritebuf(path_kernel, path, strlen(path));
    out = kcallmineek(vnode_lookup, (uint64_t)path_kernel, flags, out_vnode_mem, vfs_context, 0, 0, 0);
    *vnode = kread64(out_vnode_mem);
    return out;
}

uint64_t vnode_lookupat(const char *path, int flags, uint64_t *vnode, uint64_t ctx, uint64_t start_dvp) {
    uint64_t vnode_lookupat = gSystemInfo.kernelConstant.slide + ADDR_vnode_lookupat;
    uint64_t out;
    uint64_t out_vnode_mem;
    kalloc(&out_vnode_mem, sizeof(uint64_t));
    uint64_t path_kernel;
    kalloc(&path_kernel, strlen(path) + 1);
    kwritebuf(path_kernel, path, strlen(path));
    out = kcallmineek(vnode_lookupat, (uint64_t)path_kernel, flags, out_vnode_mem, ctx, start_dvp, 0, 0);
    *vnode = kread64(out_vnode_mem);
    kfree(out_vnode_mem, sizeof(uint64_t));
    return out;
}

uint64_t vnode_vtype(uint64_t vnode) {
    return kread64(vnode + 0x70);
}

uint64_t vnode_ref_ext(uint64_t vp, int fmode, int flags) {
    uint64_t vnode_ref_ext = gSystemInfo.kernelConstant.slide + ADDR_vnode_ref_ext;
    uint64_t out;
    uint64_t args[] = {vp, fmode, flags};
    out = kcallmineek(vnode_ref_ext, vp, fmode, flags, 0, 0, 0, 0);
    return out;
}

#define rootvnode_addr (gSystemInfo.kernelConstant.slide + ADDR_rootvnode_addr)
#define rootvp_addr (gSystemInfo.kernelConstant.slide + ADDR_rootvp_addr)
#define rootdev_addr (gSystemInfo.kernelConstant.slide + ADDR_rootdev_addr)

void set_rootvnode(uint64_t new_rootvnode) {
    printf("Setting rootvnode to 0x%llx\n", new_rootvnode);
    uint64_t new_mount = kread64(new_rootvnode + 0xd8);
    uint64_t new_devvp = kread64(new_mount + 0x980);
    uint64_t old_rootvnode = kread_ptr(rootvnode_addr);

    kwrite32(new_rootvnode + 0x54, kread32(new_rootvnode + 0x54) | 0x1); // VROOT
    kwrite64(rootvp_addr, new_devvp); // rootvp
    kwrite64(rootvnode_addr, new_rootvnode); // rootvnode
    kwrite64(proc_find(0) + 0x120, new_rootvnode); // fd_fd_cdir

    kwrite32(rootdev_addr, kread32(kread_ptr(new_devvp + 0x78) + 0x18));
}

void vfs_setmntsystem(uint64_t mp) {
    //mp->mnt_kern_flag |= MNTK_SYSTEM;
    kwrite32(mp + 0x74, kread32(mp + 0x74) | 0x40);
}

int vnode_put(uint64_t vp) {
    uint64_t vnode_put = gSystemInfo.kernelConstant.slide + ADDR_vnode_put;
    uint64_t out;
    uint64_t args[] = {vp};
    out = kcallmineek(vnode_put, vp, 0, 0, 0, 0, 0, 0);
    return out;
}

int vnode_rele(uint64_t vp) {
    uint64_t vnode_rele = gSystemInfo.kernelConstant.slide + ADDR_vnode_rele;
    uint64_t out;
    uint64_t args[] = {vp};
    out = kcallmineek(vnode_rele, vp, 0, 0, 0, 0, 0, 0);
    return out;
}

uint64_t vfs_switch_root(const char* incoming_vol_old_path, const char* outgoing_vol_new_path, uint64_t flags)
{
    // note to self:
    // incoming = the new root
    // outgoing = the new location of the old root

    // grumble grumble
#define countof(x) (sizeof(x) / sizeof(x[0]))

    struct preserved_mount {
        uint64_t pm_rootvnode;
        uint64_t pm_mount;
        uint64_t pm_new_covered_vp;
        uint64_t pm_old_covered_vp;
        const char *pm_path;
    };

    uint64_t ctx = vfs_context_kernel();
    uint64_t incoming_rootvnode = 0;
    uint64_t outgoing_vol_new_covered_vp = 0;
    uint64_t incoming_vol_old_covered_vp = 0;
    uint64_t outgoing = 0;
    uint64_t incoming = 0;

    struct preserved_mount devfs = { 0, 0, 0, 0, "dev" };
    struct preserved_mount preboot = { 0, 0, 0, 0, "private/preboot" };
    struct preserved_mount developer = { 0, 0, 0, 0, "Developer" };
    struct preserved_mount var = { 0, 0, 0, 0, "var" };
    struct preserved_mount msu = { 0, 0, 0, 0, "private/var/MobileSoftwareUpdate" };
    struct preserved_mount baseband = { 0, 0, 0, 0, "private/var/wireless/baseband_data" };
    struct preserved_mount hardware = { 0, 0, 0, 0, "private/var/hardware" };
    struct preserved_mount xarts = { 0, 0, 0, 0, "private/xarts" };
    struct preserved_mount factorydata = { 0, 0, 0, 0, "System/Library/Caches/com.apple.factorydata" };
    //struct preserved_mount usr_lib = { 0, 0, 0, 0, "usr/lib" };
    
    // only on iPhone X
    struct preserved_mount referenceframes = {0,0,0,0, "/System/Library/Pearl/ReferenceFrames"};

    struct preserved_mount *preserved[10];
    preserved[0] = &devfs;
    preserved[1] = &preboot;
    preserved[2] = &developer;
    preserved[3] = &var;
    preserved[4] = &msu;
    preserved[5] = &baseband;
    preserved[6] = &hardware;
    preserved[7] = &xarts;
    preserved[8] = &factorydata;
    //preserved[9] = &usr_lib;
    preserved[9] = &referenceframes;

    uint64_t error = 0;

    printf("%s : shuffling mount points : %s <-> / <-> %s\n", __FUNCTION__, incoming_vol_old_path, outgoing_vol_new_path);
    
    //sleep(1);

    if (outgoing_vol_new_path[0] == '/') {
        // I should have written this to be more helpful and just advance the pointer forward past the slash
        printf("Do not use a leading slash in outgoing_vol_new_path\n");
        return EINVAL;
    }

    error = vnode_lookup(incoming_vol_old_path, 0, &incoming_rootvnode, ctx);
    if (error) {
        printf("Incoming rootfs root vnode not found\n");
        error = ENOENT;
        goto done;
    }
    
    printf("found 1\n");
    //sleep(1);

    error = vnode_lookupat(outgoing_vol_new_path, 0, &outgoing_vol_new_covered_vp, ctx, incoming_rootvnode);
    if (error) {
        printf("Outgoing rootfs path not found, abandoning / switch, error = 0x%llx\n", error);
        error = ENOENT;
        goto done;
    }
    
    printf("found 2\n");
    //sleep(1);

    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];

        error = vnode_lookupat(pmi->pm_path, 0, &pmi->pm_rootvnode, ctx, kread_ptr(rootvnode_addr));
        if (error) {
            printf("skipping preserved mountpoint because not found or error: 0x%llx: %s\n", error, pmi->pm_path);
            // not fatal. try the next one in the list.
            continue;
        }

        error = vnode_lookupat(pmi->pm_path, 0, &pmi->pm_new_covered_vp, ctx, incoming_rootvnode);
        if (error) {
            printf("preserved new mount directory not found or error: 0x%llx: %s\n", error, pmi->pm_path);
            error = ENOENT;
            goto done;
        }

        printf("will preserve mountpoint across pivot: /%s\n", pmi->pm_path);
    }

    #define VNODE_REF_FORCE 0x1
    printf("found 3\n");
    vnode_ref_ext(outgoing_vol_new_covered_vp, 0, VNODE_REF_FORCE);
    printf("found 4\n");
    vnode_ref_ext(incoming_rootvnode, 0, VNODE_REF_FORCE);
    printf("found 5\n");

    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == 0) {
            continue;
        }
        vnode_ref_ext(pmi->pm_new_covered_vp, 0, VNODE_REF_FORCE);
        //pmi->pm_new_covered_vp->v_flag |= VMOUNTEDHERE;
        kwrite32(pmi->pm_new_covered_vp + 0x54, kread32(pmi->pm_new_covered_vp + 0x54) | 0x40000000);
    }
    
    printf("found 6\n");
    //sleep(1);

    //outgoing_vol_new_covered_vp->v_flag |= VMOUNTEDHERE;
    kwrite32(outgoing_vol_new_covered_vp + 0x54, kread32(outgoing_vol_new_covered_vp + 0x54) | 0x40000000);
    
    printf("found 7\n");
    //sleep(1);

    outgoing = kread64(kread_ptr(rootvnode_addr) + 0xd8);
    incoming = kread64(incoming_rootvnode + 0xd8);
    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == 0) {
            continue;
        }
        pmi->pm_mount = kread64(pmi->pm_rootvnode + 0xd8);
    }
    
    incoming_vol_old_covered_vp = kread64(incoming + 0x38);
    kwrite64(incoming + 0x38, 0);
    char incoming_mntonname[0x400];
    kreadbuf(incoming + 0xe4, &incoming_mntonname, 0x400);
    printf("incoming_mntonname: %s\n", incoming_mntonname);

    kwritebuf(incoming + 0xe4, "/", 0x400);

    kwrite32(incoming + 0x70, kread32(incoming + 0x70) | 0x4000);

    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == 0) {
            continue;
        }
        pmi->pm_old_covered_vp = kread64(pmi->pm_mount + 0x38);
        kwrite64(pmi->pm_mount + 0x38, pmi->pm_new_covered_vp);
        kwrite64(pmi->pm_new_covered_vp + 0x78, pmi->pm_mount);
        kwrite32(pmi->pm_new_covered_vp + 0x54, kread32(pmi->pm_new_covered_vp + 0x54) | 0x40000000);
    }

    kwrite64(outgoing + 0x38, outgoing_vol_new_covered_vp);
    char outgoing_mntonname[0x400];
    kreadbuf(outgoing + 0xe4, &outgoing_mntonname, 0x400);
    printf("outgoing_mntonname: %s\n", outgoing_mntonname);

    kwritebuf(outgoing + 0xe4, "/cores", 0x400);

    kwrite32(outgoing + 0x70, kread32(outgoing + 0x70) & ~0x4000);
    kwrite64(outgoing_vol_new_covered_vp + 0x78, outgoing);

    vfs_setmntsystem(outgoing);

    kwrite32(incoming_vol_old_covered_vp + 0x54, kread32(incoming_vol_old_covered_vp + 0x54) & ~0x000080);
    kwrite64(incoming_vol_old_covered_vp + 0x78, 0);

    for (size_t i = 0; i < countof(preserved); i++) {
        struct preserved_mount *pmi = preserved[i];
        if (pmi->pm_rootvnode == 0) {
            continue;
        }
        kwrite32(pmi->pm_old_covered_vp + 0x54, kread32(pmi->pm_old_covered_vp + 0x54) & ~0x40000000);
        kwrite64(pmi->pm_old_covered_vp + 0x78, 0);
    }

    set_rootvnode(incoming_rootvnode);

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

    if (incoming_rootvnode) {
        vnode_put(incoming_rootvnode);
    }


    printf("%s : done shuffling mount points with error: 0x%llx\n", __FUNCTION__, error);
    return error;
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
#ifdef iOS15
    int r = exec_cmd("/sbin/mount_apfs", "/dev/disk0s1s8", "/private/var/mnt/fake", 0, 0);
#else
    int r = exec_cmd("/sbin/mount_apfs", "/dev/disk1s8", "/private/var/mnt/fake", 0, 0);
#endif
    if (r != 0) {
        printf("Failed to mount fakefs\n");
    }
    
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

    r = exec_cmd("/sbin/mount", NULL, NULL, 0, 0);
    if (r != 0) {
        printf("Failed to exec /sbin/mount\n");
    }
}
