//
//  DOMineek.h
//  Dopamine
//
//  Created by Mineek on 26/02/2025.
//

#ifndef DOMineek_h
#define DOMineek_h

#import <Foundation/Foundation.h>

// iOS 15.8.3, iPhone 6s+ (iPhone8,2)
// kcall
#define ADDR_add_x0_x0_0x40_ret 0xfffffff005ac8480
#define ADDR_getiotrap          0xfffffff007756d9c

// rootful
#define ADDR_vfs_context_kernel 0xfffffff0070ff300
#define ADDR_vnode_lookup       0xfffffff0073216e0
#define ADDR_vnode_lookupat     0xfffffff0073216e8
#define ADDR_vnode_ref_ext      0xfffffff0073212d0
#define ADDR_rootvnode_addr     0xfffffff007856730
#define ADDR_rootvp_addr        0xfffffff0078567b0
#define ADDR_rootdev_addr       0xfffffff00785675c
#define ADDR_vnode_put          0xfffffff00731f240
#define ADDR_vnode_rele         0xfffffff0073216d0

#define iOS15

BOOL presetup_rootful(void);

void rootful(void);
void rootful_fake_fakelib(void);

uint64_t kcallmineek(uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);

#endif /* DOMineek_h */
