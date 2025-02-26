//
//  Mineek-IOKit.h
//  Dopamine
//
//  Created by Mineek on 16/12/2024.
//

#ifndef Mineek_IOKit_h
#define Mineek_IOKit_h

#import <Foundation/Foundation.h>

// IOKIT
typedef mach_port_t io_connect_t;
typedef mach_port_t io_service_t;
typedef mach_port_t io_iterator_t;
typedef mach_port_t io_object_t;
typedef mach_port_t io_registry_entry_t;

#ifndef IO_OBJECT_NULL
#define IO_OBJECT_NULL 0
#endif
extern const mach_port_t kIOMasterPortDefault;

kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt);
kern_return_t IOConnectCallAsyncMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const uint64_t *input, uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt);
        kern_return_t IOConnectMapMemory(io_connect_t connect, uint32_t memoryType, task_port_t intoTask, mach_vm_address_t *atAddress, mach_vm_size_t *ofSize, uint32_t options);
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type,io_connect_t *connect);
kern_return_t IOServiceGetMatchingServices(mach_port_t masterPort, CFDictionaryRef matching, io_iterator_t *existing);
kern_return_t IOServiceClose(io_connect_t connect);
uint32_t IOObjectGetRetainCount(io_object_t object);
uint32_t IOObjectGetKernelRetainCount(io_object_t object);
uint32_t IOObjectGetRetainCount(io_object_t object);
kern_return_t io_object_get_retain_count(mach_port_t object,uint32_t *retainCount);
kern_return_t IOObjectRelease(io_object_t object);
kern_return_t IORegistryEntrySetCFProperties(io_registry_entry_t entry, CFTypeRef properties);
kern_return_t IOConnectSetNotificationPort(io_connect_t connect, uint32_t type, mach_port_t port, uintptr_t reference);
CFMutableDictionaryRef IOServiceMatching(const char *name);
CFDataRef IOCFSerialize(CFTypeRef object, CFOptionFlags options);
CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *errorString);
kern_return_t IOConnectTrap6(io_connect_t client, uint32_t index, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f);

#endif /* Mineek_IOKit_h */
