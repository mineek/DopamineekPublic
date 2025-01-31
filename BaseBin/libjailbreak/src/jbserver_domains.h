#ifndef JBSERVER_DOMAINS
#define JBSERVER_DOMAINS

// Domain: System-Wide
// Reachable from all processes
#define JBS_DOMAIN_SYSTEMWIDE 1
enum {
    JBS_SYSTEMWIDE_GET_JBROOT = 1,
    JBS_SYSTEMWIDE_GET_BOOT_UUID,
    JBS_SYSTEMWIDE_TRUST_BINARY,
    JBS_SYSTEMWIDE_TRUST_LIBRARY,
    JBS_SYSTEMWIDE_PROCESS_CHECKIN,
    JBS_SYSTEMWIDE_FORK_FIX,
    JBS_SYSTEMWIDE_CS_REVALIDATE,
    JBS_SYSTEMWIDE_JBSETTINGS_GET,
};

// Domain: Platform
// Reachable from all processes that have CS_PLATFORMIZED or are entitled with platform-application or are the Dopamine app itself
#define JBS_DOMAIN_PLATFORM 2
enum {
    JBS_PLATFORM_SET_PROCESS_DEBUGGED = 1,
    JBS_PLATFORM_STAGE_JAILBREAK_UPDATE,
    JBS_PLATFORM_JBSETTINGS_SET,
};


// Domain: Watchdog
// Only reachable from watchdogd
#define JBS_DOMAIN_WATCHDOG 3
enum {
    JBS_WATCHDOG_INTERCEPT_USERSPACE_PANIC = 1,
    JBS_WATCHDOG_GET_LAST_USERSPACE_PANIC
};

// Domain: Root
// Only reachable from root processes
#define JBS_DOMAIN_ROOT 4
enum {
    JBS_ROOT_GET_PHYSRW = 1,
    JBS_ROOT_SIGN_THREAD,
    JBS_ROOT_GET_SYSINFO,
    JBS_ROOT_STEAL_UCRED,
    JBS_ROOT_SET_MAC_LABEL,
    JBS_ROOT_TRUSTCACHE_INFO,
    JBS_ROOT_TRUSTCACHE_ADD_CDHASH,
    JBS_ROOT_TRUSTCACHE_CLEAR,
};

#define JBS_BOOMERANG_DONE 42

#endif