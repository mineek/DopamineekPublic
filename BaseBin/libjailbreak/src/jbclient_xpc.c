#include "jbclient_xpc.h"
#include "jbclient_mach.h"
#include "jbserver.h"
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pthread.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>

#define OS_ALLOC_ONCE_KEY_MAX    100

struct _os_alloc_once_s {
	long once;
	void *ptr;
};

struct xpc_global_data {
	uint64_t    a;
	uint64_t    xpc_flags;
	mach_port_t    task_bootstrap_port;  /* 0x10 */
#ifndef _64
	uint32_t    padding;
#endif
	xpc_object_t    xpc_bootstrap_pipe;   /* 0x18 */
};

extern struct _os_alloc_once_s _os_alloc_once_table[];
extern void* _os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);

mach_port_t gJBServerCustomPort = MACH_PORT_NULL;

void jbclient_xpc_set_custom_port(mach_port_t serverPort)
{
	if (gJBServerCustomPort != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), gJBServerCustomPort);
	}
	gJBServerCustomPort = serverPort;
}

xpc_object_t jbserver_xpc_send_dict(xpc_object_t xdict)
{
	xpc_object_t xreply = NULL;

	xpc_object_t xpipe = NULL;
	if (gJBServerCustomPort != MACH_PORT_NULL) {
		// Communicate with custom port if set
		xpipe = xpc_pipe_create_from_port(gJBServerCustomPort, 0);
	}
	else {
		// Else, communicate with launchd
		struct xpc_global_data* globalData = NULL;
		if (_os_alloc_once_table[1].once == -1) {
			globalData = _os_alloc_once_table[1].ptr;
		}
		else {
			globalData = _os_alloc_once(&_os_alloc_once_table[1], 472, NULL);
			if (!globalData) _os_alloc_once_table[1].once = -1;
		}
		if (!globalData) return NULL;
		if (!globalData->xpc_bootstrap_pipe) {
			mach_port_t launchdPort = jbclient_mach_get_launchd_port();
			if (launchdPort != MACH_PORT_NULL) {
				globalData->task_bootstrap_port = launchdPort;
				globalData->xpc_bootstrap_pipe = xpc_pipe_create_from_port(globalData->task_bootstrap_port, 0);
			}
		}
		if (!globalData->xpc_bootstrap_pipe) return NULL;
		xpipe = xpc_retain(globalData->xpc_bootstrap_pipe);
	}

	if (!xpipe) return NULL;
	int err = xpc_pipe_routine_with_flags(xpipe, xdict, &xreply, 0);
	xpc_release(xpipe);
	if (err != 0) {
		return NULL;
	}
	return xreply;
}

xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t xargs)
{
	bool ownsXargs = false;
	if (!xargs) {
		xargs = xpc_dictionary_create_empty();
		ownsXargs = true;
	}

	xpc_dictionary_set_uint64(xargs, "jb-domain", domain);
	xpc_dictionary_set_uint64(xargs, "action", action);

	xpc_object_t xreply = jbserver_xpc_send_dict(xargs);
	if (ownsXargs) {
		xpc_release(xargs);
	}

	return xreply;
}

char *jbclient_get_jbroot(void)
{
	static char rootPath[PATH_MAX] = { 0 };
	static dispatch_once_t dot;

	dispatch_once(&dot, ^{
		xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_GET_JBROOT, NULL);
		if (xreply) {
			const char *replyRootPath = xpc_dictionary_get_string(xreply, "root-path");
			if (replyRootPath) {
				strlcpy(&rootPath[0], replyRootPath, sizeof(rootPath));
			}
			xpc_release(xreply);
		}
	});

	if (rootPath[0] == '\0') return NULL;
	return (char *)&rootPath[0];
}

char *jbclient_get_boot_uuid(void)
{
	static char bootUUID[37] = { 0 };
	static dispatch_once_t dot;

	dispatch_once(&dot, ^{
		xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_GET_BOOT_UUID, NULL);
		if (xreply) {
			const char *replyBootUUID = xpc_dictionary_get_string(xreply, "boot-uuid");
			if (replyBootUUID) {
				strlcpy(&bootUUID[0], replyBootUUID, sizeof(bootUUID));
			}
			xpc_release(xreply);
		}
	});

	if (bootUUID[0] == '\0') return NULL;
	return (char *)&bootUUID[0];
}

int jbclient_trust_file(int fd, struct siginfo *siginfo)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(xargs, "fd", (uint64_t)fd);
	if (siginfo) xpc_dictionary_set_data(xargs, "siginfo", siginfo, sizeof(struct siginfo));
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_TRUST_FILE, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_trust_file_by_path(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;

	int r = jbclient_trust_file(fd, NULL);
	close(fd);
	return r;
}

int jbclient_process_checkin(char **rootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_PROCESS_CHECKIN, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		const char *rootPath = xpc_dictionary_get_string(xreply, "root-path");
		const char *bootUUID = xpc_dictionary_get_string(xreply, "boot-uuid");
		const char *sandboxExtensions = xpc_dictionary_get_string(xreply, "sandbox-extensions");
		if (rootPathOut) *rootPathOut = rootPath ? strdup(rootPath) : NULL;
		if (bootUUIDOut) *bootUUIDOut = bootUUID ? strdup(bootUUID) : NULL;
		if (sandboxExtensionsOut) *sandboxExtensionsOut = sandboxExtensions ? strdup(sandboxExtensions) : NULL;
		if (fullyDebuggedOut) *fullyDebuggedOut = xpc_dictionary_get_bool(xreply, "fully-debugged");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_fork_fix(uint64_t childPid)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(xargs, "child-pid", childPid);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_FORK_FIX, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_cs_revalidate(void)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_CS_REVALIDATE, NULL);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(xargs, "key", key);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE, JBS_SYSTEMWIDE_JBSETTINGS_GET, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_object_t value = xpc_dictionary_get_value(xreply, "value");
		if (value && valueOut) *valueOut = xpc_copy(value);
		xpc_release(xreply);
		return result;
	}
	return -1;
}

bool jbclient_jbsettings_get_bool(const char *key)
{
	xpc_object_t value;
	if (jbclient_jbsettings_get(key, &value) == 0) {
		if (value) {
			bool valueBool = xpc_bool_get_value(value);
			xpc_release(value);
			return valueBool;
		}
	}
	return false;
}

uint64_t jbclient_jbsettings_get_uint64(const char *key)
{
	xpc_object_t value;
	if (jbclient_jbsettings_get(key, &value) == 0) {
		if (value) {
			uint64_t valueU64 = xpc_uint64_get_value(value);
			xpc_release(value);
			return valueU64;
		}
	}
	return 0;
}

double jbclient_jbsettings_get_double(const char *key)
{
	xpc_object_t value;
	if (jbclient_jbsettings_get(key, &value) == 0) {
		if (value) {
			double valueDouble = xpc_double_get_value(value);
			xpc_release(value);
			return valueDouble;
		}
	}
	return 0;
}

int jbclient_platform_set_process_debugged(uint64_t pid, bool fullyDebugged)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(xargs, "pid", pid);
	xpc_dictionary_set_bool(xargs, "fully-debugged", fullyDebugged);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_PLATFORM, JBS_PLATFORM_SET_PROCESS_DEBUGGED, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_platform_stage_jailbreak_update(const char *updateTar)
{
	char realUpdateTarPath[PATH_MAX];
	if (!realpath(updateTar, realUpdateTarPath)) return -1;

	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(xargs, "update-tar", realUpdateTarPath);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_PLATFORM, JBS_PLATFORM_STAGE_JAILBREAK_UPDATE, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_platform_jbsettings_set(const char *key, xpc_object_t value)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(xargs, "key", key);
	xpc_dictionary_set_value(xargs, "value", value);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_PLATFORM, JBS_PLATFORM_JBSETTINGS_SET, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_platform_jbsettings_set_bool(const char *key, bool boolValue)
{
	xpc_object_t value = xpc_bool_create(boolValue);
	int r = jbclient_platform_jbsettings_set(key, value);
	xpc_release(value);
	return r;
}

int jbclient_platform_jbsettings_set_uint64(const char *key, uint64_t uint64Value)
{
	xpc_object_t value = xpc_uint64_create(uint64Value);
	int r = jbclient_platform_jbsettings_set(key, value);
	xpc_release(value);
	return r;
}

int jbclient_platform_jbsettings_set_double(const char *key, double doubleValue)
{
	xpc_object_t value = xpc_double_create(doubleValue);
	int r = jbclient_platform_jbsettings_set(key, value);
	xpc_release(value);
	return r;
}

int jbclient_platform_set_systemwide_domain_enabled(bool enabled)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(xargs, "enabled", enabled);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_PLATFORM, JBS_PLATFORM_SET_SYSTEMWIDE_DOMAIN_ENABLED, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_watchdog_intercept_userspace_panic(const char *panicMessage)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(xargs, "panic-message", panicMessage);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_WATCHDOG, JBS_WATCHDOG_INTERCEPT_USERSPACE_PANIC, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_watchdog_get_last_userspace_panic(char **panicMessage)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_WATCHDOG, JBS_WATCHDOG_GET_LAST_USERSPACE_PANIC, NULL);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		const char *receivedMessage = xpc_dictionary_get_string(xreply, "panic-message");
		if (receivedMessage) {
			*panicMessage = strdup(receivedMessage);
		}
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_get_physrw(bool singlePTE, uint64_t *singlePTEAsidPtr)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(xargs, "single-pte", singlePTE);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_GET_PHYSRW, xargs);
	xpc_release(xargs);
	if (xreply) {
		if (singlePTEAsidPtr) {
			*singlePTEAsidPtr = xpc_dictionary_get_uint64(xreply, "single-pte-asid-ptr");
		}
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_sign_thread(mach_port_t threadPort)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(xargs, "thread-port", threadPort);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_SIGN_THREAD, xargs);
	xpc_release(xargs);
	if (xreply) {
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_get_sysinfo(xpc_object_t *sysInfoOut)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_GET_SYSINFO, NULL);
	if (xreply) {
		xpc_object_t sysInfo = xpc_dictionary_get_dictionary(xreply, "sysinfo");
		if (sysInfo && sysInfoOut) *sysInfoOut = xpc_copy(sysInfo);
		int result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_steal_ucred(uint64_t ucredToSteal, uint64_t *orgUcred)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(xargs, "ucred", ucredToSteal);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_STEAL_UCRED, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if (orgUcred) *orgUcred = xpc_dictionary_get_uint64(xreply, "org-ucred");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_set_mac_label(uint64_t slot, uint64_t label, uint64_t *orgLabel)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(xargs, "slot", slot);
	xpc_dictionary_set_uint64(xargs, "label", label);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_SET_MAC_LABEL, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if (orgLabel) *orgLabel = xpc_dictionary_get_uint64(xreply, "org-label");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_trustcache_info(xpc_object_t *infoOut)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_TRUSTCACHE_INFO, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_object_t info = xpc_dictionary_get_array(xreply, "tc-info");
		if (infoOut && info) *infoOut = xpc_copy(info);
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_trustcache_add_cdhash(uint8_t *cdhashData, size_t cdhashLen)
{
	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_data(xargs, "cdhash", cdhashData, cdhashLen);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_TRUSTCACHE_ADD_CDHASH, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_root_trustcache_clear(void)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_ROOT_TRUSTCACHE_CLEAR, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

int jbclient_boomerang_done(void)
{
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOT, JBS_BOOMERANG_DONE, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}