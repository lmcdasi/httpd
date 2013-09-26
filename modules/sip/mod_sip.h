#ifndef MOD_SIP_H
#define MOD_SIP_H

/**
 * @file  mod_sip.h
 * @brief SIP Extension Module for Apache
 *
 * @defgroup MOD_SIP mod_sip
 * @ingroup  APACHE_MODS
 * @{
 */

#include "apr_hooks.h"
#include "apr_optional.h"
#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_md5.h"
#include "apr_network_io.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_uri.h"
#include "apr_date.h"
#include "apr_strmatch.h"
#include "apr_fnmatch.h"
#include "apr_reslist.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_uuid.h"
#include "util_mutex.h"
#include "apr_global_mutex.h"
#include "apr_thread_mutex.h"

#include "httpd.h"
#include "http_config.h"
#include "ap_config.h"
#include "ap_mpm.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_main.h"
#include "http_log.h"
#include "http_connection.h"

#include "scoreboard.h"

#include "osip2/osip.h"
#include "osipparser2/headers/osip_via.h"

/* The main sip proxy configuration */
typedef struct {
    int enabled;
    int active_min;
    int active_max;
    osip_t *osip;
} sip_config;

/* Create a set of SIP_DECLARE(type), SIP_DECLARE_NONSTD(type) and
 * SIP_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define SIP_DECLARE(type)            type
#define SIP_DECLARE_NONSTD(type)     type
#define SIP_DECLARE_DATA
#elif defined(SIP_DECLARE_STATIC)
#define SIP_DECLARE(type)            type __stdcall
#define SIP_DECLARE_NONSTD(type)     type
#define SIP_DECLARE_DATA
#elif defined(PROXY_DECLARE_EXPORT)
#define SIP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define SIP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define SIP_DECLARE_DATA             __declspec(dllexport)
#else
#define SIP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define SIP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define SIP_DECLARE_DATA             __declspec(dllimport)
#endif

request_rec *sip_read_request(conn_rec *);
apr_socket_t *ap_get_client_sip_connection(conn_rec *);
const char *sip_set_enable(cmd_parms *, void *, const char *);

extern module SIP_DECLARE_DATA sip_module;

#endif /*MOD_SIP_H*/
/** @} */
