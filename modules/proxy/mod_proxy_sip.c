/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* HTTP routines for Apache proxy */

#include "mod_proxy.h"
#include "mod_sip.h"
#include "ap_regex.h"

module AP_MODULE_DECLARE_DATA proxy_sip_module;

static apr_status_t ap_proxy_sip_cleanup(const char *scheme,
                                          request_rec *r,
                                          proxy_conn_rec *backend);

/*
 * Canonicalise http-like URLs.
 *  scheme is the scheme for the URL
 *  url    is the URL starting with the first '/'
 *  def_port is the default port for this scheme.
 */
static int proxy_sip_canon(request_rec *r, char *url)
{
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;

    /* ap_port_of_scheme() */
    if (strncasecmp(url, "sip:", 5) == 0) {
        url += 5;
        scheme = "sip";
    }
    else if (strncasecmp(url, "sips:", 6) == 0) {
        url += 6;
        scheme = "sips";
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_port_of_scheme(scheme);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "SIP: canonicalising URL %s", url);

    /* do syntatic check.
     * We break the URL into host, port, path, search
     */
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01083)
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    /*
     * now parse path/search args, according to rfc1738:
     * process the path.
     *
     * In a reverse proxy, our URL has been processed, so canonicalise
     * unless proxy-nocanon is set to say it's raw
     * In a forward proxy, we have and MUST NOT MANGLE the original.
     */
    switch (r->proxyreq) {
    default: /* wtf are we doing here? */
    case PROXYREQ_REVERSE:
        if (apr_table_get(r->notes, "proxy-nocanon")) {
            path = url;   /* this is the raw path */
        }
        else {
            path = ap_proxy_canonenc(r->pool, url, strlen(url),
                                     enc_path, 0, r->proxyreq);
            search = r->args;
        }
        break;
    case PROXYREQ_PROXY:
        path = url;
        break;
    }

    if (path == NULL)
        return HTTP_BAD_REQUEST;

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else
        sport[0] = '\0';

    if (ap_strchr_c(host, ':')) { /* if literal IPv6 address */
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport,
            "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}

/* Clear all connection-based headers from the incoming headers table */
typedef struct header_dptr {
    apr_pool_t *pool;
    apr_table_t *table;
    apr_time_t time;
} header_dptr;
static ap_regex_t *warn_rx;

static int clean_warning_headers(void *data, const char *key, const char *val)
{
    apr_table_t *headers = ((header_dptr*)data)->table;
    apr_pool_t *pool = ((header_dptr*)data)->pool;
    char *warning;
    char *date;
    apr_time_t warn_time;
    const int nmatch = 3;
    ap_regmatch_t pmatch[3];

    if (headers == NULL) {
        ((header_dptr*)data)->table = headers = apr_table_make(pool, 2);
    }
/*
 * Parse this, suckers!
 *
 *    Warning    = "Warning" ":" 1#warning-value
 *
 *    warning-value = warn-code SP warn-agent SP warn-text
 *                                             [SP warn-date]
 *
 *    warn-code  = 3DIGIT
 *    warn-agent = ( host [ ":" port ] ) | pseudonym
 *                    ; the name or pseudonym of the server adding
 *                    ; the Warning header, for use in debugging
 *    warn-text  = quoted-string
 *    warn-date  = <"> HTTP-date <">
 *
 * Buggrit, use a bloomin' regexp!
 * (\d{3}\s+\S+\s+\".*?\"(\s+\"(.*?)\")?)  --> whole in $1, date in $3
 */
    while (!ap_regexec(warn_rx, val, nmatch, pmatch, 0)) {
        warning = apr_pstrndup(pool, val+pmatch[0].rm_so,
                               pmatch[0].rm_eo - pmatch[0].rm_so);
        warn_time = 0;
        if (pmatch[2].rm_eo > pmatch[2].rm_so) {
            /* OK, we have a date here */
            date = apr_pstrndup(pool, val+pmatch[2].rm_so,
                                pmatch[2].rm_eo - pmatch[2].rm_so);
            warn_time = apr_date_parse_http(date);
        }
        if (!warn_time || (warn_time == ((header_dptr*)data)->time)) {
            apr_table_addn(headers, key, warning);
        }
        val += pmatch[0].rm_eo;
    }
    return 1;
}
static apr_table_t *ap_proxy_clean_warnings(apr_pool_t *p, apr_table_t *headers)
{
   header_dptr x;
   x.pool = p;
   x.table = NULL;
   x.time = apr_date_parse_http(apr_table_get(headers, "Date"));
   apr_table_do(clean_warning_headers, &x, headers, "Warning", NULL);
   if (x.table != NULL) {
       apr_table_unset(headers, "Warning");
       return apr_table_overlay(p, headers, x.table);
   }
   else {
        return headers;
   }
}
static int clear_conn_headers(void *data, const char *key, const char *val)
{
    apr_table_t *headers = ((header_dptr*)data)->table;
    apr_pool_t *pool = ((header_dptr*)data)->pool;
    const char *name;
    char *next = apr_pstrdup(pool, val);
    while (*next) {
        name = next;
        while (*next && !apr_isspace(*next) && (*next != ',')) {
            ++next;
        }
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            *next++ = '\0';
        }
        apr_table_unset(headers, name);
    }
    return 1;
}
static void ap_proxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    header_dptr x;
    x.pool = p;
    x.table = headers;
    apr_table_unset(headers, "Proxy-Connection");
    apr_table_do(clear_conn_headers, &x, headers, "Connection", NULL);
    apr_table_unset(headers, "Connection");
}
static void add_te_chunked(apr_pool_t *p,
                           apr_bucket_alloc_t *bucket_alloc,
                           apr_bucket_brigade *header_brigade)
{
    apr_bucket *e;
    char *buf;
    const char te_hdr[] = "Transfer-Encoding: chunked" CRLF;

    buf = apr_pmemdup(p, te_hdr, sizeof(te_hdr)-1);
    ap_xlate_proto_to_ascii(buf, sizeof(te_hdr)-1);

    e = apr_bucket_pool_create(buf, sizeof(te_hdr)-1, p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static void add_cl(apr_pool_t *p,
                   apr_bucket_alloc_t *bucket_alloc,
                   apr_bucket_brigade *header_brigade,
                   const char *cl_val)
{
    apr_bucket *e;
    char *buf;

    buf = apr_pstrcat(p, "Content-Length: ",
                      cl_val,
                      CRLF,
                      NULL);
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

#define ASCII_CRLF  "\015\012"
#define ASCII_ZERO  "\060"

static void terminate_headers(apr_bucket_alloc_t *bucket_alloc,
                              apr_bucket_brigade *header_brigade)
{
    apr_bucket *e;

    /* add empty line at the end of the headers */
    e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static int pass_brigade(apr_bucket_alloc_t *bucket_alloc,
                                 request_rec *r, proxy_conn_rec *p_conn,
                                 conn_rec *origin, apr_bucket_brigade *bb,
                                 int flush)
{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    apr_brigade_length(bb, 0, &transferred);
    if (transferred != -1)
        p_conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, bb);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01084)
                      "pass request body failed to %pI (%s)",
                      p_conn->addr, p_conn->hostname);
        if (origin->aborted) {
            const char *ssl_note;

            if (((ssl_note = apr_table_get(origin->notes, "SSL_connect_rv"))
                != NULL) && (strcmp(ssl_note, "err") == 0)) {
                return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR,
                                     "Error during SSL Handshake with"
                                     " remote server");
            }
            return APR_STATUS_IS_TIMEUP(status) ? HTTP_GATEWAY_TIME_OUT : HTTP_BAD_GATEWAY;
        }
        else {
            return HTTP_BAD_REQUEST;
        }
    }
    apr_brigade_cleanup(bb);
    return OK;
}

#define MAX_MEM_SPOOL 16384

static int stream_reqbody_cl(apr_pool_t *p,
                                      request_rec *r,
                                      proxy_conn_rec *p_conn,
                                      conn_rec *origin,
                                      apr_bucket_brigade *header_brigade,
                                      apr_bucket_brigade *input_brigade,
                                      const char *old_cl_val)
{
    int seen_eos = 0, rv = 0;
    apr_status_t status = APR_SUCCESS;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *bb;
    apr_bucket *e;
    apr_off_t cl_val = 0;
    apr_off_t bytes;
    apr_off_t bytes_streamed = 0;

    if (old_cl_val) {
        char *endstr;

        add_cl(p, bucket_alloc, header_brigade, old_cl_val);
        status = apr_strtoff(&cl_val, old_cl_val, &endstr, 10);

        if (status || *endstr || endstr == old_cl_val || cl_val < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01085)
                          "could not parse request Content-Length (%s)",
                          old_cl_val);
            return HTTP_BAD_REQUEST;
        }
    }
    terminate_headers(bucket_alloc, header_brigade);

    while (!APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(input_brigade)))
    {
        apr_brigade_length(input_brigade, 1, &bytes);
        bytes_streamed += bytes;

        /* If this brigade contains EOS, either stop or remove it. */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;

            /* We can't pass this EOS to the output_filters. */
            e = APR_BRIGADE_LAST(input_brigade);
            apr_bucket_delete(e);

            if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
                e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(input_brigade, e);
            }
        }

        /* C-L < bytes streamed?!?
         * We will error out after the body is completely
         * consumed, but we can't stream more bytes at the
         * back end since they would in part be interpreted
         * as another request!  If nothing is sent, then
         * just send nothing.
         *
         * Prevents HTTP Response Splitting.
         */
        if (bytes_streamed > cl_val) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01086)
                          "read more bytes of request body than expected "
                          "(got %" APR_OFF_T_FMT ", expected %" APR_OFF_T_FMT ")",
                          bytes_streamed, cl_val);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (header_brigade) {
            /* we never sent the header brigade, so go ahead and
             * take care of that now
             */
            bb = header_brigade;

            /*
             * Save input_brigade in bb brigade. (At least) in the SSL case
             * input_brigade contains transient buckets whose data would get
             * overwritten during the next call of ap_get_brigade in the loop.
             * ap_save_brigade ensures these buckets to be set aside.
             * Calling ap_save_brigade with NULL as filter is OK, because
             * bb brigade already has been created and does not need to get
             * created by ap_save_brigade.
             */
            status = ap_save_brigade(NULL, &bb, &input_brigade, p);
            if (status != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            header_brigade = NULL;
        }
        else {
            bb = input_brigade;
        }

        /* Once we hit EOS, we are ready to flush. */
        rv = pass_brigade(bucket_alloc, r, p_conn, origin, bb, seen_eos);
        if (rv != OK) {
            return rv ;
        }

        if (seen_eos) {
            break;
        }

        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            return HTTP_BAD_REQUEST;
        }
    }

    if (bytes_streamed != cl_val) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01087)
                      "client %s given Content-Length did not match"
                      " number of body bytes read", r->connection->client_ip);
        return HTTP_BAD_REQUEST;
    }

    if (header_brigade) {
        /* we never sent the header brigade since there was no request
         * body; send it now with the flush flag
         */
        bb = header_brigade;
        return(pass_brigade(bucket_alloc, r, p_conn, origin, bb, 1));
    }

    return OK;
}

static int spool_reqbody_cl(apr_pool_t *p,
                                     request_rec *r,
                                     proxy_conn_rec *p_conn,
                                     conn_rec *origin,
                                     apr_bucket_brigade *header_brigade,
                                     apr_bucket_brigade *input_brigade,
                                     int force_cl)
{
    int seen_eos = 0;
    apr_status_t status;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *body_brigade;
    apr_bucket *e;
    apr_off_t bytes, bytes_spooled = 0, fsize = 0;
    apr_file_t *tmpfile = NULL;
    apr_off_t limit;

    body_brigade = apr_brigade_create(p, bucket_alloc);

    limit = ap_get_limit_req_body(r);

    while (!APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(input_brigade)))
    {
        /* If this brigade contains EOS, either stop or remove it. */
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;

            /* We can't pass this EOS to the output_filters. */
            e = APR_BRIGADE_LAST(input_brigade);
            apr_bucket_delete(e);
        }

        apr_brigade_length(input_brigade, 1, &bytes);

        if (bytes_spooled + bytes > MAX_MEM_SPOOL) {
            /*
             * LimitRequestBody does not affect Proxy requests (Should it?).
             * Let it take effect if we decide to store the body in a
             * temporary file on disk.
             */
            if (bytes_spooled + bytes > limit) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01088)
                              "Request body is larger than the configured "
                              "limit of %" APR_OFF_T_FMT, limit);
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
            /* can't spool any more in memory; write latest brigade to disk */
            if (tmpfile == NULL) {
                const char *temp_dir;
                char *template;

                status = apr_temp_dir_get(&temp_dir, p);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01089)
                                  "search for temporary directory failed");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                apr_filepath_merge(&template, temp_dir,
                                   "modproxy.tmp.XXXXXX",
                                   APR_FILEPATH_NATIVE, p);
                status = apr_file_mktemp(&tmpfile, template, 0, p);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01090)
                                  "creation of temporary file in directory "
                                  "%s failed", temp_dir);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            for (e = APR_BRIGADE_FIRST(input_brigade);
                 e != APR_BRIGADE_SENTINEL(input_brigade);
                 e = APR_BUCKET_NEXT(e)) {
                const char *data;
                apr_size_t bytes_read, bytes_written;

                apr_bucket_read(e, &data, &bytes_read, APR_BLOCK_READ);
                status = apr_file_write_full(tmpfile, data, bytes_read, &bytes_written);
                if (status != APR_SUCCESS) {
                    const char *tmpfile_name;

                    if (apr_file_name_get(&tmpfile_name, tmpfile) != APR_SUCCESS) {
                        tmpfile_name = "(unknown)";
                    }
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01091)
                                  "write to temporary file %s failed",
                                  tmpfile_name);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                AP_DEBUG_ASSERT(bytes_read == bytes_written);
                fsize += bytes_written;
            }
            apr_brigade_cleanup(input_brigade);
        }
        else {

            /*
             * Save input_brigade in body_brigade. (At least) in the SSL case
             * input_brigade contains transient buckets whose data would get
             * overwritten during the next call of ap_get_brigade in the loop.
             * ap_save_brigade ensures these buckets to be set aside.
             * Calling ap_save_brigade with NULL as filter is OK, because
             * body_brigade already has been created and does not need to get
             * created by ap_save_brigade.
             */
            status = ap_save_brigade(NULL, &body_brigade, &input_brigade, p);
            if (status != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }

        }

        bytes_spooled += bytes;

        if (seen_eos) {
            break;
        }

        status = ap_get_brigade(r->input_filters, input_brigade,
                                AP_MODE_READBYTES, APR_BLOCK_READ,
                                HUGE_STRING_LEN);

        if (status != APR_SUCCESS) {
            return HTTP_BAD_REQUEST;
        }
    }

    if (bytes_spooled || force_cl) {
        add_cl(p, bucket_alloc, header_brigade, apr_off_t_toa(p, bytes_spooled));
    }
    terminate_headers(bucket_alloc, header_brigade);
    APR_BRIGADE_CONCAT(header_brigade, body_brigade);
    if (tmpfile) {
        apr_brigade_insert_file(header_brigade, tmpfile, 0, fsize, p);
    }
    if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
        e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }
    /* This is all a single brigade, pass with flush flagged */
    return(pass_brigade(bucket_alloc, r, p_conn, origin, header_brigade, 1));
}

/*
 * Transform buckets from one bucket allocator to another one by creating a
 * transient bucket for each data bucket and let it use the data read from
 * the old bucket. Metabuckets are transformed by just recreating them.
 * Attention: Currently only the following bucket types are handled:
 *
 * All data buckets
 * FLUSH
 * EOS
 *
 * If an other bucket type is found its type is logged as a debug message
 * and APR_EGENERAL is returned.
 */
static apr_status_t proxy_buckets_lifetime_transform(request_rec *r,
        apr_bucket_brigade *from, apr_bucket_brigade *to)
{
    apr_bucket *e;
    apr_bucket *new;
    const char *data;
    apr_size_t bytes;
    apr_status_t rv = APR_SUCCESS;

    apr_brigade_cleanup(to);
    for (e = APR_BRIGADE_FIRST(from);
         e != APR_BRIGADE_SENTINEL(from);
         e = APR_BUCKET_NEXT(e)) {
        if (!APR_BUCKET_IS_METADATA(e)) {
            apr_bucket_read(e, &data, &bytes, APR_BLOCK_READ);
            new = apr_bucket_transient_create(data, bytes, r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_FLUSH(e)) {
            new = apr_bucket_flush_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_EOS(e)) {
            new = apr_bucket_eos_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00964)
                          "Unhandled bucket type of type %s in"
                          " proxy_buckets_lifetime_transform", e->type->name);
            apr_bucket_delete(e);
            rv = APR_EGENERAL;
        }
    }
    return rv;
}

/* Constructi Via header - used for proxying */
static osip_via_t *construct_viaHeader(osip_message_t *sipMsg) {
    osip_via_t *via;
    int i = osip_via_init(&via);
    if (i != OSIP_SUCCESS) return NULL;

    /* TODO: LMCDASI - should be taken from config - not hardcoded */
    osip_via_set_version (via, strdup("2.0"));
    osip_via_set_protocol(via, strdup("TCP"));
    osip_via_set_host(via, strdup("192.168.105.3"));
    osip_via_set_port(via, strdup("25060"));
    osip_via_set_branch(via, strdup("a7c6a8dlze.1"));

    return via;
}

/* Add via header - used for proxying the msg to a JVM */
static int add_viaHeader(osip_message_t *sipMsg) {
    sipMsg->message_property = 2;
    osip_list_add(&sipMsg->vias, construct_viaHeader(sipMsg), 0);

    return OSIP_SUCCESS;
}

/* Remove via header - used for proxying the msg to a client */
static int remove_viaHeader(osip_message_t *sipMsg) {
    /* rebuild the via header */
    osip_via_t *via = construct_viaHeader(sipMsg);
    int result = OSIP_SUCCESS;
  
    osip_list_iterator_t iterator;

    osip_via_t *tmp = (osip_via_t *) osip_list_get_first(&sipMsg->vias , &iterator);
    while (osip_list_iterator_has_elem(iterator))
    {
       if (osip_via_match(tmp, via) == 0)
       {
          osip_list_iterator_remove(&iterator);
          goto traceout;
       }

       tmp = (osip_via_t*) osip_list_get_next(&iterator);
    }

    result = OSIP_NOTFOUND;

traceout:
    osip_via_free(via);
    return result;
}

static int remove_firstViaHeader(osip_message_t *sipMsg) {
    osip_via_t *via;

    /* remove top via since we add one ... and send */
    via = osip_list_get(&sipMsg->vias, 0);
    osip_list_remove(&sipMsg->vias, 0);
    osip_via_free(via);

    return OSIP_SUCCESS;
}

/* Add record route - used for proxying the msg to a JVM */
static osip_record_route_t *create_recordRoute(osip_message_t *sipMsg, request_rec *r) {
    osip_record_route_t *recordRoute;
    osip_uri_t *recordRouteURI;

    int i = osip_record_route_init(&recordRoute);
    if (i != OSIP_SUCCESS) return NULL;

    i=osip_uri_init(&recordRouteURI);
    if (i != OSIP_SUCCESS)
    {
      osip_record_route_free(recordRoute);
      return NULL;
    }

    osip_uri_set_host(recordRouteURI, osip_strdup("192.168.105.3"));
    osip_uri_set_username(recordRouteURI, osip_strdup("sip_http_proxy"));
    osip_uri_set_port(recordRouteURI, osip_strdup("25060"));
    /* 'lr' parameter */
    osip_uri_uparam_add(recordRouteURI, osip_strdup("lr"), NULL);

    osip_record_route_set_url(recordRoute, recordRouteURI);

    return recordRoute;
}

/* Add a record route */
static int add_recordRoute(osip_message_t *sipMsg, request_rec *r) {
    osip_record_route_t *recordRoute;

    sipMsg->message_property = 2;

    recordRoute = create_recordRoute(sipMsg, r);

    osip_list_add(&sipMsg->record_routes, recordRoute, 0);

    return OSIP_SUCCESS;
}

/* Remove our record route - I made the assumption that
 * it is the first one .... when possibly not
 */
static void remove_recordRoute(osip_message_t *sipMsg) {
    osip_record_route_t *recordRoute;

    osip_message_get_record_route(sipMsg, 0, &recordRoute);

    osip_list_remove(&sipMsg->record_routes, 0);
    osip_route_free(recordRoute);
}

/* Proxy the request to a sip stack */
static int ap_proxy_sip_request(apr_pool_t *p, request_rec *r,
                         proxy_conn_rec *p_conn, proxy_worker *worker,
                         proxy_server_conf *conf,
                         apr_uri_t *uri,
                         char *url, char *server_portstr)
{
    osip_message_t *sip;
    apr_size_t length=0;
    const char *sipMsg = r->the_request;
    char *dest=NULL;
    int i, rv = OK;

    conn_rec *c = r->connection;

    /*
     * Read SIP/2.0 request from the remote server
     */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "Received SIP traffic");

    i = osip_message_init(&sip);
    if (i < 0 ) {
        return DECLINED;
    }

    ap_time_process_request(c->sbh, START_PREQUEST);
    ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);

    /* handle Via */
    if (osip_message_parse(sip, sipMsg, HUGE_STRING_LEN) < 0) {
       /* TODO: free message */
       return DECLINED;
    } else {
       add_viaHeader(sip);
       add_recordRoute(sip, r);
    }

    /*
     * Convert new sip message in str
     */
    if(osip_message_to_str(sip, &dest, &length) < 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "Unable to convert sip msg to string");

        return DECLINED;
    }

    printf("Sending data to JavaSIP stack\n");

    /*
     * Send the SIP/2.0 request to the remote server
     */
    rv = apr_socket_send(p_conn->sock, dest, &length);
    if (rv != OK)
    {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "Failed to proxy sip message: %s", dest);

        return DECLINED;
    }

    /* TODO: Find out how to free msg: undefined symbol: osip_free_func */
    osip_message_free(sip);
    osip_free(dest);
    return OK;
}

/*
 * If the date is a valid RFC 850 date or asctime() date, then it
 * is converted to the RFC 1123 format.
 */
static const char *date_canon(apr_pool_t *p, const char *date)
{
    apr_status_t rv;
    char* ndate;

    apr_time_t time = apr_date_parse_http(date);
    if (!time) {
        return date;
    }

    ndate = apr_palloc(p, APR_RFC822_DATE_LEN);
    rv = apr_rfc822_date(ndate, time);
    if (rv != APR_SUCCESS) {
        return date;
    }

    return ndate;
}

static request_rec *make_fake_req(conn_rec *c, request_rec *r)
{
    request_rec *rp = sip_read_request(c);

    proxy_run_create_req(r, rp);

    return rp;
}

static apr_status_t ap_proxy_sip_process_response(apr_pool_t * p, request_rec *r,
                                            proxy_conn_rec **backend_ptr,
                                            proxy_worker *worker,
                                            proxy_server_conf *conf,
                                            char *server_portstr,
                                            apr_socket_t *clientSocket) {
    osip_message_t *sip;
    const char *sipMsg;
    char *dest=NULL;
    apr_size_t length=0;
    int i, rv = OK;
    proxy_conn_rec *backend = *backend_ptr;
    conn_rec *c = r->connection;

    /* Get response from the remote server, and pass it up the
     * filter chain
     */
    while( (backend->r = make_fake_req(backend->connection, r)) != NULL ) {

         /* TODO: verify when I can be in such a satte */
         if (backend->r->status == HTTP_BAD_REQUEST) break;

         i = osip_message_init(&sip);
         if (i < 0 ) {
             return DECLINED;
         }

         ap_time_process_request(backend->connection->sbh, START_PREQUEST);
         ap_update_child_status_from_conn(backend->connection->sbh, SERVER_BUSY_READ, backend->connection);

         ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_WRITE, c);

         /*
          * Read and process each request found on our connection
          * until no requests are left or we decide to close.
          */
         sipMsg = backend->r->the_request;

         /* handle Via */
         if (osip_message_parse(sip, sipMsg, HUGE_STRING_LEN) < 0) {
            osip_message_free(sip);
            return DECLINED;
         } else {
            /* remove_viaHeader(sip); */
            remove_firstViaHeader(sip);
            remove_recordRoute(sip);
         } 

         /* TODO: DO I need to add another via ?!? */

         /*
          * Convert new sip message in str
          */
         if(osip_message_to_str(sip, &dest, &length) < 0) {
             ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "Unable to convert sip msg to string");
             osip_message_free(sip);
             osip_free(dest);
             return DECLINED;
         }

         backend->worker->s->read += length;

         /*
          * Send the SIP/2.0 request to the remote server
          */
         rv = apr_socket_send(clientSocket, dest, &length);
         if (rv != OK)
         {
             ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, "Failed to proxy sip message: %s", dest);
             osip_message_free(sip);
             osip_free(dest);
             return DECLINED;
         }

         osip_free(dest);
         osip_message_free(sip);
    }

    ap_proxy_release_connection(backend->worker->s->scheme, backend, r->server);

    /* Ensure that the backend is not reused */
    *backend_ptr = NULL;
    r = NULL;

    return OK;
}

static
apr_status_t ap_proxy_sip_cleanup(const char *scheme, request_rec *r,
                                   proxy_conn_rec *backend)
{
    ap_proxy_release_connection(scheme, backend, r->server);
    return OK;
}

/*
 * This handles sip:// URLs
 */
static int proxy_sip_handler(request_rec *r, proxy_worker *worker,
                              proxy_server_conf *conf,
                              char *url, const char *proxyname,
                              apr_port_t proxyport)
{
    int status;
    char server_portstr[32];
    char *scheme;
    const char *proxy_function;
    const char *u;
    proxy_conn_rec *backend = NULL;
    int is_ssl = 0;
    conn_rec *c = r->connection;
    int i, retry = 0;
    osip_t *osip;
    apr_socket_t *clientSocket;

    /*
     * Use a shorter-lived pool to reduce memory usage
     * and avoid a memory leak
     */
    apr_pool_t *p = r->pool;
    apr_uri_t *uri = apr_palloc(p, sizeof(*uri));

    /* find the scheme */
    u = strchr(url, ':');
    if (u == NULL || u[1] != '/' || u[2] != '/' || u[3] == '\0')
       return DECLINED;
    if ((u - url) > 14)
        return HTTP_BAD_REQUEST;
    scheme = apr_pstrndup(p, url, u - url);
    /* scheme is lowercase */
    ap_str_tolower(scheme);
    /* is it for us? */
    if (strcmp(scheme, "sips") == 0) {
        if (!ap_proxy_ssl_enable(NULL)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01112)
                          "SIPS: declining URL %s (mod_ssl not configured?)",
                          url);
            return DECLINED;
        }
        is_ssl = 1;
        proxy_function = "SIPS";
    } else if(strcmp(scheme, "sip") == 0) {
        proxy_function = "SIP";
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01113) "SIP: declining URL %s",
                      url);
        return DECLINED; /* only interested in HTTP, or FTP via proxy */
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "SIP: serving URL %s", url);

    /* create space for state information */
    if ((status = ap_proxy_acquire_connection(proxy_function, &backend,
                                              worker, r->server)) != OK)
        goto cleanup;


    backend->is_ssl = is_ssl;

    if (is_ssl) {
        ap_proxy_ssl_connection_cleanup(backend, r);
    }

    i = osip_init(&osip);
    if (i != OSIP_SUCCESS) {
        // TODO: How to handle this ?!? - exit ?!?
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, backend->pool, "Unable to init libosip stack - error code: %d", i);
    }

    /*
     * In the case that we are handling a reverse proxy connection and this
     * is not a request that is coming over an already kept alive connection
     * with the client, do NOT reuse the connection to the backend, because
     * we cannot forward a failure to the client in this case as the client
     * does NOT expect this in this situation.
     * Yes, this creates a performance penalty.
     */
    if ((r->proxyreq == PROXYREQ_REVERSE) && (!c->keepalives)
        && (apr_table_get(r->subprocess_env, "proxy-initial-not-pooled"))) {
        backend->close = 1;
    }

    while (retry < 2) {
        char *locurl = url;

        /* Step One: Determine Who To Connect To */
        if ((status = ap_proxy_determine_connection(p, r, conf, worker, backend,
                                                uri, &locurl, proxyname,
                                                proxyport, server_portstr,
                                                sizeof(server_portstr))) != OK)
            break;

        /* Step Two: Make the Connection */
        if (ap_proxy_connect_backend(proxy_function, backend, worker, r->server)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01114)
                          "HTTP: failed to make connection to backend: %s",
                          backend->hostname);
            status = HTTP_SERVICE_UNAVAILABLE;
            break;
        }

        /* Step Three: Create conn_rec */
        if (!backend->connection) {
            if ((status = ap_proxy_connection_create(proxy_function, backend,
                                                     c, r->server)) != OK)
                break;
            /*
             * On SSL connections set a note on the connection what CN is
             * requested, such that mod_ssl can check if it is requested to do
             * so.
             */
            if (is_ssl) {
                proxy_dir_conf *dconf;
                const char *ssl_hostname;

                /*
                 * In the case of ProxyPreserveHost on use the hostname of
                 * the request if present otherwise use the one from the
                 * backend request URI.
                 */
                dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
                if ((dconf->preserve_host != 0) && (r->hostname != NULL)) {
                    ssl_hostname = r->hostname;
                }
                else {
                    ssl_hostname = uri->hostname;
                }

                apr_table_set(backend->connection->notes, "proxy-request-hostname",
                              ssl_hostname);
            }
        }

        /* Step Four: Send the Request
         * On the off-chance that we forced a 100-Continue as a
         * kinda HTTP ping test, allow for retries
         */
        if ((status = ap_proxy_sip_request(p, r, backend, worker,
                                        conf, uri, locurl, server_portstr)) != OK) {
            if ((status == HTTP_SERVICE_UNAVAILABLE) && worker->s->ping_timeout_set) {
                backend->close = 1;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO(01115)
                              "HTTP: 100-Continue failed to %pI (%s)",
                              worker->cp->addr, worker->s->hostname);
                retry++;
                continue;
            } else {
                break;
            }

        }

        clientSocket = ap_get_conn_socket(r->connection);

        /* Step Five: Receive the Response... Fall thru to cleanup */
        status = ap_proxy_sip_process_response(p, r, &backend, worker,
                                                conf, server_portstr, clientSocket);

        break;
    }

    /* Step Six: Clean Up */
cleanup:
    if (backend) {
        if (status != OK)
            backend->close = 1;
        ap_proxy_sip_cleanup(proxy_function, r, backend);
    }
    return status;
}

static int proxy_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    /*
    void *sconf = s->module_config;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    apr_hash_t *dcrmap = apr_hash_make(conf->pool);

    apr_pool_userdata_set(dcrmap, "dcrmap", NULL, conf->pool);
    */

    return OK;
}

static void ap_proxy_sip_register_hook(apr_pool_t *p)
{
    /* post config handling */
    ap_hook_post_config(proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    proxy_hook_scheme_handler(proxy_sip_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_sip_canon, NULL, NULL, APR_HOOK_FIRST);

    warn_rx = ap_pregcomp(p, "[0-9]{3}[ \t]+[^ \t]+[ \t]+\"[^\"]*\"([ \t]+\"([^\"]+)\")?", 0);

    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, "PROXY SIP register_hooks executed");
}

AP_DECLARE_MODULE(proxy_sip) = {
    STANDARD20_MODULE_STUFF,
    NULL,              /* create per-directory config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    NULL,              /* command apr_table_t */
    ap_proxy_sip_register_hook/* register hooks */
};

