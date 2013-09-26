#include "mod_sip.h"

static int sip_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
		apr_pool_t *ptemp) {
	return OK;
}

static int sip_post_config(apr_pool_t *pconf, apr_pool_t *plog,
		apr_pool_t *ptemp, server_rec *s) {
	return OK;
}

static void *create_sip_server_config(apr_pool_t *p, server_rec *s) {
	sip_config *sconf = apr_pcalloc(p, sizeof(sip_config));

	sconf->enabled = 0;

	return sconf;
}

const char *sip_set_enable(cmd_parms *cmd, void *cfg, const char *arg) {
	sip_config *spc = ap_get_module_config(cmd->server->module_config,
			&sip_module);

	osip_t *osip;
        int i;

	if (!strcasecmp(arg, "on")) {
		spc->enabled = 1;

		i = osip_init(&osip);
		if (i != OSIP_SUCCESS) {
			// TODO: How to handle this ?!? - exit ?!?
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool,
					"Unable to init libosip stack - error code: %d", i);

			/*
			 * Mark sip as disabled since stack could not be initialized
			 */
			spc->enabled = 0;
		}
	} else {
		spc->enabled = 0;
	}

	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, cmd->pool, "SIPEnabled: %s:%d",
			arg, spc->enabled);

	return NULL;
}

static const char *sip_set_active_ports(cmd_parms *cmd, void *dummy,
		const char *min, const char *max) {
	char *error_str = NULL;

	sip_config *spc = ap_get_module_config(cmd->server->module_config,
			&sip_module);

	spc->active_min = atoi(min);
	if (!max) {
		spc->active_max = spc->active_min;
	} else {
		spc->active_max = atoi(max);
	}

	if (spc->active_min > spc->active_max || spc->active_min < 0
			|| spc->active_max > 0xFFFF) {
		error_str = apr_psprintf(cmd->pool, "Invalid range for %s (%s > %s)",
				cmd->directive->directive, min, max);
	}

	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, cmd->pool,
			"SIP Port Range: %s : %s", min, max);

	return error_str;
}

static void build_sip_headers_in(request_rec *r, const char *sipMsg, apr_size_t sipMsg_len) {
        void **dest = NULL;
	osip_message_t *sip;
        int pos = 0;

	if (osip_message_init(&sip) != OSIP_SUCCESS) return;

        if (osip_message_parse(sip, sipMsg, sipMsg_len) != OSIP_SUCCESS) return;

        if (osip_message_get_accept(sip, pos, (osip_accept_t **) dest) == OSIP_SUCCESS) {
		apr_table_setn(r->headers_in, "Accept",  (const char *) *dest);
	}
        if (osip_message_get_accept_encoding(sip, pos, (osip_accept_encoding_t **) dest) == OSIP_SUCCESS) {
                apr_table_setn(r->headers_in, "Accept", (const char *) * dest);
        }
}

request_rec *sip_read_request(conn_rec *conn) {
	request_rec *r;
	apr_pool_t *p;

        const char *sipMsg, *ll, *uri;
        apr_size_t sipMsg_len = 0;
        int seen_eos = 0;
        apr_bucket_brigade *brigade;
        int crlfPos;

	apr_pool_create(&p, conn->pool);
	apr_pool_tag(p, "request");
	r = apr_pcalloc(p, sizeof(request_rec));
	AP_READ_REQUEST_ENTRY((intptr_t) r, (uintptr_t) conn);
	r->pool = p;
	r->connection = conn;
	r->server = conn->base_server;

	r->user = NULL;
	r->ap_auth_type = NULL;

	r->allowed_methods = ap_make_method_list(p, 2);

	r->headers_in = apr_table_make(r->pool, 25);
	r->subprocess_env = apr_table_make(r->pool, 25);
	r->headers_out = apr_table_make(r->pool, 12);
	r->err_headers_out = apr_table_make(r->pool, 5);
	r->notes = apr_table_make(r->pool, 5);

	r->request_config = ap_create_request_config(r->pool);
	/* Must be set before we run create request hook */

	r->proto_output_filters = conn->output_filters;
	r->output_filters = r->proto_output_filters;
	r->proto_input_filters = conn->input_filters;
	r->input_filters = r->proto_input_filters;
	ap_run_create_request(r);
	r->per_dir_config = r->server->lookup_defaults;

	r->sent_bodyct = 0; /* bytect isn't for body */

	r->read_length = 0;
	r->read_body = REQUEST_NO_BODY;

	r->status = HTTP_OK; /* Until further notice */

	r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

	r->useragent_addr = conn->client_addr;
	r->useragent_ip = conn->client_ip;

	/*
	 * Read and process each request found on our connection
	 * until no requests are left or we decide to close.
	 */
	brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
	ap_run_pre_read_request(r, conn);

	while (!seen_eos) {
		if (ap_get_brigade(conn->input_filters, brigade, AP_MODE_READBYTES,
				APR_BLOCK_READ, HUGE_STRING_LEN) != APR_SUCCESS)
			goto traceout;

		while (!APR_BRIGADE_EMPTY(brigade)) {
			apr_bucket *bucket = APR_BRIGADE_FIRST(brigade);

			if (APR_BUCKET_IS_EOS(bucket)) {
				/* We've hit the end!  Stop!  */
				seen_eos = 1;
				break;
			}

			/* Fill-up the SIP request data into the request_rec */
			if (apr_bucket_read(bucket, &sipMsg, &sipMsg_len, APR_BLOCK_READ)
					!= APR_SUCCESS)
				goto traceout;

			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, conn->base_server,
					"Read SIP data: %s", r->the_request);

			crlfPos = sipMsg_len - 2;
			if (strncmp((sipMsg + crlfPos), "\r\n", 2) == 0) {
				/* we have seen end of SIP packet */
				seen_eos = 1;
			}

			apr_bucket_delete(bucket);
		}

		apr_brigade_cleanup(brigade);
	}

    traceout:

	if (sipMsg_len <= 0) {
		r->status = HTTP_BAD_REQUEST;
		AP_READ_REQUEST_FAILURE((uintptr_t) r);
	} else {
		r->request_time = apr_time_now();

		r->the_request = (char *) sipMsg;
		ll = r->the_request;

		r->method = ap_getword_white(r->pool, &ll);

		uri = ap_getword_white(r->pool, &ll);

		ap_parse_uri(r, uri);

		r->protocol = apr_pstrmemdup(r->pool, ll, strlen(ll));

		r->status = HTTP_OK;

		r->connection->keepalive = AP_CONN_KEEPALIVE;

		AP_READ_REQUEST_SUCCESS((uintptr_t) r, (char *) r->method,
				(char *) r->uri, (char *) r->server->defn_name, r->status);
	}

	apr_brigade_destroy(brigade);

	return r;
}

apr_socket_t *ap_get_client_sip_connection(conn_rec *c) {
	apr_socket_t *client_socket = ap_get_conn_socket(c);

	return client_socket;
}

/*
 * Process an incoming SIP connection
 */
static int ap_process_sip_connection(conn_rec *c) {
	request_rec *r;
	conn_state_t *cs = c->cs;

        /* Decline process packet is proto != sip */
        if(strcasecmp(ap_get_server_protocol(c->base_server), "sip") != 0)
                return DECLINED;

	AP_DEBUG_ASSERT(cs != NULL);
	AP_DEBUG_ASSERT(cs->state == CONN_STATE_READ_REQUEST_LINE);

	while (cs->state == CONN_STATE_READ_REQUEST_LINE) {
		ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);

		if ((r = sip_read_request(c))) {
			c->keepalive = AP_CONN_UNKNOWN;

			/* process the request if it was read without error */
			ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
			if (r->status == HTTP_OK) {
				cs->state = CONN_STATE_HANDLER;
				ap_process_async_request(r);

				r = NULL; /* do not reuse it */
			}

			if (cs->state != CONN_STATE_WRITE_COMPLETION
					&& cs->state != CONN_STATE_SUSPENDED) {
				/* Something went wrong; close the connection */
				cs->state = CONN_STATE_LINGER;
			}
		} else { /* ap_read_request failed - client may have closed */
			cs->state = CONN_STATE_LINGER;
		}
	}

	return OK;
}

static const command_rec sip_cmds[] = {
		AP_INIT_TAKE1("SIPEnable", sip_set_enable, NULL, RSRC_CONF, "Enable or Disable SIP module"),
		AP_INIT_TAKE12("SIPActiveRange", sip_set_active_ports, NULL, RSRC_CONF, "Ports the server will use for connecting to the client."), {NULL}
};

static void sip_register_hooks(apr_pool_t *p) {
	ap_hook_pre_config(sip_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(sip_post_config, NULL, NULL, APR_HOOK_MIDDLE);

	/* Middle should make SIP processing first */
	ap_hook_process_connection(ap_process_sip_connection, NULL, NULL,
			APR_HOOK_MIDDLE);

	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
			"SIP register_hooks executed");
}

AP_DECLARE_MODULE (sip) = {
		STANDARD20_MODULE_STUFF,
		NULL,
		NULL,
		create_sip_server_config,
		NULL,
		sip_cmds,
		sip_register_hooks
};
