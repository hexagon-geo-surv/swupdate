/* SPDX-FileCopyrightText: 2026 Bastian Germann
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * SWUpdate webserver based on libwebsockets.
 *
 * Provides in a single server:
 *   POST /upload   - stream SWU images to the installer
 *   POST /restart  - trigger the post-update action
 *   GET  *         - static file serving from a configurable web root
 *   GET  (ws)      - WebSocket status endpoint
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <time.h>

#include <libwebsockets.h>

#include "webserver_interface.h"
#include "network_ipc.h"
#include "progress.h"
#include "util.h"
#include "parselib.h"
#include "swupdate_settings.h"
#include "pctl.h"

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define LWS_DEFAULT_PORT    8080
#define LWS_MAX_WS_SESSIONS 16

/* -----------------------------------------------------------------------
 * Message node  (singly-linked list for the WebSocket broadcast queue)
 * --------------------------------------------------------------------- */

struct msg_node {
	struct msg_node *next;
	size_t           len;
	char             json[];  /* flexible array -- allocated inline */
};

static struct msg_node *msg_node_new(const char *json)
{
	size_t len = strlen(json);
	struct msg_node *n = malloc(sizeof(*n) + len + 1);
	if (!n)
		return NULL;
	n->next = NULL;
	n->len  = len;
	memcpy(n->json, json, len + 1);
	return n;
}

/* -----------------------------------------------------------------------
 * Global state
 * --------------------------------------------------------------------- */

static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct msg_node *g_head;
static struct msg_node *g_tail;
static struct lws_context *g_ctx;
static bool  s_run_postupdate;
static const char *s_document_root;   /* set once before lws_create_context */
static unsigned int s_watchdog_secs;  /* 0 = disabled */

static volatile sig_atomic_t s_signo;

/* -----------------------------------------------------------------------
 * Per-session state
 * --------------------------------------------------------------------- */

/* HTTP request routes */
#define ROUTE_NONE    0
#define ROUTE_UPLOAD  1

/* Upload content types */
#define CTYPE_NONE       0
#define CTYPE_MULTIPART  1
#define CTYPE_OCTET      2

struct pss {
	/* HTTP / upload */
	int             route;
	int             ctype;
	int             ipc_fd;        /* -1 when not open */
	struct lws_spa *spa;           /* multipart parser; NULL if unused */
	bool            upload_error;
	time_t          last_io_time;  /* for upload watchdog */

	/* WebSocket */
	struct msg_node *send_head;
	struct msg_node *send_tail;
	int              slot;         /* index in g_sessions[]; -1 if not WS */
};

/* -----------------------------------------------------------------------
 * WebSocket session registry  (lws service thread only -- no lock needed)
 * --------------------------------------------------------------------- */

static struct pss *g_sessions[LWS_MAX_WS_SESSIONS];

static void session_add(struct pss *pss)
{
	for (int i = 0; i < LWS_MAX_WS_SESSIONS; i++) {
		if (!g_sessions[i]) {
			g_sessions[i] = pss;
			pss->slot = i;
			return;
		}
	}
	pss->slot = -1;
	WARN("LWS: too many concurrent WebSocket sessions (max %d)",
	     LWS_MAX_WS_SESSIONS);
}

static void session_remove(struct pss *pss)
{
	if (pss->slot >= 0 && pss->slot < LWS_MAX_WS_SESSIONS)
		g_sessions[pss->slot] = NULL;

	struct msg_node *m = pss->send_head;
	while (m) {
		struct msg_node *nxt = m->next;
		free(m);
		m = nxt;
	}
	pss->send_head = pss->send_tail = NULL;
}

/* -----------------------------------------------------------------------
 * WebSocket broadcast  (called from IPC listener threads)
 * --------------------------------------------------------------------- */

static void ws_broadcast(const char *json)
{
	struct msg_node *n = msg_node_new(json);
	if (!n)
		return;

	pthread_mutex_lock(&g_lock);
	if (g_tail)
		g_tail->next = n;
	else
		g_head = n;
	g_tail = n;
	pthread_mutex_unlock(&g_lock);

	if (g_ctx)
		lws_cancel_service(g_ctx);
}

/* -----------------------------------------------------------------------
 * SPA (multipart/form-data) file upload callback
 * --------------------------------------------------------------------- */

static int spa_fileupload_cb(void *data, const char *name,
			     const char *filename, char *buf, int len,
			     enum lws_spa_fileupload_states state)
{
	struct pss *pss = data;

	(void)name;

	switch (state) {
	case LWS_UFS_OPEN: {
		struct swupdate_request req;
		swupdate_prepare_req(&req);
		req.source = SOURCE_WEBSERVER;
		if (filename)
			strncpy(req.info, filename, sizeof(req.info) - 1);
		pss->ipc_fd = ipc_inst_start_ext(&req, sizeof(req));
		if (pss->ipc_fd < 0) {
			ERROR("LWS: upload: ipc_inst_start_ext failed");
			pss->upload_error = true;
		} else {
			swupdate_download_update(0, 0);
		}
		break;
	}

	case LWS_UFS_CONTENT:
	case LWS_UFS_FINAL_CONTENT:
		if (!pss->upload_error && pss->ipc_fd >= 0 && buf && len > 0) {
			if (write(pss->ipc_fd, buf, (size_t)len) < 0) {
				ERROR("LWS: upload: IPC write: %s",
				      strerror(errno));
				pss->upload_error = true;
			}
		}
		if (state == LWS_UFS_FINAL_CONTENT && pss->ipc_fd >= 0) {
			ipc_end(pss->ipc_fd);
			pss->ipc_fd = -1;
		}
		break;

	case LWS_UFS_CLOSE:
		if (pss->ipc_fd >= 0) {
			ipc_end(pss->ipc_fd);
			pss->ipc_fd = -1;
			pss->upload_error = true;
		}
		break;
	}
	return 0;
}



/* -----------------------------------------------------------------------
 * Unified HTTP + WebSocket callback
 * --------------------------------------------------------------------- */

static const struct lws_protocols protocols[];  /* forward declaration */

static int callback_swupdate(struct lws *wsi, enum lws_callback_reasons reason,
			     void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;

	switch (reason) {

	/* ----------------------------------------------------------------
	 * Incoming HTTP request (headers complete)
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_HTTP: {
		char uri[256] = "";
		bool is_post;

		is_post = lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) > 0;
		if (is_post)
			lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_POST_URI);
		else
			lws_hdr_copy(wsi, uri, sizeof(uri), WSI_TOKEN_GET_URI);

		/* Initialise per-session HTTP state (pss is zero-filled by lws) */
		pss->ipc_fd = -1;
		pss->slot   = -1;

		if (is_post && strcmp(uri, "/upload") == 0) {
			char ct[256] = "";
			pss->route = ROUTE_UPLOAD;
			lws_hdr_copy(wsi, ct, sizeof(ct),
				     WSI_TOKEN_HTTP_CONTENT_TYPE);

			if (strncasecmp(ct, "multipart/form-data", 19) == 0) {
				static const char * const fields[] =
					{ "file", NULL };
				pss->ctype = CTYPE_MULTIPART;
				pss->spa   = lws_spa_create(wsi, fields, 1,
							    4096,
							    spa_fileupload_cb,
							    pss);
				if (!pss->spa) {
					ERROR("LWS: lws_spa_create failed");
					lws_return_http_status(wsi,
						HTTP_STATUS_INTERNAL_SERVER_ERROR,
						NULL);
					goto done_http;
				}
			} else {
				/* Treat anything else as raw octet-stream */
				struct swupdate_request req;
				pss->ctype = CTYPE_OCTET;
				swupdate_prepare_req(&req);
				req.source = SOURCE_WEBSERVER;
				pss->ipc_fd = ipc_inst_start_ext(&req,
								 sizeof(req));
				if (pss->ipc_fd < 0) {
					ERROR("LWS: upload: ipc_inst_start_ext"
					      " failed");
					lws_return_http_status(wsi,
						HTTP_STATUS_INTERNAL_SERVER_ERROR,
						NULL);
					goto done_http;
				}
				swupdate_download_update(0, 0);
			}
			pss->last_io_time = time(NULL);
			if (s_watchdog_secs)
				lws_set_timer_usecs(wsi,
					(lws_usec_t)s_watchdog_secs *
					LWS_USEC_PER_SEC);
			return 0;

		} else if (is_post && strcmp(uri, "/restart") == 0) {
			ipc_message msg = {};
			int ret = ipc_postupdate(&msg);
			lws_return_http_status(wsi,
				(ret || msg.type != ACK)
					? HTTP_STATUS_INTERNAL_SERVER_ERROR
					: HTTP_STATUS_OK,
				NULL);
			goto done_http;

		} else if (!is_post) {
			/* Static file serving */
			if (s_document_root && *s_document_root) {
				const char *p = (*uri == '/') ? uri : "/";
				if (strcmp(p, "/") == 0)
					p = "/index.html";

				char filepath[512];
				snprintf(filepath, sizeof(filepath), "%s%s",
					 s_document_root, p);

				const char *mime = lws_get_mimetype(filepath, NULL);
				if (!mime)
					mime = "application/octet-stream";
				int n = lws_serve_http_file(wsi, filepath, mime,
							    NULL, 0);
				if (n < 0 || (n > 0 &&
				    lws_http_transaction_completed(wsi)))
					return -1;
				return 0;
			}
		}

		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
done_http:
		return lws_http_transaction_completed(wsi) ? -1 : 0;
	}

	/* ----------------------------------------------------------------
	 * Receiving POST body chunks
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_HTTP_BODY:
		if (pss->route == ROUTE_UPLOAD) {
			pss->last_io_time = time(NULL);
			if (pss->ctype == CTYPE_MULTIPART) {
				if (pss->spa)
					lws_spa_process(pss->spa, in, (int)len);
			} else if (pss->ctype == CTYPE_OCTET) {
				if (!pss->upload_error && pss->ipc_fd >= 0) {
					if (write(pss->ipc_fd, in, len) < 0) {
						ERROR("LWS: upload: IPC write:"
						      " %s", strerror(errno));
						pss->upload_error = true;
					}
				}
			}
		}
		break;

	/* ----------------------------------------------------------------
	 * POST body fully received
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (pss->route == ROUTE_UPLOAD) {
			if (pss->ctype == CTYPE_MULTIPART && pss->spa) {
				lws_spa_finalize(pss->spa);
				lws_spa_destroy(pss->spa);
				pss->spa = NULL;
			} else if (pss->ctype == CTYPE_OCTET &&
				   pss->ipc_fd >= 0) {
				ipc_end(pss->ipc_fd);
				pss->ipc_fd = -1;
			}
			lws_return_http_status(wsi,
				pss->upload_error
					? HTTP_STATUS_INTERNAL_SERVER_ERROR
					: HTTP_STATUS_OK,
				NULL);
		}
		return lws_http_transaction_completed(wsi) ? -1 : 0;

	/* ----------------------------------------------------------------
	 * Static file serving complete
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		return lws_http_transaction_completed(wsi) ? -1 : 0;

	/* ----------------------------------------------------------------
	 * Connection closed (HTTP or mid-upload)
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss->ipc_fd >= 0) {
			close(pss->ipc_fd);
			pss->ipc_fd = -1;
		}
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	/* ----------------------------------------------------------------
	 * WebSocket handshake complete
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_ESTABLISHED:
		pss->ipc_fd    = -1;
		pss->spa       = NULL;
		pss->send_head = NULL;
		pss->send_tail = NULL;
		pss->slot      = -1;
		session_add(pss);
		break;

	/* ----------------------------------------------------------------
	 * WebSocket connection closed
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_CLOSED:
		session_remove(pss);
		break;

	/* ----------------------------------------------------------------
	 * Send next pending WebSocket message
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_SERVER_WRITEABLE: {
		if (!pss->send_head)
			break;

		struct msg_node *msg = pss->send_head;
		pss->send_head = msg->next;
		if (!pss->send_head)
			pss->send_tail = NULL;

		uint8_t *buf = malloc(LWS_PRE + msg->len);
		if (buf) {
			memcpy(buf + LWS_PRE, msg->json, msg->len);
			lws_write(wsi, buf + LWS_PRE, msg->len,
				  LWS_WRITE_TEXT);
			free(buf);
		}
		free(msg);

		if (pss->send_head)
			lws_callback_on_writable(wsi);
		break;
	}

	/* ----------------------------------------------------------------
	 * Broadcast queue woken by ws_broadcast() → lws_cancel_service()
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
		pthread_mutex_lock(&g_lock);
		struct msg_node *bcast = g_head;
		g_head = g_tail = NULL;
		pthread_mutex_unlock(&g_lock);

		while (bcast) {
			struct msg_node *nxt = bcast->next;
			for (int i = 0; i < LWS_MAX_WS_SESSIONS; i++) {
				struct pss *s = g_sessions[i];
				if (!s)
					continue;
				struct msg_node *copy =
					msg_node_new(bcast->json);
				if (!copy)
					continue;
				if (s->send_tail)
					s->send_tail->next = copy;
				else
					s->send_head = copy;
				s->send_tail = copy;
			}
			free(bcast);
			bcast = nxt;
		}
		lws_callback_on_writable_all_protocol(g_ctx, &protocols[0]);
		break;
	}

	/* ----------------------------------------------------------------
	 * Upload watchdog timer
	 * -------------------------------------------------------------- */
	case LWS_CALLBACK_TIMER:
		if (pss->route == ROUTE_UPLOAD && s_watchdog_secs) {
			time_t elapsed = time(NULL) - pss->last_io_time;
			if ((unsigned int)elapsed >= s_watchdog_secs) {
				ERROR("LWS: upload timeout after %ld seconds,"
				      " closing connection", (long)elapsed);
				lws_return_http_status(wsi,
					HTTP_STATUS_REQUEST_TIMEOUT, NULL);
				return -1;
			}
			/* Not yet expired -- reschedule */
			lws_set_timer_usecs(wsi,
				(lws_usec_t)s_watchdog_secs *
				LWS_USEC_PER_SEC);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		.name                  = "swupdate",
		.callback              = callback_swupdate,
		.per_session_data_size = sizeof(struct pss),
		.rx_buffer_size        = 4096,
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/* -----------------------------------------------------------------------
 * IPC listener threads  (same JSON protocol as mongoose_interface.c)
 * --------------------------------------------------------------------- */

static void *broadcast_message_thread(void __attribute__((__unused__)) *data)
{
	int fd = -1;

	for (;;) {
		ipc_message msg;
		int ret;

		if (fd < 0)
			fd = ipc_notify_connect();
		if (fd < 0) {
			sleep(1);
			continue;
		}

		ret = ipc_notify_receive(&fd, &msg);
		if (ret != sizeof(msg))
			break;

		if (strlen(msg.data.notify.msg) != 0 &&
		    msg.data.status.current != PROGRESS) {
			char text[4096];
			char str[4160];

			snescape(text, sizeof(text), msg.data.notify.msg);

			snprintf(str, sizeof(str),
				 "{\r\n"
				 "\t\"type\": \"message\",\r\n"
				 "\t\"level\": \"%d\",\r\n"
				 "\t\"text\": \"%s\"\r\n"
				 "}\r\n",
				 level_to_rfc_5424(msg.data.notify.level),
				 text);
			ws_broadcast(str);
		}
	}

	return NULL;
}

static void *broadcast_progress_thread(void __attribute__((__unused__)) *data)
{
	RECOVERY_STATUS status  = -1;
	sourcetype      source  = -1;
	unsigned int    step    = 0;
	uint8_t         percent = 0;
	int             fd      = -1;

	for (;;) {
		struct progress_msg msg;
		char str[1024];
		char escaped[512];
		int ret;

		if (fd < 0)
			fd = progress_ipc_connect(true);
		if (fd < 0) {
			sleep(1);
			continue;
		}

		ret = progress_ipc_receive(&fd, &msg);
		if (ret != sizeof(msg))
			break;

		if (msg.status != PROGRESS &&
		    (msg.status != status || msg.status == FAILURE)) {
			status = msg.status;
			snescape(escaped, sizeof(escaped),
				 get_status_string(msg.status));
			snprintf(str, sizeof(str),
				 "{\r\n"
				 "\t\"type\": \"status\",\r\n"
				 "\t\"status\": \"%s\"\r\n"
				 "}\r\n",
				 escaped);
			ws_broadcast(str);
		}

		if (msg.source != source) {
			source = msg.source;
			snprintf(str, sizeof(str),
				 "{\r\n"
				 "\t\"type\": \"source\",\r\n"
				 "\t\"source\": \"%s\"\r\n"
				 "}\r\n",
				 get_source_string(msg.source));
			ws_broadcast(str);
		}

		if (msg.status == SUCCESS && msg.source == SOURCE_WEBSERVER &&
		    s_run_postupdate) {
			ipc_message ipc = {};
			ipc_postupdate(&ipc);
		}

		if (msg.infolen) {
			snescape(escaped, sizeof(escaped), msg.info);
			snprintf(str, sizeof(str),
				 "{\r\n"
				 "\t\"type\": \"info\",\r\n"
				 "\t\"source\": \"%s\"\r\n"
				 "}\r\n",
				 escaped);
			ws_broadcast(str);
		}

		if ((msg.cur_step != step || msg.cur_percent != percent) &&
		    msg.cur_step) {
			step    = msg.cur_step;
			percent = msg.cur_percent;
			snescape(escaped, sizeof(escaped),
				 msg.cur_step ? msg.cur_image : "");
			snprintf(str, sizeof(str),
				 "{\r\n"
				 "\t\"type\": \"step\",\r\n"
				 "\t\"number\": \"%d\",\r\n"
				 "\t\"step\": \"%d\",\r\n"
				 "\t\"name\": \"%s\",\r\n"
				 "\t\"percent\": \"%d\"\r\n"
				 "}\r\n",
				 msg.nsteps, msg.cur_step,
				 escaped, msg.cur_percent);
			ws_broadcast(str);
		}
	}

	return NULL;
}

/* -----------------------------------------------------------------------
 * Configuration + entry point
 * --------------------------------------------------------------------- */

struct lws_opts {
	int   port;
	char *document_root;
	bool  run_postupdate;
	unsigned int watchdog_secs;
#ifdef CONFIG_MONGOOSESSL
	bool  ssl;
	char *ssl_cert;
	char *ssl_key;
#endif
};

static int lws_settings(void *elem, void __attribute__((__unused__)) *data)
{
	struct lws_opts *opts = data;
	char tmp[256] = "";

	GET_FIELD_INT(LIBCFG_PARSER, elem, "listening_ports", &opts->port);
	GET_FIELD_STRING_RESET(LIBCFG_PARSER, elem, "document_root", tmp);
	if (strlen(tmp)) {
		free(opts->document_root);
		opts->document_root = strdup(tmp);
	}
	GET_FIELD_BOOL(LIBCFG_PARSER, elem, "run-postupdate",
		       &opts->run_postupdate);
	GET_FIELD_INT(LIBCFG_PARSER, elem, "timeout",
		      (int *)&opts->watchdog_secs);
#ifdef CONFIG_MONGOOSESSL
	GET_FIELD_STRING_RESET(LIBCFG_PARSER, elem, "ssl_certificate", tmp);
	if (strlen(tmp)) {
		free(opts->ssl_cert);
		opts->ssl_cert = strdup(tmp);
	}
	GET_FIELD_STRING_RESET(LIBCFG_PARSER, elem, "ssl_certificate_key", tmp);
	if (strlen(tmp)) {
		free(opts->ssl_key);
		opts->ssl_key = strdup(tmp);
	}
#endif
	return 0;
}

static struct option long_options[] = {
	{ "port",            required_argument, NULL, 'p' },
	{ "document-root",   required_argument, NULL, 'r' },
	{ "timeout",         required_argument, NULL, 't' },
#ifdef CONFIG_MONGOOSESSL
	{ "ssl",      no_argument,       NULL, 's' },
	{ "ssl-cert", required_argument, NULL, 'C' },
	{ "ssl-key",  required_argument, NULL, 'K' },
#endif
	{ NULL, 0, NULL, 0 }
};

void webserver_print_help(void)
{
	fprintf(
		stdout,
		"\tlws arguments:\n"
		"\t  -p, --port <port>              : server port number  (default: %d)\n"
#ifdef CONFIG_MONGOOSESSL
		"\t  -s, --ssl                      : enable ssl support\n"
		"\t  -C, --ssl-cert <cert>          : ssl certificate to present to clients\n"
		"\t  -K, --ssl-key <key>            : key corresponding to the ssl certificate\n"
#endif
		"\t  -r, --document-root <path>     : path to document root directory\n"
		"\t  -t, --timeout                  : timeout to check if connection is lost (default: check disabled)\n",
		LWS_DEFAULT_PORT);
}

static void signal_handler(int signo) {
	s_signo = signo;
}

int start_webserver(const char *cfgfname, int argc, char *argv[])
{
	struct lws_opts opts = {
		.port           = LWS_DEFAULT_PORT,
		.document_root  = NULL,
		.run_postupdate = true,
		.watchdog_secs  = 0,
#ifdef CONFIG_MONGOOSESSL
		.ssl         = false,
		.ssl_cert    = NULL,
		.ssl_key     = NULL,
#endif
	};

	if (cfgfname) {
		swupdate_cfg_handle handle;
		swupdate_cfg_init(&handle);
		if (swupdate_cfg_read_file(&handle, cfgfname) == 0)
			read_module_settings(&handle, "webserver",
					     lws_settings, &opts);
		swupdate_cfg_destroy(&handle);
	}

	optind = 1;
	int choice;
	while ((choice = getopt_long(argc, argv,
#ifdef CONFIG_MONGOOSESSL
				     "p:r:t:sC:K:",
#else
				     "p:r:t:",
#endif
				     long_options, NULL)) != -1) {
		switch (choice) {
		case 'p':
			opts.port = (int)strtol(optarg, NULL, 10);
			break;
		case 'r':
			free(opts.document_root);
			opts.document_root = strdup(optarg);
			break;
		case 't':
			opts.watchdog_secs = (unsigned int)strtoul(optarg, NULL, 10);
			break;
#ifdef CONFIG_MONGOOSESSL
		case 's':
			opts.ssl = true;
			break;
		case 'C':
			free(opts.ssl_cert);
			opts.ssl_cert = strdup(optarg);
			break;
		case 'K':
			free(opts.ssl_key);
			opts.ssl_key = strdup(optarg);
			break;
#endif
		default:
			free(opts.document_root);
			return -EINVAL;
		}
	}

	if (optind < argc) {
		ERROR("Non-option arguments given to lws, see --help.");
		webserver_print_help();
		free(opts.document_root);
#ifdef CONFIG_MONGOOSESSL
		free(opts.ssl_cert);
		free(opts.ssl_key);
#endif
		return -EINVAL;
	}

	s_document_root  = opts.document_root ? opts.document_root : "";
	s_run_postupdate = opts.run_postupdate;
	s_watchdog_secs  = opts.watchdog_secs;

	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));
	info.port      = opts.port;
	info.protocols = protocols;
	info.gid       = (gid_t)-1;
	info.uid       = (uid_t)-1;
#ifndef CONFIG_MONGOOSEIPV6
	info.options  |= LWS_SERVER_OPTION_DISABLE_IPV6;
#endif
#ifdef CONFIG_MONGOOSESSL
	if (opts.ssl) {
		if (opts.ssl_cert && opts.ssl_key) {
			info.options                      |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
			info.ssl_cert_filepath             = opts.ssl_cert;
			info.ssl_private_key_filepath      = opts.ssl_key;
		} else {
			ERROR("LWS: TLS requires both --ssl-cert and --ssl-key");
			free(opts.document_root);
			free(opts.ssl_cert);
			free(opts.ssl_key);
			return -EINVAL;
		}
	}
#endif

	lws_set_log_level(LLL_ERR | LLL_WARN, NULL);

	g_ctx = lws_create_context(&info);
	if (!g_ctx) {
		ERROR("LWS: lws_create_context failed");
		free(opts.document_root);
#ifdef CONFIG_MONGOOSESSL
		free(opts.ssl_cert);
		free(opts.ssl_key);
#endif
		return -1;
	}

	INFO("LWS webserver listening on port %d", opts.port);

	pthread_t tid;

	if (pthread_create(&tid, NULL, broadcast_message_thread, NULL) != 0) {
		ERROR("LWS: cannot create message thread: %m");
		lws_context_destroy(g_ctx);
		free(opts.document_root);
#ifdef CONFIG_MONGOOSESSL
		free(opts.ssl_cert);
		free(opts.ssl_key);
#endif
		return -1;
	}
	pthread_detach(tid);

	if (pthread_create(&tid, NULL, broadcast_progress_thread, NULL) != 0) {
		ERROR("LWS: cannot create progress thread: %m");
		lws_context_destroy(g_ctx);
		free(opts.document_root);
#ifdef CONFIG_MONGOOSESSL
		free(opts.ssl_cert);
		free(opts.ssl_key);
#endif
		return -1;
	}
	pthread_detach(tid);

	/* Run the lws event loop in this thread until a signal arrives */
	while (s_signo == 0)
		lws_service(g_ctx, 50);

	lws_context_destroy(g_ctx);
	g_ctx = NULL;
	free(opts.document_root);
#ifdef CONFIG_MONGOOSESSL
	free(opts.ssl_cert);
	free(opts.ssl_key);
#endif
	return 0;
}
