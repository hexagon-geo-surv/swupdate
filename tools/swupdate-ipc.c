/*
 * (C) Copyright 2021
 * Stefano Babic, DENX Software Engineering, sbabic@denx.de.
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

/*
 * This is a simple example how to send a command to
 * a SWUpdate's subprocess. It sends a "feedback"
 * to the suricatta module and waits for the answer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <getopt.h>

#include "network_ipc.h"

static struct option hawkbitcfg_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"polling-time", required_argument, NULL, 'p'},
	{"enable", no_argument, NULL, 'e'},
	{"disable", no_argument, NULL, 'd'},
	{NULL, 0, NULL, 0}
};

static void usage(char *program) {
	fprintf(stdout, "%s COMMAND [OPTIONS]\n", program);
	fprintf(stdout, "\t aes <key> <ivt>\n");
	fprintf(stdout, "\t setversion <minversion> <maxversion> <current>\n");
	fprintf(stdout, "\t sendtohawkbit <action id> <status> <finished> "
			"<execution> <detail 1> <detail 2> ..\n");
	fprintf(stdout,"\t hawkbitcfg \n");
	fprintf(stdout,
		"\t\t-p, --polling-time      : Set polling time (0=from server) to ask the backend server\n"
		"\t\t-e, --enable            : Enable polling of backend server\n"
		"\t\t-d, --disable           : Disable polling of backend server\n"
		);
	exit(0);
}

static bool check_ascii_char(const char *s) {
	int i;

	if (!s)
		return false;
	for (i = 0; i < strlen(s); i++) {
		if ((s[i] >= '0' && s[i] <= '9') ||
			(s[i] >= 'A' && s[i] <= 'F'))
			continue;
		return false;
	}

	return true;
}

static void send_msg(ipc_message *msg)
{
	int rc;

	fprintf(stdout, "Sending: '%s'", msg->data.procmsg.buf);
	rc = ipc_send_cmd(msg);

	fprintf(stdout, " returned %d\n", rc);
	if (rc == 0) {
		fprintf(stdout, "Server returns %s\n",
				(msg->type == ACK) ? "ACK" : "NACK");
		if (msg->data.procmsg.len > 0) {
			fprintf(stdout, "Returned message: %s\n",
					msg->data.procmsg.buf);
		}
	}
}

static void hawkbitcfg(int argc, char *argv[]) {
	ipc_message msg;
	size_t size;
	char *buf;
	int c;
	unsigned long polling_time;
	bool enable = false;
	int opt_e = 0;
	int opt_p = 0;

	memset(&msg, 0, sizeof(msg));
	msg.data.procmsg.source = SOURCE_SURICATTA;
	msg.type = SWUPDATE_SUBPROCESS;

	size = sizeof(msg.data.procmsg.buf);
	buf = msg.data.procmsg.buf;

	/* Process options with getopt */
	while ((c = getopt_long(argc, argv, "p:edh",
				hawkbitcfg_options, NULL)) != EOF) {
		switch (c) {
		case 'p':
			opt_p = 1;
			msg.data.procmsg.cmd = CMD_CONFIG;
			polling_time = strtoul(optarg, NULL, 10);
			break;
		case 'e':
		case 'd':
			msg.data.procmsg.cmd = CMD_ENABLE;
			opt_e = 1;
			enable = (c == 'e');
			break;
		}
	}

	/*
	 * Build a json string with the command line parameters
	 * do not check anything, let SWUpdate
	 * doing the checks
	 * An error or a NACK is returned in
	 * case of failure
	 */
	if (opt_p) {
		snprintf(buf, size, "{ \"polling\" : \"%lu\"}", polling_time);
		msg.data.procmsg.len = strnlen(buf, size);
		send_msg(&msg);
	}
	if (opt_e) {
		snprintf(buf, size, "{ \"enable\" : %s}", enable ? "true" : "false");
		msg.data.procmsg.len = strnlen(buf, size);
		send_msg(&msg);
	}

	exit(0);
}

static void sendtohawkbit(int argc, char *argv[]) {
	int written, i;
	ipc_message msg;
	size_t size;
	char *buf;

	memset(&msg, 0, sizeof(msg));
	msg.data.procmsg.source = SOURCE_SURICATTA;
	msg.data.procmsg.cmd = CMD_ACTIVATION;
	msg.type = SWUPDATE_SUBPROCESS;

	size = sizeof(msg.data.procmsg.buf);
	buf = msg.data.procmsg.buf;

	/*
	 * Build a json string with the command line parameters
	 * do not check anything, let SWUpdate
	 * doing the checks
	 * An error or a NACK is returned in
	 * case of failure
	 */
	for (i = 0; i < argc; i++) {
		switch (i) {
		case 1:
			written = snprintf(buf, size, "{ \"id\" : \"%lu\"", strtoul(argv[i], NULL, 10));
			break;
		case 2:
			written = snprintf(buf, size, ", \"status\" : \"%s\"", argv[i]);
			break;
		case 3:
			written = snprintf(buf, size, ",\"finished\" : \"%s\"", argv[i]);
			break;
		case 4:
			written = snprintf(buf, size, ",\"execution\" : \"%s\"", argv[i]);
			break;
		case 5:
			written = snprintf(buf, size, ",\"details\" : [ \"%s\"", argv[i]);
			break;
		default:
			written = snprintf(buf, size, ",\"%s\"", argv[i]);
			break;
		}

		buf += written;
		size -= written;

		if (size <= 0)
			break;
	}

	if (i > 5)
		written = snprintf(buf, size, "]}");
	else
		written = snprintf(buf, size, "}");

	fprintf(stdout, "Sending: '%s'", msg.data.procmsg.buf);
	msg.data.procmsg.len = strnlen(msg.data.procmsg.buf, sizeof(msg.data.procmsg.buf));

	send_msg(&msg);

	exit(0);
}

/*
 * Simple example, it does nothing but calling the library
 */
int main(int argc, char *argv[]) {
	if (argc < 2)
		usage(argv[0]);

	if (!strcmp(argv[1], "aes")) {
		char *key, *ivt;
		if (argc != 4)
			usage(argv[0]);
		key = argv[2];
		ivt = argv[3];
		if (strlen(key) != 64 || strlen(ivt) != 32) {
			fprintf(stderr, "Wrong format for AES /IVT\n");
			usage(argv[0]);
		}
		if (!check_ascii_char(key) || !check_ascii_char(ivt)) {
			fprintf(stderr, "Wrong chars in keys\n");
			exit(1);
		}
		if (swupdate_set_aes(key, ivt)) {
			fprintf(stderr, "Error setting AES KEY\n");
			exit(1);
		}
		exit(0);
	}

	if (!strcmp(argv[1], "setversion")) {
		if (argc != 5)
			usage(argv[0]);

		if (swupdate_set_version_range(argv[2], argv[3], argv[4])) {
			fprintf(stderr, "Error IPC setting versions\n");
		}
		exit(0);
	}
	if (!strcmp(argv[1], "sendtohawkbit")) {
		if (argc < 3) {
			exit(1);
		}
		sendtohawkbit(argc - 2, &argv[2]);
	}

	if (!strcmp(argv[1], "hawkbitcfg")) {
		if (argc < 2) {
			usage(argv[0]);
			exit(1);
		}
		hawkbitcfg(argc, argv);
	}

	usage(argv[0]);

	exit(1);
}
