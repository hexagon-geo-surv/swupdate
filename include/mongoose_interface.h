/*
 * (C) Copyright 2012-2023
 * Stefano Babic <stefano.babic@swupdate.org>
 *
 * SPDX-License-Identifier:     GPL-2.0-only
 */

#pragma once

/*
 * This is used by swupdate to start the Webserver
 */
int start_mongoose(const char *cfgfname, int argc, char *argv[]);

void mongoose_print_help(void);
