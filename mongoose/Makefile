# SPDX-FileCopyrightText: 2013 Stefano Babic <stefano.babic@swupdate.org>
#
# SPDX-License-Identifier: GPL-2.0-only

ifneq ($(CONFIG_WEBSERVER),)
ifneq ($(CONFIG_MONGOOSE),)
KBUILD_CFLAGS += -DMG_ENABLE_DIRLIST=1
KBUILD_CFLAGS += -DMG_ENABLE_EPOLL=1
KBUILD_CFLAGS += -DMG_ENABLE_POSIX_FS=1
KBUILD_CFLAGS += -DMG_ENABLE_LOG=0
KBUILD_CFLAGS += -DMG_ENABLE_MD5=1
KBUILD_CFLAGS += -DMG_MAX_RECV_SIZE=262144
ifneq ($(CONFIG_MONGOOSEIPV6),)
KBUILD_CFLAGS += -DMG_ENABLE_IPV6=1
endif
ifneq ($(CONFIG_MONGOOSESSL),)
ifeq ($(CONFIG_SSL_IMPL_OPENSSL),y)
KBUILD_CFLAGS += -DMG_TLS=2
endif
ifeq ($(CONFIG_SSL_IMPL_WOLFSSL),y)
KBUILD_CFLAGS += -DMG_TLS=5
endif
ifeq ($(CONFIG_SSL_IMPL_MBEDTLS),y)
KBUILD_CFLAGS += -DMG_TLS=1
endif
endif
endif
endif

lib-$(CONFIG_MONGOOSE)	+= mongoose.o \
			   mongoose_multipart.o \
			   mongoose_interface.o
