VERSION_INFO = 2:0:0

AM_CFLAGS = -g -O2 -Wall -Werror -Wno-deprecated-declarations -fno-strict-aliasing -std=gnu99 -D_GNU_SOURCE
AM_CFLAGS += $(PTHREAD_CFLAGS)
if !USE_SYSTEM_SHARED_LIB
AM_CFLAGS += -I$(top_srcdir)/libbloom
AM_CFLAGS += -I$(top_srcdir)/libipset/include
AM_CFLAGS += -I$(top_srcdir)/libcork/include
endif
AM_CFLAGS += $(LIBPCRE_CFLAGS)

SS_COMMON_LIBS = $(INET_NTOP_LIB) $(LIBPCRE_LIBS) $(NETFILTER_CONNTRACK_LIBS) $(NFTABLES_LIBS)
if !USE_SYSTEM_SHARED_LIB
SS_COMMON_LIBS += $(top_builddir)/libbloom/libbloom.la \
                  $(top_builddir)/libipset/libipset.la \
                  $(top_builddir)/libcork/libcork.la
else
SS_COMMON_LIBS += -lbloom -lcork -lcorkipset
endif
SS_COMMON_LIBS += -lev -lsodium -lm

crypto_src = crypto.c \
             aead.c \
             stream.c \
             ppbloom.c \
             base64.c

plugin_src = plugin.c

bin_PROGRAMS = ss-redir
ss_redir_SOURCES = utils.c \
                   jconf.c \
                   json.c \
                   netutils.c \
                   cache.c \
                   udprelay.c \
                   probe.c \
                   metrics.c \
                   redir.c \
                   $(crypto_src) \
                   $(plugin_src)

ss_redir_CFLAGS = $(AM_CFLAGS)
ss_redir_LDADD = $(SS_COMMON_LIBS)
ss_redir_LDADD += -lcares

noinst_HEADERS = crypto.h stream.h aead.h json.h netutils.h redir.h uthash.h \
                 cache.h plugin.h utils.h base64.h ppbloom.h \
                 common.h jconf.h udprelay.h probe.h metrics.h
