AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-subnet.la
else
plugin_LTLIBRARIES = libstrongswan-subnet.la
endif

libstrongswan_subnet_la_SOURCES = \
	subnet_plugin.h subnet_plugin.c \
	subnet_handler.h subnet_handler.c \
	subnet_narrow.h subnet_narrow.c

libstrongswan_subnet_la_LDFLAGS = -module -avoid-version
