#
# Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
#                         University Research and Technology
#                         Corporation.  All rights reserved.
# Copyright (c) 2004-2005 The University of Tennessee and The University
#                         of Tennessee Research Foundation.  All rights
#                         reserved.
# Copyright (c) 2004-2009 High Performance Computing Center Stuttgart, 
#                         University of Stuttgart.  All rights reserved.
# Copyright (c) 2004-2005 The Regents of the University of California.
#                         All rights reserved.
# Copyright (c) 2006-2010 Cisco Systems, Inc.  All rights reserved.
# Copyright (c) 2012-2013 Los Alamos National Security, Inc.  All rights reserved.
# Copyright (c) 2013-2015 Intel, Inc. All rights reserved
# $COPYRIGHT$
# 
# Additional copyrights may follow
# 
# $HEADER$
#

AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_builddir)/src/include -I$(top_builddir)/src/api

bin_PROGRAMS = pmix_test pmix_client pmi_client pmi2_client pmix_client2 pmix_srv_self

pmix_test_SOURCES = \
        pmix_test.c

pmix_test_LDADD = \
	$(top_builddir)/libpmix-server.la -levent -levent_pthreads -lm  -lhwloc

pmix_client_SOURCES = \
        pmix_client.c

pmix_client_LDADD = \
	$(top_builddir)/libpmix.la

pmi_client_SOURCES = \
        pmi_client.c

pmi_client_LDADD = \
	$(top_builddir)/libpmix.la

pmi2_client_SOURCES = \
        pmi2_client.c

pmi2_client_LDADD = \
	$(top_builddir)/libpmix.la

pmix_client2_SOURCES = \
        pmix_client2.c

pmix_client2_LDADD = \
	$(top_builddir)/libpmix.la

pmix_srv_self_SOURCES = \
        pmix_srv_self.c

pmix_srv_self_LDADD = \
	$(top_builddir)/libpmix-server.la