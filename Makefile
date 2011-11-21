top_srcdir=.
stagedir=.
PREFIX=
prefix=/usr
libdir=lib

-include Makefile.inc
-include ${top_srcdir}/project/version.properties

VPATH=${top_srcdir}/src
LIBCARES_LIBS?=-lcares  

CC=gcc
COMPILE=libtool --mode=compile ${CC} ${CFLAGS}
LINK=libtool --mode=link ${CC} ${LDFLAGS}
INSTALL=libtool --mode=install install

CFLAGS_LIB=-Wall -fPIC -c -g -I${top_srcdir}/src ${LIBCARES_CFLAGS}
LFLAGS_LIB=-shared ${LIBCARES_LIBS}

CFLAGS_CLI=-Wall -g -I${top_srcdir}/src
LFLAGS_CLI=-L. -lcanl

CFLAGS_SER=-Wall -g -I${top_srcdir}/src
LFLAGS_SER=-L. -lcanl

HEAD_CANL=canl.h canl_locl.h

SRC_CLI=canl_sample_client.c
HEAD_CLI=canl.h
OBJ_CLI=canl_sample_client.lo

SRC_SER=canl_sample_server.c
HEAD_SER=canl.h
OBJ_SER=canl_sample_server.lo

# In order to use libtool versioning correcty, we must have:
#
# current = major + minor + offset
# revision = patch
# age = minor
#
# where offset is a sum of maximal released minor's of all previous major's
#
offset=0
version_info:=-version-info ${shell \
	perl -e '$$,=":"; @F=split "\\.","${module.version}"; print $$F[0]+$$F[1]+${offset},$$F[2],$$F[1]' }
major:=${shell \
	perl -e '$$,=":"; @F=split "\\.","${module.version}"; print $$F[0]+$$F[1]+${offset}' }

all: libcanl.la server client

libcanl.la: canl.lo canl_err.lo canl_dns.lo
	${LINK} -rpath ${stagedir}${prefix}/${libdir} ${version_info} $+ ${LFLAGS_LIB} -o $@

canl.lo: canl.c ${HEAD_CANL} canl_err.h
	${COMPILE} -c ${top_srcdir}/src/canl.c ${CFLAGS_LIB} -o $@

canl_dns.lo: canl_dns.c ${HEAD_CANL}
	${COMPILE} -c ${top_srcdir}/src/canl_dns.c ${CFLAGS_LIB} -o $@

canl_err.lo: canl_err.c ${HEAD_CANL}
	${COMPILE} -c ${top_srcdir}/src/canl_err.c ${CFLAGS_LIB} -o $@

client: ${OBJ_CLI}
	${LINK} $< ${LFLAGS_CLI} -o $@

${OBJ_CLI}: ${SRC_CLI} ${HEAD_CLI} libcanl.la
	${COMPILE} -c ${top_srcdir}/src/${SRC_CLI} ${CFLAGS_CLI} -o $@

server: ${OBJ_SER}
	${LINK} $< ${LFLAGS_SER} -o $@

${OBJ_SER}: ${SRC_SER} ${HEAD_SER} libcanl.la
	${COMPILE} -c ${top_srcdir}/src/${SRC_SER} ${CFLAGS_SER} -o $@

check:

install: all
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/bin
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/${libdir}
	${INSTALL} -m 755 server ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-server-${major}
	${INSTALL} -m 755 client ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-client-${major}
	${INSTALL} -m 755 libcanl.la ${DESTDIR}${PREFIX}${prefix}/${libdir}

stage: all
	$(MAKE) install PREFIX=${stagedir}

clean:
	rm -rfv *.o *.lo libcanl.la .libs client server
