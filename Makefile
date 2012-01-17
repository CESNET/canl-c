top_srcdir=.
stagedir=.
PREFIX=
prefix=/usr
libdir=lib

-include Makefile.inc
-include ${top_srcdir}/project/version.properties

VPATH=${top_srcdir}/src/:${top_srcdir}/src/proxy/:${top_srcdir}/examples
LIBCARES_LIBS?=-lcares  
LIBSSL_LIBS?=-lssl

CC=gcc
COMPILE=libtool --mode=compile ${CC} ${CFLAGS}
LINK=libtool --mode=link ${CC} ${LDFLAGS}
INSTALL=libtool --mode=install install

CFLAGS_LIB=-Wall -fPIC -c -g -I${top_srcdir}/src ${LIBCARES_CFLAGS} ${LIBSSL_CFLAGS} -I.
LFLAGS_LIB=-shared ${LIBCARES_LIBS} ${LIBSSL_LIBS}

CFLAGS_CLI=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_CLI=-L. -lcanl

CFLAGS_SER=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_SER=-L. -lcanl

HEAD_CANL=canl.h canl_locl.h canl_err.h canl_cred.h

SRC_CLI=canl_sample_client.c
HEAD_CLI=canl.h
OBJ_CLI=canl_sample_client.lo

SRC_SER=canl_sample_server.c
HEAD_SER=canl.h
OBJ_SER=canl_sample_server.lo

YACC=bison -y
CFLAGS=-Wall -fPIC -I${top_srcdir}/src/proxy -I.

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

libcanl.la: canl.lo canl_err.lo canl_dns.lo canl_ssl.lo canl_cert.lo canl_cred.lo signing_policy.lo doio.lo evaluate.lo list.lo normalize.lo proxycertinfo.lo scutils.lo sslutils.lo namespaces.lo data.lo lex.signing.lo lex.namespaces.lo
	${LINK} -rpath ${stagedir}${prefix}/${libdir} ${version_info} $+ ${LFLAGS_LIB} -o $@

%.lo: %.y
	${YACC} -d ${YFLAGS} $<
	mv y.tab.c $*.c
	mv y.tab.h $*.h
	${COMPILE} -c ${CFLAGS_LIB} $*.c
	flex -b -f -d ${top_srcdir}/src/proxy/namespaces.l
	flex -b -f -d ${top_srcdir}/src/proxy/signing_policy.l

%.lo: %.c ${HEAD_CANL} 
	${COMPILE} -c $< ${CFLAGS_LIB} -o $@

lex.signing.lo: lex.signing.c
	${COMPILE} -c $< ${CFLAGS_LIB} -o $@

lex.namespaces.lo: lex.namespaces.c
	${COMPILE} -c $< ${CFLAGS_LIB} -o $@

client: ${OBJ_CLI}
	${LINK} $< ${LFLAGS_CLI} -o $@

${OBJ_CLI}: ${SRC_CLI} ${HEAD_CLI} libcanl.la
	${COMPILE} -c ${top_srcdir}/examples/${SRC_CLI} ${CFLAGS_CLI} -o $@

server: ${OBJ_SER}
	${LINK} $< ${LFLAGS_SER} -o $@

${OBJ_SER}: ${SRC_SER} ${HEAD_SER} libcanl.la
	${COMPILE} -c ${top_srcdir}/examples/${SRC_SER} ${CFLAGS_SER} -o $@

canl_err.h: canl_error_codes 
	${top_srcdir}/src/gen_err_codes.pl < $^ > $@

canl_err_desc.lo: canl_err_desc.c ${HEAD_CANL}
	${COMPILE} -c canl_err_desc.c ${CFLAGS_LIB} -o $@

canl_err_desc.c: canl_error_codes canl_error_desc
	${top_srcdir}/src/gen_err_desc.pl $^ > $@

check:

install: all
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/bin
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/${libdir}
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/include
	${INSTALL} -m 755 server ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-server
	${INSTALL} -m 755 client ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-client
	${INSTALL} -m 755 libcanl.la ${DESTDIR}${PREFIX}${prefix}/${libdir}
	${INSTALL} -m 644 ${top_srcdir}/src/canl.h canl_err.h ${DESTDIR}${PREFIX}${prefix}/include

stage: all
	$(MAKE) install PREFIX=${stagedir}

clean:
	rm -rfv *.o *.lo libcanl.la .libs client server ${top_srcdir}/*.c ${top_srcdir}/*.h lex.backup

distclean:
	rm -rvf Makefile.inc config.status project/changelog *.spec debian/
