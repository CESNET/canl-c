top_srcdir=.
stagedir=$(pwd)
PREFIX=
prefix=/usr
libdir=lib

-include Makefile.inc
-include ${top_srcdir}/project/version.properties

VPATH=${top_srcdir}/src/:${top_srcdir}/src/proxy/:${top_srcdir}/examples
LIBCARES_LIBS?=-lcares  
LIBSSL_LIBS?=-lssl

CC=gcc
YACC=bison -y
LEX=flex

COMPILE=libtool --mode=compile ${CC} ${CFLAGS}
LINK=libtool --mode=link ${CC} ${LDFLAGS}
INSTALL=libtool --mode=install install

CFLAGS_LIB=-fPIC -I${top_srcdir}/src ${LIBCARES_CFLAGS} ${LIBSSL_CFLAGS} -I.
LFLAGS_LIB=-shared ${LIBCARES_LIBS} ${LIBSSL_LIBS}

CFLAGS_CLI=-I${top_srcdir}/src -I.
LFLAGS_CLI=-L. -lcanl_c

CFLAGS_SER=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_SER=-L. -lcanl_c

CFLAGS_PRX=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_PRX=-L. -lcanl_c

HEAD_CANL=canl.h canl_locl.h canl_err.h canl_cred.h canl_ssl.h canl_mech_ssl.h

SRC_CLI=canl_sample_client.c
HEAD_CLI=canl.h
OBJ_CLI=canl_sample_client.lo

SRC_SER=canl_sample_server.c
HEAD_SER=canl.h
OBJ_SER=canl_sample_server.lo

SRC_PRX=grid-proxy-init.c
HEAD_PRX=canl.h canl_cred.h
OBJ_PRX=canl_proxy_init.lo

CFLAGS:=-Wall -g -I${top_srcdir}/src/proxy -I. ${CFLAGS}

LIBCANL=libcanl_c.la

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

all: ${LIBCANL} server client proxy

${LIBCANL}:\
	canl.lo canl_err.lo canl_dns.lo canl_ssl.lo canl_cert.lo canl_cred.lo			\
	canl_err_desc.lo doio.lo evaluate.lo list.lo normalize.lo proxycertinfo.lo		\
	scutils.lo sslutils.lo data.lo namespaces_parse.lo namespaces_lex.lo			\
	signing_policy_parse.lo signing_policy_lex.lo
	${LINK} -rpath ${stagedir}${prefix}/${libdir} ${version_info} $+ ${LFLAGS_LIB} -o $@

%.lo: %.y
	${YACC} -d ${YFLAGS} $<
	mv y.tab.c $*.c
	mv y.tab.h $*.h
	${COMPILE} -c ${CFLAGS_LIB} $*.c

%.c: %.l
#	${LEX} -t $< > $@
	cp `echo $< | sed -e 's/\.l$$/.c.in/'` $@

%.lo: %.c ${HEAD_CANL} 
	${COMPILE} -c $< ${CFLAGS_LIB} -o $@

client: ${OBJ_CLI}
	${LINK} $< ${LFLAGS_CLI} -o $@

${OBJ_CLI}: ${SRC_CLI} ${HEAD_CLI} ${LIBCANL}
	${COMPILE} -c ${top_srcdir}/examples/${SRC_CLI} ${CFLAGS_CLI} -o $@

server: ${OBJ_SER}
	${LINK} $< ${LFLAGS_SER} -o $@

${OBJ_SER}: ${SRC_SER} ${HEAD_SER} ${LIBCANL}
	${COMPILE} -c ${top_srcdir}/examples/${SRC_SER} ${CFLAGS_SER} -o $@

proxy: ${OBJ_PRX}
	${LINK} $< ${LFLAGS_PRX} -o $@

${OBJ_PRX}: ${SRC_PRX} ${HEAD_PRX} ${LIBCANL}
	${COMPILE} -c ${top_srcdir}/examples/${SRC_PRX} ${CFLAGS_PRX} -o $@


canl_err.h: canl_error_codes 
	${top_srcdir}/src/gen_err_codes.pl < $^ > $@

canl_err_desc.c: canl_error_codes canl_error_desc
	${top_srcdir}/src/gen_err_desc.pl $^ > $@

check:

install: all
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/bin
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/${libdir}
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/include
	${INSTALL} -m 755 server ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-server
	${INSTALL} -m 755 client ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-client
	${INSTALL} -m 755 proxy \
		${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-proxy-init
	${INSTALL} -m 755 ${LIBCANL} ${DESTDIR}${PREFIX}${prefix}/${libdir}
	${INSTALL} -m 644 ${top_srcdir}/src/canl.h \
		${top_srcdir}/src/canl_ssl.h canl_err.h \
		${DESTDIR}${PREFIX}${prefix}/include

stage: all
	$(MAKE) install PREFIX=${stagedir}

clean:
	rm -rfv *.o *.lo ${LIBCANL} .libs client server \
		${top_srcdir}/*.c ${top_srcdir}/*.h lex.backup stage

distclean:
	rm -rvf Makefile.inc config.status project/changelog *.spec debian/
