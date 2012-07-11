top_srcdir=.
stagedir=$(shell pwd)
package=canl-c
PREFIX=
prefix=/usr
libdir=lib

default: all

-include Makefile.inc
-include ${top_srcdir}/project/version.properties

version=${module.version}

VPATH=${top_srcdir}/src/:${top_srcdir}/src/proxy/:${top_srcdir}/examples:${top_srcdir}/doc/src
KPATH = TEXINPUTS=".:${top_srcdir}/doc/src//:"
KPATHBIB = BIBINPUTS=".:$(VPATH)//:"
LIBCARES_LIBS?=-lcares  
LIBSSL_LIBS?=-lssl

CC=gcc
YACC=bison -y
LEX=flex
PDFLATEX = $(KPATH) pdflatex
BIBTEX = $(KPATHBIB) bibtex

COMPILE=libtool --mode=compile ${CC} ${CFLAGS}
LINK=libtool --mode=link ${CC} ${LDFLAGS}
INSTALL=libtool --mode=install install

SOURCES=\
	doc/src/*.cls doc/src/*.tex doc/src/images/*.pdf \
	examples/*.c \
	src/canl_error_* src/*.c src/*.h src/*.pl \
	src/proxy/*.c src/proxy/*.h src/proxy/*.in src/proxy/*.y src/proxy/*.l \
	Makefile
SOURCES_EXEC=src/*.pl

CFLAGS_LIB=-fPIC -I${top_srcdir}/src ${LIBCARES_CFLAGS} ${LIBSSL_CFLAGS} -I.
LFLAGS_LIB=-shared ${LIBCARES_LIBS} ${LIBSSL_LIBS}

CFLAGS_CLI=-I${top_srcdir}/src -I.
LFLAGS_CLI=-L. -lcanl_c

CFLAGS_SER=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_SER=-L. -lcanl_c

CFLAGS_PRX=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_PRX=-L. -lcanl_c

CFLAGS_DEL=-Wall -g -I${top_srcdir}/src -I.
LFLAGS_DEL=-L. -lcanl_c -lcrypto 

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

SRC_DEL=delegation.c
HEAD_DEL=canl.h canl_cred.h
OBJ_DEL=canl_delegation.lo

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
	perl -e '$$,=":"; @F=split "\\.","${version}"; print $$F[0]+$$F[1]+${offset},$$F[2],$$F[1]' }
major:=${shell \
	perl -e '$$,=":"; @F=split "\\.","${version}"; print $$F[0]+$$F[1]+${offset}' }

all: ${LIBCANL} server client proxy delegation doc

doc: canl.pdf

${LIBCANL}:\
	canl_err_desc.lo canl.lo canl_err.lo canl_dns.lo canl_ssl.lo \
	canl_cert.lo canl_cred.lo canl_ocsp.lo\
	doio.lo evaluate.lo list.lo normalize.lo proxycertinfo.lo\
	scutils.lo sslutils.lo data.lo namespaces_parse.lo namespaces_lex.lo\
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

%.pdf: %.tex
	$(PDFLATEX) $<
#	$(BIBTEX) `basename $< .tex`
	$(PDFLATEX) $<
	$(PDFLATEX) $<

canl.tex: ver.tex

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

delegation: ${OBJ_DEL}
	${LINK} $< ${LFLAGS_DEL} -o $@

${OBJ_DEL}: ${SRC_DEL} ${HEAD_DEL} ${LIBCANL}
	${COMPILE} -c ${top_srcdir}/examples/${SRC_DEL} ${CFLAGS_DEL} -o $@

canl_err.h: canl_error_codes 
	${top_srcdir}/src/gen_err_codes.pl < $^ > $@

canl_err_desc.c: canl_error_codes canl_error_desc
	${top_srcdir}/src/gen_err_desc.pl $^ > $@

ver.tex:
	printf "\134def\134version{${version}}\n" > ver.tex

check:

install: all
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/bin
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/${libdir}
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/include
	mkdir -p ${DESTDIR}${PREFIX}${prefix}/share/doc/canl-c-${version}
	${INSTALL} -m 755 server ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-server
	${INSTALL} -m 755 client ${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-client
	${INSTALL} -m 755 proxy \
		${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-proxy-init
	${INSTALL} -m 755 delegation \
		${DESTDIR}${PREFIX}${prefix}/bin/emi-canl-delegation
	${INSTALL} -m 755 ${LIBCANL} ${DESTDIR}${PREFIX}${prefix}/${libdir}
	${INSTALL} -m 644 ${top_srcdir}/src/canl.h \
		${top_srcdir}/src/canl_ssl.h canl_err.h \
		${DESTDIR}${PREFIX}${prefix}/include
	${INSTALL} -m 644 canl.pdf ${DESTDIR}${PREFIX}${prefix}/share/doc/canl-c-${version}

stage: all
	$(MAKE) install PREFIX=${stagedir}

clean:
	rm -rfv *.o *.lo ${LIBCANL} .libs client server proxy delegation \
		*.c *.h lex.backup stage \
		canl.aux canl.log canl.pdf canl.out canl.toc ver.tex \
		canl.bbl canl.blg
	rm -rvf dist ${package}-*.tar.gz

distclean:
	rm -rvf Makefile.inc config.status project/changelog *.spec debian/

.PHONY: default all doc check install stage clean distclean dist distcheck
