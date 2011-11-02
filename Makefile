#PWD_ROOT has to be modified before build !!!!!!
PATH_ROOT=/home/marvel/canl/emi.canl.canl-c
PATH_SRC=${PATH_ROOT}/src
CC=gcc
CFLAGS_LIB=-Wall -fPIC -c
LFLAGS_LIB=-shared -o libcanl.so -lcares

CFLAGS_CLI=-Wall -c
LFLAGS_CLI=-L${PATH_ROOT} -I${PATH_ROOT} -o client -lcanl

CFLAGS_SER=-Wall -c
LFLAGS_SER=-L${PATH_ROOT} -I${PATH_ROOT} -o server -lcanl

HEAD_CANL=${PATH_SRC}/canl.h ${PATH_SRC}/canl_locl.h

SRC_CLI=${PATH_SRC}/canl_sample_client.c
HEAD_CLI=${PATH_SRC}/canl.h
OBJ_CLI=canl_sample_client.o

SRC_SER=${PATH_SRC}/canl_sample_server.c
HEAD_SER=${PATH_SRC}/canl.h
OBJ_SER=canl_sample_server.o

libcanl.so: canl.o canl_err.o canl_dns.o
	${CC} canl.o canl_err.o canl_dns.o ${LFLAGS_LIB}

canl.o: ${PATH_SRC}/canl.c ${HEAD_CANL}
	${CC} ${PATH_SRC}/canl.c ${CFLAGS_LIB}

canl_dns.o: ${PATH_SRC}/canl_dns.c ${HEAD_CANL}
	${CC} ${PATH_SRC}/canl_dns.c ${CFLAGS_LIB}

canl_err.o: ${PATH_SRC}/canl_err.c ${HEAD_CANL}
	${CC} ${PATH_SRC}/canl_err.c ${CFLAGS_LIB}

client: ${OBJ_CLI}
	${CC} ${OBJ_CLI} ${LFLAGS_CLI}

${OBJ_CLI}: ${SRC_CLI} ${HEAD_CLI}
	${CC} ${SRC_CLI} ${CFLAGS_CLI} 

server: ${OBJ_SER}
	${CC} ${OBJ_SER} ${LFLAGS_SER}

${OBJ_SER}: ${SRC_SER} ${HEAD_SER}
	${CC} ${SRC_SER} ${CFLAGS_SER} 

clean:
	rm -f *.o

clean_all:
	rm -f *.o libcanl.so client server 
