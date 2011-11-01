#PWD_ROOT has to be modified before build !!!!!!
PATH_ROOT=/home/marvel/canl/emi.canl.canl-c
PATH_SRC=${PATH_ROOT}/src
CC=gcc
CFLAGS_LIB=-Wall -fPIC -c
LFLAGS_LIB=-shared -o libcanl.so

CFLAGS_CLI=-Wall -c
LFLAGS_CLI=-L${PATH_ROOT} -I${PATH_ROOT} -o client -lcanl

CFLAGS_SER=-Wall -c
LFLAGS_SER=-L${PATH_ROOT} -I${PATH_ROOT} -o server -lcanl

SRC_CANL=${PATH_SRC}/canl.c ${PATH_SRC}/canl_dns.c
HEAD_CANL=${PATH_SRC}/canl.h ${PATH_SRC}/canl_locl.h
OBJ_CANL=canl.o

SRC_CLI=${PATH_SRC}/canl_sample_client.c
HEAD_CLI=${PATH_SRC}/canl.h
OBJ_CLI=canl_sample_client.o

SRC_SER=${PATH_SRC}/canl_sample_server.c
HEAD_SER=${PATH_SRC}/canl.h
OBJ_SER=canl_sample_server.o

libcanl.so: ${OBJ_CANL}
	${CC} ${OBJ_CANL} ${LFLAGS_LIB}

${OBJ_CANL}: ${SRC_CANL} ${HEAD_CANL}
	${CC} ${SRC_CANL} ${CFLAGS_LIB}

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
