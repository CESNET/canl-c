#ifndef _CANL_H
#define _CANL_H
#include <sys/time.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" { 
#endif

#include <canl_err.h>

typedef void *canl_io_handler;
typedef void *canl_ctx;

typedef char (*canl_password_callback)(canl_ctx cc, void *userdata);

canl_ctx canl_create_ctx();
void canl_free_ctx(canl_ctx cc);
canl_io_handler canl_create_io_handler(canl_ctx cc);

int canl_io_connect(canl_ctx cc, canl_io_handler io, char * host, 
        int port, int flags, struct timeval *timeout);
int canl_io_accept(canl_ctx cc, canl_io_handler io, int fd,
        struct sockaddr s_addr, int flags,
        struct timeval *timeout);
size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout);
size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout);

long
canl_get_error_code(canl_ctx cc);

char *
canl_get_error_message(canl_ctx);

int canl_get_error(canl_ctx cc, char ** reason);
int canl_io_close(canl_ctx cc, canl_io_handler io);
int canl_io_destroy(canl_ctx cc, canl_io_handler io);

#ifdef __cplusplus
}       
#endif 

#endif
