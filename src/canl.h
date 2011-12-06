#ifndef _CANL_H
#define _CANL_H
#include <sys/time.h>

typedef void *canl_io_handler;
typedef void *canl_ctx;
typedef void *cred_handler;

typedef void *canl_x509;
typedef void *canl_stack_of_x509;
typedef void *canl_pkey;

typedef char (*canl_password_callback)(canl_ctx cc, void *userdata);

canl_ctx canl_create_ctx();
void canl_free_ctx(canl_ctx cc);
canl_io_handler canl_create_io_handler(canl_ctx cc);

int canl_io_connect(canl_ctx cc, canl_io_handler io, char * host, 
        int port, int flags, cred_handler ch, struct timeval *timeout);
int canl_io_accept(canl_ctx cc, canl_io_handler io, int port, int flags, cred_handler ch, 
        struct timeval *timeout, canl_io_handler * new_io);
size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout);
size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout);

int
canl_get_error_code(canl_ctx cc);

char *
canl_get_error_message(canl_ctx);

int canl_io_close(canl_ctx cc, canl_io_handler io);
int canl_io_destroy(canl_ctx cc, canl_io_handler io);

int canl_set_ctx_own_cert(canl_ctx cc, canl_x509 cert,
        canl_stack_of_x509 chain, canl_pkey key);
int canl_set_ctx_own_cert_file(canl_ctx cc, char *cert, char *key,
        canl_password_callback cb, void *userdata);
#endif
