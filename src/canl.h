#ifndef _CANL_H
#define _CANL_H
#include <sys/time.h>
#include <sys/socket.h>
#include <gssapi.h> /* for the OID structs */

#ifdef __cplusplus
extern "C" { 
#endif

#include <canl_err.h>

typedef void *canl_io_handler;
typedef void *canl_ctx;
typedef void *canl_principal;

canl_ctx canl_create_ctx();
void canl_free_ctx(canl_ctx cc);
int canl_create_io_handler(canl_ctx, canl_io_handler*);

int canl_io_connect(canl_ctx cc, canl_io_handler io, const char *host, const char *service,
        int port, gss_OID_set auth_mechs, int flags, struct timeval *timeout);
int canl_io_accept(canl_ctx cc, canl_io_handler io, int fd,
        struct sockaddr s_addr, int flags, canl_principal *peer,
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

int canl_princ_name(canl_ctx, const canl_principal, char **);
int canl_princ_mech(canl_ctx, const canl_principal, gss_OID *);
char * canl_mech2str(canl_ctx, gss_OID);
const gss_OID canl_str2mech(canl_ctx, const char mech);

#ifdef __cplusplus
}       
#endif 

#endif
