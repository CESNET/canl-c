#ifndef _CANL_H
#define _CANL_H
#include <sys/time.h>
#include <sys/socket.h>
#include <gssapi.h> /* for the OID structs */

#ifdef __cplusplus
extern "C" { 
#endif

#ifndef CANL_CALLCONV
#define CANL_CALLCONV
#endif

typedef void *canl_io_handler;
typedef void *canl_ctx;
typedef void *canl_principal;

typedef unsigned long canl_err_code;

typedef char (*canl_password_callback)(canl_ctx cc, void *userdata);

canl_ctx CANL_CALLCONV
canl_create_ctx();

void CANL_CALLCONV
canl_free_ctx(canl_ctx cc);

canl_err_code CANL_CALLCONV
canl_create_io_handler(canl_ctx cc, canl_io_handler *io);

canl_err_code CANL_CALLCONV
canl_io_connect(canl_ctx cc, canl_io_handler io, const char *host,
		const char *service, int port, gss_OID_set auth_mechs,
		int flags, struct timeval *timeout);

canl_err_code CANL_CALLCONV
canl_io_accept(canl_ctx cc, canl_io_handler io, int fd, struct sockaddr s_addr,
               int flags, canl_principal *peer, struct timeval *timeout);

size_t CANL_CALLCONV
canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer,
	     size_t size, struct timeval *timeout);

size_t CANL_CALLCONV
canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer,
	      size_t size, struct timeval *timeout);

canl_err_code CANL_CALLCONV
canl_get_error_code(canl_ctx cc);

char * CANL_CALLCONV
canl_get_error_message(canl_ctx);

canl_err_code CANL_CALLCONV
canl_io_close(canl_ctx cc, canl_io_handler io);

canl_err_code CANL_CALLCONV
canl_io_destroy(canl_ctx cc, canl_io_handler io);

canl_err_code CANL_CALLCONV
canl_princ_name(canl_ctx, const canl_principal, char **);

canl_err_code CANL_CALLCONV
canl_princ_mech(canl_ctx, const canl_principal, gss_OID *);

void CANL_CALLCONV
canl_princ_free(canl_ctx, canl_principal);

char * CANL_CALLCONV
canl_mech2str(canl_ctx, gss_OID);

const gss_OID_desc * CANL_CALLCONV
canl_str2mech(canl_ctx, const char mech);

#ifdef __cplusplus
}       
#endif 

#endif
