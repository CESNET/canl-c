#ifndef CANL_LOCL_H
#define CANL_LOCL_H
#include "canl_err.h"
#include <ares.h>
#include <ares_version.h>
#include <netdb.h>

typedef struct _glb_ctx
{
    int opened_ios;
    char * err_msg;
    CANL_ERROR err_code;
} glb_ctx;
/*
   struct ossl_ctx
   {
   SSL_METHOD ssl_meth;
   SSL_CTX ssl_ctx;
   SSL ssl_conn_ctx;
   }
 */
typedef struct _asyn_result {
    struct hostent *ent;
    int err;
} asyn_result;

typedef struct _io_handler
{
    asyn_result *ar;
    struct sockaddr *s_addr;
    int sock;
} io_handler;

#endif

void reset_error (glb_ctx *cc, CANL_ERROR err_code);
void set_error (glb_ctx *cc, CANL_ERROR err_code, const char *err_format, ...);
void update_error (glb_ctx *cc, CANL_ERROR err_code, const char *err_format, ...);
void free_hostent(struct hostent *h); //TODO is there some standard funcion to free hostent?
int asyn_getservbyname(int a_family, asyn_result *ares_result,char const *name,
	        struct timeval *timeout);
