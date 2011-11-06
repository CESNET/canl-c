#ifndef CANL_LOCL_H
#define CANL_LOCL_H
#include "canl_err.h"

typedef struct _glb_ctx
{
    int opened_ios;
    struct io_handler * io_ctx;
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
typedef struct _io_handler
{
    int something;
} io_handler;

typedef struct _asyn_result {
    struct hostent *ent;
    int err;
} asyn_result;
#endif

void reset_error (glb_ctx *cc, CANL_ERROR err_code);
void set_error (glb_ctx *cc, CANL_ERROR err_code, const char *err_format, ...);
void update_error (glb_ctx *cc, CANL_ERROR err_code, const char *err_format, ...);
