#ifndef _CANL_SSL_H
#define _CANL_SSL_H

#include <canl.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum canl_ctx_ssl_flags {
    CANL_SSL_ACCEPT_SSLv2       = 0x0001,
    CANL_SSL_DN_OSSL            = 0x0002,
    CANL_SSL_VERIFY_NONE        = 0x0004,
} canl_ctx_ssl_flags;

canl_err_code CANL_CALLCONV
canl_ctx_set_ssl_flags(canl_ctx, unsigned int);

canl_err_code CANL_CALLCONV
canl_ctx_set_ssl_cred(canl_ctx, char *, char *key, char *proxy,
		      canl_password_callback, void *);

canl_err_code CANL_CALLCONV
canl_ctx_set_ca_dir(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_set_crl_dir(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_set_ca_fn(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_sfncrl_dir(canl_ctx, const char *);

/* Set canl cert verification callbacks into SSL_CTX.
   Do not use SSL_CTX stored in canl_ctx.

   Special case: if verify_callback is not NULL, then caNl will be ready 
   to use its callback,but it must be called separately by canl_direct_pv_clb()
   (e.g. in verify_callback)-try to avoid this, unless you 
   know what you are doing.
*/
canl_err_code CANL_CALLCONV
canl_ssl_ctx_set_clb(canl_ctx cc, SSL_CTX *ssl_ctx, int ver_mode,
        int (*verify_callback)(int, X509_STORE_CTX *));

/* Call caNl proxy certificate verification callback directly. Use it only
   when you really know what you are doing. canl_ssl_ctx_set_clb() should be
   called before. (X509_STORE_CTX param of this function must correspond  to
   SSL_CTX of canl_ssl_ctx_set_clb()) 
   
   Return - 0 varification OK, 1 verification failed
   
   Note: This is one of the funcions that accept NULL as canl_ctx
         parameter, since it is intended to be called inside
         other callback funcion.
*/
int CANL_CALLCONV
canl_direct_pv_clb(canl_ctx cc, X509_STORE_CTX *store_ctx, int ok);

#ifdef __cplusplus
}
#endif

#endif
