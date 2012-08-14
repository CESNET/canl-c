#ifndef _CANL_SSL_H
#define _CANL_SSL_H

#include <canl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum canl_ctx_ssl_flags {
    CANL_ACCEPT_SSLv2		= 0x0001,
    CANL_DN_OSSL		= 0x0002,
} canl_ctx_ssl_flags;

canl_ctx CANL_CALLCONV
canl_ctx_set_ssl_flags(canl_ctx, unsigned int);

canl_err_code CANL_CALLCONV
canl_ctx_set_ssl_cred(canl_ctx, char *, char *key, char *proxy,
		      canl_password_callback, void *);

canl_err_code CANL_CALLCONV
canl_ctx_set_ca_dir(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_set_ca_fn(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_sfncrl_dir(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_set_pkcs11_lib(canl_ctx, const char *);

canl_err_code CANL_CALLCONV
canl_ctx_set_pkcs11_init_args(canl_ctx, const char *);

#ifdef __cplusplus
}
#endif

#endif
