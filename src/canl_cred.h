#ifndef _CANL_CRED_H
#define _CANL_CRED_H

#include <canl.h>

#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *canl_cred;
typedef void *canl_x509_req;

typedef enum canl_cert_type {
    CANL_EEC,
    CANL_RFC,
} canl_cert_type;

typedef struct _creds {
    EVP_PKEY *c_key;
    STACK_OF(X509) *c_cert_chain;
    X509 *c_cert;
    long c_lifetime;
    X509_EXTENSION * c_cert_ext;
    canl_cert_type c_type;
    X509_REQ *c_req;
} creds;

/* Routines to handle credentials */

canl_err_code CANL_CALLCONV
canl_cred_new(canl_ctx, canl_cred *);

canl_err_code CANL_CALLCONV
canl_cred_free(canl_ctx, canl_cred);

canl_err_code CANL_CALLCONV
canl_ctx_set_cred(canl_ctx, canl_cred);

canl_err_code CANL_CALLCONV
canl_cred_load_priv_key_file(canl_ctx, canl_cred, const char *,
			     canl_password_callback, void *);

canl_err_code CANL_CALLCONV
canl_cred_load_priv_key_pkcs11(canl_ctx, canl_cred, const char *,
			       canl_password_callback, void *);

canl_err_code CANL_CALLCONV
canl_cred_load_chain(canl_ctx, canl_cred, STACK_OF(X509) *);

canl_err_code CANL_CALLCONV
canl_cred_load_chain_file(canl_ctx, canl_cred, const char *);

canl_err_code CANL_CALLCONV
canl_cred_load_cert(canl_ctx, canl_cred, X509 *);

canl_err_code CANL_CALLCONV
canl_cred_load_cert_file(canl_ctx, canl_cred, const char *);

canl_err_code CANL_CALLCONV
canl_cred_load_cert_pkcs11(canl_ctx, canl_cred, const char *);

canl_err_code CANL_CALLCONV
canl_cred_set_lifetime(canl_ctx, canl_cred, const long);

canl_err_code CANL_CALLCONV
canl_cred_set_extension(canl_ctx, canl_cred, X509_EXTENSION *);

canl_err_code CANL_CALLCONV
canl_cred_set_cert_type(canl_ctx, canl_cred, const enum canl_cert_type);

canl_err_code CANL_CALLCONV
canl_cred_sign_proxy(canl_ctx, canl_cred, canl_cred);

canl_err_code CANL_CALLCONV
canl_cred_save_proxyfile(canl_ctx, canl_cred, const char *);

canl_err_code CANL_CALLCONV
canl_cred_save_cert(canl_ctx, canl_cred, X509 **);

canl_err_code CANL_CALLCONV
canl_cred_save_chain(canl_ctx, canl_cred, STACK_OF(X509) **);

/* Routines to handle X.509 requests */

canl_err_code CANL_CALLCONV
canl_cred_new_req(canl_ctx, canl_cred, unsigned int);

canl_err_code CANL_CALLCONV
canl_req_get_req(canl_ctx, canl_cred, X509_REQ **);

#if 0
canl_err_code CANL_CALLCONV
canl_req_get_pair(canl_ctx, canl_x509_req, EVP_PKEY **);
#endif

#ifdef __cplusplus
}
#endif

#endif
