#ifndef _CANL_MECH_SSL_H
#define _CANL_MECH_SSL_H

#include <openssl/x509.h>
#include <openssl/evp.h>

typedef struct _cert_key_store {
    X509 *cert;
    EVP_PKEY *key;
    STACK_OF(X509) *chain;
} cert_key_store;

typedef struct _mech_glb_ctx
{
    void *mech_ctx; //like SSL_CTX *
    unsigned int flags;
    char  *ca_dir;
    char  *crl_dir;
    cert_key_store *cert_key;
} mech_glb_ctx;

int do_set_ctx_own_cert_file(glb_ctx *cc, mech_glb_ctx *m_ctx,
        char *cert, char *key);
int set_key_file(glb_ctx *cc, EVP_PKEY **to, const char *key);
int set_cert_file(glb_ctx *cc, X509 **to, const char *cert);
int set_cert_chain_file(glb_ctx *cc, STACK_OF(X509) **to, const char *cert);

#endif
