#ifndef _CANL_MECH_SSL_H
#define _CANL_MECH_SSL_H

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/safestack.h>

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
    char  *ca_file;
    char  *crl_dir;
    cert_key_store *cert_key;
    proxy_verify_desc *pvd_ctx;
} mech_glb_ctx;

int do_set_ctx_own_cert_file(glb_ctx *cc, mech_glb_ctx *m_ctx,
        char *cert, char *key, char * proxy);
int set_key_file(glb_ctx *cc, EVP_PKEY **to, const char *key);
int set_cert_file(glb_ctx *cc, X509 **to, const char *cert);
int set_cert_chain_file(glb_ctx *cc, STACK_OF(X509) **to, const char *cert);
void pkey_dup(EVP_PKEY **to, EVP_PKEY *from);

#endif
