#ifndef _CANL_LOCL_H
#define _CANL_LOCL_H

#include <errno.h>
#include "canl_err.h"
#include "canl.h"
#include <ares.h>
#include <ares_version.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct _cert_key_store {
    X509 *cert;
    EVP_PKEY *key;
} cert_key_store;

typedef struct _glb_ctx
{
    int opened_ios;
    char * err_msg;
    CANL_ERROR err_code;
    CANL_ERROR_ORIGIN err_orig;
    cert_key_store *cert_key;
    SSL_CTX *ssl_ctx;
} glb_ctx;

typedef struct _ossl_ctx
{
    SSL *ssl_io;
    BIO *bio_conn;
} ossl_ctx;

typedef struct _asyn_result {
    struct hostent *ent;
    int err;
} asyn_result;

typedef struct _io_handler
{
    asyn_result *ar;
    struct sockaddr *s_addr;
    int sock;
    ossl_ctx * s_ctx;
} io_handler;

void reset_error (glb_ctx *cc, CANL_ERROR err_code);
void set_error (glb_ctx *cc, CANL_ERROR err_code, CANL_ERROR_ORIGIN err_orig,
        const char *err_format, ...);
void update_error (glb_ctx *cc, const char *err_format, ...);
void free_hostent(struct hostent *h); //TODO is there some standard funcion to free hostent?
int asyn_getservbyname(int a_family, asyn_result *ares_result,char const *name, 
        struct timeval *timeout);
int ssl_init(glb_ctx *cc, io_handler *io);
int ssl_connect(glb_ctx *cc, io_handler *io, struct timeval *timeout);
int ssl_accept(glb_ctx *cc, io_handler *io, io_handler *new_io,
        struct timeval *timeout);
int ssl_read(glb_ctx *cc, io_handler *io, void *buffer, size_t size, 
        struct timeval *tout);
int ssl_write(glb_ctx *cc, io_handler *io, void *buffer, size_t size, 
        struct timeval *tout);

int do_set_ctx_own_cert(glb_ctx *cc, canl_x509 cert, canl_stack_of_x509 chain, 
        canl_pkey key);
int do_set_ctx_own_cert_file(glb_ctx *cc, char *cert, char *key);
#endif
