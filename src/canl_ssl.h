#ifndef _CANL_SSL_H
#define _CANL_SSL_H

#include <canl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *canl_x509;
typedef void *canl_stack_of_x509;
typedef void *canl_pkey;

typedef char (*canl_password_callback)(canl_ctx cc, void *userdata);

int canl_set_ctx_own_cert(canl_ctx cc, canl_x509 cert,
        canl_stack_of_x509 chain, canl_pkey key);
int canl_set_ctx_own_cert_file(canl_ctx cc, char *cert, char *key,
        canl_password_callback cb, void *userdata);

#ifdef __cplusplus
}
#endif

#endif
