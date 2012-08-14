#ifndef _CANL_OCSP_H
#define _CANL_OCSP_H
#include "canl_locl.h"

typedef struct {
    char *ca_dir;
    char *ca_file;
    char *crl_dir;
} canl_x509store_t;

typedef struct {
    char            *url;
    X509            *cert;
    X509            *issuer;
    canl_x509store_t *store;
    X509            *sign_cert;
    EVP_PKEY        *sign_key;
    long            skew;
    long            maxage;
} canl_ocsprequest_t;

typedef enum {
    CANL_OCSPRESULT_ERROR_NOSTATUS          = -17,
    CANL_OCSPRESULT_ERROR_INVTIME           = -16,
    CANL_OCSPRESULT_ERROR_VERIFYRESPONSE    = -15,
    CANL_OCSPRESULT_ERROR_NOTCONFIGURED     = -14,
    CANL_OCSPRESULT_ERROR_NOAIAOCSPURI      = -13,
    CANL_OCSPRESULT_ERROR_INVALIDRESPONSE   = -12,
    CANL_OCSPRESULT_ERROR_CONNECTFAILURE    = -11,
    CANL_OCSPRESULT_ERROR_SIGNFAILURE       = -10,
    CANL_OCSPRESULT_ERROR_BADOCSPADDRESS    = -9,
    CANL_OCSPRESULT_ERROR_OUTOFMEMORY       = -8,
    CANL_OCSPRESULT_ERROR_UNKNOWN           = -7,
    CANL_OCSPRESULT_ERROR_UNAUTHORIZED      = -6,
    CANL_OCSPRESULT_ERROR_SIGREQUIRED       = -5,
    CANL_OCSPRESULT_ERROR_TRYLATER          = -3,
    CANL_OCSPRESULT_ERROR_INTERNALERROR     = -2,
    CANL_OCSPRESULT_ERROR_MALFORMEDREQUEST  = -1,
    CANL_OCSPRESULT_CERTIFICATE_VALID       = 0,
    CANL_OCSPRESULT_CERTIFICATE_REVOKED     = 1
} canl_ocspresult_t;

/* Methods to access canl_ocsprequest_t */
int set_ocsp_sign_cert(canl_ocsprequest_t *ocspreq, X509 *sign_cert);
int set_ocsp_sign_key(canl_ocsprequest_t *ocspreq, EVP_PKEY *sign_key);
int set_ocsp_cert(canl_ocsprequest_t *ocspreq, X509 *cert);
int set_ocsp_skew(canl_ocsprequest_t *ocspreq, int skew);
int set_ocsp_maxage(canl_ocsprequest_t *ocspreq, int maxage);
int set_ocsp_url(canl_ocsprequest_t *ocspreq, char *url);
int set_ocsp_issuer(canl_ocsprequest_t *ocspreq, X509 *issuer);
int set_ocsp_store(canl_ocsprequest_t *ocspreq, canl_x509store_t *store);

int ocsprequest_init(canl_ocsprequest_t **ocspreq);
void ocsprequest_free(canl_ocsprequest_t *or);
int canl_x509store_init(canl_x509store_t **cs);
void canl_x509store_free(canl_x509store_t *cs);

int do_ocsp_verify (canl_ocsprequest_t *data);

#endif
