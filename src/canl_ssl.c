#include "canl_locl.h"
#include "canl_ssl.h"
#include "canl_mech_ssl.h"
#include <openssl/ocsp.h>

#define SSL_SERVER_METH SSLv23_server_method()
#define SSL_CLIENT_METH SSLv3_client_method()
#define DESTROY_TIMEOUT 10
#define USENONCE 0

typedef struct {
    char *ca_dir;
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

static int do_ssl_connect( glb_ctx *cc, io_handler *io, 
        SSL *ssl, struct timeval *timeout);
static int do_ssl_accept( glb_ctx *cc, io_handler *io, 
        SSL *ssl, struct timeval *timeout);
static int check_hostname_cert(glb_ctx *cc, io_handler *io,
        SSL *ssl, const char *host);
static BIO *my_connect_ssl(char *host, int port, SSL_CTX **ctx);
static BIO *my_connect(char *host, int port, int ssl, SSL_CTX **ctx);
static int set_ocsp_sign_cert(X509 *sign_cert);
static int set_ocsp_sign_key(EVP_PKEY *sign_key);
static int set_ocsp_cert(X509 *cert);
static int set_ocsp_skew(int skew);
static int set_ocsp_maxage(int maxage);
static int set_ocsp_url(char *url);
static int set_ocsp_issuer(X509 *issuer);
static canl_x509store_t * store_dup(canl_x509store_t *store_from);
static X509_STORE * canl_create_x509store(canl_x509store_t *store);

#ifdef DEBUG
static void dbg_print_ssl_error(int errorcode);
#endif

static canl_ocsprequest_t *ocspreq = NULL;
/*static int set_ocsp_url(char *url, X509 *cert, X509 *issuer, 
  canl_x509store_t *store, X509 *sign_cert, EVP_PKEY *sign_key, 
  long skew, long maxage) {
 */ 

    static int
set_ocsp_cert(X509 *cert)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;

    if (cert) {
        if (!ocspreq->cert) {
            X509_free(ocspreq->cert);
            ocspreq->cert = NULL;
        }
        ocspreq->cert = X509_dup(cert);
        if (!ocspreq->cert)
            return 1;
    }
    return 0;
}

    static int 
set_ocsp_url(char *url)
{

    int len = 0;
    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;

    if (url) {
        if (!ocspreq->url) {
            free (ocspreq->url);
            ocspreq->url = NULL;
        }
        len = strlen(url);
        ocspreq->url = (char *) malloc((len +1) * sizeof (char));
        if (!ocspreq->url)
            return 1;
        strncpy(ocspreq->url, url, len + 1);
    }
    return 0;
}

    static int 
set_ocsp_issuer(X509 *issuer)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;
    if (issuer) {
        if (!ocspreq->issuer) {
            X509_free (ocspreq->issuer);
            ocspreq->issuer = NULL;
        }
        ocspreq->issuer = X509_dup(issuer);
        if (!ocspreq->issuer)
            return 1;
    }
    return 0;
}

    static int 
set_ocsp_sign_cert(X509 *sign_cert)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;
    if (sign_cert) {
        if (!ocspreq->sign_cert) {
            X509_free (ocspreq->sign_cert);
            ocspreq->sign_cert = NULL;
        }
        ocspreq->sign_cert = X509_dup(sign_cert);
        if (!ocspreq->sign_cert)
            return 1;
    }
    return 0;
}

    static int
set_ocsp_sign_key(EVP_PKEY *sign_key)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;
    if (sign_key) {
        if (!ocspreq->sign_key) {
            EVP_PKEY_free (ocspreq->sign_key);
            ocspreq->sign_key = NULL;
        }
        pkey_dup(&ocspreq->sign_key, sign_key);
        if (!ocspreq->sign_key)
            return 1;
    }
    return 0;
}
    static int
set_ocsp_skew(int skew)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;
    if (skew)
        ocspreq->skew = skew;
    return 0;
}
    static int
set_ocsp_maxage(int maxage)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;
    if (maxage)
        ocspreq->maxage = maxage;
    return 0;
}

static canl_x509store_t * 
store_dup(canl_x509store_t *store_from)
{
    canl_x509store_t *store_to = NULL;
    if (!store_from)
        return NULL;

    store_to = calloc(1, sizeof(*store_to));
    if (!store_to)
        return NULL;

    if (store_from->ca_dir) {
        int len = strlen(store_from->ca_dir);
        store_to->ca_dir = (char *) malloc((len + 1) * sizeof (char));    
        if (store_to->ca_dir)
            return NULL;
        strncpy (store_to->ca_dir, store_from->ca_dir, len + 1);
    }
    if (store_from->crl_dir) {
        int len = strlen(store_from->crl_dir);
        store_to->crl_dir = (char *) malloc((len + 1) * sizeof (char));    
        if (store_to->crl_dir)
            return NULL;
        strncpy (store_to->crl_dir, store_from->crl_dir, len + 1);
    }
    return store_to;
}

    static int
set_ocsp_store(canl_x509store_t *store)
{

    if (!ocspreq)
        ocspreq = calloc(1, sizeof(*ocspreq));
    if (!ocspreq)
        return 1;
    if (store){
        ocspreq->store = store_dup(store);
        if (!ocspreq->store)
            return 1;
    }
    return 0;
}


    static canl_err_code
ssl_initialize(glb_ctx *cc)
{
    mech_glb_ctx **m_glb_ctx = (mech_glb_ctx **)cc->mech_ctx;
    int err = 0;
    char *ca_cert_fn, *user_cert_fn, *user_key_fn, *user_proxy_fn;
    char *ca_cert_dirn = NULL;
    ca_cert_fn = user_cert_fn = user_key_fn = user_proxy_fn = NULL;
    SSL_CTX *ssl_ctx = NULL;

    if (!cc)
        return EINVAL;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ERR_clear_error();

    ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_ctx)
        return set_error(cc, ERR_get_error(), SSL_ERROR,
                "Cannot initialize SSL context");

    if (!*m_glb_ctx)
        *m_glb_ctx = (mech_glb_ctx *) calloc(1, sizeof(**m_glb_ctx));
    if (!*m_glb_ctx)
        return set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");

    err = proxy_get_filenames(0, &ca_cert_fn, &ca_cert_dirn, NULL, NULL, NULL);
    if (!err && (ca_cert_fn || ca_cert_dirn))
	SSL_CTX_load_verify_locations(ssl_ctx, ca_cert_fn, ca_cert_dirn);

    if (ca_cert_fn)
	free(ca_cert_fn);
    if (ca_cert_dirn)
	free(ca_cert_dirn);

    //err = SSL_CTX_set_cipher_list(ssl_ctx, "ALL:!LOW:!EXP:!MD5:!MD2");
    err = SSL_CTX_set_cipher_list(ssl_ctx, "ALL");
    if (!err) {
	err = set_error(cc, ERR_get_error(), SSL_ERROR,
			"No cipher to use");
	goto end;
    }
    /* XXX: should be only defined on the SSL level: */
    SSL_CTX_set_cert_verify_callback(ssl_ctx, proxy_app_verify_callback, 0);

    //SSL_CTX_set_purpose(ssl_ctx, X509_PURPOSE_ANY);
    //SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    // TODO proxy_verify_callback, verify_none only for testing !!!!!!!
    //SSL_CTX_set_verify_depth(ctx, 100);

    (*m_glb_ctx)->mech_ctx = ssl_ctx;
    ssl_ctx = NULL;
    err = 0;

end:
    if (ssl_ctx)
	SSL_CTX_free(ssl_ctx);

    return err;
}

static canl_err_code 
ssl_set_flags(glb_ctx *cc, unsigned int *mech_flags,  unsigned int flags)
{
    if (cc == NULL)
        return EINVAL;


    *mech_flags = (flags | *mech_flags);

    return 0;
}

static canl_err_code
ssl_set_dir(glb_ctx *cc, char **target, const char *ca_dir)
{
    int fn_len = 0;
    if (cc == NULL)
	return EINVAL;

    if (ca_dir == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "CA dir. name NULL");
    
    if (target && *target){
	free (*target);
	*target = NULL;
    }
    fn_len = strlen(ca_dir);
    *target = (char *) malloc ((fn_len + 1) * sizeof (char));
    if (!(*target)) {
	return set_error(cc, ENOMEM, POSIX_ERROR, NULL);
    }
    strncpy (*target, ca_dir, fn_len + 1);

    return 0;
}

static canl_err_code
ssl_server_init(glb_ctx *cc, void **ctx)
{
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;
    SSL_CTX *ssl_ctx = NULL; 
    SSL *ssl = NULL;
    char *user_cert_fn, *user_key_fn, *user_proxy_fn;
    int err = 0;
    user_cert_fn = user_key_fn = user_proxy_fn = NULL;
 
    if (cc == NULL)
	return EINVAL;

    if (!m_ctx || !m_ctx->mech_ctx)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");
    ssl_ctx = (SSL_CTX *) m_ctx->mech_ctx;

    err = proxy_get_filenames(0, NULL, NULL, &user_proxy_fn,
            &user_cert_fn, &user_key_fn);
    if (!err && (!m_ctx->cert_key || !m_ctx->cert_key->cert || !m_ctx->cert_key->key)) {
        if (user_cert_fn && user_key_fn && !access(user_cert_fn, R_OK) && 
                !access(user_key_fn, R_OK)) {
            err = do_set_ctx_own_cert_file(cc, m_ctx, user_cert_fn, user_key_fn, NULL);
            if (err)
                return err;
        }
    }
    if (err && (!m_ctx->cert_key || !m_ctx->cert_key->cert || 
                !m_ctx->cert_key->key))
	update_error(cc, EINVAL, POSIX_ERROR, "No key or certificate"
                " found");

    free(user_cert_fn);
    user_cert_fn = NULL;
    free(user_key_fn);
    user_key_fn = NULL;
    //TODO where to use proxy on server side
    free(user_proxy_fn);
    user_proxy_fn = NULL;

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL)
	return set_error(cc, ERR_get_error(), SSL_ERROR,
		         "Failed to create SSL connection context");

    /* TODO !!!!!!!!!!
     *  if SSL_VERIFY_NONE, then we cannot extract peer cert. of ssl
     *  if SSL_VERIFY_PEER, then client cert verification is mandatory!!!*/
    SSL_set_verify(ssl, SSL_VERIFY_PEER, proxy_verify_callback);
    
    if (!(CANL_ACCEPT_SSLv2 & m_ctx->flags))
        SSL_set_options(ssl, SSL_OP_NO_SSLv2);


//    SSL_use_certificate_file(ssl, "/etc/grid-security/hostcert.pem", SSL_FILETYPE_PEM);
//    SSL_use_PrivateKey_file(ssl, "/etc/grid-security/hostkey.pem", SSL_FILETYPE_PEM);

    SSL_set_accept_state(ssl);

    if (m_ctx->cert_key) {
        if (m_ctx->cert_key->cert) {
            err = SSL_use_certificate(ssl, m_ctx->cert_key->cert);
            if (err != 1) {
                return set_error(cc, ERR_get_error(), SSL_ERROR, "Cannot"
                        "use certificate");
            }
            else
                err = 0;
        }
        if (m_ctx->cert_key->key) {
            err = SSL_use_PrivateKey(ssl, m_ctx->cert_key->key);
            if (err != 1) {
                return set_error(cc, ERR_get_error(), SSL_ERROR, "Cannot"
                        "use private key");
            }
            else
                err = 0;
        }
    }
    else {
        set_error(cc, err, UNKNOWN_ERROR, "server key or certificate missing");
        return 1;
    }
    /*Make sure the key and certificate file match*/
    if ( (err = SSL_check_private_key(ssl)) != 1)
        return set_error(cc, ERR_get_error(), SSL_ERROR, "Private key"
               " does not match the certificate public key"); 

    *ctx = ssl;

    return 0;
}

static canl_err_code
ssl_client_init(glb_ctx *cc, void **ctx)
{
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int err = 0, i = 0;
    char *user_cert_fn, *user_key_fn, *user_proxy_fn;
    user_cert_fn = user_key_fn = user_proxy_fn = NULL;
    
    if (cc == NULL)
	return EINVAL;
    
    if (!m_ctx || !m_ctx->mech_ctx)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");
    ssl_ctx = (SSL_CTX *) m_ctx->mech_ctx;

    err = proxy_get_filenames(0, NULL, NULL, &user_proxy_fn,
            &user_cert_fn, &user_key_fn);
    if (!err && (!m_ctx->cert_key || !m_ctx->cert_key->cert || 
                !m_ctx->cert_key->key)) {
        if (user_proxy_fn && !access(user_proxy_fn, R_OK)) {
            err = do_set_ctx_own_cert_file(cc, m_ctx, NULL, NULL,
                    user_proxy_fn);
            if (err)
                return err;
        }
        else {
            if (user_cert_fn && !access(user_cert_fn, R_OK)) {
                err = do_set_ctx_own_cert_file(cc, m_ctx, 
                        user_cert_fn, NULL, NULL);
                if (err)
                    return err;
            }
            if (user_key_fn && !access(user_key_fn, R_OK)) {
                err = do_set_ctx_own_cert_file(cc, m_ctx,
                        NULL, user_key_fn, NULL);
                if (err)
                    return err;
            }
        }
    }

    if (err && (!m_ctx->cert_key || !m_ctx->cert_key->cert || 
                !m_ctx->cert_key->key))
	update_error(cc, EINVAL, POSIX_ERROR, "No key or certificate"
                " found");

    free(user_cert_fn);
    user_cert_fn = NULL;
    free(user_key_fn);
    user_key_fn = NULL;
    free(user_proxy_fn);
    user_proxy_fn = NULL;

    if (m_ctx->cert_key && m_ctx->cert_key->chain) {
        /*
         * Certificate was a proxy with a cert. chain.
         * Add the certificates one by one to the chain.
         */
        X509_STORE_add_cert(ssl_ctx->cert_store, m_ctx->cert_key->cert);
        for (i = 0; i < sk_X509_num(m_ctx->cert_key->chain); ++i) {
            X509 *cert = (sk_X509_value(m_ctx->cert_key->chain, i));

            if (!X509_STORE_add_cert(ssl_ctx->cert_store, cert)) {
                if (ERR_GET_REASON(ERR_peek_error()) == 
                        X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    ERR_clear_error();
                    continue;
                }
                else {
                    set_error(cc, 1, CANL_ERROR, "Cannot add certificate "
                            "to the SSL context's certificate store");
                }
            }
        }
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
        X509_STORE_set_verify_cb(ssl_ctx->cert_store, proxy_verify_callback);
#endif
    }

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL)
	return set_error(cc, ERR_get_error(), SSL_ERROR,
		         "Failed to create SSL connection context");

    SSL_set_connect_state(ssl);



    SSL_set_verify(ssl, SSL_VERIFY_PEER, proxy_verify_callback);
    if (!(CANL_ACCEPT_SSLv2 & m_ctx->flags))
        SSL_set_options(ssl, SSL_OP_NO_SSLv2);

    if (m_ctx->cert_key) {
        if (m_ctx->cert_key->key) {
            err = SSL_use_PrivateKey(ssl, m_ctx->cert_key->key);
            if (err != 1) {
                return set_error(cc, ERR_get_error(), SSL_ERROR, "Cannot"
                        "use private key");
            }
        }
        if (m_ctx->cert_key->cert) {
            err = SSL_use_certificate(ssl, m_ctx->cert_key->cert);
            if (err != 1) {
                return set_error(cc, ERR_get_error(), SSL_ERROR, "Cannot"
				"use certificate");
	    }
	}
               /*Make sure the key and certificate file match
         * not mandatory on client side*/
        if (m_ctx->cert_key->cert && m_ctx->cert_key->key)
            if ( (err = SSL_check_private_key(ssl)) != 1)
                return set_error(cc, ERR_get_error(), SSL_ERROR, "Private key"
                        " does not match the certificate public key"); 
    }

    *ctx = ssl;
    return 0;
}

static canl_err_code
ssl_connect(glb_ctx *cc, io_handler *io, void *auth_ctx,
	        struct timeval *timeout, const char * host)
{
    SSL *ssl = (SSL *) auth_ctx;
    int err = 0, flags;

    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }
    if (ssl == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL not initialized");

    flags = fcntl(io->sock, F_GETFL, 0);
    (void)fcntl(io->sock, F_SETFL, flags | O_NONBLOCK);

    //setup_SSL_proxy_handler(cc->ssl_ctx, cacertdir);
    SSL_set_fd(ssl, io->sock);

    err = do_ssl_connect(cc, io, ssl, timeout); 
    if (err) {
        goto end;
    }
    /*check server hostname on the certificate*/
    err = check_hostname_cert(cc, io, ssl, host);

end:
    return err;
}

static int check_hostname_cert(glb_ctx *cc, io_handler *io,
			       SSL *ssl, const char *host)
{
    X509 * serv_cert = NULL;
    X509_EXTENSION *ext = NULL;
    int i = 0;
    GENERAL_NAMES *ialt = NULL;
    char *pBuffer = NULL;
    int correspond = 0;
    X509_NAME *sn = NULL;

    /*if extensions are present, hostname has to correspond
     *  to subj. alt. name*/
    serv_cert = SSL_get_peer_certificate(ssl);
    if (!serv_cert)
        return set_error(cc, CANL_ERR_unknownMsg, CANL_ERROR,
                "Server certificate missing");
    i = X509_get_ext_by_NID(serv_cert, NID_subject_alt_name, -1);
    if (i != -1) {
        /* subj. alt. name extention present */
        if(!(ext = X509_get_ext(serv_cert, i)) ||
                !(ialt = X509V3_EXT_d2i(ext)) )
            goto end;
        for(i = 0; i < sk_GENERAL_NAME_num(ialt); i++) {
            const GENERAL_NAME *gen = sk_GENERAL_NAME_value(ialt, i);
            switch (gen->type) {
                case GEN_DNS:
                    ASN1_STRING_to_UTF8((unsigned char**)&pBuffer, gen->d.ia5);
#ifdef DEBUG
                    printf(" %s",pBuffer);
#endif
                    if (!strcmp(pBuffer, host)) {
                        correspond = 1;
                        OPENSSL_free(pBuffer);
                        pBuffer = NULL;
                        goto end;
                    }
                    OPENSSL_free(pBuffer);
                    pBuffer = NULL;
                    break;
            }
        }
    }
    /*else hostname has to correspond to common name*/
    else {
        sn = X509_get_subject_name(serv_cert); 
        i = X509_NAME_get_index_by_NID(sn, NID_commonName, -1);
        if (i != -1) {
            while (1) {
                X509_NAME_ENTRY *cn = X509_NAME_get_entry(sn, i);
                ASN1_STRING_to_UTF8((unsigned char**)&pBuffer,
                        X509_NAME_ENTRY_get_data(cn));
                if (!strcmp(pBuffer, host)) { //TODO substr maybe
                    correspond = 1;
                    OPENSSL_free(pBuffer);
                    pBuffer = NULL;
                    goto end;
                }
                i = X509_NAME_get_index_by_NID(sn, NID_commonName, i);
                OPENSSL_free(pBuffer);
                pBuffer = NULL;
                if (i == -1)
                    break;
            }
        }
        else
            return set_error(cc, CANL_ERR_unknownMsg, CANL_ERROR,
                    "Common name entry does not exist"); //TODO check
    }

end:
    X509_free(serv_cert);
    if (correspond)
        return 0;
    else {
        return set_error(cc, CANL_ERR_unknownMsg, CANL_ERROR, 
                "Cannot validate server hostname against its certificate" );
        //TODO check
    }
}

static canl_err_code
ssl_accept(glb_ctx *cc, io_handler *io, void *auth_ctx, struct timeval *timeout)
{
    SSL *ssl = (SSL *) auth_ctx;
    int err = 0, flags;

    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }
    if (auth_ctx == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL not initialized");

    flags = fcntl(io->sock, F_GETFL, 0);
    (void)fcntl(io->sock, F_SETFL, flags | O_NONBLOCK);

    //setup_SSL_proxy_handler(cc->ssl_ctx, cacertdir);
    SSL_set_fd(ssl, io->sock);

    err = do_ssl_accept(cc, io, ssl, timeout);
    if (err) {
        goto end;
    }

end:
    return err;
}

/*
 * Encapsulates select behaviour
 *
 * Returns:
 *     > 0 : Ready to read or write.
 *     = 0 : timeout reached.
 *     < 0 : error.
 */
int do_select(int fd, time_t starttime, int timeout, int wanted)
{
    int ret = 0;
    fd_set rset;
    fd_set wset;

    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if (wanted == 0 || wanted == SSL_ERROR_WANT_READ)
        FD_SET(fd, &rset);
    if (wanted == 0 || wanted == SSL_ERROR_WANT_WRITE)
        FD_SET(fd, &wset);

    if (timeout != -1) {
        struct timeval endtime;

        time_t curtime = time(NULL);

        if (curtime - starttime >= timeout)
            return 0;

        endtime.tv_sec = timeout - (curtime - starttime);
        endtime.tv_usec = 0;

        ret = select(fd+1, &rset, &wset, NULL, &endtime);
    }
    else {
        ret = select(fd+1, &rset, &wset, NULL, NULL);
    }

    if (ret == 0)
        return 0;

    if ((wanted == SSL_ERROR_WANT_READ && !FD_ISSET(fd, &rset)) ||
            (wanted == SSL_ERROR_WANT_WRITE && !FD_ISSET(fd, &wset)))
        return -1;

    if (ret < 0 && (!FD_ISSET(fd, &rset) || !FD_ISSET(fd, &wset)))
        return 1;

    return ret;
}

#define TEST_SELECT(ret, ret2, timeout, curtime, starttime, errorcode) \
    ((ret) > 0 && ((ret2) <= 0 && (((timeout) == -1) ||                  \
            (((timeout) != -1) &&                 \
             ((curtime) - (starttime)) < (timeout))) && \
        ((errorcode) == SSL_ERROR_WANT_READ ||                 \
         (errorcode) == SSL_ERROR_WANT_WRITE)))

static int do_ssl_connect(glb_ctx *cc, io_handler *io,
			  SSL *ssl, struct timeval *timeout)
{
    time_t starttime, curtime;
    int ret = -1, ret2 = -1;
    unsigned long ssl_err = 0;
    int err = 0;
    canl_err_origin e_orig = UNKNOWN_ERROR;
    long errorcode = 0;
    int expected = 0;
    int locl_timeout = -1;

    /* do not take tv_usec into account in this function*/
    if (timeout)
        locl_timeout = timeout->tv_sec;
    else
        locl_timeout = -1;
    curtime = starttime = time(NULL);
    ERR_clear_error();

    do {
        ret = do_select(io->sock, starttime, locl_timeout, expected);
        if (ret > 0) {
            ret2 = SSL_connect(ssl);
            if (ret2 < 0) {
                ssl_err = ERR_get_error();
                e_orig = SSL_ERROR;
            }
            expected = errorcode = SSL_get_error(ssl, ret2);
        }
        curtime = time(NULL);
    } while (TEST_SELECT(ret, ret2, locl_timeout, curtime, starttime, errorcode));

    timeout->tv_sec = timeout->tv_sec - (curtime - starttime);
    //TODO split ret2 and ret into 2 ifs to set approp. err. msg and check ag.
    if (ret2 <= 0 || ret <= 0) {
        if (timeout && (curtime - starttime >= locl_timeout)){
            timeout->tv_sec=0;
            timeout->tv_usec=0;
            err = ETIMEDOUT; 
            update_error (cc, err, POSIX_ERROR, "Connection stuck during"
		   " handshake: timeout reached");
        }
        else if (ret2 < 0 && ssl_err)
            return update_error(cc, ssl_err, e_orig, "Error during SSL handshake");
        else if (ret2 == 0)//TODO is 0 (conn closed by the other side) error?
            update_error (cc, ECONNREFUSED, POSIX_ERROR, "Connection closed"
                    " by the other side");
        else
            update_error (cc, err, UNKNOWN_ERROR, "Error during SSL handshake");
        return 1;
    }
    return 0;
}

static int do_ssl_accept(glb_ctx *cc, io_handler *io,
			 SSL *ssl, struct timeval *timeout)
{
    time_t starttime, curtime;
    int ret = -1, ret2 = -1;
    unsigned long ssl_err = 0;
    int err = 0;
    long errorcode = 0;
    int expected = 0;
    int locl_timeout = -1;

    /* do not take tv_usec into account in this function*/
    if (timeout)
        locl_timeout = timeout->tv_sec;
    else
        locl_timeout = -1;
    curtime = starttime = time(NULL);
    ERR_clear_error();

    do {
        ret = do_select(io->sock, starttime, locl_timeout, expected);
        if (ret > 0) {
            ret2 = SSL_accept(ssl);
            if (ret2 < 0) {
                ssl_err = ERR_peek_error();
            }
            expected = errorcode = SSL_get_error(ssl, ret2);
        }
        curtime = time(NULL);
#ifdef DEBUG
        dbg_print_ssl_error(errorcode);
#endif
    } while (ret > 0 && (ret2 <= 0 && ((locl_timeout == -1) ||
           ((locl_timeout != -1) &&
            (curtime - starttime) < locl_timeout)) &&
           (errorcode == SSL_ERROR_WANT_READ ||
            errorcode == SSL_ERROR_WANT_WRITE)));
#ifdef DEBUG
if (errorcode == SSL_ERROR_WANT_READ)
	printf("SSL_ERR_WANT_READ");
if (errorcode == SSL_ERROR_WANT_WRITE)
	printf("SSL_ERR_WANT_WRITE");
printf ("STR: %s \n",ERR_error_string(ssl_err,NULL));
printf ("LIB: %s ;",ERR_lib_error_string(ssl_err));
printf ("FUNC: %s ;",ERR_func_error_string(ssl_err));
printf ("LIB: %s \n",ERR_reason_error_string(ssl_err));
#endif

timeout->tv_sec = timeout->tv_sec - (curtime - starttime);

    //TODO split ret2 and ret into 2 ifs to set approp. error message
    if (ret2 <= 0 || ret <= 0) {
        if (timeout && (curtime - starttime >= locl_timeout)){
            timeout->tv_sec=0;
            timeout->tv_usec=0;
            err = ETIMEDOUT;
            set_error (cc, err, POSIX_ERROR, "Connection stuck"
                    " during handshake: timeout reached"); 
        }
        else if (ret2 == 0)
            set_error (cc, ECONNREFUSED, POSIX_ERROR, "Connection closed by"
		    " the other side");
        else if (ret2 < 0 && ssl_err)
            set_error (cc, ssl_err, SSL_ERROR, "Error during SSL handshake");
	else
	    set_error (cc, 0, UNKNOWN_ERROR, "Error during SSL handshake");
        return 1;
    }
    return 0;
}

/* this function has to return # bytes written or ret < 0 when sth went wrong*/
static size_t
ssl_write(glb_ctx *cc, io_handler *io, void *auth_ctx,
	      void *buffer, size_t size, struct timeval *timeout)
{
    int ret = 0, nwritten=0, ret2 = 0;
    const char *str;
    int fd = -1; 
    time_t starttime, curtime;
    int expected = 0, error = 0;
    int locl_timeout;
    SSL *ssl = (SSL *) auth_ctx;

    if (cc == NULL)
        return -1;

    if (io == NULL) {
        set_error(cc, EINVAL, POSIX_ERROR,
                "Connection not established");
        return -1;
    }

    if (ssl == NULL) {
	set_error(cc, EINVAL, POSIX_ERROR, "SSL not initialized");
        return -1;
    }

    fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
    str = buffer;//TODO !!!!!! text.c_str();

    curtime = starttime = time(NULL);
    if (timeout) {
        locl_timeout = timeout->tv_sec;
    }
    else {
        locl_timeout = -1;
    }
    ERR_clear_error();

    do {
        ret = do_select(fd, starttime, locl_timeout, expected);
        curtime = time(NULL);

        if (ret > 0) {
            ret2 = SSL_write(ssl, str + nwritten,
                    size - nwritten);

            if (ret2 <= 0) {
                expected = error = SSL_get_error(ssl, ret2);
            }
        }
        nwritten += ret;
        if ((size_t)nwritten == size)
            goto end;
    } while (TEST_SELECT(ret, ret2, locl_timeout, curtime, starttime, error));

end:
    curtime = time(NULL);
    if (timeout)
        timeout->tv_sec = timeout->tv_sec - (curtime - starttime);
    if (ret <= 0 || ret2 <= 0) { // what if ret2 == 0? conn closed?
        if (locl_timeout != -1 && (curtime - starttime >= locl_timeout)){
            timeout->tv_sec = 0;
            timeout->tv_usec = 0;
            set_error(cc, ETIMEDOUT, POSIX_ERROR, "Connection stuck"
                    " during write: timeout reached");
            return -1;
        }
        else {
            set_error(cc, 0, UNKNOWN_ERROR, "Error during SSL write");
            return -1;
        }
    }

    return ret2;
}

static size_t
ssl_read(glb_ctx *cc, io_handler *io, void *auth_ctx,
	     void *buffer, size_t size, struct timeval *tout)
{
    int ret = 0, nwritten=0, ret2 = 0;
    char *str;
    int fd = -1;
    time_t starttime, curtime;
    int expected = 0, error = 0;
    int timeout;
    SSL *ssl = (SSL *) auth_ctx;

    if (cc == NULL)
	return -1;

    if (io == NULL) {
	set_error(cc, EINVAL, POSIX_ERROR,
                "Connection not established");
        return -1;
    }

    if (ssl == NULL) {
	set_error(cc, EINVAL, POSIX_ERROR, "SSL not initialized");
        return -1;
    }

    fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
    str = buffer;//TODO !!!!!! text.c_str();

    curtime = starttime = time(NULL);
    if (tout) {
        timeout = tout->tv_sec;
    }
    else
        timeout = -1;
    ERR_clear_error();

    do {
        ret = do_select(fd, starttime, timeout, expected);
        curtime = time(NULL);

        if (ret > 0) {
            ret2 = SSL_read(ssl, str + nwritten,
                    size - nwritten);

            if (ret2 <= 0) {
                expected = error = SSL_get_error(ssl, ret2);
            }
        }
    } while (TEST_SELECT(ret, ret2, timeout, curtime, starttime, error));

    if (tout)
        tout->tv_sec = tout->tv_sec - (curtime - starttime);
    if (ret <= 0 || ret2 <= 0) { // what if ret2 == 0? conn closed?
        if (timeout != -1 && (curtime - starttime >= timeout)){
	    tout->tv_sec = 0;
	    tout->tv_usec = 0;
            set_error(cc, ETIMEDOUT, POSIX_ERROR, "Connection stuck"
                   " during read: timeout reached");
            return -1;
        }
        else {
            set_error(cc, 1, UNKNOWN_ERROR, "Error during SSL read");
            return -1;
        }
    }

    return ret2;
}

/* ret > 1 if connection does not exist or has been closed before
 * ret = 0 connection closed successfully (one direction)
 * ret = 1 connection closed successfully (both directions)
 * ret < 0 error occured (e.g. timeout reached) */
static canl_err_code
ssl_close(glb_ctx *cc, io_handler *io, void *auth_ctx)
{
    int timeout = DESTROY_TIMEOUT;
    time_t starttime, curtime;
    int expected = 0, error = 0, ret = 0, ret2 = 0;
    int fd;
    unsigned long ssl_err = 0;
    SSL *ssl = (SSL *) auth_ctx;

    if (!cc)
        return EINVAL;
    if (!io)
        return set_error(cc, EINVAL, POSIX_ERROR,
			 "Connection not initialized");
    if (ssl == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL not initialized");

    fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
    curtime = starttime = time(NULL);
    
    /* check the shutdown state*/
    ret = SSL_get_shutdown(ssl);
    if (ret & SSL_SENT_SHUTDOWN) {
        if (ret & SSL_RECEIVED_SHUTDOWN)
            return 1;
        else
            return 0;
    }
    /* TODO check the proper states, maybe also call SSL_shutdown
    if (ret & SSL_RECEIVED_SHUTDOWN) {
        return 0;
    } */

    do {
        ret = do_select(fd, starttime, timeout, expected);
	curtime = time(NULL);

	if (ret > 0) {
	    ret2 = SSL_shutdown(ssl);
	    if (ret2 < 0) {
                ssl_err = ERR_peek_error();
		expected = error = SSL_get_error(ssl, ret2);
            }
        }
    } while (TEST_SELECT(ret, ret2, timeout, curtime, starttime, error));

    if (timeout != -1 && (curtime - starttime >= timeout)){
        set_error(cc, ETIMEDOUT, POSIX_ERROR, "Connection stuck"
                " during ssl shutdown : timeout reached");
        return -1;
    }
    /* TODO set_error*/
    if (ret < 0) {
        set_error(cc, 0, UNKNOWN_ERROR, "Error during SSL shutdown");
        return -1;
    }
    /* successful shutdown (uni/bi directional)*/
    if (ret2 == 0 || ret2 == 1)
        return ret2;
    else {
        set_error(cc, ssl_err, SSL_ERROR, "Error during SSL shutdown");
        return -1;
    }
}

static canl_err_code
ssl_free(glb_ctx *cc, void *ctx)
{
    SSL_free(ctx);
    return 0;
}

static canl_err_code
ssl_finish(glb_ctx *cc, void *ctx)
{
    SSL_CTX_free(ctx);
    return 0;
}

/*maybe move to better file*/
canl_err_code 
canl_ctx_set_ssl_cred(canl_ctx cc, char *cert, char *key, char *proxy,
        canl_password_callback cb, void *userdata)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)glb_cc->mech_ctx;

    if (!m_ctx)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");

    if (!cc)
        return EINVAL;
    if(!cert ) {
        set_error(glb_cc, EINVAL, POSIX_ERROR, "invalid parameter value");
        return EINVAL;
    }

    err = do_set_ctx_own_cert_file(glb_cc, m_ctx, cert, key, proxy);
    if(err) {
//        update_error(glb_cc, "can't set cert or key to context");
    }
    return err;
}

canl_err_code
canl_ctx_set_crl_dir(canl_ctx cc, const char *dir)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)glb_cc->mech_ctx;
    
    if (!cc)
        return EINVAL;
    
    if (!m_ctx)
	return set_error(glb_cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");
    
    return ssl_set_dir(glb_cc, &m_ctx->crl_dir, dir);
}

canl_err_code
canl_ctx_set_ca_dir(canl_ctx cc, const char *dir)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)glb_cc->mech_ctx;
    
    if (!cc)
        return EINVAL;
    
    if (!m_ctx)
	return set_error(glb_cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");
    
    return ssl_set_dir(glb_cc, &m_ctx->ca_dir, dir);
}

static canl_err_code
ssl_get_peer(glb_ctx *cc, io_handler *io, void *auth_ctx, canl_principal *peer)
{
    struct _principal_int *princ;
    SSL *ssl = (SSL *) auth_ctx;
    X509 *cert = NULL;
    X509_NAME *subject = NULL;
    int ret;

    if (peer == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "invalid parameter value");

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
	return set_error(cc, CANL_ERR_NoClientCertificate, CANL_ERROR, "No peer certificate");

    princ = calloc(1, sizeof(*princ));
    if (princ == NULL)
	return set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");

    subject = X509_get_subject_name(cert);
    princ->name = strdup(X509_NAME_oneline(subject, NULL, 0));
    if (princ->name == NULL) {
	ret = set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");
	goto end;
    }

    *peer = princ;
    princ = NULL;
    ret = 0;

end:
    if (princ)
	free(princ);

    return ret;
}

#ifdef DEBUG
static void dbg_print_ssl_error(int errorcode)
{
    printf("[DBG CANL] ");
    switch (errorcode) {
        case SSL_ERROR_NONE:
            printf ("SSL_ERROR_NONE\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL_ERROR_ZERO_RETURN\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf ("SSL_ERROR_WANT_READ\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            printf ("SSL_ERROR_WANT_WRITE\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf ("SSL_ERROR_WANT_CONNECT\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf ("SSL_ERROR_WANT_ACCEPT\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf ("SSL_ERROR_WANT_X509_LOOKUP\n");
            break;
        case SSL_ERROR_SYSCALL:
            printf ("SSL_ERROR_SYSCALL\n");
            break;
        case SSL_ERROR_SSL:
            printf ("SSL_ERROR_SSL\n");
            break;
        default:
            printf ("no known error\n");
            break;
    }
}
#endif

static X509_STORE *
canl_create_x509store(canl_x509store_t *store)
{
    return NULL;
}

int do_ocsp_verify (canl_ocsprequest_t *data)
{
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *basic = NULL;
    X509_STORE *store = 0;
    int rc = 0, reason = 0, ssl = 0, status = 0;
    char *host = NULL, *path = NULL, *port = NULL;
    OCSP_CERTID *id = NULL;
    char *chosenurl = NULL;
    BIO *bio = NULL;
    SSL_CTX *ctx = NULL;
    canl_ocspresult_t result = 0;
    ASN1_GENERALIZEDTIME  *producedAt, *thisUpdate, *nextUpdate;
    /*get url from cert or use some implicit value*/

    /*get connection parameters out of url*/
    if (!OCSP_parse_url(chosenurl, &host, &port, &path, &ssl)) {
        result = CANL_OCSPRESULT_ERROR_BADOCSPADDRESS;
        goto end;
    }
    if (!(req = OCSP_REQUEST_new())) {
        result = CANL_OCSPRESULT_ERROR_OUTOFMEMORY;
        goto end;
    }

    id = OCSP_cert_to_id(0, data->cert, data->issuer);

    /* Add id and nonce*/
    if (!id || !OCSP_request_add0_id(req, id))
        goto end;
    if (USENONCE)
        OCSP_request_add1_nonce(req, 0, -1);

    /* sign the request */
       if (data->sign_cert && data->sign_key &&
       !OCSP_request_sign(req, data->sign_cert, data->sign_key, 
       EVP_sha1(), 0, 0)) {
       result = CANL_OCSPRESULT_ERROR_SIGNFAILURE;
       goto end;
       }
    
    ctx = SSL_CTX_new(SSLv3_client_method());
    if (ctx == NULL) {
        result = CANL_OCSPRESULT_ERROR_OUTOFMEMORY;
        goto end;
    }
    //SSL_CTX_set_cert_store(ctx, store);
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);

    /* establish a connection to the OCSP responder */
    if (!(bio = my_connect(host, atoi(port), ssl, &ctx))) {
        result = CANL_OCSPRESULT_ERROR_CONNECTFAILURE;
        goto end;
    }

    /* send the request and get a response */
    resp = OCSP_sendreq_bio(bio, path, req);
    if ((rc = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        switch (rc) {
            case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
                result = CANL_OCSPRESULT_ERROR_MALFORMEDREQUEST; break;
            case OCSP_RESPONSE_STATUS_INTERNALERROR:
                result = CANL_OCSPRESULT_ERROR_INTERNALERROR;    break;
            case OCSP_RESPONSE_STATUS_TRYLATER:
                result = CANL_OCSPRESULT_ERROR_TRYLATER;         break;
            case OCSP_RESPONSE_STATUS_SIGREQUIRED:
                result = CANL_OCSPRESULT_ERROR_SIGREQUIRED;      break;
            case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
                result = CANL_OCSPRESULT_ERROR_UNAUTHORIZED;     break;
        }
        goto end;
    }

    /* verify the response */
    result = CANL_OCSPRESULT_ERROR_INVALIDRESPONSE;
    if (!(basic = OCSP_response_get1_basic(resp))) 
        goto end;
    if (USENONCE && OCSP_check_nonce(req, basic) <= 0) 
        goto end;
    /*TODO make the store*/ 
    if (data->store && !(store = canl_create_x509store(data->store)))
        goto end;
    /*TODO check the second parametr (responder_cert) and the last one*/
    if ((rc = OCSP_basic_verify(basic, 0, store, 0)) <= 0)
        if ((rc = OCSP_basic_verify(basic, NULL, store, 0)) <= 0)
            goto end;

    if (!OCSP_resp_find_status(basic, id, &status, &reason, &producedAt,
                &thisUpdate, &nextUpdate))
        goto end;
    if (!OCSP_check_validity(thisUpdate, nextUpdate, data->skew, data->maxage))
        goto end;

    /* All done.  Set the return code based on the status from the response. */
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        result = CANL_OCSPRESULT_CERTIFICATE_REVOKED;
        /*TODO myproxy_log("OCSP status revoked!"); */
    } else {
        result = CANL_OCSPRESULT_CERTIFICATE_VALID;
        /*TODO myproxy_log("OCSP status valid"); */
    }
end:
    /*TODO check what's this 
      if (result < 0 && result != CANL_OCSPRESULT_ERROR_NOTCONFIGURED) {
      ssl_error_to_verror();
      TODO myproxy_log("OCSP check failed");
      myproxy_log_verror();
      } */

    if (host) OPENSSL_free(host);
    if (port) OPENSSL_free(port);
    if (path) OPENSSL_free(path);
    if (req) OCSP_REQUEST_free(req);
    if (resp) OCSP_RESPONSE_free(resp);
    if (basic) OCSP_BASICRESP_free(basic);
    if (ctx) SSL_CTX_free(ctx);   /* this does X509_STORE_free(store) */

    return 0;
}

static BIO *
my_connect_ssl(char *host, int port, SSL_CTX **ctx) {
      BIO *conn = 0;

        if (!(conn = BIO_new_ssl_connect(*ctx))) goto error_exit;
          BIO_set_conn_hostname(conn, host);
            BIO_set_conn_int_port(conn, &port);

              if (BIO_do_connect(conn) <= 0) goto error_exit;
                return conn;

error_exit:
                  if (conn) BIO_free_all(conn);
                    return 0;
}

static BIO *
my_connect(char *host, int port, int ssl, SSL_CTX **ctx) {
    BIO *conn;
    SSL *ssl_ptr;

    if (ssl) {
        if (!(conn = my_connect_ssl(host, port, ctx))) goto error_exit;
        BIO_get_ssl(conn, &ssl_ptr);
        /*TODO figure out, how to check cert without canl_ctx
        if (!check_hostname_cert(SSL_get_peer_certificate(ssl_ptr), host))
            goto error_exit;*/
        if (SSL_get_verify_result(ssl_ptr) != X509_V_OK) goto error_exit;
        return conn;
    }

    if (!(conn = BIO_new_connect(host))) goto error_exit;
    BIO_set_conn_int_port(conn, &port);
    if (BIO_do_connect(conn) <= 0) goto error_exit;
    return conn;

error_exit:
    if (conn) BIO_free_all(conn);
    return 0;
}

canl_mech canl_mech_ssl = {
    TLS,
    ssl_initialize,
    ssl_set_flags,
    ssl_finish,
    ssl_client_init,
    ssl_server_init,
    ssl_free,
    ssl_connect,
    ssl_accept,
    ssl_close,
    ssl_read,
    ssl_write,
    ssl_get_peer,
};
