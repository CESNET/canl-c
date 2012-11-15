#include "canl_locl.h"
#include "canl_ssl.h"
#include "canl_mech_ssl.h"
#include <openssl/ocsp.h>

#define SSL_SERVER_METH SSLv23_server_method()
#define SSL_CLIENT_METH SSLv3_client_method()
#define DESTROY_TIMEOUT 10

static int do_ssl_connect( glb_ctx *cc, io_handler *io, 
        SSL *ssl, struct timeval *timeout);
static int do_ssl_accept( glb_ctx *cc, io_handler *io, 
        SSL *ssl, struct timeval *timeout);
static int check_hostname_cert(glb_ctx *cc, io_handler *io,
        SSL *ssl, const char *host);

canl_error map_verify_result(unsigned long ssl_err,
        const X509_STORE_CTX *store_ctx, SSL *ssl);
static canl_error map_proxy_error(int reason);

static int setup_SSL_proxy_handler(glb_ctx *cc, SSL_CTX *ssl, char *cadir,
        int leave_pvd);
extern proxy_verify_desc *pvd_setup_initializers(char *cadir);
extern void pvd_destroy_initializers(void *data);

#ifdef DEBUG
static void dbg_print_ssl_error(int errorcode);
#endif

/*static int set_ocsp_url(char *url, X509 *cert, X509 *issuer, 
  canl_x509store_t *store, X509 *sign_cert, EVP_PKEY *sign_key, 
  long skew, long maxage) {
 */ 

    static canl_err_code
ssl_initialize(glb_ctx *cc)
{
    mech_glb_ctx **m_glb_ctx = (mech_glb_ctx **) &cc->mech_ctx;
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
    if (!err){
        /* set ca dir and ca file to SSL_CTX*/
        if (ca_cert_fn || ca_cert_dirn)
            if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_cert_fn,
                        ca_cert_dirn))
                err = set_error(cc, ERR_get_error(), SSL_ERROR,
                        "Cannot set verify locations");
        /* set ca dir and/or ca file to canl glb_ctx*/
        if (!(*m_glb_ctx)->ca_file && ca_cert_fn && !access(ca_cert_fn, R_OK)) {
            err = canl_ctx_set_ca_fn(cc, ca_cert_fn);
            if (err)
                return err;
        }
        if (!(*m_glb_ctx)->ca_dir && ca_cert_dirn && !access(ca_cert_dirn, R_OK)) {
            err = canl_ctx_set_ca_dir(cc, ca_cert_dirn);
            if (err)
                return err;
        }
    }


    if (ca_cert_fn)
        free(ca_cert_fn);
    if (ca_cert_dirn)
        free(ca_cert_dirn);

    //err = SSL_CTX_set_cipher_list(ssl_ctx, "ALL:!LOW:!EXP:!MD5:!MD2");
    err = SSL_CTX_set_cipher_list(ssl_ctx, "ALL");
    if (!err) {
        err = set_error(cc, ERR_get_error(), SSL_ERROR,
                "Error setting cipher list");
        goto end;
    }
    /* XXX: should be only defined on the SSL level: */
    SSL_CTX_set_cert_verify_callback(ssl_ctx, proxy_app_verify_callback, 0);

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
    char *user_cert_fn, *user_key_fn; 
    int err = 0;
    user_cert_fn = user_key_fn = NULL;
 
    if (cc == NULL)
	return EINVAL;

    if (!m_ctx || !m_ctx->mech_ctx)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");
    ssl_ctx = (SSL_CTX *) m_ctx->mech_ctx;

    err = proxy_get_filenames(0, NULL, NULL, NULL,
            &user_cert_fn, &user_key_fn);
    if (!err && (!m_ctx->cert_key || !m_ctx->cert_key->cert || 
                !m_ctx->cert_key->key)) {
        if (user_cert_fn && user_key_fn && !access(user_cert_fn, R_OK) && 
                !access(user_key_fn, R_OK)) {
            err = do_set_ctx_own_cert_file(cc, m_ctx,
                    user_cert_fn, user_key_fn, NULL);
            if (err) {
                free(user_cert_fn);
                free(user_key_fn);
                return err;
            }
        }
    }
    if (user_cert_fn){
	free(user_cert_fn);
	user_cert_fn = NULL;
    }
    if (user_key_fn){
	free(user_key_fn);
	user_key_fn = NULL;
    }
    if (err || (!m_ctx->cert_key || !m_ctx->cert_key->cert || 
                !m_ctx->cert_key->key))
	return set_error(cc, CANL_ERR_noCertFound, CANL_ERROR,
                "No key or certificate found");


    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL)
	return set_error(cc, ERR_get_error(), SSL_ERROR,
		         "Failed to create SSL connection context");

    if (CANL_SSL_VERIFY_NONE & m_ctx->flags)
        SSL_set_verify(ssl, SSL_VERIFY_NONE, proxy_verify_callback);
    else
        SSL_set_verify(ssl, SSL_VERIFY_PEER, proxy_verify_callback);
    
    if (!(CANL_SSL_ACCEPT_SSLv2 & m_ctx->flags))
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
        set_error(cc, CANL_ERR_noCertFound, CANL_ERROR,
		"server key or certificate missing");
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
                goto err;
        }
        else {
            if (user_cert_fn && !access(user_cert_fn, R_OK)) {
                err = do_set_ctx_own_cert_file(cc, m_ctx, 
                        user_cert_fn, NULL, NULL);
                if (err)
                    goto err;
            }
            if (user_key_fn && !access(user_key_fn, R_OK)) {
                err = do_set_ctx_own_cert_file(cc, m_ctx,
                        NULL, user_key_fn, NULL);
                if (err)
                    goto err;
            }
        }
    }

    if (err || (!m_ctx->cert_key || !m_ctx->cert_key->cert || 
                !m_ctx->cert_key->key))
        update_error(cc, CANL_ERR_noCertFound, CANL_ERROR,
                "No key or certificate found");

    if (user_cert_fn){
        free(user_cert_fn);
        user_cert_fn = NULL;
    }
    if (user_key_fn){
        free(user_key_fn);
        user_key_fn = NULL;
    }
    if (user_proxy_fn) {
        free(user_proxy_fn);
        user_proxy_fn = NULL;
    }

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
    
    if (CANL_SSL_VERIFY_NONE & m_ctx->flags)
        SSL_set_verify(ssl, SSL_VERIFY_NONE, proxy_verify_callback);
    else
        SSL_set_verify(ssl, SSL_VERIFY_PEER, proxy_verify_callback);

    if (!(CANL_SSL_ACCEPT_SSLv2 & m_ctx->flags))
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
err:
    if (user_cert_fn){
        free(user_cert_fn);
        user_cert_fn = NULL;
    }
    if (user_key_fn){
        free(user_key_fn);
        user_key_fn = NULL;
    }
    if (user_proxy_fn) {
        free(user_proxy_fn);
        user_proxy_fn = NULL;
    }
    return err;
}

static int setup_SSL_proxy_handler(glb_ctx *cc, SSL_CTX *ssl, char *cadir,
        int leave_pvd)
{
    proxy_verify_desc *new_pvd = NULL;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;
    new_pvd =  pvd_setup_initializers(cadir);
    if (new_pvd){
        SSL_CTX_set_ex_data(ssl, PVD_SSL_EX_DATA_IDX, new_pvd);
        if (!leave_pvd)
            m_ctx->pvd_ctx = new_pvd;
        return 0;
    }
    return 1;
}

static canl_err_code
ssl_connect(glb_ctx *cc, io_handler *io, void *auth_ctx,
	        struct timeval *timeout, const char * host)
{
    SSL *ssl = (SSL *) auth_ctx;
    SSL_CTX *ssl_ctx = NULL;
    int err = 0, flags;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;


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

    ssl_ctx = SSL_get_SSL_CTX(ssl);
    setup_SSL_proxy_handler(cc, ssl_ctx, m_ctx->ca_dir, 0);
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
    SSL_CTX *ssl_ctx = NULL;
    int err = 0, flags;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;

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

    ssl_ctx = SSL_get_SSL_CTX(ssl);
    setup_SSL_proxy_handler(cc, ssl_ctx, m_ctx->ca_dir, 0);
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
    long errorcode = 0;
    int expected = 0;
    int locl_timeout = -1;
    canl_error canl_err = 0;

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
            update_error (cc, ETIMEDOUT, POSIX_ERROR, "Connection stuck during"
		   " handshake: timeout reached");
        }
        else if (ret2 < 0 && ssl_err){
            canl_err = map_verify_result(ssl_err, NULL, ssl);
            if (canl_err)
                update_error (cc, canl_err, CANL_ERROR,
                        "Error during SSL handshake");
            else
                update_error(cc, ssl_err, SSL_ERROR,
                        "Error during SSL handshake");
        }
        else if (ret2 == 0)//TODO is 0 (conn closed by the other side) error?
            update_error (cc, ECONNREFUSED, POSIX_ERROR, "Connection closed"
                    " by the other side");
        else
            /*ret2 < 0 && !ssl_err*/
            update_error (cc, CANL_ERR_noRouteToServer, CANL_ERROR, "Error"
                    " during SSL handshake"
                    " in communication with the server");
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
    long errorcode = 0;
    int expected = 0;
    int locl_timeout = -1;
    canl_error canl_err = 0;

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
            set_error (cc, ETIMEDOUT, POSIX_ERROR, "Connection stuck"
                    " during handshake: timeout reached"); 
        }
        else if (ret2 == 0)
            set_error (cc, ECONNREFUSED, POSIX_ERROR, "Connection closed by"
		    " the other side");
        else if (ret2 < 0 && ssl_err){
            canl_err = map_verify_result(ssl_err, NULL, ssl);
            if (canl_err)
                set_error(cc, canl_err, CANL_ERROR,
                        "Error during SSL handshake");
            else
                set_error(cc, ssl_err, SSL_ERROR,
                        "Error during SSL handshake");
        }
	else
            /*ret2 < 0 && !ssl_err*/
            set_error (cc, 0, UNKNOWN_ERROR, "Error during SSL handshake"
                    " in communication with the server");
        return 1;
    }
    return 0;
}

canl_error
map_verify_result(unsigned long ssl_err, const X509_STORE_CTX *store_ctx,
        SSL *ssl)
{
    long result = 0;
    canl_error canl_err = 0;
    int err_lib = 0;

    /*Try PRXYERR codes first*/
    if (ssl_err)
        if ((err_lib = ERR_GET_LIB(ssl_err)) == ERR_USER_LIB_PRXYERR_NUMBER) {
            canl_err = map_proxy_error(ERR_GET_REASON(ssl_err));
            if (canl_err)
                return canl_err;
        }

    /*Then try to get verify error out of X509_STORE_CTX or SSL*/
    if (store_ctx)
        result = X509_STORE_CTX_get_error(store_ctx);
    else if (ssl)
        result = SSL_get_verify_result(ssl);
    else
        return 0;

    /*We have openssl cert verification result code*/
    switch (result) {
        case X509_V_OK:
            return 0;
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            canl_err = CANL_ERR_pathLenghtExtended;
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            canl_err = CANL_ERR_noIssuerPublicKey;
            break;
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            canl_err = CANL_ERR_signatureNotVerified;
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
            canl_err = CANL_ERR_certificateNotYetValid;
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
            canl_err = CANL_ERR_certificateExpired;
            break;
        case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
            canl_err = CANL_ERR_unknownCriticalExt;
            break;
        case X509_V_ERR_CERT_REVOKED:
            canl_err = CANL_ERR_certRevoked;
            break;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            canl_err = CANL_ERR_noValidCrlFound;
            break;
        case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
            canl_err = CANL_ERR_proxyLength;
            break;
        case X509_V_ERR_INVALID_PURPOSE:
            canl_err = CANL_ERR_invalidPurpose;
            break;
        default:
            break;
    }

    return canl_err;
}

/*go through PRXYERR reasons and map them on canl error codes*/
static canl_error
map_proxy_error(int reason)
{
    canl_error canl_err = 0;
    switch (reason) {
        case PRXYERR_R_UNKNOWN_CRIT_EXT:
            canl_err = CANL_ERR_unknownCriticalExt;
            break;
        case PRXYERR_R_CA_POLICY_VIOLATION: //TODO map
            break;
        case PRXYERR_R_CERT_REVOKED:
            canl_err = CANL_ERR_certRevoked;
        case PRXYERR_R_CRL_HAS_EXPIRED: //TODO map
            break;
        case PRXYERR_R_CRL_NEXT_UPDATE_FIELD: //TODO map
            break;
        case PRXYERR_R_CRL_SIGNATURE_FAILURE: //TODO map
            break;
        case PRXYERR_R_LPROXY_MISSED_USED: //TODO map
            break;
        case PRXYERR_R_BAD_PROXY_ISSUER:
//          canl_err = CANL_ERR_certWrongProxyIssuer; //TODO does not exist yet
            break;
        case PRXYERR_R_BAD_MAGIC: //Todo map
            break;
    }
    
    return canl_err;
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
ssl_finish(glb_ctx *cc, void *ctx)
{
    SSL_free(ctx);
    return 0;
}

static canl_err_code
ssl_free_ctx(glb_ctx *cc)
{
    mech_glb_ctx *m_ctx = cc->mech_ctx;
    SSL_CTX_free(m_ctx->mech_ctx);
    m_ctx->mech_ctx = NULL;

    if (!m_ctx)
        return 0;

    if (m_ctx->ca_dir){
        free(m_ctx->ca_dir);
        m_ctx->ca_dir = NULL;
    }
    if (m_ctx->ca_file){
        free(m_ctx->ca_file);
        m_ctx->ca_file = NULL;
    }
    if (m_ctx->crl_dir){
        free(m_ctx->crl_dir);
        m_ctx->crl_dir = NULL;
    }

    if (m_ctx->cert_key){
        if (m_ctx->cert_key->cert){
            X509_free(m_ctx->cert_key->cert);
            m_ctx->cert_key->cert = NULL;
        }
        if (m_ctx->cert_key->key){
            EVP_PKEY_free(m_ctx->cert_key->key);
            m_ctx->cert_key->key = NULL;
        }
        if (m_ctx->cert_key->chain){
            sk_X509_pop_free(m_ctx->cert_key->chain, X509_free);
            m_ctx->cert_key->chain = NULL;
        }
        free(m_ctx->cert_key);
        m_ctx->cert_key = NULL;
    }
    if (m_ctx->pvd_ctx){
        pvd_destroy_initializers(m_ctx->pvd_ctx);
        m_ctx->pvd_ctx = NULL;
    }
    free(m_ctx);
    cc->mech_ctx = NULL;
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
canl_ctx_set_ssl_flags(canl_ctx cc, unsigned int flags)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)glb_cc->mech_ctx;

    if (!m_ctx)
	return set_error(cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");

    if (!cc)
        return EINVAL;

    m_ctx->flags |= flags;
    return 0;
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

canl_err_code
canl_ctx_set_ca_fn(canl_ctx cc, const char *fn)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)glb_cc->mech_ctx;
    
    if (!cc)
        return EINVAL;
    
    if (!m_ctx)
	return set_error(glb_cc, EINVAL, POSIX_ERROR, "Mech context not"
                " initialized");
    
    return ssl_set_dir(glb_cc, &m_ctx->ca_file, fn);
}

canl_err_code CANL_CALLCONV
canl_ssl_ctx_set_clb(canl_ctx cc, SSL_CTX *ssl_ctx, int ver_mode,
        int (*verify_callback)(int, X509_STORE_CTX *))
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int (*vc)(int, X509_STORE_CTX *) = NULL;

    vc = (verify_callback) ? verify_callback : proxy_verify_callback;

    if (!cc)
        return EINVAL;
    if (!ssl_ctx)
        return set_error(glb_cc, EINVAL, POSIX_ERROR, "SSL context not"
                " initialized");
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)glb_cc->mech_ctx;
    
    setup_SSL_proxy_handler(glb_cc, ssl_ctx, m_ctx->ca_dir, 1);
    SSL_CTX_set_cert_verify_callback(ssl_ctx, proxy_app_verify_callback, NULL);

    SSL_CTX_set_verify(ssl_ctx, ver_mode, vc);

    return 0;
}

    int CANL_CALLCONV
canl_direct_pv_clb(canl_ctx cc, X509_STORE_CTX *store_ctx, int ok)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    if (!store_ctx){
        if (glb_cc)
            set_error(glb_cc, EINVAL, POSIX_ERROR, "X509_STORE_CTX not"
                    " initialized");
        return 0;
    }

    return proxy_verify_callback(ok, store_ctx);
}

static canl_err_code
ssl_get_peer(glb_ctx *cc, io_handler *io, void *auth_ctx, canl_principal *peer)
{
    struct _principal_int *princ;
    SSL *ssl = (SSL *) auth_ctx;
    X509 *cert = NULL;
    X509_NAME *subject = NULL;
    int ret;
    BIO *name_out = BIO_new(BIO_s_mem());
    long name_len = 0;
    mech_glb_ctx *m_ctx = (mech_glb_ctx *)cc->mech_ctx;

    if (peer == NULL)
	return set_error(cc, EINVAL, POSIX_ERROR, "invalid parameter value");

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
	return set_error(cc, CANL_ERR_noPeerCertificate, CANL_ERROR, "No peer certificate");

    princ = calloc(1, sizeof(*princ));
    if (princ == NULL)
	return set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");

    subject = X509_get_subject_name(cert);
    if (CANL_SSL_DN_OSSL & m_ctx->flags)
        ret = X509_NAME_print_ex(name_out, subject, 0, 0);
    else
        ret = X509_NAME_print_ex(name_out, subject, 0, XN_FLAG_RFC2253);
    if (!ret){
        ret = set_error(cc, CANL_ERR_unknown, CANL_ERROR,
                "Cannot extract subject name out of"
                " the peer's certificate"); //TODO error code
        goto end;
    }
    name_len = BIO_ctrl_pending(name_out);
    if (name_len) {
        princ->name = (char *) malloc((name_len +1) * sizeof(char));
        if (princ->name == NULL) {
            ret = set_error(cc, ENOMEM, POSIX_ERROR, "Not enough memory");
            goto end;
        }
    }
    else {
        ret = set_error(cc, CANL_ERR_unknown, CANL_ERROR,
                "Zero subject name length"); //TODO error code
        goto end;
    }

    BIO_read(name_out, princ->name, name_len);
    princ->name[name_len] = '\0';

    *peer = princ;
    princ = NULL;
    ret = 0;

end:
    if (princ)
	free(princ);

    BIO_vfree(name_out);
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


canl_mech canl_mech_ssl = {
    TLS,
    ssl_initialize,
    ssl_set_flags,
    ssl_finish,
    ssl_client_init,
    ssl_server_init,
    ssl_free_ctx,
    ssl_connect,
    ssl_accept,
    ssl_close,
    ssl_read,
    ssl_write,
    ssl_get_peer,
};
