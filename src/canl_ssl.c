#include "canl_locl.h"

#define SSL_SERVER_METH SSLv23_server_method()
#define SSL_CLIENT_METH SSLv3_client_method()
#define DESTROY_TIMEOUT 10

static int do_ssl_connect( glb_ctx *cc, io_handler *io, SSL *ssl, struct timeval *timeout);
static int do_ssl_accept( glb_ctx *cc, io_handler *io, SSL *ssl, struct timeval *timeout);
static int check_hostname_cert(glb_ctx *cc, io_handler *io, SSL *ssl, const char *host);
#ifdef DEBUG
static void dbg_print_ssl_error(int errorcode);
#endif

static canl_err_code
ssl_initialize(glb_ctx *cc, void **ctx)
{
    int err = 0;
    char *ca_cert_fn, *user_cert_fn, *user_key_fn, *user_proxy_fn;
    char *ca_cert_dirn = NULL;
    ca_cert_fn = user_cert_fn = user_key_fn = user_proxy_fn = NULL;
    SSL_CTX *ssl_ctx = NULL;

    if (!cc)
	return EINVAL;

    SSL_library_init();
    SSL_load_error_strings();
    ERR_clear_error();

    ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!ssl_ctx)
	return set_error(cc, ERR_get_error(), ssl_error,
			 "Cannot initialize SSL context");
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

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
	err = set_error(cc, ERR_get_error(), ssl_error,
			"No cipher to use");
	goto end;
    }

    //SSL_CTX_set_purpose(ssl_ctx, X509_PURPOSE_ANY);
    //SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    // TODO proxy_verify_callback, verify_none only for testing !!!!!!!
    //SSL_CTX_set_verify_depth(ctx, 100);

    *ctx = ssl_ctx;
    ssl_ctx = NULL;
    err = 0;

end:
    if (ssl_ctx)
	SSL_CTX_free(ssl_ctx);

    return err;
}

static canl_err_code
ssl_server_init(glb_ctx *cc, void *mech_ctx, void **ctx)
{
    SSL_CTX *ssl_ctx = (SSL_CTX *) mech_ctx;
    SSL *ssl = NULL;

    if (cc == NULL)
	return EINVAL;

    if (ssl_ctx == NULL)
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

#if 0
    err = proxy_get_filenames(0, &ca_cert_fn, &ca_cert_dirn, &user_proxy_fn,
            &user_cert_fn, &user_key_fn);
    if (!err && (!cc->cert_key || !cc->cert_key->cert || !cc->cert_key->key)) {
        if (user_cert_fn && user_key_fn && !access(user_cert_fn, R_OK) && 
                !access(user_key_fn, R_OK)) {
            err = do_set_ctx_own_cert_file(cc, user_cert_fn, user_key_fn);
            if (err)
                return err;
        }
    }

    free(user_cert_fn);
    user_cert_fn = NULL;
    free(user_key_fn);
    user_key_fn = NULL;
    //TODO where to use proxy on server side
    free(user_proxy_fn);
    user_proxy_fn = NULL;
#endif

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL)
	return set_error(cc, ERR_get_error(), ssl_error,
		         "Failed to create SSL connection context");

    /* XXX: should be only defined on the SSL level: */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, proxy_verify_callback);
    SSL_CTX_set_cert_verify_callback(ssl_ctx, proxy_app_verify_callback, 0);

    SSL_use_certificate_file(ssl, "/etc/grid-security/hostcert.pem", SSL_FILETYPE_PEM);
    SSL_use_PrivateKey_file(ssl, "/etc/grid-security/hostkey.pem", SSL_FILETYPE_PEM);

    SSL_set_accept_state(ssl);

#if 0
    if (cc->cert_key) {
        if (cc->cert_key->cert) {
            err = SSL_CTX_use_certificate(ssl_ctx, cc->cert_key->cert);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
            else
                err = 0;
        }
        if (cc->cert_key->key) {
            err = SSL_CTX_use_PrivateKey(ssl_ctx, cc->cert_key->key);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
            else
                err = 0;
        }
    }
    else {
        set_error(cc, err, unknown_error, "server key or certificate missing");
        return 1;
    }
    /*Make sure the key and certificate file match*/
    if ( (err = SSL_CTX_check_private_key(ssl_ctx)) != 1) {
        ssl_err = ERR_get_error();
        e_orig = ssl_error;
        set_error(cc, ssl_err, e_orig, "Private key does not match"
                " the certificate public key"); 
        return 1;
    }
#endif

    *ctx = ssl;

    return 0;
}

static canl_err_code
ssl_client_init(glb_ctx *cc, void *mech_ctx, void **ctx)
{
    SSL_CTX *ssl_ctx = (SSL_CTX *) mech_ctx;
    SSL *ssl = NULL;

    if (cc == NULL)
	return EINVAL;

    if (ssl_ctx == NULL)
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL)
	return set_error(cc, ERR_get_error(), ssl_error,
		         "Failed to create SSL connection context");

    SSL_set_connect_state(ssl);

#if 0
    err = proxy_get_filenames(0, &ca_cert_fn, &ca_cert_dirn, &user_proxy_fn,
            &user_cert_fn, &user_key_fn);
    if (!err && (!cc->cert_key || !cc->cert_key->cert || !cc->cert_key->key)) {
        if (user_proxy_fn && !access(user_proxy_fn, R_OK)) {
            err = do_set_ctx_own_cert_file(cc, user_proxy_fn, user_proxy_fn);
            if (err)
                return err;
        }
    }

    free(user_cert_fn);
    user_cert_fn = NULL;
    free(user_key_fn);
    user_key_fn = NULL;
    free(user_proxy_fn);
    user_proxy_fn = NULL;

    if (cc->cert_key) {
        if (cc->cert_key->key) {
            err = SSL_CTX_use_PrivateKey(ssl_ctx, cc->cert_key->key);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
        }
        else if (cc->cert_key->cert) {
            err = SSL_CTX_use_certificate(ssl_ctx, cc->cert_key->cert);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
        }
    }
#endif

    *ctx = ssl;
    return 0;
}

static canl_err_code
ssl_connect(glb_ctx *cc, io_handler *io, void *auth_ctx,
	        struct timeval *timeout, const char * host)
{
    SSL_CTX *ctx;
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
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

    ctx = SSL_get_SSL_CTX(ssl);

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
    unsigned char *pBuffer = NULL;
    int correspond = 0;
    struct sockaddr *addr = NULL;
    socklen_t addrlen = 0;
    X509_NAME *sn = NULL;

    /*if extensions are present, hostname has to correspond
     *  to subj. alt. name*/
    serv_cert = SSL_get_peer_certificate(ssl);
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
            return set_error(cc, CANL_ERR_unknownMsg, canl_error,
                    "Common name entry does not exist"); //TODO check
    }

end:
    X509_free(serv_cert);
    if (correspond)
        return 0;
    else {
        return set_error(cc, CANL_ERR_unknownMsg, canl_error, 
                "Cannot validate server hostname against its certificate" );
        //TODO check
    }
}

static canl_err_code
ssl_accept(glb_ctx *cc, io_handler *io, void *auth_ctx, struct timeval *timeout)
{
    SSL_CTX *ctx = NULL;
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
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

    ctx = SSL_get_SSL_CTX(ssl);

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
    CANL_ERROR_ORIGIN e_orig = unknown_error;
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
                e_orig = ssl_error;
            }
            expected = errorcode = SSL_get_error(ssl, ret2);
        }
        curtime = time(NULL);
    } while (TEST_SELECT(ret, ret2, locl_timeout, curtime, starttime, errorcode));

    //TODO split ret2 and ret into 2 ifs to set approp. err. msg and check ag.
    if (ret2 <= 0 || ret <= 0) {
        if (timeout && (curtime - starttime >= locl_timeout)){
            timeout->tv_sec=0;
            timeout->tv_usec=0;
            err = ETIMEDOUT; 
            set_error (cc, err, posix_error, "Connection stuck during"
		   " handshake: timeout reached");
        }
        else if (ret2 < 0)
            return set_error(cc, ssl_err, e_orig, "Error during SSL handshake");
        else if (ret2 == 0)//TODO is 0 (conn closed by the other side) error?
            set_error (cc, 0, ssl_error, "Connection closed"
                    " by the other side");
        else
            set_error (cc, err, unknown_error, "Error during SSL handshake");
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
    CANL_ERROR_ORIGIN e_orig = unknown_error;
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
                e_orig = ssl_error;
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

    //TODO split ret2 and ret into 2 ifs to set approp. error message
    if (ret2 <= 0 || ret <= 0) {
        if (timeout && (curtime - starttime >= locl_timeout)){
            timeout->tv_sec=0;
            timeout->tv_usec=0;
            err = ETIMEDOUT;
            set_error (cc, err, posix_error, "Connection stuck"
                    " during handshake: timeout reached"); 
        }
        else if (ret2 <= 0)
            set_error (cc, ssl_err, ssl_error, "Connection closed by"
		    " the other side");
	else
	    set_error (cc, 0, unknown_error, "Error during SSL handshake");
        return 1;
    }
    return 0;
}

/* this function has to return # bytes written or ret < 0 when sth went wrong*/
static canl_err_code
ssl_write(glb_ctx *cc, io_handler *io, void *auth_ctx,
	      void *buffer, size_t size, struct timeval *timeout)
{
    int err = 0;
    int ret = 0, nwritten=0;
    const char *str;
    int fd = -1; 
    time_t starttime, curtime;
    int do_continue = 0;
    int expected = 0;
    int locl_timeout;
    int touted = 0;
    int to = 0; // bool
    SSL *ssl = (SSL *) auth_ctx;

    if (cc == NULL)
	return EINVAL;

    if (io == NULL)
	return set_error(cc, EINVAL, posix_error,
			 "Connection not established");

    if (ssl == NULL)
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

    fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
    str = buffer;//TODO !!!!!! text.c_str();

    curtime = starttime = time(NULL);
    if (timeout) {
        locl_timeout = timeout->tv_sec;
        to = 1;
    }
    else {
        to = 0;
        locl_timeout = -1;
    }
    ERR_clear_error();

    do {
        ret = do_select(fd, starttime, locl_timeout, expected);

        do_continue = 0;
        if (ret > 0) {
            int v;
            errno = 0;
            ret = SSL_write(ssl, str + nwritten,
                    strlen(str) - nwritten);
            v = SSL_get_error(ssl, ret);

            switch (v) {
                case SSL_ERROR_NONE:
                    nwritten += ret;
                    if ((size_t)nwritten == strlen(str))
                        do_continue = 0;
                    else
                        do_continue = 1;
                    break;

                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    expected = v;
                    ret = 1;
                    do_continue = 1;
                    break;

                default:
                    do_continue = 0;
            }
        }
        curtime = time(NULL);
        if (to)
            locl_timeout = locl_timeout - (curtime - starttime);
        if (to && locl_timeout <= 0){
            touted = 1;
            goto end;
        }
    } while (ret <= 0 && do_continue);

end:
    if (err) {
        errno = err;
        set_error (cc, err, posix_error, "Error during SSL write"); 
        return -1;
    }
    if (touted){
       err = ETIMEDOUT;
       set_error(cc, err, posix_error, "Connection stuck during"
               " write: timeout reached"); 
       return -1;
    }
    if (ret <=0){
        err = -1;//TODO what to assign??????
        set_error (cc, err, unknown_error, "Error during SSL write");
    }
    return ret;
}

static canl_err_code
ssl_read(glb_ctx *cc, io_handler *io, void *auth_ctx,
	     void *buffer, size_t size, struct timeval *tout)
{
    int err = 0;
    int ret = 0, nwritten=0, ret2 = 0;
    char *str;
    int fd = -1;
    time_t starttime, curtime;
    int expected = 0, error = 0;
    int timeout;
    SSL *ssl = (SSL *) auth_ctx;

    if (cc == NULL)
	return EINVAL;

    if (io == NULL)
	return set_error(cc, EINVAL, posix_error,
			 "Connection not established");

    if (ssl == NULL)
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

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
                    strlen(str) - nwritten);

            if (ret2 <= 0) {
                expected = error = SSL_get_error(ssl, ret2);
            }
        }
    } while (TEST_SELECT(ret, ret2, timeout, curtime, starttime, error));

    if (ret <= 0 || ret2 <= 0) { // what if ret2 == 0? conn closed?
        err = -1; //TODO what to assign
        if (timeout != -1 && (curtime - starttime >= timeout)){
            set_error(cc, ETIMEDOUT, posix_error, "Connection stuck"
                   " during read: timeout reached");
        }
        else
            set_error(cc, err, unknown_error, "Error during SSL read");
    }
    else
        err = ret2;
    return err;
}

/* ret > 1 if connection does not exist or has been closed before
 * ret = 0 connection closed successfully (one direction)
 * ret = 1 connection closed successfully (both directions)
 * ret < 0 error occured (e.g. timeout reached) */
static canl_err_code
ssl_close(glb_ctx *cc, io_handler *io, void *auth_ctx)
{
    SSL_CTX *ctx;
    int timeout = DESTROY_TIMEOUT;
    time_t starttime, curtime;
    int expected = 0, error = 0, ret = 0, ret2 = 0;
    int fd;
    unsigned long ssl_err = 0;
    SSL *ssl = (SSL *) auth_ctx;

    if (!cc)
        return EINVAL;
    if (!io)
        return set_error(cc, EINVAL, posix_error,
			 "Connection not initialized");
    if (ssl == NULL)
	return set_error(cc, EINVAL, posix_error, "SSL not initialized");

    ctx = SSL_get_SSL_CTX(ssl);

    fd = BIO_get_fd(SSL_get_rbio(ssl), NULL);
    curtime = starttime = time(NULL);
    
    /* check the shutdown state*/
    ret = SSL_get_shutdown(ssl);
    if (ret & SSL_SENT_SHUTDOWN)
        if (ret & SSL_RECEIVED_SHUTDOWN)
            return 1;
        else
            return 0;
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
        set_error(cc, ETIMEDOUT, posix_error, "Connection stuck"
                " during ssl shutdown : timeout reached");
        return -1;
    }
    /* TODO set_error*/
    if (ret < 0) {
        set_error(cc, 0, unknown_error, "Error during SSL shutdown");
        return -1;
    }
    /* successful shutdown (uni/bi directional)*/
    if (ret2 == 0 || ret2 == 1)
        return ret2;
    else {
        set_error(cc, ssl_err, ssl_error, "Error during SSL shutdown");
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

canl_err_code 
canl_ctx_set_ssl_cred(canl_ctx cc, char *cert, char *key,
        canl_password_callback cb, void *userdata)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;

    if (!cc)
        return EINVAL;
    if(!cert ) {
        set_error(glb_cc, EINVAL, posix_error, "invalid parameter value");
        return EINVAL;
    }

    err = do_set_ctx_own_cert_file(glb_cc, cert, key);
    if(err) {
//        update_error(glb_cc, "can't set cert or key to context");
    }
    return err;
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

struct canl_mech canl_mech_ssl = {
    TLS,
    NULL,
    ssl_initialize,
    ssl_finish,
    ssl_client_init,
    ssl_server_init,
    ssl_free,
    ssl_connect,
    ssl_accept,
    ssl_close,
    ssl_read,
    ssl_write
};
