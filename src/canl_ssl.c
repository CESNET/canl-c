#include "canl_locl.h"

#define SSL_SERVER_METH SSLv23_server_method()
#define SSL_CLIENT_METH SSLv3_client_method()
#define DESTROY_TIMEOUT 10

static int do_ssl_connect( glb_ctx *cc, io_handler *io, struct timeval *timeout);
static int do_ssl_accept( glb_ctx *cc, io_handler *io, struct timeval *timeout);
#ifdef DEBUG
static void dbg_print_ssl_error(int errorcode);
#endif
int ssl_server_init(glb_ctx *cc)
{
    int err = 0;
    unsigned long ssl_err = 0;
    CANL_ERROR_ORIGIN e_orig = unknown_error;
    char *ca_cert_fn, *user_cert_fn, *user_key_fn, *user_proxy_fn;
    char *ca_cert_dirn = NULL;
    ca_cert_fn = user_cert_fn = user_key_fn = user_proxy_fn = NULL;

    if (!cc) {
	return EINVAL;
    }

    //OpenSSL_add_all_algorithms();
    //OpenSSL_add_all_ciphers();
    ERR_clear_error();

    cc->ssl_ctx = SSL_CTX_new(SSL_SERVER_METH);
    if (!cc->ssl_ctx){
        err = ERR_get_error();
        e_orig = ssl_error;
        goto end;
    }

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

    SSL_CTX_load_verify_locations(cc->ssl_ctx, ca_cert_fn, ca_cert_dirn);
    free(ca_cert_fn);
    ca_cert_fn = NULL;
    free(ca_cert_dirn);
    ca_cert_dirn = NULL;

    //err = SSL_CTX_set_cipher_list(cc->ssl_ctx, "ALL:!LOW:!EXP:!MD5:!MD2");
    err = SSL_CTX_set_cipher_list(cc->ssl_ctx, "ALL");
    if (!err) {
        ssl_err = ERR_get_error();
        set_error(cc, ssl_err, e_orig, "no cipher to use");
        return err;
    }
    err = 0;

    //SSL_CTX_set_purpose(cc->ssl_ctx, X509_PURPOSE_ANY);
    //SSL_CTX_set_mode(cc->ssl_ctx, SSL_MODE_AUTO_RETRY);
    // TODO proxy_verify_callback, verify_none only for testing !!!!!!!
    SSL_CTX_set_verify(cc->ssl_ctx, SSL_VERIFY_NONE, proxy_verify_callback);
    //SSL_CTX_set_verify_depth(ctx, 100);
    SSL_CTX_set_cert_verify_callback(cc->ssl_ctx, proxy_app_verify_callback, 0);
    if (cc->cert_key) {
        if (cc->cert_key->cert) {
            err = SSL_CTX_use_certificate(cc->ssl_ctx, cc->cert_key->cert);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
            else
                err = 0;
        }
        if (cc->cert_key->key) {
            err = SSL_CTX_use_PrivateKey(cc->ssl_ctx, cc->cert_key->key);
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
    if ( (err = SSL_CTX_check_private_key(cc->ssl_ctx)) != 1) {
        ssl_err = ERR_get_error();
        e_orig = ssl_error;
        set_error(cc, ssl_err, e_orig, "Private key does not match"
                " the certificate public key"); 
        return 1;
    }
    else
        err = 0;

end:
    if (ssl_err) {
        set_error(cc, ssl_err, e_orig, "Cannot initialize SSL context");
        return 1;
    }
    else if (err) {
        set_error(cc, err, e_orig, "Cannot initialize SSL context");
        return 1;
    }
    return 0;
}

int ssl_client_init(glb_ctx *cc, io_handler *io)
{
    unsigned long ssl_err = 0;
    int err = 0;
    CANL_ERROR_ORIGIN e_orig = unknown_error;
    char *ca_cert_fn, *user_cert_fn, *user_key_fn, *user_proxy_fn;
    char *ca_cert_dirn = NULL;
    ca_cert_fn = user_cert_fn = user_key_fn = user_proxy_fn = NULL;

    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        e_orig = posix_error;
        goto end;
    }

    //OpenSSL_add_all_algorithms();
    //OpenSSL_add_all_ciphers();
    ERR_clear_error();

    cc->ssl_ctx = SSL_CTX_new(SSL_CLIENT_METH);
    if (!cc->ssl_ctx){
        ssl_err = ERR_get_error();
        e_orig = ssl_error;
        goto end;
    }
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

    SSL_CTX_load_verify_locations(cc->ssl_ctx, ca_cert_fn, ca_cert_dirn);
    free(ca_cert_fn);
    ca_cert_fn = NULL;
    free(ca_cert_dirn);
    ca_cert_dirn = NULL;
    
    //err = SSL_CTX_set_cipher_list(cc->ssl_ctx, "ALL:!LOW:!EXP:!MD5:!MD2");
    err = SSL_CTX_set_cipher_list(cc->ssl_ctx, "ALL");
    if (!err) {
        ssl_err = ERR_get_error();
        set_error(cc, ssl_err, e_orig, "no cipher to use");
        return err;
    }
    err = 0;

    //SSL_CTX_set_options(cc->ssl_ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS | SSL_OP_NO_SSLv2);
    //TODO testing 
    SSL_CTX_set_verify(cc->ssl_ctx, SSL_VERIFY_NONE, proxy_verify_callback);
    //SSL_CTX_set_verify_depth(ctx, 100);
    //SSL_CTX_load_verify_locations(ctx, NULL, cacertdir);
    //SSL_CTX_set_purpose(cc->ssl_ctx, X509_PURPOSE_ANY);
    //SSL_CTX_set_mode(cc->ssl_ctx, SSL_MODE_AUTO_RETRY);


    if (cc->cert_key) {
        if (cc->cert_key->key) {
            err = SSL_CTX_use_PrivateKey(cc->ssl_ctx, cc->cert_key->key);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
        }
        else if (cc->cert_key->cert) {
            err = SSL_CTX_use_certificate(cc->ssl_ctx, cc->cert_key->cert);
            if (err != 1) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
                goto end;
            }
        }
    }

end:
    if (ssl_err) {
        set_error(cc, ssl_err, e_orig, "cannot initialize SSL context");
    return 1;
    }
    else if (err) {
        set_error(cc, err, e_orig, "cannot initialize SSL context");
    return 1;
    }
    return 0;
}

int ssl_connect(glb_ctx *cc, io_handler *io, struct timeval *timeout)
{
    int err = 0, flags;

    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }

    flags = fcntl(io->sock, F_GETFL, 0);
    (void)fcntl(io->sock, F_SETFL, flags | O_NONBLOCK);

    io->s_ctx->bio_conn = BIO_new_socket(io->sock, BIO_NOCLOSE);
    (void)BIO_set_nbio(io->s_ctx->bio_conn,1);

    io->s_ctx->ssl_io = SSL_new(cc->ssl_ctx);
    //setup_SSL_proxy_handler(cc->ssl_ctx, cacertdir);
    SSL_set_bio(io->s_ctx->ssl_io, io->s_ctx->bio_conn, io->s_ctx->bio_conn);

    io->s_ctx->bio_conn = NULL;

    err = do_ssl_connect(cc, io, timeout); 
    if (err) {
        goto end;
    }
    /*
       if (post_connection_check(io->s_ctx->ssl_io)) {
       opened = 1;
       (void)Send("0");
       return 1;
       }
     */

end:
    return err;
}

int ssl_accept(glb_ctx *cc, io_handler *io,
        struct timeval *timeout)
{
    int err = 0, flags;

    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }

    flags = fcntl(io->sock, F_GETFL, 0);
    (void)fcntl(io->sock, F_SETFL, flags | O_NONBLOCK);

    io->s_ctx->bio_conn = BIO_new_socket(io->sock, BIO_NOCLOSE);
    (void)BIO_set_nbio(io->s_ctx->bio_conn,1);

    io->s_ctx->ssl_io = SSL_new(cc->ssl_ctx);
    //setup_SSL_proxy_handler(cc->ssl_ctx, cacertdir);
    SSL_set_bio(io->s_ctx->ssl_io, io->s_ctx->bio_conn, 
            io->s_ctx->bio_conn);

    err = do_ssl_accept(cc, io, timeout);
        if (err) {
        goto end;
    }

    /*
       if (post_connection_check(io->s_ctx->ssl_io)) {
       opened = 1;
       (void)Send("0");
       return 1;
       }
     */

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

static int do_ssl_connect( glb_ctx *cc, io_handler *io, struct timeval *timeout)
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
            ret2 = SSL_connect(io->s_ctx->ssl_io);
            if (ret2 < 0) {
                ssl_err = ERR_get_error();
                e_orig = ssl_error;
            }
            expected = errorcode = SSL_get_error(io->s_ctx->ssl_io, ret2);
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

static int do_ssl_accept( glb_ctx *cc, io_handler *io, struct timeval *timeout)
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
            ret2 = SSL_accept(io->s_ctx->ssl_io);
            if (ret2 < 0) {
                ssl_err = ERR_peek_error();
                e_orig = ssl_error;
            }
            expected = errorcode = SSL_get_error(io->s_ctx->ssl_io, ret2);
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
int ssl_write(glb_ctx *cc, io_handler *io, void *buffer, size_t size, struct timeval *timeout)
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

    if (!io->s_ctx || !io->s_ctx->ssl_io) {
        set_error(cc, EINVAL, posix_error, "SSL not initialized");
        return -1;
    }
    
    fd = BIO_get_fd(SSL_get_rbio(io->s_ctx->ssl_io), NULL);
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
            ret = SSL_write(io->s_ctx->ssl_io, str + nwritten,
                    strlen(str) - nwritten);
            v = SSL_get_error(io->s_ctx->ssl_io, ret);

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

int ssl_read(glb_ctx *cc, io_handler *io, void *buffer, size_t size, struct timeval *tout)
{
    int err = 0;
    int ret = 0, nwritten=0, ret2 = 0;
    char *str;
    int fd = -1;
    time_t starttime, curtime;
    int expected = 0, error = 0;
    int timeout;

    if (!io->s_ctx || !io->s_ctx->ssl_io) {
        err = EINVAL;
        set_error(cc, err, posix_error, "wrong ssl handler"); 
        return -1;
    }

    fd = BIO_get_fd(SSL_get_rbio(io->s_ctx->ssl_io), NULL);
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
            ret2 = SSL_read(io->s_ctx->ssl_io, str + nwritten,
                    strlen(str) - nwritten);

            if (ret2 <= 0) {
                expected = error = SSL_get_error(io->s_ctx->ssl_io, ret2);
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
int ssl_close(glb_ctx *cc, io_handler *io)
{
    int timeout = DESTROY_TIMEOUT;
    time_t starttime, curtime;
    int expected = 0, error = 0, ret = 0, ret2 = 0;
    int fd;
    unsigned long ssl_err = 0;

    if (!io->s_ctx->ssl_io) {
        return 2;
    }

    fd = BIO_get_fd(SSL_get_rbio(io->s_ctx->ssl_io), NULL);
    curtime = starttime = time(NULL);
    
    /* check the shutdown state*/
    ret = SSL_get_shutdown(io->s_ctx->ssl_io);
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
	    ret2 = SSL_shutdown(io->s_ctx->ssl_io);
	    if (ret2 < 0) {
                ssl_err = ERR_peek_error();
		expected = error = SSL_get_error(io->s_ctx->ssl_io, ret2);
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
