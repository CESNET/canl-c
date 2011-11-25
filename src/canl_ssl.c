#include "canl_locl.h"

static int do_ssl_connect( glb_ctx *cc, io_handler *io, struct timeval *timeout);

int ssl_init(glb_ctx *cc, io_handler *io)
{
    int err = 0;

    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }

    SSL_load_error_strings();
    SSL_library_init();

    io->s_ctx->ssl_meth = SSLv23_method();
    io->s_ctx->ssl_ctx = SSL_CTX_new(io->s_ctx->ssl_meth);
    if (!io->s_ctx->ssl_ctx){
        err = 1; //TODO set appropriate
        update_error(cc, err, "cannot create SSL context (ssl_init)");
            goto end;
    }

end:
    if (err)
        update_error(cc, err, ""); //TODO update error
    return err;

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

    io->s_ctx->ssl_io = SSL_new(io->s_ctx->ssl_ctx);
    //setup_SSL_proxy_handler(io->s_ctx->ssl_ctx, cacertdir);
    SSL_set_bio(io->s_ctx->ssl_io, io->s_ctx->bio_conn, io->s_ctx->bio_conn);

    io->s_ctx->bio_conn = NULL; //TODO ???? 

    if ((err = do_ssl_connect(cc, io, timeout))) {
        update_error(cc, err, ""); //TODO update error
        goto end;
    }

    /*
       if (post_connection_check(io->s_ctx->ssl_io)) {
       opened = true;
       (void)Send("0");
       return true;
       }
     */

end:
    if (err)
        update_error(cc, err, ""); //TODO update error
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
    fd_set rset;
    fd_set wset;

    FD_ZERO(&rset);
    FD_ZERO(&wset);

    if (wanted == 0 || wanted == SSL_ERROR_WANT_READ)
        FD_SET(fd, &rset);
    if (wanted == 0 || wanted == SSL_ERROR_WANT_WRITE)
        FD_SET(fd, &wset);

    int ret = 0;

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
    int ret = -1, ret2 = -1, err = 0;
    long errorcode = 0;
    int expected = 0;
    int locl_timeout = -1;

    /* do not take tv_usec into account in this function*/
    if (timeout)
        locl_timeout = timeout->tv_sec;
    else
        locl_timeout = -1;
    curtime = starttime = time(NULL);

    do {
        ret = do_select(io->sock, starttime, locl_timeout, expected);
        if (ret > 0) {
            ret2 = SSL_connect(io->s_ctx->ssl_io);
            expected = errorcode = SSL_get_error(io->s_ctx->ssl_io, ret2);
        }
        curtime = time(NULL);
    } while (TEST_SELECT(ret, ret2, locl_timeout, curtime, starttime, errorcode));

    //TODO split ret2 and ret into 2 ifs to set approp. error message
    if (ret2 <= 0 || ret <= 0) {
        if (timeout && (curtime - starttime >= locl_timeout)){
            timeout->tv_sec=0;
            timeout->tv_usec=0;
            err = ETIMEDOUT; 
            update_error (cc, err, "Connection stuck during handshake: timeout reached (do_ssl_connect)");
        }
        else{
            err = -1; //TODO set approp. error message
            update_error (cc, err, "Error during SSL handshake (do_ssl_connect)");
        }
        return err;
    }

    return 0;
}

/* this function has to return # bytes written or ret < 0 when sth went wrong*/
int ssl_write(glb_ctx *cc, io_handler *io, void *buffer, size_t size, struct timeval *timeout)
{
    int err = 0;
    int ret = 0, nwritten=0;
    const char *str;
    int fd; 
    time_t starttime, curtime;
    int do_continue = 0;
    int expected = 0;
    int locl_timeout;
    int tout = 0;

    if (!io->s_ctx->ssl_io) {
        err = EINVAL;
        goto end;
    }

    if (!cc) {
        return -1;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }

    if (!buffer) {
        err = EINVAL; //TODO really?
        update_error(cc, err, "Nothing to write (ssl_write)");
        errno = err;
        return -1;
    }
    
    fd = BIO_get_fd(SSL_get_rbio(io->s_ctx->ssl_io), NULL);
    str = buffer;//TODO !!!!!! text.c_str();

    curtime = starttime = time(NULL);
    if (timeout) {
        locl_timeout = timeout->tv_sec;
    }
    else
        locl_timeout = -1;

    do {
        ret = do_select(fd, starttime, locl_timeout, expected);

        do_continue = 0;
        if (ret > 0) {
            int v;
            errno = 0;
            ret = SSL_write(io->s_ctx->ssl_io, str + nwritten, strlen(str) - nwritten);
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
        locl_timeout = locl_timeout - (curtime - starttime);
        if (locl_timeout != -1 && locl_timeout <= 0){
            tout = 1;
            goto end;
        }
    } while (ret <= 0 && do_continue);

end:
    if (err) {
        errno = err;
        update_error (cc, err, "Error during SSL write (ssl_write)");
        return -1;
    }
    if (tout){
       errno = err = ETIMEDOUT;
       update_error(cc, err, "Connection stuck during write: timeout reached (ssl_write)");
       return -1;
    }
    if (ret <=0){
        err = -1;//TODO what to assign??????
        update_error (cc, err, "Error during SSL write (ssl_write)");
    }
    return ret;
}
