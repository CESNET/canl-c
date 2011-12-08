#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "canl_locl.h"
#include "sys/socket.h"
#include "string.h"

#define BACKLOG 10 //TODO just for testing - max incoming connections

static void io_destroy(glb_ctx *cc, io_handler *io);
static int init_io_content(glb_ctx *cc, io_handler *io);
canl_ctx canl_create_ctx()
{
    glb_ctx *ctx = NULL;
    int err = 0;

    /*create context*/
    ctx = (glb_ctx *) calloc(1, sizeof(*ctx));
    if (!ctx) {
        err = ENOMEM;
        goto end;
    }

end:
    if (err)
        return NULL;
    else
        return ctx;
}

void canl_free_ctx(canl_ctx cc)
{
    glb_ctx *ctx = (glb_ctx*) cc;

    if (!cc) {
        goto end;
    }


    /*delete content*/

    if (ctx->err_msg) {
        free(ctx->err_msg);
        ctx->err_msg = NULL;
    }

    free(ctx);
    cc = ctx = NULL;

end:
    return;

}

canl_io_handler canl_create_io_handler(canl_ctx cc)
{
    io_handler *new_io_h = NULL;
    glb_ctx *g_cc = cc;
    int err = 0;

    if (!g_cc) {
        err = EINVAL;
        return NULL;
    }

    /*create io handler*/
    new_io_h = (io_handler *) calloc(1, sizeof(*new_io_h));
    if (!new_io_h){
        err = ENOMEM;
        return NULL;
    }

    /* allocate memory and initialize io content*/
    if ((err = init_io_content(g_cc ,new_io_h))){
        goto end;
    }

    SSL_library_init();
    SSL_load_error_strings();

end:
    if (err) {
        update_error(g_cc,"cannot create canl_io_handler");
        if ((err = canl_io_destroy(cc, (canl_io_handler)new_io_h)))
            update_error(g_cc, "cannot destroy canl_ctx");
        new_io_h = NULL;
    }
    return new_io_h;
}

static int init_io_content(glb_ctx *cc, io_handler *io)
{
    int err = 0;
    if (!cc) {
        return EINVAL;
    }
    if (!io) {
        err = EINVAL;
        goto end;
    }

    io->s_ctx = (ossl_ctx *) calloc(1, sizeof(*(io->s_ctx)));
    if (!io->s_ctx) {
        err = ENOMEM;
        goto end;
    }

    io->sock = -1;

end:
    if (err)
        update_error(cc, "failed to initialize io_handler");
    return err;
}

int canl_io_connect(canl_ctx cc, canl_io_handler io, char * host, int port, 
        int flags, cred_handler ch, struct timeval *timeout)
{
    int err = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    struct sockaddr_in *sa_in = NULL;
    struct sockaddr s_addr;
    struct _asyn_result ar;
    int i = 0;

    memset(&ar, 0, sizeof(ar));
    memset(&s_addr, 0, sizeof(s_addr));

    if (!glb_cc) {
        return EINVAL;
    }

    if (!io_cc)
        return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    /*dns TODO - wrap it for using ipv6 and ipv4 at the same time*/

    switch (err = asyn_getservbyname(AF_INET, &ar, host, NULL)) {
        case NETDB_SUCCESS:
            err = 0;
            break;
        case TRY_AGAIN:
            err = ETIMEDOUT;
            goto end;
        case NETDB_INTERNAL:
            err = EHOSTUNREACH; //TODO check
            goto end;
        default:
            err = EHOSTUNREACH; //TODO check
            goto end;
    }

    if (err)
        /* XXX add error msg from ares */
        return set_error(cc, err, posix_error,
                "Cannot resolve the server hostname (%s)", host);

    sa_in = (struct sockaddr_in *) &s_addr;

    io_cc->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (io_cc->sock == -1)
        return set_error(cc, err, posix_error, "Failed to create socket: %s",
                strerror(err));

    sa_in->sin_family = AF_INET;
    sa_in->sin_port = htons(port);

    i = 0;
    /* XXX can the list be empty? */
    while (ar.ent->h_addr_list[i])
    {
        memcpy(&sa_in->sin_addr.s_addr, ar.ent->h_addr_list[i], 
                sizeof(struct in_addr));
        /* XXX timeouts missing */
        err = connect(io_cc->sock, (struct sockaddr*) sa_in, sizeof(*sa_in));
        if (err) 
            err = errno;
        else
            break; //success
        i++;
    }

    if (err)
        return set_error(cc, ECONNREFUSED, posix_error,
                "Failed to make network connection to server %s", host);

    err = ssl_client_init(glb_cc, io_cc);
    if (err)
        goto end;

    err = ssl_connect(glb_cc, io_cc, timeout); //TODO timeout
    if (err)
        goto end;

    /*write succes or failure to cc, io*/
    //if (err)
    /*cc or io set error*/
    //else
    /*cc or io set succes*/
    err = 0;

end:
    return err;
}

/*TODO select + timeout, EINTR!!! */ 
int canl_io_accept(canl_ctx cc, canl_io_handler io, int new_fd,
        struct sockaddr s_addr, int flags, cred_handler ch, 
        struct timeval *timeout)
{
    int err = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;

    if (!glb_cc) 
        return EINVAL; /* XXX Should rather be a CANL error */

    if (!io_cc)
        return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    io_cc->sock = new_fd;

    err = ssl_server_init(glb_cc);
    if (err)
        goto end;

    err = ssl_accept(glb_cc, io_cc, timeout); 
    if (err)
	goto end;

    err = 0;

end:
    if (err)
        (io_cc)->sock = -1;

    return err;
}

//TODO improve
/* close connection, preserve some info for the future reuse */
int canl_io_close(canl_ctx cc, canl_io_handler io)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;
    /*check cc and io*/
    if (!cc) {
        return EINVAL; /* XXX Should rather be a CANL error */
    }

    if (!io)
	return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    err = ssl_close(glb_cc, io_cc);
    if (err <= 0)
        return err;

    if (io_cc->sock != -1) {
        close (io_cc->sock);
        io_cc->sock = -1;
    }

    return err;

    /*set cc and io accordingly*/
}

static void io_destroy(glb_ctx *cc, io_handler *io)
{
    io_handler *io_cc = (io_handler*) io;
    int err = 0;

    if (io_cc->s_ctx) {
        /*TODO maybe new function because of BIO_free and SSL_free*/
        if (io_cc->s_ctx->ssl_io) {
            SSL_free(io_cc->s_ctx->ssl_io);
            io_cc->s_ctx->ssl_io = NULL;
        }
        if (io_cc->s_ctx->bio_conn) {
            err = BIO_free(io_cc->s_ctx->bio_conn);
            io_cc->s_ctx->bio_conn = NULL;
        }
    }
    free (io_cc->s_ctx);
    io_cc->s_ctx = NULL;
}

int canl_io_destroy(canl_ctx cc, canl_io_handler io)
{
    int err = 0;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    io_handler *io_cc = (io_handler*) io;
    /*check cc and io*/

    if (!glb_cc) {
        return EINVAL; /* XXX Should rather be a CANL error */
    }

    if (!io_cc)
	return set_error(glb_cc, EINVAL, posix_error,  "Invalid io handler");

    canl_io_close(cc, io);

    io_destroy(glb_cc, io_cc);
    free (io_cc);

    return err;
}

size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_recvd = 0;
    
    if (!cc)
        return -1;

    if (!io) {
	 set_error(cc, EINVAL, posix_error, "IO handler not initialized");
	 return -1;
    }
    
    if (!buffer || !size) {
	set_error(cc, EINVAL, posix_error, "No memory to write into");
	return -1;
    }

    b_recvd = ssl_read(glb_cc, io_cc, buffer, size, timeout);
    if (b_recvd <= 0) {
	update_error(glb_cc, "Can't read from connection");
    }
    return b_recvd;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_written = 0;

    if (!cc)
        return -1;

    if (!io) {
	set_error(cc, EINVAL, posix_error, "IO handler not initialized");
	return -1;
    }

    if (!buffer || !size) {
	set_error(cc, EINVAL, posix_error, "No memory to read from");
	return -1;
    }

    b_written = ssl_write(glb_cc, io_cc, buffer, size, timeout);
    if (b_written <= 0) {
        update_error(glb_cc, "Can't write to connection");
    }
    return b_written;
}

int canl_set_ctx_own_cert(canl_ctx cc, canl_x509 cert, 
        canl_stack_of_x509 chain, canl_pkey key)
{
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;

    if (!cc)
        return EINVAL;
    if(!cert) {
        set_error(glb_cc, EINVAL, posix_error, "invalid parameter value");
        return err;
    }

    err = do_set_ctx_own_cert(glb_cc, cert, chain, key);
    if(err) {
        update_error(glb_cc, "can't set cert or key to context");
    }
        return err;
}

//TODO callback and userdata process
int canl_set_ctx_own_cert_file(canl_ctx cc, char *cert, char *key,
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
        update_error(glb_cc, "can't set cert or key to context");
    }
        return err;
}
