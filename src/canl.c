#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "canl.h"
#include "canl_locl.h"
#include "sys/socket.h"
#include "string.h"

static void io_clean(canl_ctx cc, canl_io_handler io);

canl_ctx canl_create_ctx()
{
    glb_ctx *ctx = NULL;
    int err = 0;

    /*create context*/
    ctx = (glb_ctx *) malloc(sizeof(*ctx));
    if (!ctx) {
        err=1; //use errno instead
        //set_error(ctx);
        goto end;
    }

    /*openssl init. -check return value
      ssl_library_init();
      ssl_load_error_strings();
      canl_ctx->ssl_ctx->ssl_meth = ;//choose ssl method SSLv3_method();
      canl_ctx->ssl_ctx = SSL_CTX_new (canl_ctx->ssl_ct->ssl_meth)
     */

    /*initial values ...*/
    ctx->err_msg = NULL;
    ctx->err_code = no_error;
    ctx->opened_ios = 0;

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

    if (!cc) {
        goto end;
    }

    /*create io handler*/
    new_io_h = (io_handler *) malloc(sizeof(*new_io_h));
    if (!new_io_h)
        //set_error(ctx->err_msg);
        goto end;

    /*read cc and set io_handler accordingly ...*/
    new_io_h->ar = NULL;
    new_io_h->s_addr = NULL;
    new_io_h->sock = -1;

end:
    return new_io_h;
}

int canl_io_connect(canl_ctx cc, canl_io_handler io, char * host, int port, 
        int flags, cred_handler ch, struct timeval *timeout)
{
    int err = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int sock;
    struct sockaddr_in *sa_in = NULL;

    /*check cc and io*/
    if (!cc) {
        err = 1;
        goto end;
    }

    if (!io) {
        err = 1;
        goto end;
    }
    if (io_cc->ar) {
        free (io_cc->ar);
        io_cc->ar = NULL;
    }
    io_cc->ar = (asyn_result *) malloc(sizeof(*(io_cc->ar)));
    if (!io_cc->ar) {
        err = 1;
        goto end;
    }
    io_cc->ar->ent = (struct hostent *) calloc (1, sizeof(struct hostent));
    if (!io_cc->ar->ent) {
        err=1;
        goto end;
    }

    /*dns TODO - wrap it for using ipv6 and ipv4 at the same time*/
    err = asyn_getservbyname(AF_INET, io_cc->ar, host, NULL);
    if (err)
        goto end;
    
    io_cc->s_addr = (struct sockaddr *) malloc(sizeof(struct sockaddr));
    if (!io_cc->s_addr) {
        err = 1;
        goto end;
    }
    sa_in = (struct sockaddr_in *) io_cc->s_addr;
    

    /*open socket TODO just for testing purpose*/
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock != -1)
        io_cc->sock = sock;
    
    sa_in->sin_family = AF_INET;
    sa_in->sin_port = htons(port);
    //TODO loop through h_addr_list
    memcpy(&sa_in->sin_addr.s_addr, io_cc->ar->ent->h_addr, sizeof(struct in_addr));
    err = connect(io_cc->sock, (struct sockaddr*) sa_in, sizeof(*sa_in));

    /*call openssl */

    /*write succes or failure to cc, io*/
    //if (err)
    /*cc or io set error*/
    //else
    /*cc or io set succes*/
end:
    if (err) {
        io_clean(cc, io);
    }
    return err;
}

int canl_io_accept(canl_ctx cc, canl_io_handler io, int port,
        int flags, cred_handler ch, struct timeval *timeout, 
        canl_io_handler *new_io)
{
    int err;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;

    /*check cc and io*/
    if (!cc) {
        err = 1;
        goto end;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = 1;
        goto end;
    }
    /*check cc and io*/

    /*wait for client*/

    /*call openssl to make a secured connection, optional?*/

    /*write succes or failure to cc, io*/
    //if (err)
    /*cc or io set error*/
    //else
    /*cc or io set succes*/

end:
    return err;
}

//TODO improve
/* close connection, preserve some info for the future reuse */
int canl_io_close(canl_ctx cc, canl_io_handler io)
{
    int err = 0;
    /*check cc and io*/
    if (!cc) {
        err = 1;
        goto end;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = 1;
        goto end;
    }

    /*ssl close*/

    /*set cc and io accordingly*/

end:
    return err;
}
static void io_clean(canl_ctx cc, canl_io_handler io)
{
    io_handler *io_cc = (io_handler*) io;
    /*check cc and io*/
    if (!cc) {
        return;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        return;
    }

    // delete io_handle content
    if (io_cc->ar) {
        free_hostent(io_cc->ar->ent);
        io_cc->ar->ent = NULL;
        io_cc->ar = NULL;
    }
    if (io_cc->s_addr) {
        free (io_cc->s_addr);
        io_cc->s_addr = NULL;
    }
}

int canl_io_destroy(canl_ctx cc, canl_io_handler io)
{
    int err = 0;
    io_handler *io_cc = (io_handler*) io;
    /*check cc and io*/
    if (!cc) {
        err = 1;
        goto end;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = 1;
        goto end;
    }

    io_clean(cc, io);
    // delete io itself
    if (io_cc) {
        free (io_cc);
        io = NULL;
    }
end:
    return err;
}

size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    int err = 0;
    if (!cc) {
        err = 1;
        goto end;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = 1;
        goto end;
    }

    //TODO testing: read something without using openssl
    err = recv(io_cc->sock, buffer, size, 0);
end:
    return err;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    int err = 0;
    if (!cc) {
        err = 1;
        goto end;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = 1;
        goto end;
    }

    //TODO testing: read something without using openssl
    err = send(io_cc->sock, "Hello, world!", 13, 0);

end:
    return err;
}
