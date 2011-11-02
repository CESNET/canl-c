#include <stdio.h>
#include <stdlib.h>
#include "canl.h"
#include "canl_locl.h"

canl_ctx canl_create_ctx()
{
    struct glb_ctx *new_ctx = NULL;
    int err = 0;
    
    /*create context*/
    new_ctx = (struct glb_ctx *) malloc(sizeof(*new_ctx));
    if (!new_ctx) {
	err=1; //use errno instead
        //set_error(ctx->err_msg);
	goto end;
    }

    /*openssl init. -check return value
      ssl_library_init();
      ssl_load_error_strings();
      canl_ctx->ssl_ctx->ssl_meth = ;//choose ssl method SSLv3_method();
      canl_ctx->ssl_ctx = SSL_CTX_new (canl_ctx->ssl_ct->ssl_meth)
     */

    /*initial values ...*/
    new_ctx->io_ctx = NULL;
    new_ctx->err_msg = NULL;
end:
    if (err)
        return NULL;
    else
        return new_ctx;
}

void canl_free_ctx(canl_ctx cc)
{
    struct glb_ctx *ctx = (struct glb_ctx*) cc;

    if (!cc) {
        goto end;
    }


    /*delete content*/
    if (ctx->io_ctx) {
	canl_io_destroy(ctx, ctx->io_ctx);
	ctx->io_ctx = NULL;
    }

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
    struct io_handler *new_io_h = NULL;

    if (!cc) {
	goto end;
    }

    /*create io handler*/
    new_io_h = (struct io_handler *) malloc(sizeof(*new_io_h));
    if (!new_io_h)
        //set_error(ctx->err_msg);
	goto end;

    /*read cc and set io_handler accordingly ...*/

end:
    return new_io_h;
}

int canl_io_connect(canl_ctx cc, canl_io_handler io, char * host, int port, 
                    int flags, cred_handler ch, struct timeval *timeout)
{
    int err;
    struct io_handler *io_cc = (struct io_handler*) io;
    struct glb_ctx *glb_cc = (struct glb_ctx*) cc;

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

    /*dns*/
    //err = dns_resolve(&ret_addr, ipver, host, port, timeout);

    /*open socket*/

    /*call openssl to make a secured connection, optional?*/

    /*write succes or failure to cc, io*/
    //if (err)
	/*cc or io set error*/
    //else
	/*cc or io set succes*/
end:
    return err;
}

int canl_io_accept(canl_ctx cc, canl_io_handler io, int port,
                   int flags, cred_handler ch, struct timeval *timeout, 
                   canl_io_handler *new_io)
{
    int err;
    struct io_handler *io_cc = (struct io_handler*) io;
    struct glb_ctx *glb_cc = (struct glb_ctx*) cc;

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

int canl_io_destroy(canl_ctx cc, canl_io_handler io)
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
    }

    // delete io_handle content
    
    // delete io itself
    if (io) {
	free (io);
	io = NULL;
    }
end:
    return err;
}

size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
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

    //read something using openssl

end:
    return err;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    int err;
    if (!cc) {
        err = 1;
	goto end;
    }

    if (!io) {
        //set_error(ctx->err_msg);
	err = 1;
	goto end;
    }

    //write sometring using openssl

end:
    return err;
}

/* what about reason pointer? */
size_t canl_io_get_error(canl_ctx cc, char ** reason)
{
    int err = 0;
    if (!cc) {
        err = 1;
        goto end;
    }

    struct glb_ctx *my_ctx = (struct glb_ctx*) cc;
    *reason = my_ctx->err_msg;

end:
    return err;
}
