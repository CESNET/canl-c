#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "canl_locl.h"
#include "sys/socket.h"
#include "string.h"

#define BACKLOG 10 //TODO just for testing - max incoming connections

static int  io_clear(glb_ctx *cc, io_handler *io);
static int init_io_content(glb_ctx *cc, io_handler *io);
canl_ctx canl_create_ctx()
{
    glb_ctx *ctx = NULL;
    int err = 0;

    /*create context*/
    ctx = (glb_ctx *) malloc(sizeof(*ctx));
    if (!ctx) {
        err = ENOMEM;
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
    glb_ctx *g_cc = cc;
    int err = 0;

    if (!g_cc) {
        err = EINVAL;
        return NULL;
    }

    /*create io handler*/
    new_io_h = (io_handler *) malloc(sizeof(*new_io_h));
    if (!new_io_h){
        err = ENOMEM;
        return NULL;
    }

    /*read cc and set io_handler accordingly ...*/
    new_io_h->ar = NULL;
    new_io_h->s_addr = NULL;
    new_io_h->sock = -1;

    /* allocate memory and initialize io content*/
    if ((err = init_io_content(g_cc ,new_io_h))){
        goto end;
    }

end:
    if (err) {
        update_error(g_cc,"cannot create canl_io_handler"
                "canl_create_io_handler");
        if ((err = canl_io_destroy(cc, (canl_io_handler)new_io_h)))
            update_error(g_cc, "cannot destroy canl_ctx"
                    "canl_create_io_handler");
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

    io->ar = (asyn_result *) calloc(1, sizeof(*(io->ar)));
    if (!io->ar) {
        err = ENOMEM;
        goto end;
    }

    io->ar->ent = (struct hostent *) calloc(1, sizeof(struct hostent));
    if (!io->ar->ent) {
        err = ENOMEM;
        goto end;
    }

    io->s_addr = (struct sockaddr *) calloc(1, sizeof(struct sockaddr));
    if (!io->s_addr) {
        err = ENOMEM;
        goto end;
    }

    io->s_ctx = (ossl_ctx *) calloc(1, sizeof(*(io->s_ctx)));
    if (!io->s_ctx) {
        err = ENOMEM;
        goto end;
    }

end:
    if (err)
        update_error(cc, "failed to initialize io_handler"
                "(init_io_content)");
    return err;
}

int canl_io_connect(canl_ctx cc, canl_io_handler io, char * host, int port, 
        int flags, cred_handler ch, struct timeval *timeout)
{
    int err = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int sock;
    struct sockaddr_in *sa_in = NULL;
    int i = 0;
    int err_clear = 0;

    /*check cc and io*/
    if (!glb_cc) {
        return EINVAL;
    }

    if (!io_cc || !io_cc->ar || !io_cc->ar->ent || !io_cc->s_addr) {
        err = EINVAL;
        goto end;
    }

    /*dns TODO - wrap it for using ipv6 and ipv4 at the same time*/

    switch (err = asyn_getservbyname(AF_INET, io_cc->ar, host, NULL)) {
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

    sa_in = (struct sockaddr_in *) io_cc->s_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock != -1)
        io_cc->sock = sock;
    else {
        err = errno;
        goto end;
    }

    sa_in->sin_family = AF_INET;
    sa_in->sin_port = htons(port);

    i = 0;
    while (io_cc->ar->ent->h_addr_list[i])
    {
        memcpy(&sa_in->sin_addr.s_addr, io_cc->ar->ent->h_addr_list[i], 
                sizeof(struct in_addr));
        err = connect(io_cc->sock, (struct sockaddr*) sa_in, sizeof(*sa_in));
        if (err) 
            err = errno;
        else
            break; //success
        i++;
    }

    /*call openssl */
    err = ssl_init(glb_cc, io_cc);
    if (err)
        goto end;
    err = ssl_connect(glb_cc, io_cc, timeout); //TODO timeout
    
    /*write succes or failure to cc, io*/
    //if (err)
    /*cc or io set error*/
    //else
    /*cc or io set succes*/
end:
    if (err) {
        update_error(cc, "failed to connect (canl_io_connect)");
        if ((err_clear = io_clear(glb_cc, io_cc)))
            update_error(cc, "failed to clean io_handler"
                   " (canl_io_connect)");
    }
    return err;
}

int canl_io_accept(canl_ctx cc, canl_io_handler io, int port,
        int flags, cred_handler ch, struct timeval *timeout, 
        canl_io_handler *new_io)
{
    int err = 0, sockfd = 0, new_fd = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    io_handler **io_new_cc = (io_handler**) new_io;

    struct addrinfo hints, *servinfo, *p;
    socklen_t sin_size;
    int yes=1;
    char * PORT = "4321"; //TODO for testing purposes only

    /*check cc and io*/
    if (!glb_cc) 
        return -1;

    if (!io_cc || !io_cc->ar || !io_cc->ar->ent || !io_cc->s_addr) {
        err = EINVAL;
        goto end;
    }
    if (!*io_new_cc || !(*io_new_cc)->ar || !(*io_new_cc)->ar->ent 
            || !(*io_new_cc)->s_addr) {
        err = EINVAL;
        goto end;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((err = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        update_error(glb_cc, "getaddrinfo: %s\n", gai_strerror(err));
        /*TODO what kind of error return?, getaddrinfo returns its own 
          error codes*/
        goto end;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                        p->ai_protocol)) == -1) {
            // set err? no
            err = errno;
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                    sizeof(int)) == -1) {
            err = errno;
            freeaddrinfo(servinfo); // all done with this structure
            return -1;
        }
        if ((err = bind(sockfd, p->ai_addr, p->ai_addrlen))) {
            close(sockfd);
            err = errno;
            continue;
        }
        break;
    }

    if (p == NULL) {
        update_error(glb_cc, "failed to bind (canl_io_accept)"); //TODO is it there?????
        freeaddrinfo(servinfo); // all done with this structure
        goto end;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if ((err = listen(sockfd, BACKLOG))) {
        err = errno;
        goto end;
    }

    /*wait for client*/
    printf("server: waiting for connections...\n");
    sin_size = sizeof((*io_new_cc)->s_addr);
    new_fd = accept(sockfd, (*io_new_cc)->s_addr, &sin_size);
    if (new_fd == -1){
        err = errno;
        goto end;
    }
    else
        (*io_new_cc)->sock = new_fd;
    /* TODO everything fine - set new_io_cc according to their_addr*/

    /*call openssl */
    err = ssl_init(glb_cc, *io_new_cc);
    if (err)
        goto end;
    err = ssl_accept(glb_cc, io_cc, (*io_new_cc), timeout); 

end:
    if (err)
        update_error(glb_cc, "cannot accept connection (canl_io_accept)");
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
        return EINVAL;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = EINVAL;
        goto end;
    }

    /*ssl close*/

    /*set cc and io accordingly*/

end:
    if (err)
        update_error(glb_cc, "cannot close connection (canl_io_close)");
    return err;
}
static int io_clear(glb_ctx *cc, io_handler *io)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;
    /*check cc and io*/
    if (!cc) {
        return EINVAL;
    }

    if (!io) {
        err = EINVAL;
        goto end;
    }

    // delete io_handler content
    if (io_cc->ar) {
        if (io_cc->ar->ent)
            free_hostent(io_cc->ar->ent);
        io_cc->ar->ent = NULL;
        free (io_cc->ar);
        io_cc->ar = NULL;
    }
    if (io_cc->s_addr) {
        free (io_cc->s_addr);
        io_cc->s_addr = NULL;
    }

end:
    if (err)
        update_error(glb_cc, "cannot clear io_handle (io_clear)");
    return err;

}

int canl_io_destroy(canl_ctx cc, canl_io_handler io)
{
    int err = 0;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    io_handler *io_cc = (io_handler*) io;
    /*check cc and io*/
    if (!cc) {
        return EINVAL;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = EINVAL;
        goto end;
    }

    err = io_clear(glb_cc, io_cc);
    if (err)
        goto end;
    // delete io itself
    if (io_cc) {
        free (io_cc);
        io = NULL;
    }
end:
    if (err)
        update_error(glb_cc, "can't destroy io_handle (canl_io_destroy)");
    return err;
}

size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;
    int b_recvd = 0;
    errno = 0;
    
    if (!cc) {
        return -1;
    }

    if (!io) {
        //set_error(ctx->err_msg);
        err = EINVAL;
        goto end;
    }
    
    if (!buffer || !size) {
        err = EINVAL;
        update_error(glb_cc, "no memory to write into (canl_io_read)");
        return -1;
    }

    //read something using openssl
    b_recvd = ssl_read(glb_cc, io_cc, buffer, size, timeout);
    if (b_recvd == -1) {
        err = errno; //TODO check again
        goto end;
    }
end:
    if (err)
        update_error(glb_cc, "can't read from connection"
                " (canl_io_read)");
    return b_recvd;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_written = 0;
    int err = 0;
    errno = 0;

    if (!cc) {
        return -1;
    }

    if (!io) {
        err = EINVAL;
        goto end;
    }

    if (!buffer || !size) {
        err = EINVAL;
        update_error(glb_cc, "nothing to write (canl_io_write)");
        return -1;
    }

    //write something using openssl
    b_written = ssl_write(glb_cc, io_cc, buffer, size, timeout);
    if (b_written == -1) {
        err = errno; //TODO check again
        goto end;
    }

end:
    if (err) {
        update_error(glb_cc, "can't write to connection"
                " (canl_io_write)");
        return -1;
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
        set_error(glb_cc, EINVAL, posix_error, "invalid parameter value"
               " (canl_set_ctx_own_cert)");
        return err;
    }

    err = do_set_ctx_own_cert(glb_cc, cert, chain, key);
    if(err) {
        update_error(glb_cc, "can't set cert or key to context"
                " (canl_set_ctx_own_cert)");
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
        set_error(glb_cc, EINVAL, posix_error, "invalid parameter value"
               " (canl_set_ctx_own_cert_file)");
        return EINVAL;
    }

    err = do_set_ctx_own_cert_file(glb_cc, cert, key);
    if(err) {
        update_error(glb_cc, "can't set cert or key to context"
                " (canl_set_ctx_own_cert_file)");
    }
        return err;
}
