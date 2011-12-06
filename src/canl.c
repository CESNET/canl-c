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
    struct sockaddr_in *sa_in = NULL;
    int i = 0;

    if (!glb_cc) {
        return EINVAL;
    }

    if (!io_cc || !io_cc->ar || !io_cc->ar->ent || !io_cc->s_addr)
	return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

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

    if (err)
	/* XXX add error msg from ares */
	return set_error(cc, err, posix_error,
	                 "Cannot resolve the server hostname (%s)", host);

    sa_in = (struct sockaddr_in *) io_cc->s_addr;

    io_cc->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (io_cc->sock == -1)
	return set_error(cc, err, posix_error, "Failed to create socket: %s",
			 strerror(err));

    sa_in->sin_family = AF_INET;
    sa_in->sin_port = htons(port);

    i = 0;
    /* XXX can the list be empty? */
    while (io_cc->ar->ent->h_addr_list[i])
    {
        memcpy(&sa_in->sin_addr.s_addr, io_cc->ar->ent->h_addr_list[i], 
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
int canl_io_accept(canl_ctx cc, canl_io_handler io, int port,
        int flags, cred_handler ch, struct timeval *timeout, 
        canl_io_handler *new_io)
{
    int err = 0, sockfd = 0, new_fd = 0;
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    io_handler **io_new_cc = (io_handler**) new_io;
    char str_port[8];
    struct addrinfo hints, *servinfo, *p;
    socklen_t sin_size;
    int yes=1;

    if (!glb_cc) 
        return EINVAL; /* XXX Should rather be a CANL error */

    if (!io_cc || !io_cc->ar || !io_cc->ar->ent || !io_cc->s_addr)
	return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    /* XXX perhaps remove entirely from the API ? */
    if (!*io_new_cc || !(*io_new_cc)->ar || !(*io_new_cc)->ar->ent 
            || !(*io_new_cc)->s_addr) {
        err = EINVAL;
        goto end;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if (snprintf(str_port, 8, "%d", port) < 0)
	return set_error(cc, EINVAL, posix_error, "Wrong port requested (%d)", port);

    /* XXX timeouts - use c-ares, too */
    if ((err = getaddrinfo(NULL, str_port, &hints, &servinfo)) != 0) {
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
	if ((err = listen(sockfd, BACKLOG))) {
	    close(sockfd);
	    err = errno;
	    continue;
    }


        break;
    }

    freeaddrinfo(servinfo); // all done with this structure
    if (p == NULL) {
	return set_error(glb_cc, -1, unknown_error,
			 "Failed to acquire a server socket");
    }

#ifdef DEBUG
    printf("server: waiting for connections...\n");
#endif
    sin_size = sizeof((*io_new_cc)->s_addr);
    new_fd = accept(sockfd, (*io_new_cc)->s_addr, &sin_size);
    if (new_fd == -1){
	return set_error(glb_cc, errno, posix_error,
			 "Failed to accept network connection: %s",
			 strerror(errno));
    }
    (*io_new_cc)->sock = new_fd;

    err = ssl_server_init(glb_cc, *io_new_cc);
    if (err)
        goto end;

    err = ssl_accept(glb_cc, io_cc, (*io_new_cc), timeout); 
    if (err)
	goto end;

    err = 0;

end:
    if (err)
        (*io_new_cc)->sock = 0;

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
        err = EINVAL;
        set_error(glb_cc, err, posix_error,  "invalid io handler"
                " canl_io_close)");
        return err;
    }

    return err;

    /*ssl close*/

    /*set cc and io accordingly*/
}
static void io_destroy(glb_ctx *cc, io_handler *io)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int err = 0;

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
    if (io_cc->sock) {
        close (io_cc->sock);
        io_cc->sock = 0;
    }
    if (io_cc->s_ctx) {
        /*TODO maybe new function because of BIO_free and SSL_free*/
        if (io_cc->s_ctx->ssl_io) {
            SSL_free(io_cc->s_ctx->ssl_io);
            io_cc->s_ctx->ssl_io = NULL;
        }
        if (io_cc->s_ctx->bio_conn) {
            err = BIO_free(io_cc->s_ctx->bio_conn);
            /* TODO check it?
            if (!err) {
                ssl_err = ERR_peek_error();
                set_error(io_cc, err, ssl_error, "cannot free BIO"
                       " (io_destroy)");
                err = 1;
            } */
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
        return EINVAL;
    }

    if (!io_cc) {
        err = EINVAL;
        set_error(glb_cc, err, posix_error,  "invalid io handler"
                " canl_io_destroy)");
        return err;
    }

    err = ssl_close(glb_cc, io_cc);
    if (err <= 0)
        return err;

    io_destroy(glb_cc, io_cc);
    // delete io itself
    if (io_cc) {
        free (io_cc);
        io_cc = NULL;
    }

    return err;
}

size_t canl_io_read(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_recvd = 0;
    
    if (!cc)
        return EINVAL; /* XXX Should rather be a CANL error */

    if (!io)
	 return set_error(cc, EINVAL, posix_error, "IO handler not initialized");
    
    if (!buffer || !size)
	return set_error(cc, EINVAL, posix_error, "No memory to write into");

    //read something using openssl
    b_recvd = ssl_read(glb_cc, io_cc, buffer, size, timeout);
    if (b_recvd <= 0) {
    update_error(glb_cc, "can't read from connection"
            " (canl_io_read)");
    }
    return b_recvd;
}

size_t canl_io_write(canl_ctx cc, canl_io_handler io, void *buffer, size_t size, struct timeval *timeout)
{
    io_handler *io_cc = (io_handler*) io;
    glb_ctx *glb_cc = (glb_ctx*) cc;
    int b_written = 0;

    if (!cc)
        return EINVAL; /* XXX Should rather be a CANL error */

    if (!io)
	return set_error(cc, EINVAL, posix_error, "IO handler not initialized");

    if (!buffer || !size)
	return set_error(cc, EINVAL, posix_error, "No memory to write into");

    //write something using openssl
    b_written = ssl_write(glb_cc, io_cc, buffer, size, timeout);
    if (b_written <= 0) {
        update_error(glb_cc, "can't write to connection"
                " (canl_io_write)");
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
