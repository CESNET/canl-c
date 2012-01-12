#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <canl.h>

#define BUF_LEN 1000
#define BACKLOG 10

int main(int argc, char *argv[])
{
    canl_ctx my_ctx;
    canl_io_handler my_io_h = NULL;
    int err = 0;
    int opt, port = 4321;
    char *serv_cert = NULL;
    char *serv_key = NULL;
    char buf[BUF_LEN];
    int buf_len = 0;
    struct timeval timeout;

    while ((opt = getopt(argc, argv, "hp:c:k:")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "Usage: %s [-p port] [-c certificate]"
                        " [-k private key] [-h] \n", argv[0]);
                exit(0);
            case 'p':
                port = atoi(optarg);
                break;
            case 'c':
                serv_cert = optarg;
                break;
            case 'k':
                serv_key = optarg;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-p port] [-c certificate]"
                        " [-k private key] [-h] \n", argv[0]);
                exit(-1);
        }
    }

    my_ctx = canl_create_ctx();
    if (!my_ctx){
        printf("[SERVER] canl context cannot be created\n");
        return -1;
    }

    err = canl_create_io_handler(my_ctx, &my_io_h);
    if (err) {
        printf("[SERVER] io handler cannot be created: %s\n",
	       canl_get_error_message(my_ctx));
        goto end;
    }

    if (serv_cert || serv_key){
        err = canl_set_ctx_own_cert_file(my_ctx, serv_cert, serv_key, 
                NULL, NULL);
        if (err) {
            printf("[SERVER] cannot set certificate or key to context: %s\n",
		   canl_get_error_message(my_ctx));
            goto end;
        }
    }

    /* ACCEPT from canl_io_accept*/
    int sockfd = 0, new_fd = 0;
    char str_port[8];
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr s_addr;
    socklen_t sin_size;
    int yes=1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if (snprintf(str_port, 8, "%d", port) < 0) {
        printf ("[SERVER] Wrong port request");
        return 1;
    }

    /* XXX timeouts - use c-ares, too */
    if ((err = getaddrinfo(NULL, str_port, &hints, &servinfo)) != 0) {
        printf("[SERVER] getaddrinfo: %s\n", gai_strerror(err));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                        p->ai_protocol)) == -1) {
            err = errno;
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                    sizeof(int)) == -1) {
            err = errno;
	    continue;
        }
        if ((err = bind(sockfd, p->ai_addr, p->ai_addrlen))) {
            err = errno;
            close(sockfd);
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
	/* Beware that only the last error is displayed here ... */
        printf("Failed to acquire a server socket: %s\n",
	       strerror(err));
        return 1;
    }

    printf("server: waiting for connections...\n");
    sin_size = sizeof(s_addr);
    new_fd = accept(sockfd, &s_addr, &sin_size);
    if (new_fd == -1){
        printf("Failed to accept network connection: %s", strerror(errno));
    }

    timeout.tv_sec = 150;
    timeout.tv_usec = 0;

    /* canl_create_io_handler has to be called for my_io_h*/
    /* TODO timeout in this function? and select around it*/
    err = canl_io_accept(my_ctx, my_io_h, new_fd, s_addr, 0, NULL, &timeout);
    if (err) {
        printf("[SERVER] connection cannot be established: %s\n",
	       canl_get_error_message(my_ctx));
        goto end;
    }
    printf("[SERVER] connection established\n");

    strncpy(buf, "This is a testing message to send", sizeof(buf));
    buf_len = strlen(buf) + 1;

    printf("[SERVER] Trying to send sth to the client\n");
    err = canl_io_write (my_ctx, my_io_h, buf, buf_len, &timeout);
    if (err <= 0) {
        printf("[SERVER] cannot send message to the client: %s\n",
	       canl_get_error_message(my_ctx));
        goto end;
    }
    else {
        buf[err] = '\0';
        printf("[SERVER] message \"%s\" sent successfully\n", buf);
    }

    err = canl_io_read (my_ctx, my_io_h, buf, sizeof(buf)-1, NULL);
    if (err <= 0) {
	printf("[SERVER] Failed to receive reply from client: %s\n",
	       canl_get_error_message(my_ctx));
	goto end;
    }

    buf[err] = '\0';
    printf ("[SERVER] received: %s\n", buf);
    err = 0;

end:
    if (my_io_h)
        err = canl_io_destroy(my_ctx, my_io_h);

    canl_free_ctx(my_ctx);

    return err;
}
