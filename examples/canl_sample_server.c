#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#include <canl.h>
#include <canl_ssl.h>

#define BUF_LEN 1000
#define BACKLOG 10
#define DEF_PORT 4321
#define DEF_TIMEOUT 150

int main(int argc, char *argv[])
{
    canl_ctx my_ctx;
    canl_io_handler my_io_h = NULL;
    int err = 0;
    int opt, port = DEF_PORT;
    char *serv_cert = NULL;
    char *serv_key = NULL;
    char *ca_dir = NULL;
    char buf[BUF_LEN];
    int buf_len = 0;
    struct timeval timeout;
    canl_principal princ = NULL;
    int get_peer_princ = 0;
    int ocsp_on = 0;
    char *name = NULL;
    
    timeout.tv_sec = DEF_TIMEOUT;
    timeout.tv_usec = 0;


    while ((opt = getopt(argc, argv, "nhop:c:k:d:t:")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "Usage: %s [-p port] [-c certificate]"
                        " [-k private key] [-d ca_dir] [-h] "
                        "[-t timeout] [-n {print peer's princ name}] "
                        " [-o {turn OCSP on}] "
                        " \n", argv[0]);
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
            case 'd':
                ca_dir = optarg;
                break;
            case 't':
                timeout.tv_sec = atoi(optarg);
                break;
            case 'n':
                get_peer_princ = 1;
                break;
            case 'o':
                ocsp_on = 1;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-p port] [-c certificate]"
                        " [-k private key] [-d ca_dir] [-h] "
                        "[-t timeout] [-n {print peer's princ name}] "
                        " [-o {turn OCSP on}] "
                        " \n", argv[0]);
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
        printf("[SERVER] io handler cannot be created:\n[CANL] %s\n",
	       canl_get_error_message(my_ctx));
        goto end;
    }

    if (serv_cert || serv_key){
	err = canl_ctx_set_ssl_cred(my_ctx, serv_cert, serv_key, NULL, 
                                    NULL, NULL);
        if (err) {
            printf("[SERVER] cannot set certificate or key to"
                   " context:\n[CANL] %s\n",
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
    if (ocsp_on)
        canl_ctx_set_ssl_flags(my_ctx, CANL_SSL_OCSP_VERIFY_ALL);
    new_fd = accept(sockfd, &s_addr, &sin_size);
    if (new_fd == -1){
        printf("Failed to accept network connection: %s", strerror(errno));
    }

    /* canl_create_io_handler has to be called for my_io_h*/
    /* TODO timeout in this function? and select around it*/
    if (get_peer_princ) {
        err = canl_io_accept(my_ctx, my_io_h, new_fd, s_addr, 
                0, &princ, &timeout);
        if (err) {
            printf("[SERVER] connection cannot be established:\n[CANL] %s\n",
                    canl_get_error_message(my_ctx));
            goto end;
        }


        err = canl_princ_name(my_ctx, princ, &name);
        printf("[SERVER] connection established with %s\n", name);
        free(name);
        canl_princ_free(my_ctx, princ);
    }
    else{
        err = canl_io_accept(my_ctx, my_io_h, new_fd, s_addr, 
                0, NULL, &timeout);
        if (err) {
            printf("[SERVER] connection cannot be established:\n[CANL] %s\n",
                    canl_get_error_message(my_ctx));
            goto end;
        }
        printf("[SERVER] connection established\n");
    }

    strncpy(buf, "This is a testing message to send", sizeof(buf));
    buf_len = strlen(buf) + 1;

    printf("[SERVER] Trying to send sth to the client\n");
    err = canl_io_write (my_ctx, my_io_h, buf, buf_len, &timeout);
    if (err <= 0) {
        printf("[SERVER] cannot send message to the client:\n[CANL] %s\n",
	       canl_get_error_message(my_ctx));
        goto end;
    }
    else {
        buf[err] = '\0';
        printf("[SERVER] message \"%s\" sent successfully\n", buf);
    }

    buf[0] = '\0';
    err = canl_io_read (my_ctx, my_io_h, buf, sizeof(buf)-1, &timeout);
    if (err <= 0) {
	printf("[SERVER] Failed to receive reply from client:\n[CANL] %s\n",
	       canl_get_error_message(my_ctx));
	goto end;
    }

    buf[err] = '\0';
    printf ("[SERVER] received: %s\n", buf);
    err = 0;

end:
    if (my_io_h)
        canl_io_destroy(my_ctx, my_io_h);

    canl_free_ctx(my_ctx);

    return err;
}
