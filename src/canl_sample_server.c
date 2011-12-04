#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "canl.h"

#define BUF_LEN 1000
static void print_error_from_canl(canl_ctx cc);

int main(int argc, char *argv[])
{
    canl_ctx my_ctx;
    canl_io_handler my_io_h;
    canl_io_handler my_new_io_h;
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
                break;
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

    my_io_h = canl_create_io_handler(my_ctx);
    if (!my_io_h) {
        printf("[SERVER] io handler cannot be created\n");
        goto end;
    }

    my_new_io_h = canl_create_io_handler(my_ctx);
    if (!my_new_io_h) {
        printf("[SERVER] io handler cannot be created\n");
        goto end;
    }

    if (serv_cert || serv_key){
        err = canl_set_ctx_own_cert_file(my_ctx, serv_cert, serv_key, 
                NULL, NULL);
        if (err) {
            printf("[SERVER] cannot set certificate or key to context\n");
            goto end;
        }
    }

    timeout.tv_sec = 150;
    timeout.tv_usec = 0;

    /* canl_create_io_handler has to be called for my_new_io_h and my_io_h*/
    /* TODO timeout in this function?*/
    err = canl_io_accept(my_ctx, my_io_h, port, 0, NULL, &timeout, &my_new_io_h);
    if (err) {
        printf("[SERVER] connection cannot be established\n");
        goto end;
    }
    else {
        printf("[SERVER] connection established\n");
    }

    strcpy(buf, "This is the testing message to send");
    buf_len = strlen(buf) + 1;

    printf("[SERVER] Trying to send sth to the client\n");
    err = canl_io_write (my_ctx, my_new_io_h, buf, buf_len, &timeout);
    if (err <= 0) {
        printf("[SERVER] cannot send message to the client\n");
        goto end;
    }
    else {
        buf[err] = '\0';
        printf("[SERVER] message \"%s\" sent successfully\n", buf);
    }

    err = canl_io_read (my_ctx, my_new_io_h, buf, sizeof(buf)-1, NULL);
    if (err > 0) {
        buf[err] = '\0';
        printf ("[SERVER] received: %s\n", buf);
    }
    else
        printf("[SERVER] nothing received from client\n");

end:
    print_error_from_canl(my_ctx);

    if (my_new_io_h) {
        err = canl_io_close(my_ctx, my_new_io_h);
        if (err){
            printf("[SERVER] Cannot close connection\n");
            print_error_from_canl(my_ctx);
        }
    }

    if (my_new_io_h) {
        err = canl_io_destroy(my_ctx, my_new_io_h);
        if (err){
            printf("[SERVER] Cannot destroy connection\n");
            print_error_from_canl(my_ctx);
        }
        my_new_io_h = NULL;
    }

    if (my_io_h) {
        err = canl_io_close(my_ctx, my_io_h);
        if (err){
            printf("[SERVER] Cannot close connection\n");
            print_error_from_canl(my_ctx);
        }
    }

    if (my_io_h) {
        err = canl_io_destroy(my_ctx, my_io_h);
        if (err){
            printf("[SERVER] Cannot destroy connection\n");
            print_error_from_canl(my_ctx);
        }
        my_io_h = NULL;
    }

    canl_free_ctx(my_ctx);

    return err;
}

static void print_error_from_canl(canl_ctx cc)
{
    char *reason = NULL;
    canl_get_error(cc, &reason);
    if (reason != NULL) {
        printf("%s\n", reason);
        free (reason);
        reason = NULL;
    }
}
