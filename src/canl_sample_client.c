#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "canl.h"

#define BUF_LEN 1000

int main(int argc, char *argv[])
{
    canl_ctx my_ctx;
    canl_io_handler my_io_h;
    int err = 0;
    char *err_msg = NULL;
    char buf[BUF_LEN];
    int buf_len = 0;
    char *p_server = NULL;
    char *def_server = "www.linuxfoundation.org";
    int opt, port = 80;
    struct timeval timeout;

    while ((opt = getopt(argc, argv, "hp:s:")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "Usage: %s [-p port]" 
                        "[-s server] [-h] \n", argv[0]);
                exit(0);
            case 'p':
                port = atoi(optarg);
                break;
            case 's':
                p_server = optarg;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-p port]" 
                        "[-s server] [-h] \n", argv[0]);
                exit(-1);
        }
    }

    if (!p_server)
        p_server = def_server;

    my_ctx = canl_create_ctx();
    if (!my_ctx){
        // set_error("context cannot be created\n");
        goto end;
    }

    my_io_h = canl_create_io_handler(my_ctx);
    if (!my_io_h) {
        //set_error("io handler cannot be created\n");
        goto end;
    }

   timeout.tv_sec = 150;
   timeout.tv_usec = 0;

    err = canl_io_connect(my_ctx, my_io_h, p_server, port, 0, NULL, &timeout);
    if (err) {
        printf("[CLIENT] connection to %s cannot be established: %s\n",
	       p_server, canl_get_error_message(my_ctx));
        goto end;
    }
    else {
        printf("[CLIENT] connection established\n");
    }

    strcpy(buf, "This is the testing message to send");
    buf_len = strlen(buf) + 1;

    printf("[CLIENT] Trying to send sth to the server\n");
    err = canl_io_write (my_ctx, my_io_h, buf, buf_len, &timeout);
    if (err <= 0) {
        printf("can't write using ssl\n");
        goto end;
    }
    else {
        buf[err] = '\0';
        printf("[CLIENT] message \"%s\" sent successfully\n", buf);
    }

    err = canl_io_read (my_ctx, my_io_h, buf, sizeof(buf)-1, &timeout);
    if (err > 0) {
        buf[err] = '\0';
        printf ("[CLIENT] received: %s\n", buf);
    }

    err = canl_io_close(my_ctx, my_io_h);
    if (err){
        printf("[CLIENT] Cannot close connection to server\n");
    }

    err = canl_io_destroy(my_ctx, my_io_h);
    if (err){
        printf("[CLIENT] Cannot destroy connection with server\n");
    }
    my_io_h = NULL;

end:
    canl_free_ctx(my_ctx);

    return err;
}
