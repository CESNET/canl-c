#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "canl.h"

#define BUF_LEN 1000

int main(int argc, char *argv[])
{
    canl_ctx my_ctx;
    canl_io_handler my_io_h;
    int err = 0;
    char *err_msg = NULL;
    char buf[BUF_LEN];
    char *p_server = NULL;
    char *def_server = "www.linuxfoundation.org";
    int opt, port = 80;

    while ((opt = getopt(argc, argv, "hp:s:")) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stderr, "Usage: %s [-p port]" 
                        "[-s server] [-h] \n", argv[0]);
                break;
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

    err = canl_io_connect(my_ctx, my_io_h, p_server, port, 0, NULL, NULL);
    if (err) {
        printf("connection cannot be established\n");
        goto end;
    }

    err = canl_io_write (my_ctx, my_io_h, NULL, 0, NULL);
    if (err) {
        //set_error ("cannot write");
    }

    err = canl_io_read (my_ctx, my_io_h, buf, sizeof(buf)-1, NULL);
    if (err > 0) {
        buf[err] = '\0';
        printf ("received: %s\n", buf);
    }

    err = canl_io_close(my_ctx, my_io_h);
    if (err){
        //set_error ("cannot close io");
    }

    err = canl_io_destroy(my_ctx, my_io_h);
    if (err){
        //set_error ("cannot destroy io");
    }
    my_io_h = NULL;

end:
    canl_get_error(my_ctx, &err_msg);
    if (err_msg != NULL)
        printf("%s\n", err_msg);

    canl_free_ctx(my_ctx);

    return err;
}
