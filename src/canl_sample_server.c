#include <stdio.h>
#include "canl.h"

int main()
{
    canl_ctx my_ctx;
    canl_io_handler my_io_h;
    int err = 0;
    char *err_msg = NULL;

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

    err = canl_io_accept(my_ctx, my_io_h, 1234, 0, NULL, NULL, NULL);
    if (err) {
        //set_error("cannot make a connection");
        goto end;
    }

    err = canl_io_connect(my_ctx, my_io_h, NULL, 1234, 0, NULL, NULL);
    if (err) {
	//set_error("cannot make a connection");
	canl_io_destroy(my_ctx, my_io_h);
	goto end;
    }

    err = canl_io_write (my_ctx, my_io_h, NULL, 0, NULL);
    if (err) {
	//set_error ("cannot write");
    }
 
    err = canl_io_read (my_ctx, my_io_h, NULL, 0, NULL);
    if (err) {
	//set_error ("cannot read");
    }

    err = canl_io_close(my_ctx, my_io_h);
    if (err){
	//set_error ("cannot close io");
    }

    err = canl_io_destroy(my_ctx, my_io_h);
    if (err){
	//set_error ("cannot destroy io");
    }

end:
    canl_io_get_error(my_ctx, &err_msg);
    if (err_msg != NULL)
        printf("%s\n", err_msg);
    
    canl_free_ctx(my_ctx);

    return err;
}
