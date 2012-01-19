#!/usr/bin/perl

$err_name = "";

$num = 0;

print STDOUT qq (/*
 * Automatically generated file. Don't edit.
 */

typedef enum canl_error {);

while (<STDIN>) {
    chomp;
    next if /^\s*#/;
    printf ("\n    CANL_ERR_%s%s,",
	    $_,
	    (!$num++) ? " = 1024" : "");
}

print STDOUT qq (
} canl_error;
);
