#!/usr/bin/perl

$err_name = "";

print STDOUT qq (
/* Automatically generated file. Don't edit. */

typedef enum _CANL_ERROR {);

while (<STDIN>) {
    chomp;

    next if /^\s*#/;

    printf ("\n    EMI_Err_%s,", $_);
}

print STDOUT qq (
} CANL_ERROR;
);
