#!/usr/bin/perl

my $codes_file = $ARGV[0];
my $desc_file = $ARGV[1];

my %codes;
my $err_name, $err_dsc, $openssl_err_lib, $openssl_err_reason;

sub make_c_line
{
    my ($err_name, $err_dsc, $openssl_err_lib, $openssl_err_reason) = @_;

    printf("\n    { CANL_ERR_%s, \"%s\", %s, %s },",
	   $err_name, $err_dsc,
	   ($openssl_err_lib) ? $openssl_err_lib : "ERR_LIB_NONE",
	   ($openssl_err_reason) ? $openssl_err_reason : 0);
}

die ("Usage: $0 <codes> <description>") if (!$codes_file || !$desc_file);

open (ERRS, $codes_file) or die ("Failed to open $codes_file: $!");
while (<ERRS>) {
    chomp;
    next if /^\s*#/;
    $codes{$_} = 1;
}
close (ERRS);

print qq (/*
 * Automatically generated file. Don't edit.
 */

#include "canl_locl.h"
#include "canl_mech_ssl.h"

canl_err_desc canl_err_descs[] = {);

open (DESC, $desc_file) or die ("Failed to open $desc_file: $!");
while (<DESC>) {
    chomp;
    next if /^\s*#/;

    $line = $_;
    if (!$line) {
	make_c_line($err_name, $err_dsc, $openssl_err_lib, $openssl_err_reason)
	    if ($err_name);
	$err_name = $err_dsc = $openssl_err_lib = $openssl_err_reason = "";
	next;
    }

    if (!$err_name) {
	($err_name, $err_dsc) = split(/=/, $line, 2);
	defined($codes{$err_name}) or die("Unknown error code ('$err_name') read");
	next;
    }

    if ($line =~ m/(.+)\.openssl_code=(.+),(.+)/) {
	($name, $openssl_err_lib, $openssl_err_reason) = ($1,$2,$3);
	die ("Parsing error (\"$line\")") if ($name != $err_name);
	next;
    }
}
close (DESC);

make_c_line ($err_name, $err_dsc, $openssl_err_lib, $openssl_err_reason)
    if ($err_name);

print STDOUT qq (
};

int canl_err_descs_num = sizeof(canl_err_descs)/sizeof(*canl_err_descs);
);
