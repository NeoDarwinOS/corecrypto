#! /usr/bin/perl

# COPYRIGHT (C) 2026, SAMUEL ZORMEISTER - SPDX-License-Identifier: MPL-2.0

#
# HOW TO USE:
#
#   aesvs_generator.pl /path/to/rsp /path/to/newheader
#

# This is a fat todo, and I'm not on my 'Mac' to test anything. I'll update this in the future - sam

my ($input, $output) = @ARGV;

if (not defined $input) {
  die "No input specified...\n";
} else if (not defined $output) {
  die "No output specified...\n";
}

