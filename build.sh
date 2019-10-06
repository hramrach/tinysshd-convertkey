#!/usr/bin/env bash

#  This file is governed by Licenses which are listed in
#  the LICENSE file, which shall be included in all copies
#  and redistributions of this project.

name='tinysshd-convertkey'

say() { X=$1; Y=$2; shift 2; printf "\e[1m$X\e[0m  $Y\n" "$@"; }
err() { >&2 say 'ERR!' "$1"; exit 1; }

say 'BUILDING ...' 'running build process with autotools ..'

say '\nAUTORECONF' 'create necessary files ..'
autoreconf --force --verbose --install || err 'autoreconf failed!'

say '\nCONFIGURE' 'create Makefile ..'
./configure || err './configure failed!'

say '\nMAKE' 'building %s ..' "$name"
make clean "$name" || err 'make failed!'

say '\nSUCCESS!' 'Compiled file is saved in: %s\nYou can install with something like: $ sudo make install' "./${name}"
