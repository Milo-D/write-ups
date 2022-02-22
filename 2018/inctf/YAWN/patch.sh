#!/bin/bash

#
# patching the challenge binary, so that
# it runs with libc 2.23 and ld 2.23
#

ln -s libc-2.23.so libc.so.6
ln -s ld-2.23.so ld.so.2

patchelf --set-rpath . program
patchelf --set-interpreter ld.so.2 program