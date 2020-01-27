#!/bin/bash
set -e
shopt -s extglob
shopt -s expand_aliases

. /etc/bashrc.swg

ORIG_URI="svn.finjan.com/orig"
NAME="frox"
VER="0.7.18"
SRCDIR="$NAME"
INST_ROOT="instroot"

CONF_OPTS="--enable-local-cache --enable-virus-scan --enable-ssl --enable-transparent-data --enable-ccp --enable-configfile=/etc/frox.conf --prefix=/tmp --enable-run-as-root --enable-libiptc"
    
CPPFLAGS="-D__EXPORTED_HEADERS__ -I${WASP_ROOT}/Proxy2/FTP_EXT_Plugin/"
CFLAGS=" -O2 -Wall -Werror -Wno-error=strict-aliasing -Wno-error=implicit-function-declaration"
LDFLAGS=-L${WASP_ROOT}/lib

FUNC="clean|configure|build"

function clean(){
    set +e
    echo "Running $FUNCNAME()"
    for dir in $INST_ROOT;do
        [ -d $dir ] && rm -rf $dir
    done 
    pushd $SRCDIR
    make clean
    pushd include
    for f in ipt_kernel_headers.h libiptc.h sstr.h stamp-h config.h;do
        [ -e $f ] && rm -v $f
    done
    popd
    for f in config.log config.status;do
        [ -e $f ] && rm -v $f
    done
    find ./ -name Makefile -delete
    popd
    set -e
}

function configure(){
    echo "Running $FUNCNAME()"
    pushd $SRCDIR
        echo "$CONF_OPTS"
        ./configure $CONF_OPTS CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" CFLAGS="$CFLAGS"
    popd
}

function build(){
    echo "Running $FUNCNAME()"
    pushd $SRCDIR
        echo "$CONF_OPTS"
        ./configure $CONF_OPTS CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" CFLAGS="$CFLAGS"
        make
    popd
}

function all(){
    echo "Running $FUNCNAME()"
    clean
    build
}

if [ $# == 0 ];then
    all
    exit 0
fi

for v in $*;do
    echo "Running $v"
    case $v in
        @($FUNC)) eval "$v";;
        *) echo "Error: unknown func $v";;
    esac
done

exit 0
