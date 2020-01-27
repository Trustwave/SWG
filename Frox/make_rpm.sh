#!/bin/bash
set -e

NAME=frox
BUILD_LOG="$(pwd)/build.log"
DATEFORMAT="+%F-%H:%M:%S"

make_rpm(){
    echo "$(date $DATEFORMAT) -- Starting $FUNCNAME()" | tee -a $BUILD_LOG
    if [ -n "$PKG_VER" ];then
        VER=$(echo -n "$PKG_VER" | sed s'/~.*//')
        VERSION="pkg_version $VER"
    else
        VERSION="_place_holder 1"
    fi 
    rpmbuild --define "$VERSION" -bb ${NAME}.spec 2>&1 | tee -a $BUILD_LOG
}

all(){
    make_rpm
}

all
