#!/bin/bash

function usage() {
    echo "$0 [deploy | demo]"
}

function adjust_theme() {
    :
}

function reset_theme() {
    :
}

if [ $# -eq 1 ]; then

    adjust_theme

    if [ "$1" = "deploy" ]; then
        hugo -D

    elif [ "$1" = "demo" ]; then
        hugo server -D

    else
        usage $0
    fi

    reset_theme

else
    usage $0
fi
