#!/bin/bash

function usage() {
    echo "$0 [deploy | demo]"
}

function adjust_theme() {
    sed -i '3i \ \ \ \ {{ partial "social_icons.html" $.Site.Params.socialIcons }}' \
    ./themes/PaperMod/layouts/partials/footer.html
}

function reset_theme() {
    sed -i '3d' ./themes/PaperMod/layouts/partials/footer.html
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
