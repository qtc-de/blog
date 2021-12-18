#!/bin/bash


#############################
#       Setup Hugo          #
#############################
echo "[+] Installing hugo."

pacman -Qi hugo &>/dev/null

if [ $? -ne 0 ]; then

    set -x
    sudo pacman -S hugo
    set +x
    pacman -Qi hugo &>/dev/null

    if [ $? -ne 0 ]; then
        echo "[-] Unable to install hugo."
        exit 1
    fi
fi

set -e
hugo new site blog -f yml


#############################
#   Initlaize Git + Theme   #
#############################
echo "[+] Initializing theme."
cd blog
git init
git submodule add --depth=1 -- https://github.com/adityatelange/hugo-PaperMod.git themes/PaperMod
git submodule update --init --recursive
cd ..


#############################
#      Copy Resources       #
#############################
echo "[+] Copying resources."
cp resources/config.yml blog/config.yml
cp -r resources/img blog/static
cp -r resources/content/* blog/content

echo "[+] Blog is ready!"
