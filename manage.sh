#!/bin/bash

function usage() {
    echo "$0 [deploy | demo]"
}

function adjust_theme() {

    # center figure captions
    echo -e "figcaption {\n  text-align: center;\n}" > ./themes/PaperMod/assets/css/extended/figure.css

    # add autonumbering for articles (credits to https://codingnconcepts.com/hugo/auto-number-headings-hugo/)
    sed -i '3d' ./themes/PaperMod/layouts/_default/single.html
    sed -i '3i<article class="post-single {{- if .Param "autonumbering" }} autonumbering {{- end }}">' \
    ./themes/PaperMod/layouts/_default/single.html

    cat <<EOF > ./themes/PaperMod/assets/css/extended/autonumbering.css
body{counter-reset: h2}
h2{counter-reset: h3 0 figcaption 0}
h3{counter-reset: h4}
h4{counter-reset: h5}

article.autonumbering h2:before {counter-increment: h2; content: counter(h2) ". "; }
article.autonumbering h3:before {counter-increment: h3; content: counter(h2) "." counter(h3) ". "; }
article.autonumbering h4:before {counter-increment: h4; content: counter(h2) "." counter(h3) "." counter(h4) ". "; }
article.autonumbering h5:before {counter-increment: h5; content: counter(h2) "." counter(h3) "." counter(h4) "." counter(h5) ". "; }

article.autonumbering div.toc ul { counter-reset: item; }
article.autonumbering div.toc li a:before { content: counters(item, ".") ". "; counter-increment: item; }

article.autonumbering figcaption:before {counter-increment: figcaption; content: "Fig. " counter(h2) "." counter(figcaption) ". - "; }
EOF
}

function reset_theme() {
    sed -i '3d' ./themes/PaperMod/layouts/_default/single.html
    sed -i '3i<article class="post-single">' \
    ./themes/PaperMod/layouts/_default/single.html
    rm ./themes/PaperMod/assets/css/extended/figure.css \
       ./themes/PaperMod/assets/css/extended/autonumbering.css
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
