### qtc's Personal Blog

----

This repository contains all files required to setup my personal blog. Instead of
creating a private repository for this purpose, I decided to make the repository
public, which allows everyone to contribute to this blog. If you have any suggestions,
feel free to create an issue or pull request.


### Demo and Deploy

----

To launch or deploy the blog in it's intended form, you should use the ``manage.sh`` script.
This script applies a small theme adjustment before the actual demo or deployment is started.
This is required because the theme is included as a submodule within this repository and
direct changes are not possible.

To start the demo version of the blog run:

```console
$ ./manage.sh demo
```

To create a deployment run:

```console
$ ./manage.sh deploy
```


### Acknowledgements

----

This blog is powered by [hugo](https://github.com/gohugoio/hugo) and the [hugo-PaperMod](
https://github.com/adityatelange/hugo-PaperMod) theme. Credits also go to my colleague
[Konstantin](https://twitter.com/kwnypwny) who inspired me to create this blog.
