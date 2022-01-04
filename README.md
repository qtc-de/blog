### qtc's Personal Blog

----

This repository contains all files required to setup my personal blog. Instead of
creating a private repository for this purpose, I decided to make the repository
public, which allows everyone to contribute to this blog. If you have any suggestions,
feel free to create an issue or pull request. The deployed version of the blog can be
found over here:

[https://blog.tneitzel.eu/](https://blog.tneitzel.eu/)


### Demo and Deploy

----

To launch or deploy the blog in it's intended form, you should use the ``manage.sh`` script.
The script contains two hooks that are run during start and stop of the script. These hooks
can be used to apply theme modifications that are not part of our [PaperMod fork](https://github.com/qtc-de/hugo-PaperMod)
yet. The applied modifications change from time to time and may be empty.

To start the demo version of the blog run:

```console
$ ./manage.sh demo
```

To create a deployment run:

```console
$ ./manage.sh deploy
```

### Articles

----

Currently, the following articles are available:

* [Attacking Java RMI via SSRF](https://blog.tneitzel.eu/posts/01-attacking-java-rmi-via-ssrf/)


### Acknowledgements

----

This blog is powered by [hugo](https://github.com/gohugoio/hugo) and the [hugo-PaperMod](
https://github.com/adityatelange/hugo-PaperMod) theme. Credits also go to my colleague
[Konstantin](https://twitter.com/kwnypwny) who inspired me to create this blog and to
Ashish Lahoti for [his explanation](https://codingnconcepts.com/hugo/auto-number-headings-hugo/)
on how to implement auto numbered headings using CSS.
