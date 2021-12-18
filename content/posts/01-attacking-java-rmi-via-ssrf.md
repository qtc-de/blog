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

If you ever implemented something yourself using *Java RMI*, you probably
doubt that the protocol can be targeted by an *SSRF* attack. For those who
never used *RMI* in practice, here is a short example how a typical *RMI*
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

Despite ``ref`` is an object created in your local *JVM*, calls on this object
are forwarded to the *RMI* server. This demonstrates that *Java RMI* uses an *object
oriented RPC* mechanism, where local objects are used to consume remote services.
This *object oriented RPC* implementation creates the impression of a strong coupling
between the local objects and the remote service and makes *SSRF* attacks seem impossible. 
But this is not the case as the *RMI protocol* is, like *HTTP*, a stateless protocol and
there is only a loosely coupling between local objects and remote services. But we go ahead
of ourselves and should start with the *RMI registry*.

#### The RMI Registry

The *RMI registry* is a naming service that is often used to make *RMI* services available
on the network. In order to connect to an *RMI* service, clients usually need a certain
amount of information:

* The IP address and TCP port the service is available on
* The class / interface that is implemented by the *RMI* service
* The ``ObjID`` of the remote object that implements the service

All this information is stored within the *RMI registry*  and can be accessed under a human readable
name (*boundname*). In the example above, we looked up the human readable name *remote-service*
from the *RMI registry* and obtained an object that contains all required information to use the
*RMI* service.

An important detail is now, that the *RMI registry* is an *RMI service* itself. However, in contrast
to the ``RemoteService`` *RMI service* from the example above, the *RMI registry* is a well known
*RMI service*. This means, that the implemented class and the assigned ``ObjID`` are fixed and known
by each *RMI client*. Hence, to communicate with the *RMI registry*, only the IP address and the
TCP port are required. This makes the *RMI registry* a more easy target for *SSRF* attacks and we should
discuss it first before going over to non well known *RMI services*.

#### The Java RMI Protocol

Whether or not the *RMI registry* can now be targeted by *SSRF* attacks depends on the structure of the
*RMI* protocol. In the following graphic I tried to visualize how a typical *RMI* communication looks like:

![Java RMI Protocol](/img/01-rmi-ssrf/02-java-rmi-protocol.png)

The typical *RMI* communication consists out of a *handshake* and one or more *method calls*. During the
*handshake*, some static data and information on the server and client host are exchanged. It is worth noting
that none of the exchanged information depends on previously received information. Therefore, it is possible
to predict all values that are used in the handshake, which will be important when performing *SSRF* attacks.

After the *handshake* completed, the client can start to dispatch method calls. It is generally possible
to dispatch multiple method calls in one communication channel, but apart from reducing the amount of
network traffic, it does not has any benefits. As mentioned previously, the *RMI* protocol is stateless and
it makes no difference whether multiple calls are dispatched in one or within multiple communication channels.

From the *SSRF* perspective, the handshake part of the *RMI* protocol looks problematic. *SSRF* vulnerabilities
usually only allow a one shot kind of attack and interactive communication like a handshake is usually not possible.
In the case of *Java RMI* however, the handshake does not matter, since *Java RMI* reads data one by one from
the underlying *TCP* stream. This allows the client to send all required data right at the beginning without waiting
for any server responses. The following diagram shows the *RMI* protocol again, but this time how it would be
utilized during an *SSRF* attack:

![Java RMI Protocol During SSRF](/img/01-rmi-ssrf/03-java-rmi-protocol-ssrf.png)

Another problem we have not talked about so far are data types. It should be obvious that a basic *HTTP* based
*SSRF* vulnerability cannot be utilized to perform *SSRF* attacks on *RMI* services. Already the first few bytes
(*RMI Magic*) would cause an corrupted stream and lead to an error on the *RMI* service. Instead, you need to be
able to send arbitrary bytes to the target *RMI service*, which is a common restriction. Especially null bytes need
to be allowed, which causes problems even with *gopher* based *SSRF* attacks on newer curl versions \[[1](https://www.digeex.de/blog/tinytinyrss/)\].
However, if this condition is met and you can send arbitrary data to the *RMI* service, you can dispatch
calls as usual.

#### SSRF Attacks on Java RMI Registry Endpoints

To demonstrate the *SSRFibility* of *Java RMI* we will now attack an *RMI registry* endpoint using an *SSRF* vulnerability.
In order to make this as comfortable as possible, we use remote-method-guesser \[[2](https://github.com/qtc-de/remote-method-guesser)\],
a *Java RMI* vulnerability scanner with integrated *SSRF* support. The *remote-method-guesser* repository also contains
an *SSRF* example server \[[3](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)\]
that we can use for demonstration purposes. The setup we use for the following demonstration looks like this:

* *HTTP* service vulnerable to *SSRF* on ``172.17.0.2:8000``
* *RMI registry* listening on ``localhost:1090`` on the remote server
* Outdated Java version that is vulnerable to *RMI registry* deserialization bypasses
* ``CommonsCollections3.1`` being available on the *RMI* application's classpath


### References

----

* \[1\] [Exploiting Tiny Tiny RSS](https://www.digeex.de/blog/tinytinyrss/)
* \[2\] [remote-method-guesser (GitHub)](https://github.com/qtc-de/remote-method-guesser)
* \[3\] [ssrf-example-server (GitHub)](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg-ssrf-server)
