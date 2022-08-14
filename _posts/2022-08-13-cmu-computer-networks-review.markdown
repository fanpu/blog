---
title: "CMU 15-441/641 Computer Networks Course Details and Review"
layout: post
tags: [course-review, general]
cover: assets/images/posts/mojave_national_preserve.avif
class: post-template
navigation: True
author: fanpu
toc: true
published: true
---

Computer Networks is one of the lesser-known systems classes at Carnegie Mellon
that turned out to be surprisingly fun and transformative.  It is quite
different from any of the other systems classes that I have taken, which usually
swing between either being very micro-level such as OS (15-410) where a lot of
emphasis is on concurrency and the things happening at the hardware/software
interface, or macro-level such as Distributed Systems (15-440) where you care
about things like distributed cache consistency and permisionless distributed
consensus protocols.

On the other hand, in Computer Networks, you are thrusted into the bizzare
situation of having to contend with algorithms and protocols that evolved from
many historical different considerations.

First, you have the usual culprit of historical short-sightedness (or shall we say, the disappointing lack of ability to predict the future). Imagine spending hours mulling over packet fragmentation

considerations of historical developments, commercial interests, regulation, 

## Projects

### Project 1: A Web Server Called Liso

The first project project involved writing a HTTP web server in `C` using the
Berkeley Sockets API that serves content from a `www` directory, including
dynamic `CGI` scripts. The implementation details were largely unspecified, we
were instead directed to refer to the specifications for HTTP 1.1 outlined in
[RFC 2616](http://www.ietf.org/rfc/rfc2616.txt) and to make our best judgement
based on that. Given the finite length of the RFC but the infinite weird
requests that users can come up to mess with your web server, a lot of care must
be taken to guard against edge cases. This was the first time that I have really
tried to read an RFC and I actually found it very well-organized.

### Project 2: TCP in the Wild
The second project was my favorite, and it involved implementing TCP on top of
UDP with the Reno congestion control protocol together with a partner.  This was
followed by an analysis into how the protocol can be improved by performing data
transfer between a client and server using our TCP stack, and then using
`tcpdump` to perform packet capture and generate network I/O graphs. We
performed close analysis on the TCP sawtooth patterns on these graphs, so as to
come up with our own TCP congestion control protocol that has to non-trivially
improve on both throughout and Jain's Faireness Index (for fairness when
multiple connections connect on the same link) as compared to TCP Reno.

{% include image.html file="/assets/images/posts/tcp_reno_state_diagram.avif"
description="TCP Reno Congestion Control State Diagram" %}

An interesting thing that happened was that I actually found a race condition
bug in the autograder for this project. When we went from the first checkpoint
that checked for the implementation of the TCP three-way handshake and RTT
estimation to the second checkpoint that required the implementation of the rest
of the TCP state diagram, we began to fail a few very basic tests. The
autograder claimed that we did not complete a TCP handshakes after a `SYN`
packet was sent by the client. This completely puzzled me as our TCP
implementation was able to complete the handshakes on many of the other
occassions and proceed with multiple file transfers followed by teardown, and we
should not have any regressions from the first checkpoint. I performed a lot of
manual testing with 

### Project 3: Video Delivery

The final project comprises two independent portions: writing an adaptive
bitrate proxy, and writing a load balancer. We had the option to only complete
the adaptive bitrate proxy if we are working individually, or otherwise do both
if we work in pairs. Almost everyone in the class opted to do the first project
solo. Since I had already written load balancers twice, once for 15-319 Cloud
Computing and once for 15-440 Distributed Systems, I also chose to just do the
first project.

#### Adaptive Bitrate Proxy

For the 



## Other courses at CMU
This post is written as part of a collection of posts to help shed light on some
of CMU's less well-known classes that I found interesting and useful, in hopes
of encouraging more people to consider taking them.