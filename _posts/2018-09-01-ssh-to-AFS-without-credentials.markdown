---
layout: post
tags: [AFS, DevOps, code]
title: SSH to Andrew File System (AFS) Without Credentials
cover: assets/images/posts/lawn.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---
This is the first part of a 2-part guide on how you can SSH to the Andrew File System without keying in your credentails, as well as mounting the Andrew File System (AFS) locally on your Linux machine. This is highly useful if you are a student or faculty member from one of the many universities around the world whose computing systems runs on AFS, such as CMU, MIT, Stanford, Caltech, to list a few. If you have long passwords and wish to open multiple SSH sessions (although you probably would want to check [tmux](https://www.ocf.berkeley.edu/~ckuehl/tmux/) out), this will come in useful. By mounting AFS locally, you no longer have to SSH in to edit, manage, or copy your files; everything can be done natively in your file explorer or via the command line.

### The Andrew File System
The AFS is a distributed file system that was developed in Carnegie Mellon University in the early 1980s, one of the first of its kind. Named after Andrew Carnegie and Andrew Mellon, the founders of the present-day Carnegie Mellon University, AFS was designed for scale, and introduced novel but now industry-standard techniques such as edge caching on the client to reduce bandwidth consumption by a single client. A quirk of AFS that may surprise people familiar with Unix-like operating
system environments is that AFS introduces its own AFS File Permissions that allows for more fine-grained access controls compared to traditional Unix file permission bits, which you can read more about [here](https://computing.cs.cmu.edu/help-support/afs-acls.html).

The following guide is tailored for Ubuntu as that is what most people would use, but I personally got it working on my Arch Linux machine and the steps should be similar for other Linux distributions as well, as well as OSX, but I have not tested this personally. Also, the user input for the cells and realms used is customized for CMU. Replace it accordingly with the information of your own school otherwise.

### Setting up Kerberos
Kerberos is what AFS uses for authentication. Before we mount AFS, we must ensure that we are authenticated with a Kerberos ticket with the server. To install the Kerberos client:

{% highlight shell %}
$ apt-get install krb5-user

------TRUNCATED OUTPUT------
------TRUNCATED OUTPUT------
------TRUNCATED OUTPUT------

Configuring Kerberos Authentication
-----------------------------------

When users attempt to use Kerberos and specify a principal or user name without specifying what administrative Kerberos realm that principal belongs to, the system appends the default realm.  The default realm may also be used as the realm of a Kerberos service running on the local machine.  Often, the default realm is the uppercase version of the local DNS domain.

Default Kerberos version 5 realm: andrew.cmu.edu   # Replace with your school's realm
{% endhighlight %}

After installing Kerberos, you are now ready to authenticate.

{% highlight bash %}
$ kinit <YOUR_USERNAME>   # i.e. kinit fzeng
Password for fzeng@ANDREW.CMU.EDU:
{% endhighlight %}

You can run `klist` to check the status of your tickets. Take note of their expiry date; in the case of CMU, it is valid for 24 hours and so you need to re-authenticate with Kerberos every 24 hours.

{% highlight shell %}
$ klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: fzeng@ANDREW.CMU.EDU

Valid starting     Expires            Service principal
09/30/18 04:49:17  10/01/18 04:49:15  krbtgt/ANDREW.CMU.EDU@ANDREW.CMU.EDU
{% endhighlight %}

### Setting up GSSAPI Authentication
Kerberos authentication requires GSSAPI (Generic Security Services Application Programming Interface). To set this up, in your `~/.ssh/config` file (create it if it does not exist), add

{% highlight bash %}
# Inside ~/.ssh/config
Host andrew   # Replace with name of your choice
  HostName linux.andrew.cmu.edu   # Replace with your school's timeshare server hostname
  User fzeng # Replace with your username
  GSSAPIAuthentication yes
  GSSAPIDelegateCredentials yes
{% endhighlight %}

### Trying it out
You should now be able to SSH to AFS without entering your credentials!

{% highlight shell %}
$ ssh andrew   # Replace with the Host name you defined in ~/.ssh/config
{% endhighlight %}

This concludes Part 1 of the tutorial. In Part 2 we will discuss how we can mount AFS locally with OpenAFS.
