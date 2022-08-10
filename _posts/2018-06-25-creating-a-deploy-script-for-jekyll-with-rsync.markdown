---
layout: post
tags: [DevOps, code]
cover: assets/images/posts/rsync.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---
Static site generators like [Jekyll](https://jekyllrb.com) makes it easy to write and build static websites. However, this still comes with the problem of a suitable deployment method. I will share about my thought process and the best approach I found for tackling this problem.

### Initial Idea: Build Docker image on successful CircleCI build and deploy
> Simplicity: 1/5
>
> Ease of use: 5/5
>
> Maintainability: 2/5

Having read a bit on DevOps best practices for continuous deployment, my first idea was to add [CircleCI](https://circleci.com/) integration to Github (where the code for this [blog](https://github.com/fanpu/blog) is hosted), and configure it to build the site into a Docker image when it passes a series of sanity checks (since there is almost no point running/writing tests for a static site). There will be a post-build hook for the server hosting my blog to fetch the latest image for my blog and to serve
that latest build. Of course, using Docker also means that I will have to dig into NGINX and `proxy_pass` the requests to the container. I will also need to configure the container to autorestart in the event the server goes down.

To anyone this probably seems like overkill and rightly so. I was bringing production DevOps concepts (i.e continuous deployment, immutable deploys, zero-downtime) onto the table without any strong justifications. To further complicate things I found out that CircleCI just updated to 2.0, which has very different syntax from 1.0, meaning that most guides are obsolete. Having so many moving parts also increases the chances of failure, making it a hassle to maintain. The only pros to this approach
is that if setup correctly, deploying will be as simple as pushing my code. Given the overwhelming cons however I decided not to explore this approach any further.


### Second Possible Approach: Create a Bare Git Repository on the Server and Building with Git Hooks
> Simplicity: 3/5
>
> Ease of use: 4/5
>
> Maintainability: 3/5

The second approach is largely inspired by [this post](https://www.digitalocean.com/community/tutorials/how-to-deploy-a-jekyll-site-using-git-hooks-on-ubuntu-16-04) and it centers on using Git hooks to build and deploy. You first create a bare Git repository (a bare Git repository is one used by a server machine to host the code and contains no working tree, more information [here](http://www.saintsjd.com/2011/01/what-is-a-bare-git-repository/)) on the server, and create a **git** user and  an ssh key pair for that user. Then, create a post-receive hook in the `hooks` directory with the following contents:

{% highlight bash %}
#!/usr/bin/env bash

GIT_REPO=$HOME/blog.git
TMP_GIT_CLONE=/tmp/blog
PUBLIC_WWW=/var/www/html # depending on your distribution or server config this will differ

git clone $GIT_REPO $TMP_GIT_CLONE
pushd $TMP_GIT_CLONE
bundle exec jekyll build -d $PUBLIC_WWW
popd
rm -rf $TMP_GIT_CLONE

exit
{% endhighlight %}

The script clones the repository to the `/tmp` directory, and then builds the site at the directory where it is served. The temporary directory is then deleted. `pushd` functions similarly to `cd` by pushing to the command line directory stack, and `popd` pops from this stack and returns to the directory at the top of the stack.

An interesting concept that I learned from the post is on the creation of non-interactive shells, which seemed quite smart to me. Basically, you create a shell script that prints a helpful message that the ssh attempt was successful, and then exit.

{% highlight bash %}
#!/usr/bin/env bash
# in ~/git-shell-commands/no-interactive-login
printf '%s\n' "You've successfully authenticated to the server as $USER user, but interactive sessions are disabled."

exit 128
{% endhighlight %}

Exit code 128 means ["Invalid argument to exit"](http://tldp.org/LDP/abs/html/exitcodes.html). Make the script executable, and update the shell for the **git** user as follows.

{% highlight bash %}
sudo usermod -s $(which git-shell) git
{% endhighlight %}

Attempting to ssh as the **git** user will now cause the login shell to execute and immediately terminate.

{% highlight terminal %}
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-109-generic x86_64)
...
You've successfully authenticated to the server as git user, but interactive sessions are disabled.
Connection to production_server_ip closed.
{% endhighlight %}

While feasible and definitely not difficult to set up, my main jibe with this deployment method is the need to host my code on Git repository on the server. I would very much rather have it hosted and open sourced on GitHub and be able to leverage its many powerful capabilities. Furthermore, in the event that I ever lose access to the server (i.e lost my private key or failed to pay my server bills) and lose my local copy of the files the results are catastrophic. I also did not like how this
method of deployment basically ties me to the server and increases friction significantly should I want to deploy elsewhere on a new machine instead.

As a result, I give it 3 in terms of simplicity due to some set up required, 4 for ease of use since it removes my ability to use GitHub's powerful browsing features, and 3 for maintainability since it is easy for me to lose the files and there is a lot of overhead in switching to other servers. These factors are enough to convince me to find an alternative method.

### The Chosen Method: Deploying with rsync
> Simplicity: 5/5
>
> Ease of use: 4/5
>
> Maintainability: 5/5

A bit of a backstory: after editing our internal [Slate](https://github.com/lord/slate) API documentation in [Saleswhale](https://www.saleswhale.com) after I updated the API, I was trying to find out how to deploy the changes. Our Rails and Ember apps are deployed using [Fabric](https://github.com/fabric/fabric), and naturally I was looking for something similar. I found a `deploy.sh` script that only contained two lines. I told my senior colleague who wrote it that I am in disbelief that
this is all it took, and he laughed and told me that yes it works, now you go try it. The first line was to build the project, and the second line is to **rysnc** the contents to the server. I hope that I will be able to share this magical feeling of disbelief with you after you see how simple it can get.

This section takes a lot of reference from the official [Jekyll docs](https://jekyllrb.com/docs/deployment-methods/#rsync) so you can take a look if you want to dive in deeper. First, install **rrsync** on the server. **rrsync** (restricted rsync) offers some benefits on top of *rsync* by restricting the directories that *rsync* can access. Create a new keypair for *rsync* on your client at `~/.ssh/jekyll_rsync_id_rsa`, and add the following contents to `~/.ssh/authorized_keys` on the server.

{% highlight terminal %}
command="$HOME/bin/rrsync <folder>",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-rsa <cert>
{% endhighlight %}

For me, I replaced `<folder>` with `/usr/share/nginx/blog` and `<cert>` is public key for your newly generated keypair. **rsync** will only be able to access and modify contents within the specified folder.

On the client, append a new entry for your newly created key to your `.ssh/config`:

{% highlight shell %}
# Jekyll rsync
Host jekyll-rsync
  HostName <server hostname or ip>
  User <user>
  IdentityFile ~/.ssh/jekyll_rsync_id_rsa
{% endhighlight %}

Change the values as appropriate for your configuration. Then, create a script `deploy` in your project directory.

{% highlight shell %}
#!/bin/sh
JEKYLL_ENV=production bundle exec jekyll build
rsync -crvz --rsh='ssh -p22' --delete-after --delete-excluded  _site/ jekyll-rsync:
{% endhighlight %}

Lastly, you can exclude the deploy script from being included in the output folder by adding the following to the `_config.yml` file:

{% highlight ruby %}
# Do not copy these files to the output directory
exclude: ["deploy"]
{% endhighlight %}

Set deploy as executable with `chmod +x deploy`, and run `./deploy`. You will see your newly built site on production in no time!

I personally like this method very much due to its ease of setup and extensibility, and give it a 5 for simplicity without recommendations. I would downgrade its ease of use slightly to 4 simply because I have to run the deploy script separately from pushing the code, however this can be easily solved via a post-commit hook. I did not opt for this however as I would rather not have to wait a while for it to build and copy each commit as I tend to commit multiple times at once. Maintainability
gets a 5 as there is no tight coupling between the client and server, and the setup is easy enough to make any transfer friction negligible. This method of deployment is in fact what I am currently using and I am very happy with it.

Using **rsync** for deploying static sites keeps things simple and taking advantage of the 80/20 rule. Let me know in the comments what are your thoughts, and if there are other deployment methods that you would use and recommend. Thanks for reading!
