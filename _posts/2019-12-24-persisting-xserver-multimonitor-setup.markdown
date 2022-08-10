---
layout: post
tags: [Linux]
cover: assets/images/posts/cut_winter.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---
I have been using a multiple monitor setup on my Linux system for a long time, and one thing that always annoyed me was that the default monitor arrangement detected by X Server doesn't reflect its physical positioning (why should it?). Due to a combination of laziness and the fact that reordering it with nvidia-settings's X Server Display Configuration takes only a few seconds, I never bothered to find the time to find a proper fix for it. However, the fix is actually incredibly simple.

First, generate or create an xorg.conf file based on your current display settings. If you are using an Nvidia card, then this can be easily done under `X Server Display Configuration -> Save to X Configuration File`. If not, generate it such as by running `Xorg :0 -configure` as described [here](https://wiki.archlinux.org/index.php/Xorg#Using_xorg.conf).

Next, copy the xorg.conf file to the directory that sources your xorg configs, which is `/etc/X11/xorg.conf.d` for Arch Linux, and you are done.

Now, your monitors will be arranged in the correct position on boot. This will still function correctly even if no external monitors are being used, since the display names for the monitors will be unresolved and ignored.

One may ask what other ways are there of achieving this. Another simple way would be to use xrandr to apply the changes in your `.xinitrc`. For instance, I could put the following snippet in a script and execute it in my `.xinitrc`:

{% highlight shell %}
#!/bin/sh
xrandr --output DP-0 --off --output DP-1 --mode 1920x1080 --pos 3840x0 --rotate normal --output DP-2 --off --output DP-3 --off --output HDMI-0 --mode 1920x1080 --pos 1920x0 --rotate normal --output DP-4 --primary --mode 1920x1080 --pos 0x0 --rotate normal
{% endhighlight %}

However, I like this solution a lot less as it has to perform an additional resizing/reorienting of the display outputs after starting the X Server, when it could have been simply been initialized correctly as in the first solution. In accordance to the Unix spirit, xrandr has its place in updating screen configurations, and is therefore better suited to tasks of that nature.
