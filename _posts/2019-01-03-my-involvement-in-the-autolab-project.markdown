---
layout: post
tags: [CMU, Autolab, DevOps, Infrastructure]
title: My Involvement in the Autolab Project
cover: assets/images/posts/autolab.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---
I joined the [Autolab](http://www.autolabproject.com/) team at the close of the semester this year. The Autolab team builds and maintains Autolab, an autograding platform for programming assignments that is currently being used by around 20 universities around the world. It is used very extensively in most computer science courses to grade programming assignments in Carnegie Mellon. In this post, I will share how I came to join Autolab, and the role that I am planning to play in it.

### Why I Joined
Autolab caught my interest as it was being used in the programming class that I was taking in the fall ([15-122](https://www.cs.cmu.edu/~15122/schedule.shtml)), and it was built with [Ruby on Rails](https://rubyonrails.org/), which was the backend language I used while I was still working in [Saleswhale](https://www.saleswhale.com/). It was also an actively maintained open source project with some degree of community participation, and I had been intending to contribute to open source for the longest time, and therefore seemed like the perfect opportunity. Furthermore, the faculty member who started this project, [David O'Hallaron](https://www.cs.cmu.edu/~droh/) from CMU's School of Computer Science authored the textbook [Computer Systems: A Programmer's Perspective](http://csapp.cs.cmu.edu/), which I read and learned a lot from on x86-64 and understanding how computer programs run at the system level while I was still serving my National Service. I therefore looked up to him and found it to be a great opportunity to also interact with an esteemed faculty member.

### Joining the Team
Following an online application process, I had to first go through an on-site interview, followed by the challenge of setting up both Autolab and Tango locally on my machine and testing that the autograding functionality works within a week. Autolab is the name for the frontend application that the users see, while Tango is the grading backend that spins up a virtual machine for each assignment to be graded in its own isolated environment.
I'm not sure if other people who interviewed to join in the past also received the same challenge, but I found it apt because I expressed my interest in working on the DevOps and infrastructure side of things. I was given a week for this task, although I managed to get everything wired up in two hours owing to my familiarity to all the tools and frameworks used such as Ruby on Rails, Docker, and Redis. However, I would admit that there are a few gotchas that would stump someone attempting to install Autolab without previous Ruby on Rails experience.

### Meeting with David O'Hallaron
Having managed to setup both Autolab and Tango, I had my first meeting with Prof. O'Hallaron two weeks later. Given my inclinations towards DevOps and infrastructure, he shared that it was an opportune time that I joined, since I was able to play a role that is currently unfulfilled because the other team members are all full-stack developers. He then talked about the history of the Autolab project, and his visions for where it should go next. He then revealed how the greatest hurdle towards wider adoption of the Autolab system was the difficulty in installing and setting up, since many professors and teachers do not have the specific Ruby on Rails and systems administration knowledge to be able to set up Autolab and Tango easily. Therefore, he offered me the opportunity to be able to develop a simple auto-deployment system for Autolab and Tango that would be easy for people without such specialized knowledge to setup.

### First Autolab Meeting
I was invited to join the last Autolab meeting of the semester before finals week. I sat in and saw how each team member shared updates on the things that they worked on that week, as well as how they handled issues anposed by the community (usually installation problems). One of them also merged a pull request that was submitted. I introduced myself, and since they already somewhat knew what I was doing, I started asking more specific questions related to automating deployment - What are the use cases, for local testing or production? What is the average expertise level in command line tools of someone attempting to setup Autolab? What is the current infrastructure and deployment process in CMU like? (I found out that it is handled by Computing Services, which has its custom code deployment and upgrading infrastructure). Who wrote the current [OneClick install script](https://autolab.github.io/docs/one-click/), and what are the major issues with it that people have reported?

From the meeting, I found that the team was well-organised and that the people on the team were technically sharp and pretty smart. Later that night, I emailed Prof O'Hallaron and told him that I have made my decision to join Autolab.

### Current Progress
Over the current winter break, I have been making some progress porting the OneClick install script to Ansible such that most steps would be idempotent. This is because a chief complaint was that the OneClick install script would break whenever the installation failed halfway through. Writing the deployment script in Ansible in a declarative, easy-to-read yml syntax would also make it more maintainable and simple for other people in the future to modify and extend it. In a future post I would dive into more details on how I am using Ansible to automate both Autolab and Tango deployment.
