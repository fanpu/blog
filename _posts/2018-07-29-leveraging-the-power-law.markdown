---
layout: post
tags: [software engineering, startup, productivity]
cover: assets/images/posts/drama.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---
It was three years ago that I was introduced the concept of the "power law" in Peter Thiel's book, [Zero to One: Notes on Startups, Or How To Build The Future](http://zerotoonebook.com/). Thiel stated that "We don't live in a normal world, we live under a power law. Exponential equations describe severely unequal distributions". This, in effect, is very similar to the 80/20 rule that I discussed in my previous post, and observations of such a distribution can be found ranging from income
distributions to the fact that the best venture capital fund investments grow to a value that eclipses the rest of their portfolios combined. The power law is extremely unintuitive for humans as we are accustomed to seeing things in a linear fashion. However, we ignore the power law at our own peril. A single outlier performs much better than a large average sample combined, and it is precisely the power law that we must understand in order to unlock this phenomenom. However, I will not go into
too much detail about the power law here. You can read Thiel's book for a much better and deeper understanding, and that is a book that I would highly recommend.

The focus of today's post is on how you as someone ordinary can leverage the power law in your daily life to become extraordinary. Just a few days ago during lunch my colleague Vincent joked that when he read Rich Dad Poor Dad at eight years old, his main takeaway was to make your money work for you, but then as a kid he didn't have any money. While the power law has been well documented in terms of wealth (the rich getting richer and the poor getting poorer), I don't believe that that
is its most important application, and I would like to show you that there are many other ways that you can leverage this law in a manner that is accessible to everyone.

### Invest in Tooling
Tooling refers to the tools, workflow, and setups that you use in order to get your work done. In a software engineering context, it means your text editor or IDE, your mastery of the language, your development environment, and scripts and automated task runners that you write to help to boost your productivity.

#### Your Editor
A good mastery of your text editor or IDE is one of the best ways to improve your output as a programmer. If you find yourself making repetitive edits, try to find out if there is already a plugin available that solves the problem, because chances are that someone else has also faced the same problem before. If you have difficulty navigating and orientating yourself in a large codebase in your text editor, see if there are suitable plugins that implements IDE-like code browsing and tracing
features. The seconds that you shave off may seem insignificant, but if you aggregate this over the number of times that you'll be writing code throughout your lifetime, you will see that the time saving compounds and you will become an order of magnitude more productive than someone who does not have this knowledge.

I used to be an Emacs user for many years, and after a few months of tweaking I generally settled down into my configuration and did not really bother to find ways to improve my workflow. The most that I did after was basically downloading new syntax highlighters for new languages that I am developing for with [Melpa](https://melpa.org/), a package manager in Emacs. This remained the status quo until an unfortunate accident resulted in the loss of my `/home` partition and along with it my carefully curated `.emacs` file. I then thought that this was a better time than ever to give Vim a try, since I would have to re-configure my entire workflow anyway. Attempting to find similar tools to what I have grown comfortable to using in Emacs was like a renaissance in development tooling to me, as I opened my eyes again to all the different plugins available which solved many pain points that I had never really bothered to fix. I also consulted my colleagues for recommendations, and today some of my most frequently used tools include [ack](https://github.com/mileszs/ack.vim) for searching, [ctrlp](https://github.com/kien/ctrlp.vim) for fuzzy file search, and [acp](https://github.com/vim-scripts/AutoComplPop) for code completion. Looking back, I realised I became so much more productive. It was such a happy accident in hindsight.

#### Automation and Removing Bottlenecks
Large projects in particular are especially susceptible to complicated setup, building, testing, and deploy processes, which comes at a cost of slower iteration speed and less programmer happiness. Many of the things that must be done may be very peculiar to your particular architecture and business logic, and there often will not be an off-the-shelf solution which will automate the pain away. This is where your creativity comes into play by attempting to automate the process as far as possible. Set up a continuous integration pipeline to run all your tests on push, develop a deploy script, and maybe even write your own internal tools to help bootstrap the tedious testing and QA process, the last point of which I will elaborate further because I have just recently done something similar.

As you may know, [Saleswhale](http://www.saleswhale.com/) is a conversational email sales automation tool, and so a big part of what we do is handling all these emails. We have a dedicated mailer microservice that integrates with Gmail and Outlook, which our main application microservice will interface with in order to send and receive email. However, the mailer microservice presents itself as a significant bottleneck in testing, as the Gmail and Outlook send APIs are entirely asynchronous and
we had to manually log in to and reply from the test email accounts to simulate the lead in the conversation. Because of this significant time cost, engineers tend to avoid having to incorporate interfacing with the mailer microservice in their development process, and automated end-to-end testing is infeasible. To help to reduce this testing time, I developed a mock-mailer microservice that replicates all the endpoints as the real mailer microservice but does not actually call Gmail or Outlook. To help generate the lead email reply, I also created a web interface that allows us to easily set the sentiment of the reply and any additional custom behavior. This allows an entire engagement to be mocked in less than a minute, with highly customizable options to generate states that are very tedious to create manually. The new mock mailer microservice saw immediate adoption by the other engineers into their development workflow, and I hope the compounded time savings will go a long way towards helping to increase our iteration speed and helping us move faster.


By investing in tooling, you become more productive as knowledge of your tools deepens, and you find ways to automate redundant tasks, allowing you to re-invest the time savings into accomplishing even more things.

### Optimize for Learning
Learning, like wealth, also compounds. Learning does not refer to just simply textbook learning, but also industry and professional knowledge, soft skills, and effective habits. You should adopt a growth mindset and seek to continuously improve yourself. The school motto of my high school, Hwa Chong Institution, is 自强不息, which means to tirelessly and relentlessly strive for self-improvement. Creating a strong foundation for your knowledge allows you to build more knowledge upon it, giving you an increasingly wider base that you can draw on to learn new things even faster. Since learning compounds, you should aim to optimize for
learning as early as possible. Optimizing for learning may seem counter-intuitive for outsiders, who cannot see the real intent behind your decisions. For instance, you may accept a job that pays less but offers significantly more in terms of the learning vertical. While you may take a pay cut initially, you will go much higher and realise more career opportunities down the line.

### Invest in your Learning Rate
Because you will be learning all your life, and because of its compounding effects, even a small change in your learning rate will result in a dramatic change in the results over the long run. Develop techniques and habits which will make you a more effective learner. Be conscious about your learning, and keep an active lookout for things that may hinder your progress or result in procrastination. Learning can be made into an iterative process, so keep on trying and
experimenting with different learning methods to see what works best. Personally, I found the course [Learning How to Learn](https://www.coursera.org/learn/learning-how-to-learn) by Dr. Barbara Oakley extremely helpful in increasing my learning rate. She covers and explains many things that I wished I knew when I was in high school, so that I wouldn't have had to undergo so much frustration and spent so much time unncessarily studying blindly.

### In short...
The effects of compounding are both scary and exciting. Leverage it early and leverage it often, and seek to find ways to increase the exponent so that it compounds ever faster. In the book [Delivering Happiness](http://deliveringhappiness.com/), Zappos CEO Tony Hsieh says "Think about what it means to improve just 1% per day and build upon that every single day. Doing so has a dramatic effect and will make us 37x better, not 365% (3.65x) better, at the end of the year". While 37x might seem
slightly exaggerated, the effects of compounding cannot be understated. I hope this post has been insightful and I would be glad to hear your comments below!




