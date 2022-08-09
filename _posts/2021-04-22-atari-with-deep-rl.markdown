---
title: "Playing Atari using Deep Reinforcement Learning"
layout: post
tags: [machine learning]
cover: assets/images/posts/devils_postpile.jpg_resized
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---
In this post, we study the first deep reinforcement learning model that was successfully able to learn control policies directly from high dimensional sensory inputs, as applied to games on the Atari platform.

This first model was a convolutional neural network (CNN) that takes in raw pixels as input and outputs the value function $$Q$$ estimating future rewards. This value estimate is then used to decide on the best action to take at the current time step. Back when this paper was written, deep nets were only commonly applied to supervised learning problems, where there is a corresponding label for every classification of the image; this was the first approach to show that it is possible to train a CNN even with sparse "rewards" and to solve the "credit assignment problem". This model was also shown to be able to generalize across multiple games: the same architecture was shown to perform decently on six Atari 2600 games in the Arcade Learning Environment, and even surpasses a human expert on three of them.

However, this approach has a major flaw in that the deep network used to approximate the $$Q$$ function gives a biased estimate: there is an overestimation caused by taking maximum estimated values in the Bellman equation. Besides, this variant of Q-learning also involves bootstrapping, which requires learning estimates from estimates. This makes the overestimation problem even more severe and can even cause divergence in the worst case.  It has also been shown that the first DQN mentioned above suffered from substantial overestimations in some games in the Atari 2600 domain.

Continue reading the rest of the paper [in PDF format here]({% link /assets/research/atari_deeprl.pdf %}). Written in collaboration with Joelle Lim and Albert Gao, originally for 10-701 Introduction to Machine Learning (PhD).

*Banner picture: Devil's Postpile, Mammoth Lakes*