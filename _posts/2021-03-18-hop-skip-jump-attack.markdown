---
title: "HopSkipJumpAttack: An Efficient Adversarial Attack against Machine Learning Algorithms"
layout: post
tags: [machine learning]
cover: assets/images/posts/sulphur_springs.jpg
class: post-template
navigation: True
author: fanpu
---

Many machine learning algorithms have been shown to be susceptible to adversarial examples. For example, image classification neural networks can wrongly classify an image when a small perturbation, unnoticeable to the human eye, is added to the original image which it has previously correctly classified. The goal of an adversarial attack can thus be rephrased as an optimization problem to compute the "smallest" perturbation needed, such that the perturbed example will be misclassified.

State-of-the-art adversarial attacks can be roughly divided into three categories: gradient-based, score-based and
decision-based attacks. 
In $$\textbf{gradient-based attacks}$$, also denoted as white-box attacks, adversaries are given access to the original underlying target model, and many attacks are often heavily reliant on detailed information including the gradient of the loss with respect to the input.
In $$\textbf{score-based attacks}$$, adversaries are given predicted scores (e.g. class probabilities or logits) of the targeted model, and most attacks also rely on these numerical predictions to estimate the gradient.
Lastly, in $$\textbf{decision-based attacks}$$, adversaries are only given black-box access to the decisions of the victim model. 

Continue reading the rest of the paper [in PDF format here]({% link /assets/research/hop_skip_jump_attack.pdf %}). Written in collaboration with Joelle Lim and Albert Gao, originally for 10-701 Introduction to Machine Learning (PhD).