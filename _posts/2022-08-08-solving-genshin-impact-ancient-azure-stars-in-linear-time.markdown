---
title: "Solving Genshin Impact's Ancient Azure Stars quest in Linear Time"
layout: post
tags: [general, code]
cover: assets/images/posts/mona.avif
class: post-template
navigation: True
author: fanpu
toc: true 
comments: true
---
It is summer yet again, and miHoYo has blessed us with the *Summertime Odyssey*
event that explores the (often dark and painful) backstories of the cast
comprising Kazuha, Xinyan, Fischl, and Mona, back on the setting of the *Golden
Apple Archipelago*.

One puzzle that I found interesting from a computational perspective was a major
part of Mona's questline *Ancient Azure Stars*, which is the main topic of this
post. In this puzzle, you are given a pattern that resembles a constellation
that you need to imitate. For readers unfamiliar with Genshin Impact, Mona
(pictured in the banner) is an astrologist with the ability to perform
divinations, and therefore the idea of forming constellations is very fitting
for her character.  The puzzle is interesting because even though its mechanics
allows for an exponential search space (and also multiple possible solutions),
clever algorithmic techniques can speed up finding a valid solution to almost
linear time. This post is meant to be accessible to people with only some
exposure to algorithms, and takes things step by step.

## How the Puzzle Works

The premise is relatively simple: somewhere in the room (perhaps towards the
roof), a target constellation is shown, such as the following:

![Genshin Impact Ancient Azure Starts Puzzle
1](/assets/images/posts/genshin-puzzle-1.avif){: width="100%"}

There are several devices on the ground, initially all inactive, that will
project a beam of light when activated, which is achieved by hitting it.
These devices can be rotated at discrete intervals corresponding to pointing
towards some other device.  This means that all devices must be pointing at
another device.

Your job is to rotate and activate the right devices such that the pattern
formed by the beams corresponds to the desired target constellation. For
the previous example, we have the following solution:

![Genshin Impact Ancient Azure Starts Puzzle 1](/assets/images/posts/genshin-puzzle-1-solved.avif){: width="100%"}

The puzzles seem to get progressively harder, with an increasing number of stars
in the constellations, and an exponentially growing state space. Or do they?

![Genshin Impact Ancient Azure Starts Puzzle
3](/assets/images/posts/genshin-puzzle-3.avif){: width="100%"}

## An Algorithmic Perspective

Let's make some observations. We can view the problem as forming an unweighted directed
graph $$G$$ on $$n$$ vertices and $$m$$ edges, where a beam going from device
$$u$$ to $$v$$ corresponds to a directed edge $$(u, v)$$ in the graph. Each
device can only emit at most one beam, which is when it is activated.  

Furthermore, let's assume that when we treat all directed edges as undirected,
the graph is connected (it is possible to reach any vertex from any other
vertex). This is admissible since we can just re-run our algorithm later on each
individual connected component of the graph. Then we also have that $$n \leq
m$$.

We know that a tree has $$n-1$$ edges and is minimally connected, meaning that
the absence of any edge would cause it to be disconnected. Therefore, since
$$G$$ is connected, there must also be an embedding of a tree $$T$$ that forms a
subgraph of $$G$$ ($$A$$ is a subgraph of $$B$$ if the vertices and edges of
$$A$$ form a subset of those of $$B$$) that is also connected.

Let $$C$$ be the (connected) constellation that we are trying to form, with
$$n_c$$ vertices and $$m_c$$ edges. Since it is connected, we require $$m_c \geq
n_c - 1$$. 

### The Easy Case

If $$m_c = n_c - 1$$, then we have a tree, and it is a fact of life that many
hard problems are actually very easy on trees (if you are interested, look up
the treewidth of a graph, which measures how much a graph is like a tree. The
smallest treewidth is 1. Trees have treewidth 1, graphs that can be formed by
series and parallel composition have treewidth 2, but the intuition quickly
breaks down from here. Many $$\NP$$-hard problems can in fact be solved
efficiently on graphs with bounded treewidth!). 

We then have a trivial algorithm of just rooting the graph on any vertex, and
performing any tree search (say depth-first search) from said vertex, where the
reverse of the direction of graph traversal on each edge determines where the
beam should go, with the root vertex de-activated. This works because we are
essentially pointing the beam of each child vertex towards its parent vertex,
and each vertex can only have at most one parent. It takes the optimal $$O(m)$$ time.

### The Other Case

Otherwise, $$m_c = n_c$$. But then the graph is no longer minimally connected,
which means that there exists some edge $$(u, v)$$ where removing $$(u, v)$$
still causes the resulting graph $$G \setminus (u, v)$$ to still be connected as a tree. 

Suppose we know what $$(u, v)$$ is (it does not have to be unique, and in fact
is not).  Then this makes us really happy, since we can just use the same
algorithm as the easy case, but choose vertex $$u$$ to be the root, and finally
send a beam from $$u$$ to $$v$$. But how do we find $$(u, v)$$?

There is a simple way of doing so by performing depth-first search (DFS) from
any arbitrary vertex, making sure to maintain a visited array, where initially
all vertices are unvisited except for the root vertex and vertices are marked
visited whenever we visit them during DFS. The moment we find that we re-visit
a visited vertex $$v$$ from some vertex $$u$$, we know that we have found $$(u,
v)$$, since it implies that we just found a cycle! This runs in $$O(m)$$.

## Putting It Together
Taking both steps together, we get an overall $$O(m)$$ running time, which is
actually also $$O(n)$$ given our previous note that $$n \leq m$$. This is also
the best achievable bound, since we certainly must examine all the inputs which
already takes $$O(n)$$ time for the algorithm. It certainly looks like Mona will
be speeding through these puzzles in no time after all!

![Genshin Impact Mona](/assets/images/posts/mona_end.avif){: width="100%"}

Dear readers, let me know if you enjoyed this post in the comments below, and
feel free to drop suggestions for future topics!

*Banner picture: Mona Megistus, Genshin Impact. Copyrights and/or trademarks of any character and/or image used belong to miHoYo.*