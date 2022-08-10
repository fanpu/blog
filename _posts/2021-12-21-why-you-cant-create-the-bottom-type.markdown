---
title: "Why you can't create a value with the Bottom type (and why it's still useful)"
layout: post
tags: [code]
cover: assets/images/posts/coyote_valley.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

If you've used any sort of object-oriented language, you may be familiar with the notion but not the name of the top-level type $$\top$$. For instance, in Java, the `Object` class forms the root of the class hierarchy, and similarly, in Python, all objects inherit from `object`. 

The inheritance relationship in object-oriented languages is known as subtyping in programming language theory, which forms a preordered set. Preordered sets (or prosets) satisfies two properties:

1. Reflexivity, i.e $$S <: S$$ where $$S<:T$$ denotes that $$S$$ is a subtype of $$T$$
2. Transitivity, i.e if $$S <: U $$ and $$U <: T$$, then $$S <: T$$

Note that prosets only differ from partially ordered sets from their exclusion of the anti-symmetric property.

The top and bottom type $$\top$$ and $$\bot$$ respectively are therefore defined to be the maximal and minimal element of the proset of types respectively.

It is clear that a value with the $$\top$$ type can be instantiated in any language (because one can do so), but what about $$\bot$$?

## Impossibility of instantiating a term with type $$\bot$$

We show that in fact, while type systems can leverage $$\bot$$ for various reasons, it is impossible to create a value with such a type. To see why, we use Pierce's presentation of the simply typed lambda calculus with functions, records, and subtyping in order to reason about the problem formally. The rule for subsumption of types is given below:

\begin{prooftree}
\RightLabel{\(SUB\)}
\AxiomC{$\Gamma \vdash t : S$}
\AxiomC{$S <: T$}
\BinaryInfC{$\Gamma \vdash t : T$}
\end{prooftree}

It says that that if we have a term $$t$$ of type $$S$$, and $$S$$ is a subtype of $$T$$, then we can derive that $$t$$ also has type $$T$$. 

So now assume for the sake of contradiction that we can indeed produce a value $$t$$ with type $$S = \bot$$. Consider two scenarios, where we first let $$T$$ be the abstraction with type $$\top \rightarrow \top$$ and derive $$\vdash v : \top \rightarrow \top$$, and then separately consider $$T$$ to be the empty record type $$\{\}$$ which then allows us to derive $$\vdash v : \{\}$$. 

We appeal to the Canonical Forms lemma to drive our final argument. The Canonical Forms lemma states that if a term $$v$$ is a value of a particular type, then $$v$$ must be of a certain form. For instance, if $$v$$ is of type $$\textsf{bool}$$, then it must be either $$\textsf{true}$$ or $$\textsf{false}$$.

The Canonical Forms lemma states that if $$v$$ is a closed value of type $$T_1 \rightarrow T_2$$, then $$v$$ has the form $$\lambda x : S_1.t_2$$ for some type $$S_1$$ and term $$t_2$$, and if $$v$$ is a closed value of type $$\{l_i : T_i^{i \in 1 \dots n} \}$$, then $$v$$ has the form $$\{k_j = v_j^{j \in 1\dots m} \}$$, with $$\{ l_i^{i \in 1 \dots n }\} \subseteq \{ k_a^{a \in 1\dots m}\}$$, which loosely speaking is saying that all the fields in the records should also be values. However, since the form of $$t$$ cannot be both a function or record, we have a contradiction, and so $$t$$ cannot possibly exist.

## Applications of the $$\bot$$ type

If we cannot create a value with the $$\bot$$ type, what good can it be? It can actually be used to represent the type of computation that diverges (i.e never completes evaluation and returns a result), such as `typing.NoReturn` in Python. It is the zero type that is called $$\textsf{Void}$$ in Haskell (note that many programming languages like C and Java use `void` as a return type for functions that returns with no value when they really mean the unit type that holds no information). In intuitionistic logic, $$\bot$$ is analogous to false, as it is impossible to ever produce such a term since the computation will never terminate.

I hope that you learned something from this post and found it useful. Let me know about your thoughts in the comments below!

*Banner picture: View from Coyote Valley Trail, Rocky Mountain National Park*

