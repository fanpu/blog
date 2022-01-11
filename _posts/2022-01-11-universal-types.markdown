---
title: "Universal types, and why your type checker doesn't suck as much as you think"
layout: post
tags: [code]
cover: assets/images/posts/horse_lake_2.jpg_resized
class: post-template
navigation: True
author: fanpu
---

Universal types are very useful for performing generic programming, which allows you to use the same code over different types. For instance, the C++ STL (Standard Template Library) allows you to work on things like containers over any arbitrary type. You would surely not want to re-implement the logic for every concrete type that you use. Such a feature is known as parametric polymorphism. It is different from the other kind of polymorphism normally found in object-oriented languages that allows for overloading and run-time dispatch, which is known as ad-hoc polymorphism. 

To formally introduce and discuss universal types, we work in the context of System F with universal (or polymorphic) types. System F is an extension of the simply-typed lambda calculus with universal quantification over types. The typing rules for System F are given below:

\begin{prooftree}
\RightLabel{\(var\)}
\AxiomC{$x:T \in \Gamma $}
\UnaryInfC{$\Gamma \vdash x : T$}
\end{prooftree}

\begin{prooftree}
\RightLabel{\(abs\)}
\AxiomC{$\Gamma, x : T_1 \vdash t_2: T_2 $}
\UnaryInfC{$\Gamma \vdash \lambda x : T_1.t_2 : T_1 \rightarrow T_2$}
\end{prooftree}

\begin{prooftree}
\RightLabel{\(app\)}
\AxiomC{$\Gamma \vdash t_1 : T_{11} \rightarrow T_{12}$}
\AxiomC{$\Gamma \vdash t_2 : T_{11} $}
\BinaryInfC{$\Gamma \vdash t_1\ t_2 : T_{12} $}
\end{prooftree}

\begin{prooftree}
\RightLabel{\(tabs\)}
\AxiomC{$\Gamma, X \vdash t_2 : T_2$}
\UnaryInfC{$\Gamma \vdash \lambda X.t_2 : \forall X.T_2$}
\end{prooftree}

\begin{prooftree}
\RightLabel{\(tapp\)}
\AxiomC{$\Gamma \vdash t_1 : \forall X.T_{12} $}
\UnaryInfC{$\Gamma \vdash t_1\ [T_2] : [X \rightarrow T_2] T_{12} $}
\end{prooftree}

The first three rules are our old friends from the simply-typed lambda calculus, corresponding to variable typing, lambda abstraction, and lambda application. 
The rules $$\textsf{tabs}$$ and $$\textsf{tapp}$$ (type abstraction and type application) are new. We use capitalized variable names in order to denote that it is a type variable. So $$\textsf{tabs}$$ says that if we add a type $$X$$ in our context and we can derive a term $$t_2$$ of type $$T_2$$ from it, then we can produce an abstraction that takes in any type $$X$$ and returns a term of type $$T_2$$ when applied. The standard technique of applying alpha conversion applies in the case that there are conflicting variable names in nested closures. 

As an example, consider the empty context $$\Gamma = \cdot$$. If we add a type variable $$X$$ to it, we can derive the polymorphic identity function $$\lambda X. \lambda x : X.x$$ with type $$\forall X.X \rightarrow X$$. 

$$\textsf{tapp}$$ says that given a lambda abstraction $$t_1$$ over types, we can apply it on any type $$T_2$$ to obtain a result that have instances of $$X$$ substituted by $$T_2$$. We put square brackets around $$T_2$$ on the bottom left to make explicit that this is a type application, while the bracket notation on the right refers to substitution. Continuing off from our previous example, we can perform the application $$\lambda X. \lambda x [\textsf{Nat}]$$ to specialize our polymorphic function to be $$\textsf{Nat} \rightarrow \textsf{Nat}$$.

Since we allow quantification over types, System F is a second-order lambda-calculus. In fact, we can go further and quantify over types of types, which is known as kinds. You can then say why not go further and take the type over kinds, and if repeat this process indefinitely you will actually achieve the language known as System $$\text{F}_\omega$$!

Languages from the ML family provides parametric polymorphism. However, it seems like not all is well. Consider the following piece of innocent OCaml code that simply defines the identity function and then tries to call it with two values of different types:

{% highlight ocaml %}
let id : 'a -> 'a = fun x -> x in
(id 0, id "hello")
{% endhighlight %}

Despite how we seemingly typed it to use any generic type variable, the compiler complains to us:

{% highlight ocaml %}
File "./ident.ml", line 2, characters 10-17:
2 | (id 0, id "hello")
              ^^^^^^^
Error: This expression has type string but an expression was expected of type
         int
{% endhighlight %}

This is because OCaml uses the Hindley-Milner type inference algorithm in order to perform type reconstruction. From a high level point of view, it produces constraints on the types based on how they are used, and then tries to unify these constraints in the most general way possible. As such, it discovers both constraints $$'a = \textsf{int}$$ and also $$'a = \textsf{string}$$, which cannot be unified (on the other hand, something like $$X = Y, Y = \textsf{int}$$ can be unified). If we want the example to work, we actually need to provide more information to the compiler and tell it that we actually want $$'a$$ to be universally quantified by using polymorphic type annotations:

{% highlight ocaml %}
let id : 'a. 'a -> 'a = fun x -> x in
(id 0, id "hello")
{% endhighlight %}

Notice how the typing rule `'a. 'a -> 'a` closely resembles our type $$\forall X.X \rightarrow X$$ in System F. 

Another way to achieve the same thing is by using explicit type parameters, which now really looks like our term in System F, $$\lambda A. \lambda x.x$$:

{% highlight ocaml %}
let id = fun (type a) (x : a) -> x in
(id 0, id "hello")
{% endhighlight %}

The first approach (polymorphic type annotations) is more idiomatic as explicit type parameters could cause issues when the function is recursive ([see the following post if you want more information](https://blog.janestreet.com/ensuring-that-a-function-is-polymorphic-in-ocaml-3-12/)).

However, was this failure just a limitation of our type inference algorithm, and might there be a smarter way such that type inference in a language with first-class parametric polymorphism is possible? Interestingly enough, this was a very difficult question to answer, and was an open problem for around 20 years before Joe Wells proved that it is actually undecidable. Therefore, as a compromise, OCaml uses a weaker form of polymorphism known as let-polymorphism. Let-polymorphism essentially substitutes the binding into the resulting expression itself before typechecking, which allows each instance to be constrained independently of the others.
