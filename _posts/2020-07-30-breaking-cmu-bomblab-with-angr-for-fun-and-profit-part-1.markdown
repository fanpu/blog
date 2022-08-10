---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 1"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/arapaho.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

I have recently been learning about [Angr](https://angr.io/), a binary analysis framework developed by UC Santa Barbara and Arizona State University. It caught my eye because of its versatility and utility in reverse engineering binaries whose disassembly and decompilation are hard to understand manually. Oftentimes, it is simply due to the fact that it was compiled from newer or relatively less popular languages like Rust or Haskell, where the state of currently publicly available decompilers leaves much to be desired. Angr's ability to perform symbolic execution therefore allows us to blackbox certain functionality within the program (or even the entire program) by attempting to find the right input for a desired output.

### But what is symbolic execution anyway?
Do you recall when you had to first begin manipulating symbols in math class during elementary school? Yes, algebra! Symbolic execution can be thought of as manipulating symbols in order to derive certain constraints. These constraints can then be solved by a Satisfiability Modulo Theories (SMT) solver like [Z3](https://github.com/Z3Prover/z3). 

Here is a simple example:

{% highlight c linenos %}
{% raw %}
int x;
scanf("%d", &x);
int y = x + 5;
if (y == 20) {
  print_flag();
}
{% endraw %}
{% endhighlight %}

Suppose we want Angr to figure out how how to reach line 5 (`print_flag`) of the program during its execution. From a very high level, you can tell Angr that the instruction corresponding to what happens at line 4 is an address that you want it to find, and Angr will be able to work backwards and deduce symbolically that we need to constrain `y = 20`, which implies that we have to then constrain `x=15`, and so the user input from stdin must correspond to 15.

Of course, this is a very contrived example, and in practice the constraints are usually in ranges (i.e `x > 0`), and you can end up with a lot of potential inputs for a desired output (maybe even infinitely many). When situations like this happens, you can ask Angr to return an arbitrary valid input, or return `n` such inputs, and many other options which you can refer to [here](https://docs.angr.io/core-concepts/solver#more-solving-methods).

### Bomblab
Now that we have a basic understanding of what Angr is and what symbolic execution is about, let's put our newfound skills to the test! I decided to try it out with Carnegie Mellon's Bomb Lab (you can download it [here](http://csapp.cs.cmu.edu/3e/bomb.tar)). It is the second lab for the class 15-213 Introduction to Computer Systems in CMU which I took last year, and which is a required class for all computer science majors. Back then when I took the class, I printed out the disassembly from `objdump` onto paper and traced all of the function calls and loops manually. I also did some basic dynamic analysis with `gdb` to debug my inputs and confirm that my intuition for what was happening was correct. It was a slow but fun and rewarding process.

Let's see how easily we can solve Bomblab with Angr together! I have structured this walkthrough into 7 separate posts, one post for each phase of the bomb (including the secret phase). I will also approach it without relying on any prior knowledge of the phases. Without further ado, let's get started!

### Phase 1
It's always good to first check the attributes of the binary. The main thing I am concerned about is PIE (position independent code), because that would potentially make referencing addresses more difficult (Angr does have support for PIE though):

{% highlight bash linenos %}
{% raw %}
$ checksec bomb
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
{% endraw %}
{% endhighlight %}

Awesome, we see that there is no PIE, and that this is also a 64 bit binary.

Let's create a new Angr project skeleton:

{% highlight python linenos %}
{% raw %}
import angr
import claripy
import sys

def phase_1(argv):
    # Create an Angr project.
    path_to_binary = argv[1] # :string
    project = angr.Project(path_to_binary)

if __name__ == '__main__':
    phase_1(sys.argv)
{% endraw %}
{% endhighlight %}


Now let's look at the disassembly in gdb (truncated to the interesting parts for brevity):

{% highlight c linenos %}
{% raw %}
   0x0000000000400e19 <+121>:	call   0x4013a2 <initialize_bomb>
   0x0000000000400e1e <+126>:	mov    edi,0x402338
   0x0000000000400e23 <+131>:	call   0x400b10 <puts@plt>
   0x0000000000400e28 <+136>:	mov    edi,0x402378
   0x0000000000400e2d <+141>:	call   0x400b10 <puts@plt>
   0x0000000000400e32 <+146>:	call   0x40149e <read_line>
   0x0000000000400e37 <+151>:	mov    rdi,rax
   0x0000000000400e3a <+154>:	call   0x400ee0 <phase_1>
   0x0000000000400e3f <+159>:	call   0x4015c4 <phase_defused>
   0x0000000000400e44 <+164>:	mov    edi,0x4023a8
   0x0000000000400e49 <+169>:	call   0x400b10 <puts@plt>
   0x0000000000400e4e <+174>:	call   0x40149e <read_line>
   0x0000000000400e53 <+179>:	mov    rdi,rax
   0x0000000000400e56 <+182>:	call   0x400efc <phase_2>
   0x0000000000400e5b <+187>:	call   0x4015c4 <phase_defused>
   0x0000000000400e60 <+192>:	mov    edi,0x4022ed
   0x0000000000400e65 <+197>:	call   0x400b10 <puts@plt>
   0x0000000000400e6a <+202>:	call   0x40149e <read_line>
   0x0000000000400e6f <+207>:	mov    rdi,rax
   0x0000000000400e72 <+210>:	call   0x400f43 <phase_3>
   0x0000000000400e77 <+215>:	call   0x4015c4 <phase_defused>
   0x0000000000400e7c <+220>:	mov    edi,0x40230b
   0x0000000000400e81 <+225>:	call   0x400b10 <puts@plt>
   0x0000000000400e86 <+230>:	call   0x40149e <read_line>
   0x0000000000400e8b <+235>:	mov    rdi,rax
   0x0000000000400e8e <+238>:	call   0x40100c <phase_4>
   0x0000000000400e93 <+243>:	call   0x4015c4 <phase_defused>
   0x0000000000400e98 <+248>:	mov    edi,0x4023d8
   0x0000000000400e9d <+253>:	call   0x400b10 <puts@plt>
   0x0000000000400ea2 <+258>:	call   0x40149e <read_line>
   0x0000000000400ea7 <+263>:	mov    rdi,rax
   0x0000000000400eaa <+266>:	call   0x401062 <phase_5>
   0x0000000000400eaf <+271>:	call   0x4015c4 <phase_defused>
   0x0000000000400eb4 <+276>:	mov    edi,0x40231a
   0x0000000000400eb9 <+281>:	call   0x400b10 <puts@plt>
   0x0000000000400ebe <+286>:	call   0x40149e <read_line>
   0x0000000000400ec3 <+291>:	mov    rdi,rax
   0x0000000000400ec6 <+294>:	call   0x4010f4 <phase_6>
   0x0000000000400ecb <+299>:	call   0x4015c4 <phase_defused>
{% endraw %}
{% endhighlight %}

Here we see that there are 6 phases in the `main` function, which are logically isolated from one another. We also see that it calls a `read_line` function, which is not a standard glibc function. Let's look at `phase_1`:


{% highlight c linenos %}
{% raw %}
gef➤  disas phase_1
Dump of assembler code for function phase_1:
   0x0000000000400ee0 <+0>:	sub    rsp,0x8
   0x0000000000400ee4 <+4>:	mov    esi,0x402400
   0x0000000000400ee9 <+9>:	call   0x401338 <strings_not_equal>
   0x0000000000400eee <+14>:	test   eax,eax
   0x0000000000400ef0 <+16>:	je     0x400ef7 <phase_1+23>
   0x0000000000400ef2 <+18>:	call   0x40143a <explode_bomb>
   0x0000000000400ef7 <+23>:	add    rsp,0x8
   0x0000000000400efb <+27>:	ret 
{% endraw %}
{% endhighlight %}

What it does is really simple - compare the user input to the string at 0x402400, and we easily solve it without Angr. But let's try doing it with Angr anyway, because it will yield several valuable learning points.

The first thing to take note of is that user input is being read with a custom `read_line` function. Let's take a look at that:

{% highlight c linenos %}
{% raw %}
   0x000000000040149e <+0>:	sub    rsp,0x8
   0x00000000004014a2 <+4>:	mov    eax,0x0
   0x00000000004014a7 <+9>:	call   0x4013f9 <skip>
   0x00000000004014ac <+14>:	test   rax,rax
   0x00000000004014af <+17>:	jne    0x40151f <read_line+129>
   0x00000000004014b1 <+19>:	mov    rax,QWORD PTR [rip+0x202290]        # 0x603748 <stdin@@GLIBC_2.2.5>
   0x00000000004014b8 <+26>:	cmp    QWORD PTR [rip+0x2022a9],rax        # 0x603768 <infile>
   0x00000000004014bf <+33>:	jne    0x4014d5 <read_line+55>
   0x00000000004014c1 <+35>:	mov    edi,0x4025d5
   0x00000000004014c6 <+40>:	call   0x400b10 <puts@plt>
   0x00000000004014cb <+45>:	mov    edi,0x8
   0x00000000004014d0 <+50>:	call   0x400c20 <exit@plt>
   0x00000000004014d5 <+55>:	mov    edi,0x4025f3
   0x00000000004014da <+60>:	call   0x400ae0 <getenv@plt>
   0x00000000004014df <+65>:	test   rax,rax
   0x00000000004014e2 <+68>:	je     0x4014ee <read_line+80>
   0x00000000004014e4 <+70>:	mov    edi,0x0
   0x00000000004014e9 <+75>:	call   0x400c20 <exit@plt>
   0x00000000004014ee <+80>:	mov    rax,QWORD PTR [rip+0x202253]        # 0x603748 <stdin@@GLIBC_2.2.5>
   0x00000000004014f5 <+87>:	mov    QWORD PTR [rip+0x20226c],rax        # 0x603768 <infile>
   0x00000000004014fc <+94>:	mov    eax,0x0
   0x0000000000401501 <+99>:	call   0x4013f9 <skip>
   0x0000000000401506 <+104>:	test   rax,rax
   0x0000000000401509 <+107>:	jne    0x40151f <read_line+129>
   0x000000000040150b <+109>:	mov    edi,0x4025d5
   0x0000000000401510 <+114>:	call   0x400b10 <puts@plt>
   0x0000000000401515 <+119>:	mov    edi,0x0
   0x000000000040151a <+124>:	call   0x400c20 <exit@plt>
   0x000000000040151f <+129>:	mov    edx,DWORD PTR [rip+0x20223b]        # 0x603760 <num_input_strings>
   0x0000000000401525 <+135>:	movsxd rax,edx
   0x0000000000401528 <+138>:	lea    rsi,[rax+rax*4]
   0x000000000040152c <+142>:	shl    rsi,0x4
   0x0000000000401530 <+146>:	add    rsi,0x603780
   0x0000000000401537 <+153>:	mov    rdi,rsi
   0x000000000040153a <+156>:	mov    eax,0x0
   0x000000000040153f <+161>:	mov    rcx,0xffffffffffffffff
   0x0000000000401546 <+168>:	repnz scas al,BYTE PTR es:[rdi]
   0x0000000000401548 <+170>:	not    rcx
   0x000000000040154b <+173>:	sub    rcx,0x1
   0x000000000040154f <+177>:	cmp    ecx,0x4e
   0x0000000000401552 <+180>:	jle    0x40159a <read_line+252>
   0x0000000000401554 <+182>:	mov    edi,0x4025fe
   0x0000000000401559 <+187>:	call   0x400b10 <puts@plt>
   0x000000000040155e <+192>:	mov    eax,DWORD PTR [rip+0x2021fc]        # 0x603760 <num_input_strings>
   0x0000000000401564 <+198>:	lea    edx,[rax+0x1]
   0x0000000000401567 <+201>:	mov    DWORD PTR [rip+0x2021f3],edx        # 0x603760 <num_input_strings>
   0x000000000040156d <+207>:	cdqe   
   0x000000000040156f <+209>:	imul   rax,rax,0x50
   0x0000000000401573 <+213>:	movabs rdi,0x636e7572742a2a2a
   0x000000000040157d <+223>:	mov    QWORD PTR [rax+0x603780],rdi
   0x0000000000401584 <+230>:	movabs rdi,0x2a2a2a64657461
   0x000000000040158e <+240>:	mov    QWORD PTR [rax+0x603788],rdi
   0x0000000000401595 <+247>:	call   0x40143a <explode_bomb>
   0x000000000040159a <+252>:	sub    ecx,0x1
   0x000000000040159d <+255>:	movsxd rcx,ecx
   0x00000000004015a0 <+258>:	movsxd rax,edx
   0x00000000004015a3 <+261>:	lea    rax,[rax+rax*4]
   0x00000000004015a7 <+265>:	shl    rax,0x4
   0x00000000004015ab <+269>:	mov    BYTE PTR [rcx+rax*1+0x603780],0x0
   0x00000000004015b3 <+277>:	add    edx,0x1
   0x00000000004015b6 <+280>:	mov    DWORD PTR [rip+0x2021a4],edx        # 0x603760 <num_input_strings>
   0x00000000004015bc <+286>:	mov    rax,rsi
   0x00000000004015bf <+289>:	add    rsp,0x8
   0x00000000004015c3 <+293>:	ret    
{% endraw %}
{% endhighlight %}

We don't see any functions which reads in input directly being called, like scanf, read, or fgets. Digging further though, we see that the input is actually being read in the `skip` function, which calls fgets:

{% highlight c linenos %}
{% raw %}
gef➤  disas 0x4013f9
Dump of assembler code for function skip:
   0x00000000004013f9 <+0>:	push   rbx
   0x00000000004013fa <+1>:	movsxd rax,DWORD PTR [rip+0x20235f]        # 0x603760 <num_input_strings>
   0x0000000000401401 <+8>:	lea    rdi,[rax+rax*4]
   0x0000000000401405 <+12>:	shl    rdi,0x4
   0x0000000000401409 <+16>:	add    rdi,0x603780
   0x0000000000401410 <+23>:	mov    rdx,QWORD PTR [rip+0x202351]        # 0x603768 <infile>
   0x0000000000401417 <+30>:	mov    esi,0x50
   0x000000000040141c <+35>:	call   0x400b80 <fgets@plt>
   0x0000000000401421 <+40>:	mov    rbx,rax
   0x0000000000401424 <+43>:	test   rax,rax
   0x0000000000401427 <+46>:	je     0x401435 <skip+60>
   0x0000000000401429 <+48>:	mov    rdi,rax
   0x000000000040142c <+51>:	call   0x4013bc <blank_line>
   0x0000000000401431 <+56>:	test   eax,eax
   0x0000000000401433 <+58>:	jne    0x4013fa <skip+1>
   0x0000000000401435 <+60>:	mov    rax,rbx
   0x0000000000401438 <+63>:	pop    rbx
   0x0000000000401439 <+64>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

The point here is that we don't want to reverse precisely what `read_line` does, and just rely on our intuition that it basically reads in a line. We also see that there are a couple of checks in the loops, which can potentially lead to state explosion. 

### State Explosion
State explosion is an extremely important concept in symbolic execution, and it is the primary reason why achieving general symbolic execution is hard. With every branch, our number of states double. This exponential growth in the number of states can quickly render our search infeasible, which is why it is important for us to limit the number of potential paths as much as possible. Doing this automatically is currently an area of active research. There is a great paper from CMU titled [Enhancing Symbolic Execution with Veritesting](https://users.ece.cmu.edu/~aavgerin/papers/veritesting-icse-2014.pdf), which introduces the idea of veritesting in order to mitigate state explosion. This is achieved by combining both static and dynamic symbolic execution to produce heuristics to avoid states which are likely to lead to failure, and by combining branches. Angr does support veritesting in its simulation manager, but this is out of scope for this series. Do read the paper if you are interested for more!

In order to prevent that, we will inject our own symbolic memory for the input instead, and bypass the `read_line` function entirely.

If we look at the disassembly for `main`, the place where we call `phase_1` is a good point to start program execution. We can then simply pass the symbolic input in the `rdi` register!

{% highlight python linenos %}
{% raw %}
    # Tell Angr where to start executing 
    start_addr = 0x00400e3a
    initial_state = project.factory.blank_state(addr=start_addr)

    fake_addr = 0x40000000
    phase_1_input = claripy.BVS('phase_1_input', 100 * 8)
    initial_state.memory.store(fake_addr, phase_1_input)
    initial_state.regs.rdi = fake_addr
{% endraw %}
{% endhighlight %}

`claripy.BVS` creates a symbolic value referred to by `phase_1_input`, with a size of 100 bytes or 100 * 8 bits. 100 bytes should be big enough, if Angr is unable to find a solution, we can always add more. BVS stands for bit vector symbolic. It has a cousin, BVV, which stands for bit vector value, that holds concrete values. Our string input value is stored at `fake_addr`. `fake_addr` was chosen arbitrarily, it can simply be any area of memory not being used by any of the other sections (text, heap, stack, libs) during execution. So with this, we have now a reference to our symbolic bit vector in `rdi`!

Now, if we look back at the disassembly for `phase_1`, we see that it primarily calls `strings_not_equal`. We have a hunch about what it does, let's look at it in assembly:

{% highlight c linenos %}
{% raw %}
gef➤  disas strings_not_equal
Dump of assembler code for function strings_not_equal:
   0x0000000000401338 <+0>:	push   r12
   0x000000000040133a <+2>:	push   rbp
   0x000000000040133b <+3>:	push   rbx
   0x000000000040133c <+4>:	mov    rbx,rdi
   0x000000000040133f <+7>:	mov    rbp,rsi
   0x0000000000401342 <+10>:	call   0x40131b <string_length>
   0x0000000000401347 <+15>:	mov    r12d,eax
   0x000000000040134a <+18>:	mov    rdi,rbp
   0x000000000040134d <+21>:	call   0x40131b <string_length>
   0x0000000000401352 <+26>:	mov    edx,0x1
   0x0000000000401357 <+31>:	cmp    r12d,eax
   0x000000000040135a <+34>:	jne    0x40139b <strings_not_equal+99>
   0x000000000040135c <+36>:	movzx  eax,BYTE PTR [rbx]
   0x000000000040135f <+39>:	test   al,al
   0x0000000000401361 <+41>:	je     0x401388 <strings_not_equal+80>
   0x0000000000401363 <+43>:	cmp    al,BYTE PTR [rbp+0x0]
   0x0000000000401366 <+46>:	je     0x401372 <strings_not_equal+58>
   0x0000000000401368 <+48>:	jmp    0x40138f <strings_not_equal+87>
   0x000000000040136a <+50>:	cmp    al,BYTE PTR [rbp+0x0]
   0x000000000040136d <+53>:	nop    DWORD PTR [rax]
   0x0000000000401370 <+56>:	jne    0x401396 <strings_not_equal+94>
   0x0000000000401372 <+58>:	add    rbx,0x1
   0x0000000000401376 <+62>:	add    rbp,0x1
   0x000000000040137a <+66>:	movzx  eax,BYTE PTR [rbx]
   0x000000000040137d <+69>:	test   al,al
   0x000000000040137f <+71>:	jne    0x40136a <strings_not_equal+50>
   0x0000000000401381 <+73>:	mov    edx,0x0
   0x0000000000401386 <+78>:	jmp    0x40139b <strings_not_equal+99>
   0x0000000000401388 <+80>:	mov    edx,0x0
   0x000000000040138d <+85>:	jmp    0x40139b <strings_not_equal+99>
   0x000000000040138f <+87>:	mov    edx,0x1
   0x0000000000401394 <+92>:	jmp    0x40139b <strings_not_equal+99>
   0x0000000000401396 <+94>:	mov    edx,0x1
   0x000000000040139b <+99>:	mov    eax,edx
   0x000000000040139d <+101>:	pop    rbx
   0x000000000040139e <+102>:	pop    rbp
   0x000000000040139f <+103>:	pop    r12
   0x00000000004013a1 <+105>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

Again, we see lots of comparisons and jumps, which is what we don't like since it can easily lead to state explosion. We can solve this by using a hook, which is a way of overwriting instructions to call our own instructions instead. Angr provides an easy way to do this via what is known as a SimProcedure, which allows you to replace a function with one that you write in Python:

{% highlight python linenos %}
{% raw %}
    class ReplacementStringsNotEqual(angr.SimProcedure):
        def run(self, string_1_address, string_2_address):
            # Load 100 bytes from string_1_address to string_1
            string_1 = self.state.memory.load(
                string_1_address,
                100
            )

            # Load 100 bytes from string_2_address to string_2
            string_2 = self.state.memory.load(
                string_2_address,
                100
            )

            return claripy.If(
                string_1 == string_2,
                claripy.BVV(0, 32),
                claripy.BVV(1, 32)
            )

    strings_not_equal_symbol = 'strings_not_equal'
    project.hook_symbol(strings_not_equal_symbol, ReplacementStringsNotEqual())
{% endraw %}
{% endhighlight %}

In this code snippet, we replace all function calls to `'strings_not_equal'` to our own function defined in `ReplacementStringsNotEqual`. We can use `project.hook_symbol` because the binary includes debugging symbols, which are debugging information that was not stripped by the compiler after compilation. While it makes the binary larger, it is useful as it makes debugging with a debugger easier. However, if you encounter stripped binaries, then you would need to hook by the address of the function instead. 

Recall that `strings_not_equal` takes in two string pointers as input, and therefore we need to load it into memory first. `state.memory.load(addr, size)` allows us to load `size` number of bytes from `address` to a variable. We can then compare the two input strings, and return 0 or 1 accordingly. We then return a concrete 32 bit integer value of either 0 or 1, depending on the results of the comparison. Note that we cannot directly return a Python integer, because Python integers do not have sizes.

We are now done with the basic set-up. Add the following lines to create a simulation manager, which will help to explore our states later on:

{% highlight python linenos %}
{% raw %}
    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)
{% endraw %}
{% endhighlight %}

### Find and Avoid
Now we are faced with the question of how to tell Angr what we want it to do. 

{% highlight python linenos %}
{% raw %}
    # Defines when we have hit a successful state 
    def is_successful(state):
        # Dump whatever has been printed out by the binary so far into a string.
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return b"Phase 1 defused" in stdout_output

    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=is_successful, avoid=explode_addr)
{% endraw %}
{% endhighlight %}

The above introduces a few new concepts. Let's start from the end - `simulation.explore` tells Angr to explore states starting from our initial state, and to terminate whenever it has found something that matches the `find` condition, and also to stop exploring states that have fulfilled the `avoid` condition. Our `find=is_successful` condition is what happens when we clear the stage. We see in the disassembly of `main` that after `phase_defused` is called after `phase_1`, we call `puts` with `0x4023a8`, which corresponds to:

{% highlight python linenos %}
{% raw %}
gef➤  x/s 0x4023a8
0x4023a8:	"Phase 1 defused. How about the next one?"
{% endraw %}
{% endhighlight %}

So what `is_successful` does is that if Angr ever sees "Phase 1 defused" from stdout of the program, it will know that it has succeeded.

On the flipside, `explode_addr` is set to the address of `explode_bomb`, which we can see in the disassembly of Phase 1:

{% highlight python linenos %}
{% raw %}
gef➤  disas phase_1
Dump of assembler code for function phase_1:
   0x0000000000400ee0 <+0>:	sub    rsp,0x8
   0x0000000000400ee4 <+4>:	mov    esi,0x402400
   0x0000000000400ee9 <+9>:	call   0x401338 <strings_not_equal>
   0x0000000000400eee <+14>:	test   eax,eax
   0x0000000000400ef0 <+16>:	je     0x400ef7 <phase_1+23>
   0x0000000000400ef2 <+18>:	call   0x40143a <explode_bomb>
   0x0000000000400ef7 <+23>:	add    rsp,0x8
   0x0000000000400efb <+27>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

This tells Angr to avoid calling `explode_bomb` and truncate such states from its search.

Finally, we check if we are able to find a solution:

{% highlight python linenos %}
{% raw %}
    # Check that we have found a solution
    if simulation.found:
        solution_state = simulation.found[0]

        # Case symbolic value to bytes
        solution = solution_state.se.eval(phase_1_input, cast_to=bytes)
        print(solution)
    else:
        raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

Here, if a solution was found, we convert our symbolic `phase_1_input` value into bytes and print it, and if not, an exception is raised.

### Full Solution Script
The full solution script for Phase 1 is below:

{% highlight python linenos %}
{% raw %}
import angr
import claripy
import sys

def phase_1(argv):
    # Create an Angr project.
    path_to_binary = argv[1] # :string
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x00400e3a
    initial_state = project.factory.blank_state(addr=start_addr)

    fake_addr = 0x40000000
    phase_1_input = claripy.BVS('phase_1_input', 100 * 8)
    initial_state.memory.store(fake_addr, phase_1_input)
    initial_state.regs.rdi = fake_addr

    class ReplacementStringsNotEqual(angr.SimProcedure):
        def run(self, string_1_address, string_2_address):
            # Load 100 bytes from string_1_address to string_1
            string_1 = self.state.memory.load(
                string_1_address,
                100
            )

            # Load 100 bytes from string_2_address to string_2
            string_2 = self.state.memory.load(
                string_2_address,
                100
            )

            return claripy.If(
                string_1 == string_2,
                claripy.BVV(0, 32),
                claripy.BVV(1, 32)
            )

    strings_not_equal_symbol = 'strings_not_equal'
    project.hook_symbol(strings_not_equal_symbol, ReplacementStringsNotEqual())

    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    # Defines when we have hit a successful state 
    def is_successful(state):
        # Dump whatever has been printed out by the binary so far into a string.
        stdout_output = state.posix.dumps(sys.stdout.fileno())

        return b"Phase 1 defused" in stdout_output # :boolean

    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=is_successful, avoid=explode_addr)

    # Check that we have found a solution
    if simulation.found:
        solution_state = simulation.found[0]

        # Case symbolic value to bytes
        solution = solution_state.se.eval(phase_1_input, cast_to=bytes)
        print(solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    phase_1(sys.argv)
{% endraw %}
{% endhighlight %}

And if we run it, we get the following output:

{% highlight python linenos %}
{% raw %}
$ python solve.py bomb
WARNING | 2020-07-30 21:27:56,670 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-07-30 21:27:56,670 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-07-30 21:27:56,670 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-07-30 21:27:56,671 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-07-30 21:27:56,671 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-07-30 21:27:56,671 | angr.state_plugins.symbolic_memory | Filling register 20 with 4 unconstrained bytes referenced from 0x400eee (phase_1+0xe in bomb (0x400eee))
CRITICAL | 2020-07-30 21:27:56,752 | angr.sim_state | The name state.se is deprecated; please use state.solver.
b"Border relations with Canada have never been better.\x00\x00\x00\x00Wow! You've defused the secret stage!\x00flyers"
{% endraw %}
{% endhighlight %}

Because we specified 100 bytes for our symbolic input, we got 100 bytes back. Since strings are null terminated, our correct input for phase 1 is therefore "Border relations with Canada have never been better.". We verify that it works when run with the actual binary:

{% highlight c linenos %}
{% raw %}
$ ./bomb
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Border relations with Canada have never been better.
Phase 1 defused. How about the next one?
{% endraw %}
{% endhighlight %}

Awesome! I hope you have enjoyed the first part of this series and that it was helpful to you :). You can continue on to the second part [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-2).
