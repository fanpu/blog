---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 6"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/lake_placid.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

Hello from Part 6 of this series on cracking CMU's Bomblab with Angr. If you are new here, I would recommend starting with part 1 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit).

### Phase 6

Let's disassemble Phase 6:

{% highlight c linenos %}
{% raw %}
gef➤  disas phase_6
Dump of assembler code for function phase_6:
   0x00000000004010f4 <+0>:	push   r14
   0x00000000004010f6 <+2>:	push   r13
   0x00000000004010f8 <+4>:	push   r12
   0x00000000004010fa <+6>:	push   rbp
   0x00000000004010fb <+7>:	push   rbx
   0x00000000004010fc <+8>:	sub    rsp,0x50
   0x0000000000401100 <+12>:	mov    r13,rsp
   0x0000000000401103 <+15>:	mov    rsi,rsp
   0x0000000000401106 <+18>:	call   0x40145c <read_six_numbers>
   0x000000000040110b <+23>:	mov    r14,rsp
   0x000000000040110e <+26>:	mov    r12d,0x0
   0x0000000000401114 <+32>:	mov    rbp,r13
   0x0000000000401117 <+35>:	mov    eax,DWORD PTR [r13+0x0]
   0x000000000040111b <+39>:	sub    eax,0x1
   0x000000000040111e <+42>:	cmp    eax,0x5
   0x0000000000401121 <+45>:	jbe    0x401128 <phase_6+52>
   0x0000000000401123 <+47>:	call   0x40143a <explode_bomb>
   0x0000000000401128 <+52>:	add    r12d,0x1
   0x000000000040112c <+56>:	cmp    r12d,0x6
   0x0000000000401130 <+60>:	je     0x401153 <phase_6+95>
   0x0000000000401132 <+62>:	mov    ebx,r12d
   0x0000000000401135 <+65>:	movsxd rax,ebx
   0x0000000000401138 <+68>:	mov    eax,DWORD PTR [rsp+rax*4]
   0x000000000040113b <+71>:	cmp    DWORD PTR [rbp+0x0],eax
   0x000000000040113e <+74>:	jne    0x401145 <phase_6+81>
   0x0000000000401140 <+76>:	call   0x40143a <explode_bomb>
   0x0000000000401145 <+81>:	add    ebx,0x1
   0x0000000000401148 <+84>:	cmp    ebx,0x5
   0x000000000040114b <+87>:	jle    0x401135 <phase_6+65>
   0x000000000040114d <+89>:	add    r13,0x4
   0x0000000000401151 <+93>:	jmp    0x401114 <phase_6+32>
   0x0000000000401153 <+95>:	lea    rsi,[rsp+0x18]
   0x0000000000401158 <+100>:	mov    rax,r14
   0x000000000040115b <+103>:	mov    ecx,0x7
   0x0000000000401160 <+108>:	mov    edx,ecx
   0x0000000000401162 <+110>:	sub    edx,DWORD PTR [rax]
   0x0000000000401164 <+112>:	mov    DWORD PTR [rax],edx
   0x0000000000401166 <+114>:	add    rax,0x4
   0x000000000040116a <+118>:	cmp    rax,rsi
   0x000000000040116d <+121>:	jne    0x401160 <phase_6+108>
   0x000000000040116f <+123>:	mov    esi,0x0
   0x0000000000401174 <+128>:	jmp    0x401197 <phase_6+163>
   0x0000000000401176 <+130>:	mov    rdx,QWORD PTR [rdx+0x8]
   0x000000000040117a <+134>:	add    eax,0x1
   0x000000000040117d <+137>:	cmp    eax,ecx
   0x000000000040117f <+139>:	jne    0x401176 <phase_6+130>
   0x0000000000401181 <+141>:	jmp    0x401188 <phase_6+148>
   0x0000000000401183 <+143>:	mov    edx,0x6032d0
   0x0000000000401188 <+148>:	mov    QWORD PTR [rsp+rsi*2+0x20],rdx
   0x000000000040118d <+153>:	add    rsi,0x4
   0x0000000000401191 <+157>:	cmp    rsi,0x18
   0x0000000000401195 <+161>:	je     0x4011ab <phase_6+183>
   0x0000000000401197 <+163>:	mov    ecx,DWORD PTR [rsp+rsi*1]
   0x000000000040119a <+166>:	cmp    ecx,0x1
   0x000000000040119d <+169>:	jle    0x401183 <phase_6+143>
   0x000000000040119f <+171>:	mov    eax,0x1
   0x00000000004011a4 <+176>:	mov    edx,0x6032d0
   0x00000000004011a9 <+181>:	jmp    0x401176 <phase_6+130>
   0x00000000004011ab <+183>:	mov    rbx,QWORD PTR [rsp+0x20]
   0x00000000004011b0 <+188>:	lea    rax,[rsp+0x28]
   0x00000000004011b5 <+193>:	lea    rsi,[rsp+0x50]
   0x00000000004011ba <+198>:	mov    rcx,rbx
   0x00000000004011bd <+201>:	mov    rdx,QWORD PTR [rax]
   0x00000000004011c0 <+204>:	mov    QWORD PTR [rcx+0x8],rdx
   0x00000000004011c4 <+208>:	add    rax,0x8
   0x00000000004011c8 <+212>:	cmp    rax,rsi
   0x00000000004011cb <+215>:	je     0x4011d2 <phase_6+222>
   0x00000000004011cd <+217>:	mov    rcx,rdx
   0x00000000004011d0 <+220>:	jmp    0x4011bd <phase_6+201>
   0x00000000004011d2 <+222>:	mov    QWORD PTR [rdx+0x8],0x0
   0x00000000004011da <+230>:	mov    ebp,0x5
   0x00000000004011df <+235>:	mov    rax,QWORD PTR [rbx+0x8]
   0x00000000004011e3 <+239>:	mov    eax,DWORD PTR [rax]
   0x00000000004011e5 <+241>:	cmp    DWORD PTR [rbx],eax
   0x00000000004011e7 <+243>:	jge    0x4011ee <phase_6+250>
   0x00000000004011e9 <+245>:	call   0x40143a <explode_bomb>
   0x00000000004011ee <+250>:	mov    rbx,QWORD PTR [rbx+0x8]
   0x00000000004011f2 <+254>:	sub    ebp,0x1
   0x00000000004011f5 <+257>:	jne    0x4011df <phase_6+235>
   0x00000000004011f7 <+259>:	add    rsp,0x50
   0x00000000004011fb <+263>:	pop    rbx
   0x00000000004011fc <+264>:	pop    rbp
   0x00000000004011fd <+265>:	pop    r12
   0x00000000004011ff <+267>:	pop    r13
   0x0000000000401201 <+269>:	pop    r14
   0x0000000000401203 <+271>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

It looks like it is using the same `read_six_numbers` function from Phase 2, and the six numbers are at the bottom of the stack again. One small difference is that before `read_six_numbers` is called, `r13` is set to `rsp` in line 9. Since `r13` is a callee saved register, we need to initialize it to `rsp`.

 
{% highlight python linenos %}
{% raw %}
def phase_6(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x0040110b
    initial_state = project.factory.blank_state(addr=start_addr)


    num_12 = claripy.BVS('num_12', 64)
    num_34 = claripy.BVS('num_34', 64)
    num_56 = claripy.BVS('num_56', 64)

    initial_state.stack_push(num_56)
    initial_state.stack_push(num_34)
    initial_state.stack_push(num_12)

    # Setup initial registers
    initial_state.regs.r13 = initial_state.regs.rsp
    initial_state.regs.rsi = initial_state.regs.rsp

    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)
{% endraw %}
{% endhighlight %}

With this done, that means we can just re-use the rest of the code for Phase 2 and it will just work, right? Rightttttt?

Well, no, unfortunately not. I tried it and the script ran for 1 minute... 2 minutes... 5 minutes... 10 minutes...,  and I did not have a good feeling about this as my laptop was becoming something of a portable heater at this point. From the disassembly you can see that there are a lot of jumps and comparisons, way more than in previous phases, and this is leading to state explosion. We need to find a better way. 

### Mitigating State Explosion by Splitting Up Analysis
We mitigate the exponential growth in states by decreasing the depth of the search tree of the simulation manager. This can be done by splitting up the function into multiple distinct parts, and then searching through each of them in order. This way, we will search through multiple trees of smaller depths, which could make the problem tractable. Of course, the assumption here is that the function can indeed be split into distinct parts. Let's try to verify this assumption by seeing how the code jumps around. I decided to do this with Radare, which allows us to see this in a more graphical manner. We could manually eyeball it with GDB's output as well, but that is just too painful.

Let's open up Radare, and seek to our `phase_6` function with `s`:

{% highlight c linenos %}
{% raw %}
$ r2 bomb
[0x00400c90]> s sym.phase_6
{% endraw %}
{% endhighlight %}

Now output the disassembly with `pdf`, which stands for Print Disassemble Function:

![Disassembly graph of phase_6](/assets/images/screenshots/phase_6_r2.png)

You can see the lines on the left going up and down. Those represents the jumps that can be taken. We also see that there are some obvious blocks in the structure. My original intuition was that the address at 0x00401158 seemed like a pretty good place to split the blocks, since it just finished a bunch of complicated logic in the first half and it looked like a natural transition point. Let's see how this looks like in code:

{% highlight python linenos %}
{% raw %}
    block_1_end = 0x00401158 # after the first distinct block. Note that this will change later
    block_2_end = 0x00401203 # right before ret

    explode_addr = 0x0040143a # explode_bomb

    # Find all possible ways to reach find condition
    while len(simulation.active) > 0:
        simulation.explore(find=block_1_end, avoid=explode_addr)

    # Find out how many states we have now
    if simulation.found:
        block_1_states = simulation.found
        print("States found after block 1: ", len(block_1_states))
    else:
        raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

I called the two blocks that we divide the function into as `block 1` and `block 2`. `block_1_end` is where we split the two blocks apart. `block_2_end` is simply the end of the function.

An important point to highlight is that instead of just performing `simulation.explore` and `simulation.found` like previously, now we need to find all the states that can reach `block_1_end`. If we just did `simulation.found` instead, it would stop at the first valid solution that it found, which may not include the states that are actually necessary for us to get to the final solution. Therefore, we keep exploring while `simulation.active` is true, which means that there are still available states to explore.

This means that `block_1_states` will hold all the possible states that can reach `block_1_end`, and we can then use each of them as a launching point to reach the end of the function:


{% highlight c linenos %}
{% raw %}
    for state in block_1_states:
        simulation = project.factory.simgr(state)
        simulation.explore(find=block_2_end, avoid=explode_addr)

        # Check whether we found a solution
        if simulation.found:
            solution_state = simulation.found[0]

            num_12_sol = solution_state.se.eval(num_12, cast_to=int)
            num_34_sol = solution_state.se.eval(num_34, cast_to=int)
            num_56_sol = solution_state.se.eval(num_56, cast_to=int)

            def unpack_ints(n):
                lower_32_mask = (1 << 32) - 1
                return (n & lower_32_mask, (n >> 32) & lower_32_mask)

            num_1_sol, num_2_sol = unpack_ints(num_12_sol)
            num_3_sol, num_4_sol = unpack_ints(num_34_sol)
            num_5_sol, num_6_sol = unpack_ints(num_56_sol)

            print(f"{num_1_sol} {num_2_sol} {num_3_sol} {num_4_sol} {num_5_sol} {num_6_sol}")
            return

    raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

In the above, we begin afresh from each of the states that we found in block 1, and then try to see if it leads to a solution. This time round we only need to grab the first valid solution, like usual.

I tried running the script: 

{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
States found after block 1:  1
{% endraw %}
{% endhighlight %}

What?! There is only 1 state found after block 1? That seems like we did not reduce the depth of the search tree by much, since we did not reduce the number of times it branched. Indeed, I kept waiting and waiting and...there was no additional output.

For this to work, we need more states to be found after block 1, the more the merrier (but not so much that now you have state explosion in block 1).

The next address I tried to set `block_1_end` to was `0x00401181`, which is right after another distinct mini logic block:

{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
States found:  10
Block 1 cleared
WARNING | 2020-08-02 23:43:25,320 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-02 23:43:25,320 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-02 23:43:25,320 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-02 23:43:25,320 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-02 23:43:25,320 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-02 23:43:25,320 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0030 with 8 unconstrained bytes referenced from 0x4011fb (phase_6+0x107 in bomb (0x4011fb))
WARNING | 2020-08-02 23:43:25,322 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0038 with 8 unconstrained bytes referenced from 0x4011fc (phase_6+0x108 in bomb (0x4011fc))
WARNING | 2020-08-02 23:43:25,323 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0040 with 8 unconstrained bytes referenced from 0x4011fd (phase_6+0x109 in bomb (0x4011fd))
WARNING | 2020-08-02 23:43:25,324 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0048 with 8 unconstrained bytes referenced from 0x4011ff (phase_6+0x10b in bomb (0x4011ff))
WARNING | 2020-08-02 23:43:25,326 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0050 with 8 unconstrained bytes referenced from 0x401201 (phase_6+0x10d in bomb (0x401201))
CRITICAL | 2020-08-02 23:43:25,330 | angr.sim_state | The name state.se is deprecated; please use state.solver.
4 3 2 1 6 5
{% endraw %}
{% endhighlight %}

We found 10 states after block 1. This is what we like to see! And indeed, after a few minutes of waiting, we get our well-deserved result: `4 3 2 1 6 5`.

### Full Solution Script
{% highlight c linenos %}
{% raw %}
import angr
import claripy
import sys

def phase_6(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x0040110b
    initial_state = project.factory.blank_state(addr=start_addr)

    num_12 = claripy.BVS('num_12', 64)
    num_34 = claripy.BVS('num_34', 64)
    num_56 = claripy.BVS('num_56', 64)

    initial_state.stack_push(num_56)
    initial_state.stack_push(num_34)
    initial_state.stack_push(num_12)

    # Setup initial registers
    initial_state.regs.r13 = initial_state.regs.rsp
    initial_state.regs.rsi = initial_state.regs.rsp

    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    block_1_end = 0x00401181
    block_2_end = 0x00401203 # right before ret

    explode_addr = 0x0040143a # explode_bomb

    # Find all possible ways to reach find condition
    while len(simulation.active) > 0:
        simulation.explore(find=block_1_end, avoid=explode_addr)

    # Find out how many states we have now
    if simulation.found:
        block_1_states = simulation.found
        print("States found after block 1: ", len(block_1_states))
    else:
        raise Exception('Could not find the solution')

    for state in block_1_states:
        simulation = project.factory.simgr(state)
        simulation.explore(find=block_2_end, avoid=explode_addr)

        # Check whether we found a solution
        if simulation.found:
            solution_state = simulation.found[0]

            num_12_sol = solution_state.se.eval(num_12, cast_to=int)
            num_34_sol = solution_state.se.eval(num_34, cast_to=int)
            num_56_sol = solution_state.se.eval(num_56, cast_to=int)

            def unpack_ints(n):
                lower_32_mask = (1 << 32) - 1
                return (n & lower_32_mask, (n >> 32) & lower_32_mask)

            num_1_sol, num_2_sol = unpack_ints(num_12_sol)
            num_3_sol, num_4_sol = unpack_ints(num_34_sol)
            num_5_sol, num_6_sol = unpack_ints(num_56_sol)

            print(f"{num_1_sol} {num_2_sol} {num_3_sol} {num_4_sol} {num_5_sol} {num_6_sol}")
            return

    raise Exception('Could not find the solution')

if __name__ == '__main__':
    phase_6(sys.argv)
{% endraw %}
{% endhighlight %}

Let's try it on the actual binary:

{% highlight c linenos %}
{% raw %}
$ ./bomb
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Border relations with Canada have never been better.
Phase 1 defused. How about the next one?
1 2 4 8 16 32
That's number 2.  Keep going!
1 311
Halfway there!
7 0
So you got that one.  Try this one.
9?>567
Good work!  On to the next...
4 3 2 1 6 5
Congratulations! You've defused the bomb!
{% endraw %}
{% endhighlight %}

It worked! We've come a long way and you should be proud of yourselves. If any of you actually solved this before (wink wink 15-213 students), you would remember how long this phase took, where you would slowly realise that you were dealing with a linked list and then you probably had to graph out the pointers in the linked list to figure out what their relationships were, but Angr solved it without us having to be aware of what is happening at all!

Thanks for reading thus far, and I hope to see you again for the last and final phase - the Secret Phase, which you can find [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-7)!
