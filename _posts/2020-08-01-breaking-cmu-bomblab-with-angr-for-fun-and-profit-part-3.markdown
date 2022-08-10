---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 3"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/lily_mountain.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

We're back now with Part 3 of this series on cracking CMU's Bomblab using Angr! If you are new, I would recommend starting with part 1 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit).

### Phase 3

If you went through what we did for phase 2, the idea behind phase 3 is also super similar.

Start again by creating a function stub for phase 3:

{% highlight python linenos %}
{% raw %}
def phase_3(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)
{% endraw %}
{% endhighlight %}

Let's see the disassembly for Phase 3:

{% highlight c linenos %}
{% raw %}
gef➤  disas phase_3
Dump of assembler code for function phase_3:
   0x0000000000400f43 <+0>:	sub    rsp,0x18
   0x0000000000400f47 <+4>:	lea    rcx,[rsp+0xc]
   0x0000000000400f4c <+9>:	lea    rdx,[rsp+0x8]
   0x0000000000400f51 <+14>:	mov    esi,0x4025cf
   0x0000000000400f56 <+19>:	mov    eax,0x0
   0x0000000000400f5b <+24>:	call   0x400bf0 <__isoc99_sscanf@plt>
   0x0000000000400f60 <+29>:	cmp    eax,0x1
   0x0000000000400f63 <+32>:	jg     0x400f6a <phase_3+39>
   0x0000000000400f65 <+34>:	call   0x40143a <explode_bomb>
   0x0000000000400f6a <+39>:	cmp    DWORD PTR [rsp+0x8],0x7
   0x0000000000400f6f <+44>:	ja     0x400fad <phase_3+106>
   0x0000000000400f71 <+46>:	mov    eax,DWORD PTR [rsp+0x8]
   0x0000000000400f75 <+50>:	jmp    QWORD PTR [rax*8+0x402470]
   0x0000000000400f7c <+57>:	mov    eax,0xcf
   0x0000000000400f81 <+62>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f83 <+64>:	mov    eax,0x2c3
   0x0000000000400f88 <+69>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f8a <+71>:	mov    eax,0x100
   0x0000000000400f8f <+76>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f91 <+78>:	mov    eax,0x185
   0x0000000000400f96 <+83>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f98 <+85>:	mov    eax,0xce
   0x0000000000400f9d <+90>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f9f <+92>:	mov    eax,0x2aa
   0x0000000000400fa4 <+97>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400fa6 <+99>:	mov    eax,0x147
   0x0000000000400fab <+104>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400fad <+106>:	call   0x40143a <explode_bomb>
   0x0000000000400fb2 <+111>:	mov    eax,0x0
   0x0000000000400fb7 <+116>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400fb9 <+118>:	mov    eax,0x137
   0x0000000000400fbe <+123>:	cmp    eax,DWORD PTR [rsp+0xc]
   0x0000000000400fc2 <+127>:	je     0x400fc9 <phase_3+134>
   0x0000000000400fc4 <+129>:	call   0x40143a <explode_bomb>
   0x0000000000400fc9 <+134>:	add    rsp,0x18
   0x0000000000400fcd <+138>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

We see a `sscanf` call, which reads formatted input from a string. This is probably what builds the arguments, based on the previous `read_line` call, since `rdi` is not modified before `sscanf` is called. Let's check out the format string that was passed in:

{% highlight c linenos %}
{% raw %}
gef➤  x/s 0x4025cf
0x4025cf:	"%d %d"
{% endraw %}
{% endhighlight %}

Cool, so two integers. We can follow more or less the same format as in Phase 2 by pushing these two values onto the stack. We define the start address to be the instruction after the `sscanf` call:

{% highlight python linenos %}
{% raw %}
    start_addr = 0x00400f60
    initial_state = project.factory.blank_state(addr=start_addr)

    num_12 = claripy.BVS('num_12', 64)

    initial_state.stack_push(num_12)
{% endraw %}
{% endhighlight %}

However, there is one major difference. In Phase 2, our arguments were at the bottom of the stack, and so we could just push them onto the stack. However, in this case, we see that we have a stack size of 0x18 from line 3, but the addresses of the two arguments that were populated by `sscanf` are `rsp + 0xc` and `rsp + 0x8` respectively. This means that we need an additional 8 bytes of padding afterwards:

{% highlight python linenos %}
{% raw %}
    padding_length_in_bytes = 8
    initial_state.regs.rsp -= padding_length_in_bytes
{% endraw %}
{% endhighlight %}

Let's set our find condition to be right before the `ret`, and avoid to be `explode_bomb` as usual, and then copy and paste what we had for Phase 2 to extract the solution:

{% highlight python linenos %}
{% raw %}
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00400fcd # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)

    # Check that we have found a solution
    if simulation.found:
        solution_state = simulation.found[0]

        num_12_sol = solution_state.se.eval(num_12, cast_to=int)

        def unpack_ints(n):
            lower_32_mask = (1 << 32) - 1
            return (n & lower_32_mask, (n >> 32) & lower_32_mask)

        num_1_sol, num_2_sol = unpack_ints(num_12_sol)

        print(f"{num_1_sol} {num_2_sol}")
    else:
        raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

### Full Solution Script


{% highlight python linenos %}
{% raw %}
import angr
import claripy
import sys

def phase_3(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x00400f60
    initial_state = project.factory.blank_state(addr=start_addr)

    num_12 = claripy.BVS('num_12', 64)

    initial_state.stack_push(num_12)

    padding_length_in_bytes = 8
    initial_state.regs.rsp -= padding_length_in_bytes

    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00400fcd # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)

    # Check that we have found a solution
    if simulation.found:
        solution_state = simulation.found[0]

        num_12_sol = solution_state.se.eval(num_12, cast_to=int)

        def unpack_ints(n):
            lower_32_mask = (1 << 32) - 1
            return (n & lower_32_mask, (n >> 32) & lower_32_mask)

        num_1_sol, num_2_sol = unpack_ints(num_12_sol)

        print(f"{num_1_sol} {num_2_sol}")
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    phase_3(sys.argv)
{% endraw %}
{% endhighlight %}

Let's try running it:

{% highlight c linenos %}
{% raw %}
$ solve.py bomb
WARNING | 2020-08-02 19:42:16,368 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-02 19:42:16,368 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-02 19:42:16,368 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-02 19:42:16,369 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-02 19:42:16,369 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-02 19:42:16,369 | angr.state_plugins.symbolic_memory | Filling register rax with 8 unconstrained bytes referenced from 0x400f60 (phase_3+0x1d in bomb (0x400f60))
CRITICAL | 2020-08-02 19:42:17,120 | angr.sim_state | The name state.se is deprecated; please use state.solver.
1 311
{% endraw %}
{% endhighlight %}

Now using the solution on the actual bomb:

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
{% endraw %}
{% endhighlight %}

Nice, it worked, and this was pretty fast too given how similar it was to phase 2! You can continue to Part 4 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-4)
