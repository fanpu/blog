---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 4"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/erie.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

Welcome back to Part 4 of cracking CMU's Bomblab using Angr! If you just stumbled upon this, I would recommend starting with part 1 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit).

### Phase 4

Let's disassemble Phase 4:

{% highlight c linenos %}
{% raw %}
gef➤  disas phase_4
Dump of assembler code for function phase_4:
   0x000000000040100c <+0>:	sub    rsp,0x18
   0x0000000000401010 <+4>:	lea    rcx,[rsp+0xc]
   0x0000000000401015 <+9>:	lea    rdx,[rsp+0x8]
   0x000000000040101a <+14>:	mov    esi,0x4025cf
   0x000000000040101f <+19>:	mov    eax,0x0
   0x0000000000401024 <+24>:	call   0x400bf0 <__isoc99_sscanf@plt>
   0x0000000000401029 <+29>:	cmp    eax,0x2
   0x000000000040102c <+32>:	jne    0x401035 <phase_4+41>
   0x000000000040102e <+34>:	cmp    DWORD PTR [rsp+0x8],0xe
   0x0000000000401033 <+39>:	jbe    0x40103a <phase_4+46>
   0x0000000000401035 <+41>:	call   0x40143a <explode_bomb>
   0x000000000040103a <+46>:	mov    edx,0xe
   0x000000000040103f <+51>:	mov    esi,0x0
   0x0000000000401044 <+56>:	mov    edi,DWORD PTR [rsp+0x8]
   0x0000000000401048 <+60>:	call   0x400fce <func4>
   0x000000000040104d <+65>:	test   eax,eax
   0x000000000040104f <+67>:	jne    0x401058 <phase_4+76>
   0x0000000000401051 <+69>:	cmp    DWORD PTR [rsp+0xc],0x0
   0x0000000000401056 <+74>:	je     0x40105d <phase_4+81>
   0x0000000000401058 <+76>:	call   0x40143a <explode_bomb>
   0x000000000040105d <+81>:	add    rsp,0x18
   0x0000000000401061 <+85>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

The `sscanf` and the call to `func4` is interesting. Let's check out `func4` first:

{% highlight c linenos %}
{% raw %}
gef➤  disas func4
Dump of assembler code for function func4:
   0x0000000000400fce <+0>:	sub    rsp,0x8
   0x0000000000400fd2 <+4>:	mov    eax,edx
   0x0000000000400fd4 <+6>:	sub    eax,esi
   0x0000000000400fd6 <+8>:	mov    ecx,eax
   0x0000000000400fd8 <+10>:	shr    ecx,0x1f
   0x0000000000400fdb <+13>:	add    eax,ecx
   0x0000000000400fdd <+15>:	sar    eax,1
   0x0000000000400fdf <+17>:	lea    ecx,[rax+rsi*1]
   0x0000000000400fe2 <+20>:	cmp    ecx,edi
   0x0000000000400fe4 <+22>:	jle    0x400ff2 <func4+36>
   0x0000000000400fe6 <+24>:	lea    edx,[rcx-0x1]
   0x0000000000400fe9 <+27>:	call   0x400fce <func4>
   0x0000000000400fee <+32>:	add    eax,eax
   0x0000000000400ff0 <+34>:	jmp    0x401007 <func4+57>
   0x0000000000400ff2 <+36>:	mov    eax,0x0
   0x0000000000400ff7 <+41>:	cmp    ecx,edi
   0x0000000000400ff9 <+43>:	jge    0x401007 <func4+57>
   0x0000000000400ffb <+45>:	lea    esi,[rcx+0x1]
   0x0000000000400ffe <+48>:	call   0x400fce <func4>
   0x0000000000401003 <+53>:	lea    eax,[rax+rax*1+0x1]
   0x0000000000401007 <+57>:	add    rsp,0x8
   0x000000000040100b <+61>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

I was so happy when I saw this. There is no input expected at all, and everything is self contained, so we could basically ignore this whole function.

Let's see the format string for `sscanf` again to see what's expected of us:

{% highlight c linenos %}
{% raw %}
gef➤  x/s 0x4025cf
0x4025cf:	"%d %d"
{% endraw %}
{% endhighlight %}

Wow, another 2 integers? They are surely making our life very easy. In fact, even the stack offsets of the arguments that `sscanf` extracts to are the same as in Phase 3, of being `0x8` and `0xc` from the stack base. 

We can literally re-use the same exploit script as Phase 3, except we need to change the start address and the find address accordingly.

### Full Solution Script
{% highlight python linenos %}
{% raw %}
import angr
import claripy
import sys

def phase_4(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x00401029
    initial_state = project.factory.blank_state(addr=start_addr)

    num_12 = claripy.BVS('num_12', 64)

    initial_state.stack_push(num_12)

    padding_length_in_bytes = 8
    initial_state.regs.rsp -= padding_length_in_bytes

    
    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00401061 # right before ret
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
    phase_4(sys.argv)
{% endraw %}
{% endhighlight %}

If we run it, we get the following:


{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
WARNING | 2020-08-02 19:55:49,080 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-02 19:55:49,081 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-02 19:55:49,081 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-02 19:55:49,081 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-02 19:55:49,081 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-02 19:55:49,081 | angr.state_plugins.symbolic_memory | Filling register rax with 8 unconstrained bytes referenced from 0x401029 (phase_4+0x1d in bomb (0x401029))
CRITICAL | 2020-08-02 19:55:49,906 | angr.sim_state | The name state.se is deprecated; please use state.solver.
7 0
{% endraw %}
{% endhighlight %}

Trying it on the bomb itself:

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
{% endraw %}
{% endhighlight %}

Easy peasy lemon squeezy! This took basically no effort at all. You can continue on to Part 5 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-5).
