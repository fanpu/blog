---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 2"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/emerald_lake.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

Welcome to Part 2 of this series on cracking CMU's Bomblab using Angr! If you are new, I would recommend starting with part 1 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit).

### Phase 2

First we create a function stub for phase 2, which can be appended to our phase 1 exploit:

{% highlight c linenos %}
{% raw %}
def phase_2(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)
{% endraw %}
{% endhighlight %}

Let's see how Phase 2 is called:

{% highlight c linenos %}
{% raw %}
   0x0000000000400e4e <+174>:	call   0x40149e <read_line>
   0x0000000000400e53 <+179>:	mov    rdi,rax
   0x0000000000400e56 <+182>:	call   0x400efc <phase_2>
   0x0000000000400e5b <+187>:	call   0x4015c4 <phase_defused>
   0x0000000000400e60 <+192>:	mov    edi,0x4022ed
   0x0000000000400e65 <+197>:	call   0x400b10 <puts@plt>
{% endraw %}
{% endhighlight %}

So similarly to Phase 1, it gets its input from `read_line`, which is then passed to `phase_2`.

Let's disassemble Phase 2 and see what we've got:

{% highlight c linenos %}
{% raw %}
gef➤  disas phase_2
Dump of assembler code for function phase_2:
   0x0000000000400efc <+0>:	push   rbp
   0x0000000000400efd <+1>:	push   rbx
   0x0000000000400efe <+2>:	sub    rsp,0x28
   0x0000000000400f02 <+6>:	mov    rsi,rsp
   0x0000000000400f05 <+9>:	call   0x40145c <read_six_numbers>
   0x0000000000400f0a <+14>:	cmp    DWORD PTR [rsp],0x1
   0x0000000000400f0e <+18>:	je     0x400f30 <phase_2+52>
   0x0000000000400f10 <+20>:	call   0x40143a <explode_bomb>
   0x0000000000400f15 <+25>:	jmp    0x400f30 <phase_2+52>
   0x0000000000400f17 <+27>:	mov    eax,DWORD PTR [rbx-0x4]
   0x0000000000400f1a <+30>:	add    eax,eax
   0x0000000000400f1c <+32>:	cmp    DWORD PTR [rbx],eax
   0x0000000000400f1e <+34>:	je     0x400f25 <phase_2+41>
   0x0000000000400f20 <+36>:	call   0x40143a <explode_bomb>
   0x0000000000400f25 <+41>:	add    rbx,0x4
   0x0000000000400f29 <+45>:	cmp    rbx,rbp
   0x0000000000400f2c <+48>:	jne    0x400f17 <phase_2+27>
   0x0000000000400f2e <+50>:	jmp    0x400f3c <phase_2+64>
   0x0000000000400f30 <+52>:	lea    rbx,[rsp+0x4]
   0x0000000000400f35 <+57>:	lea    rbp,[rsp+0x18]
   0x0000000000400f3a <+62>:	jmp    0x400f17 <phase_2+27>
   0x0000000000400f3c <+64>:	add    rsp,0x28
   0x0000000000400f40 <+68>:	pop    rbx
   0x0000000000400f41 <+69>:	pop    rbp
   0x0000000000400f42 <+70>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

We see that `read_six_numbers` is passed with the result of `read_line` in `rdi`, and a pointer to the stack in `rsi`. We can infer that it most likely tries to extract 6 integers from the buffer passed by `read_line` into the buffer pointed by `rsi`, which would look something like `int[6]`. We know that it must be an 32 bit `int` and not a 64 bit `long long`, because otherwise the buffer would require at least 0x30 bytes, but we see that the stack is only decremented by 0x28.

A good place to start our program execution will be after returning from `read_six_numbers`. The reason why we want to avoid `read_six_numbers` is again due to state explosion - if you disassemble the function, you see lots of branches and jumps. Not good!

{% highlight python linenos %}
{% raw %}
    # Tell Angr to start executing from the instruction after read_six_numbers
    start_addr = 0x00400f0a
    initial_state = project.factory.blank_state(addr=start_addr)
{% endhighlight %}

### Symbolic Values on the Stack
Since we do not know the stack address at runtime, we will need to push our symbolic arguments onto the stack. (I lied a bit - we can actually control it, but manipulating it this way is more prone to errors). So what we want is for our stack to look something like this right after we return from `read_six_numbers`:

{% highlight c %}
{% raw %}
+-------+-------+ <- rsp + 0x18
| num_6 | num_5 |
+-------+-------+ <- rsp + 0x10
| num_4 | num_3 |
+-------+-------+ <- rsp + 0x8
| num_2 | num_1 |
+-------+-------+ <- rsp
{% endraw %}
{% endhighlight %}

We can set this up by pushing symbolic values on the stack. Since this is a 64 bit binary and we are dealing with 32 bit ints, each time we push we will actually be pushing 2 ints:


{% highlight python linenos %}
{% raw %}
    num_12 = claripy.BVS('num_12', 64)
    num_34 = claripy.BVS('num_34', 64)
    num_56 = claripy.BVS('num_56', 64)

    initial_state.stack_push(num_56)
    initial_state.stack_push(num_34)
    initial_state.stack_push(num_12)
{% endraw %}
{% endhighlight %}

In more complicated functions, we may actually have to set up the stack nicely (i.e ensuring `rbp` is at a reasonable value, potentially adding other padding onto the stack). However, in this case, we can easily see that there are no memory references using `rbp` as an offset, and there seems to be no other local variables being used on the stack. We will also set our termination condition to be within this stack frame, so we do not need to worry about setting things like return addresses on the stack correctly.

Let's initialize our simulation manager, and also define our find and avoid conditions:

{% highlight python linenos %}
{% raw %}
    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00400f42 # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)
{% endraw %}
{% endhighlight %}

We set our success address to be right before `phase_2` returns, since we did not set the return address as mentioned previously. Similarly as before, we avoid the `explode_bomb` function as well.

### Some Final Housekeeping
Finally, let's deal with getting our solution:

{% highlight python linenos %}
{% raw %}
    # Check that we have found a solution
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
    else:
        raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

Here, we get a 64 bit int in `num_12_sol` and so on. We then unpack it to retrieve the individual values. Based on the ordering on the stack, the first number would be in the lower 32 bits, and the second number would be in the higher 32 bits.

### Full Solution Script
Here is the full script for phase 2:

{% highlight python linenos %}
{% raw %}
import angr
import claripy
import sys

def phase_1(argv):
    # omitted
    pass

def phase_2(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x00400f0a
    initial_state = project.factory.blank_state(addr=start_addr)

    num_12 = claripy.BVS('num_12', 64)
    num_34 = claripy.BVS('num_34', 64)
    num_56 = claripy.BVS('num_56', 64)

    initial_state.stack_push(num_56)
    initial_state.stack_push(num_34)
    initial_state.stack_push(num_12)
    
    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00400f42 # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)

    # Check that we have found a solution
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
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    phase_1(sys.argv)
    phase_2(sys.argv)
{% endraw %}
{% endhighlight %}

Let's run it!

{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
WARNING | 2020-07-30 23:45:46,677 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-07-30 23:45:46,677 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-07-30 23:45:46,678 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-07-30 23:45:46,678 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-07-30 23:45:46,678 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-07-30 23:45:46,678 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0008 with 8 unconstrained bytes referenced from 0x400f40 (phase_2+0x44 in bomb (0x400f40))
WARNING | 2020-07-30 23:45:46,679 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0010 with 8 unconstrained bytes referenced from 0x400f41 (phase_2+0x45 in bomb (0x400f41))
CRITICAL | 2020-07-30 23:45:46,682 | angr.sim_state | The name state.se is deprecated; please use state.solver.
1 2 4 8 16 32
{% endraw %}
{% endhighlight %}

Now try it on the bomb itself:

{% highlight c linenos %}
{% raw %}
$ ./bomb
Welcome to my fiendish little bomb. You have 6 phases with
which to blow yourself up. Have a nice day!
Border relations with Canada have never been better.
Phase 1 defused. How about the next one?
1 2 4 8 16 32
That's number 2.  Keep going!
{% endraw %}
{% endhighlight %}

Awesome! We got the solution without even having to deal with the headache of figuring what Phase 2 is actually doing. While Phase 1 was relatively trivial and Angr solving it was probably not really impressive, this is something that should be making you excited now! :) 

Thanks for reading, and I hope you've enjoyed the journey so far. You can go straight to the next part [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-3).
