---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 7"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/campton.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

Welcome to the final part of cracking CMU's Bomblab with Angr. If you are new here, I would recommend starting with part 1 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit).

### Secret Phase
We knew about the secret phase because we literally saw the string "Wow! You've defused the secret stage!" from Angr's output for Phase 1, because the string was located right after the compare string for Phase 1in memory. If we do `info func` in GDB, we indeed see a `secret_phase` and `fun7` function.

{% highlight c linenos %}
{% raw %}
gef➤  info func
[...]
0x0000000000401204  fun7
0x0000000000401242  secret_phase
[...]
{% endraw %}
{% endhighlight %}

Let's check `fun7` first:

{% highlight c linenos %}
{% raw %}
gef➤  disas fun7
Dump of assembler code for function fun7:
   0x0000000000401204 <+0>:	sub    rsp,0x8
   0x0000000000401208 <+4>:	test   rdi,rdi
   0x000000000040120b <+7>:	je     0x401238 <fun7+52>
   0x000000000040120d <+9>:	mov    edx,DWORD PTR [rdi]
   0x000000000040120f <+11>:	cmp    edx,esi
   0x0000000000401211 <+13>:	jle    0x401220 <fun7+28>
   0x0000000000401213 <+15>:	mov    rdi,QWORD PTR [rdi+0x8]
   0x0000000000401217 <+19>:	call   0x401204 <fun7>
   0x000000000040121c <+24>:	add    eax,eax
   0x000000000040121e <+26>:	jmp    0x40123d <fun7+57>
   0x0000000000401220 <+28>:	mov    eax,0x0
   0x0000000000401225 <+33>:	cmp    edx,esi
   0x0000000000401227 <+35>:	je     0x40123d <fun7+57>
   0x0000000000401229 <+37>:	mov    rdi,QWORD PTR [rdi+0x10]
   0x000000000040122d <+41>:	call   0x401204 <fun7>
   0x0000000000401232 <+46>:	lea    eax,[rax+rax*1+0x1]
   0x0000000000401236 <+50>:	jmp    0x40123d <fun7+57>
   0x0000000000401238 <+52>:	mov    eax,0xffffffff
   0x000000000040123d <+57>:	add    rsp,0x8
   0x0000000000401241 <+61>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

Nothing out of the ordinary here, it is entirely self contained, so we can blackbox it.

Let's now disassemble `secret_phase`:

{% highlight c linenos %}
{% raw %}
gef➤  disas secret_phase
Dump of assembler code for function secret_phase:
   0x0000000000401242 <+0>:	push   rbx
   0x0000000000401243 <+1>:	call   0x40149e <read_line>
   0x0000000000401248 <+6>:	mov    edx,0xa
   0x000000000040124d <+11>:	mov    esi,0x0
   0x0000000000401252 <+16>:	mov    rdi,rax
   0x0000000000401255 <+19>:	call   0x400bd0 <strtol@plt>
   0x000000000040125a <+24>:	mov    rbx,rax
   0x000000000040125d <+27>:	lea    eax,[rax-0x1]
   0x0000000000401260 <+30>:	cmp    eax,0x3e8
   0x0000000000401265 <+35>:	jbe    0x40126c <secret_phase+42>
   0x0000000000401267 <+37>:	call   0x40143a <explode_bomb>
   0x000000000040126c <+42>:	mov    esi,ebx
   0x000000000040126e <+44>:	mov    edi,0x6030f0
   0x0000000000401273 <+49>:	call   0x401204 <fun7>
   0x0000000000401278 <+54>:	cmp    eax,0x2
   0x000000000040127b <+57>:	je     0x401282 <secret_phase+64>
   0x000000000040127d <+59>:	call   0x40143a <explode_bomb>
   0x0000000000401282 <+64>:	mov    edi,0x402438
   0x0000000000401287 <+69>:	call   0x400b10 <puts@plt>
   0x000000000040128c <+74>:	call   0x4015c4 <phase_defused>
   0x0000000000401291 <+79>:	pop    rbx
   0x0000000000401292 <+80>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

Pretty standard, no new gotchas here. We can start executing after the `strtol` function call, and then set a symbolic int to `rax`:

{% highlight python linenos %}
{% raw %}
def secret_phase(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x0040125a # right after strtol
    initial_state = project.factory.blank_state(addr=start_addr)

    num = claripy.BVS('secret_phase_input', 4 * 8) # 32 bits

    initial_state.regs.rax = num

{% endraw %}
{% endhighlight %}

The success address will be right before ret as usual. In order to get the result, we cast the symbolic output to an int.

{% highlight python linenos %}
{% raw %}
    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00401292 # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)

    if simulation.found:
        solution_state = simulation.found[0]

        # Case symbolic value to int 
        solution = solution_state.se.eval(num, cast_to=int)
        print(solution)
    else:
        raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

### Full Solution Script
{% highlight c linenos %}
{% raw %}
import angr
import claripy
import sys

def secret_phase(argv):
    path_to_binary = argv[1]
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x0040125a # right after strtol
    initial_state = project.factory.blank_state(addr=start_addr)

    num = claripy.BVS('secret_phase_input', 4 * 8) # 32 bits

    initial_state.regs.rax = num

    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x00401292 # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)

    if simulation.found:
        solution_state = simulation.found[0]

        # Case symbolic value to int 
        solution = solution_state.se.eval(num, cast_to=int)
        print(solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    secret_phase(sys.argv)
{% endraw %}
{% endhighlight %}

If we run it, we get the following:

{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
WARNING | 2020-08-04 00:07:02,736 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-04 00:07:02,736 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-04 00:07:02,736 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-04 00:07:02,736 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-04 00:07:02,737 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-04 00:07:02,737 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff8 with 8 unconstrained bytes referenced from 0x401291 (secret_phase+0x4f in bomb (0x401291))
CRITICAL | 2020-08-04 00:07:02,812 | angr.sim_state | The name state.se is deprecated; please use state.solver.
22
{% endraw %}
{% endhighlight %}

We got the answer fairly quickly! If you had done Bomblab before and did the secret phase, you would remember that `fun7` was a tricky little recursive function, but Angr just crushed it so easily! 

Now, we get to the question of how the secret stage can actually be triggered. Unfortunately, I could not really find a way to do this symbolically with Angr due to the state explosion problem. This is because there is quite a big gap between when the input is set, and when the condition to go into the secret phase is satisfied. 

To make it clearer about what I mean, I decided to just tell you how it works, because ultimately this is a series on learning about Angr and not learning how to reverse. Basically, `read_line` keeps track of a global variable `num_input_strings` which increments by 1 each time it is called. It then uses this as an index into a global buffer, and this buffer is used to store the input by the user for each stage. When `num_input_strings` is 6 (i.e we cleared all stages) we perform the following check in `phase_defused`:

{% highlight c linenos %}
{% raw %}
   0x00000000004015d8 <+20>:	cmp    DWORD PTR [rip+0x202181],0x6        # 0x603760 <num_input_strings>
   0x00000000004015df <+27>:	jne    0x40163f <phase_defused+123>
   0x00000000004015e1 <+29>:	lea    r8,[rsp+0x10]
   0x00000000004015e6 <+34>:	lea    rcx,[rsp+0xc]
   0x00000000004015eb <+39>:	lea    rdx,[rsp+0x8]
   0x00000000004015f0 <+44>:	mov    esi,0x402619
   0x00000000004015f5 <+49>:	mov    edi,0x603870
   0x00000000004015fa <+54>:	call   0x400bf0 <__isoc99_sscanf@plt>
   0x00000000004015ff <+59>:	cmp    eax,0x3
   0x0000000000401602 <+62>:	jne    0x401635 <phase_defused+113>
   0x0000000000401604 <+64>:	mov    esi,0x402622
   0x0000000000401609 <+69>:	lea    rdi,[rsp+0x10]
   0x000000000040160e <+74>:	call   0x401338 <strings_not_equal>
   0x0000000000401613 <+79>:	test   eax,eax
   0x0000000000401615 <+81>:	jne    0x401635 <phase_defused+113>
{% endraw %}
{% endhighlight %}

It just happens that the global buffer used by Phase 4 is the one that is pointed to by the `rdi` argument for `sscanf`, `0x603870`. This is the most clear if you use dynamic analysis to inspect the value of the buffer after setting a breakpoint at this point, where you will see your Phase 4 input in the buffer.

The format string used for `sscanf` is as follows:
{% highlight c linenos %}
{% raw %}
gef➤  x/s 0x402619
0x402619:	"%d %d %s"
{% endraw %}
{% endhighlight %}

So we only continue down if we extract all three tokens, and with the third token being "DrEvil":

{% highlight c linenos %}
{% raw %}
gef➤  x/s 0x402622
0x402622:	"DrEvil"
{% endraw %}
{% endhighlight %}

This means that all we need to do to trigger the secret phase is to change our Phase 4 input from `7 0
` to `7 0 DrEvil`!

Trying it out on the actual binary:

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
7 0 DrEvil
So you got that one.  Try this one.
9?>567
Good work!  On to the next...
4 3 2 1 6 5
Curses, you've found the secret phase!
But finding it and solving it are quite different...
22
Wow! You've defused the secret stage!
Congratulations! You've defused the bomb!
{% endraw %}
{% endhighlight %}

Hooray, we did it!

Through this series, we learned about what symbolic execution is, how path explosion is the main pitfall for symbolic execution, and various strategies for combating it. I personally learned a lot by doing this and felt much more comfortable with Angr than when I initially started out. I hope that you found this useful, and as always feedback and comments are greatly appreciated! 
