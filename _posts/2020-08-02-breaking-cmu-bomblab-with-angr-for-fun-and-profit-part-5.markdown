---
title: "Breaking CMU's Bomblab with Angr for Fun and Profit - Part 5"
layout: post
tags: [rev, ctf]
cover: assets/images/posts/niagara_falls.avif
class: post-template
navigation: True
author: fanpu
toc: true
comments: true
---

This is Part 5 on cracking CMU's Bomblab with Angr. If you just stumbled upon this, I would recommend starting with part 1 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit).

### Phase 5

Let's disassemble Phase 5:

{% highlight c linenos %}
{% raw %}
gef➤  disas phase_5
Dump of assembler code for function phase_5:
   0x0000000000401062 <+0>:	push   rbx
   0x0000000000401063 <+1>:	sub    rsp,0x20
   0x0000000000401067 <+5>:	mov    rbx,rdi
   0x000000000040106a <+8>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000401073 <+17>:	mov    QWORD PTR [rsp+0x18],rax
   0x0000000000401078 <+22>:	xor    eax,eax
   0x000000000040107a <+24>:	call   0x40131b <string_length>
   0x000000000040107f <+29>:	cmp    eax,0x6
   0x0000000000401082 <+32>:	je     0x4010d2 <phase_5+112>
   0x0000000000401084 <+34>:	call   0x40143a <explode_bomb>
   0x0000000000401089 <+39>:	jmp    0x4010d2 <phase_5+112>
   0x000000000040108b <+41>:	movzx  ecx,BYTE PTR [rbx+rax*1]
   0x000000000040108f <+45>:	mov    BYTE PTR [rsp],cl
   0x0000000000401092 <+48>:	mov    rdx,QWORD PTR [rsp]
   0x0000000000401096 <+52>:	and    edx,0xf
   0x0000000000401099 <+55>:	movzx  edx,BYTE PTR [rdx+0x4024b0]
   0x00000000004010a0 <+62>:	mov    BYTE PTR [rsp+rax*1+0x10],dl
   0x00000000004010a4 <+66>:	add    rax,0x1
   0x00000000004010a8 <+70>:	cmp    rax,0x6
   0x00000000004010ac <+74>:	jne    0x40108b <phase_5+41>
   0x00000000004010ae <+76>:	mov    BYTE PTR [rsp+0x16],0x0
   0x00000000004010b3 <+81>:	mov    esi,0x40245e
   0x00000000004010b8 <+86>:	lea    rdi,[rsp+0x10]
   0x00000000004010bd <+91>:	call   0x401338 <strings_not_equal>
   0x00000000004010c2 <+96>:	test   eax,eax
   0x00000000004010c4 <+98>:	je     0x4010d9 <phase_5+119>
   0x00000000004010c6 <+100>:	call   0x40143a <explode_bomb>
   0x00000000004010cb <+105>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x00000000004010d0 <+110>:	jmp    0x4010d9 <phase_5+119>
   0x00000000004010d2 <+112>:	mov    eax,0x0
   0x00000000004010d7 <+117>:	jmp    0x40108b <phase_5+41>
   0x00000000004010d9 <+119>:	mov    rax,QWORD PTR [rsp+0x18]
   0x00000000004010de <+124>:	xor    rax,QWORD PTR fs:0x28
   0x00000000004010e7 <+133>:	je     0x4010ee <phase_5+140>
   0x00000000004010e9 <+135>:	call   0x400b30 <__stack_chk_fail@plt>
   0x00000000004010ee <+140>:	add    rsp,0x20
   0x00000000004010f2 <+144>:	pop    rbx
   0x00000000004010f3 <+145>:	ret    
End of assembler dump.
{% endraw %}
{% endhighlight %}

We see `strings_not_equal`, like in Phase 1, and also `string_length`. Also, right after the `string_length` call there is a comparison with 6, so we can assume that it wants 6 bytes of input. Let's craft the input again in the same stack frame as the function by setting `rdi` to our symbolic bitvector of 6 bytes:


{% highlight python linenos %}
{% raw %}
def phase_5(argv):
    # Create an Angr project.
    path_to_binary = argv[1] # :string
    project = angr.Project(path_to_binary)

    # Tell Angr where to start executing 
    start_addr = 0x00401062
    initial_state = project.factory.blank_state(addr=start_addr)

    fake_addr = 0x40000000
    input_len = 6
    phase_5_input = claripy.BVS('phase_5_input', input_len * 8)
    initial_state.memory.store(fake_addr, phase_5_input)
    initial_state.regs.rdi = fake_addr
{% endraw %}
{% endhighlight %}

Recall how we had to replace `strings_not_equal` with our own custom implementation back in Phase 1 to avoid state explosion? I recently found out that there was a really simple way of doing this by using the built-in libc ones that Angr already helpfully provides. For instance, `strings_not_equal` can simply be replaced with the libc `strcmp`, whose definition can be found [here](https://github.com/angr/angr/blob/master/angr/procedures/libc/strcmp.py). Similarly, `string_length` is the same as the libc `strlen`, which can be found [here](https://github.com/angr/angr/blob/master/angr/procedures/libc/strlen.py). So let us replace those using this method, to avoid state explosion:


{% highlight python linenos %}
{% raw %}
    strcmp = angr.SIM_PROCEDURES['libc']['strcmp']
    strlen = angr.SIM_PROCEDURES['libc']['strlen']

    strings_not_equal_symbol = 'strings_not_equal'
    string_length_symbol = "string_length"

    project.hook_symbol(strings_not_equal_symbol, strcmp())
    project.hook_symbol(string_length_symbol, strlen())
{% endraw %}
{% endhighlight %}

Finally, we set our success address to be at the `ret` statement, and the same avoid address as before:

{% highlight python linenos %}
{% raw %}
    # Create a simulation manager initialized with the starting state
    simulation = project.factory.simgr(initial_state)

    success_addr = 0x004010f3 # right before ret
    explode_addr = 0x0040143a # explode_bomb

    simulation.explore(find=success_addr, avoid=explode_addr)

    if simulation.found:
        solution_state = simulation.found[0]

        # Case symbolic value to bytes
        solution = solution_state.se.eval(phase_5_input, cast_to=bytes)
        print(solution)
    else:
        raise Exception('Could not find the solution')
{% endraw %}
{% endhighlight %}

### Almost There?
Let's try running it!

{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
WARNING | 2020-08-02 20:48:21,569 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-02 20:48:21,569 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-02 20:48:21,569 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-02 20:48:21,569 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-02 20:48:21,569 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-02 20:48:21,569 | angr.state_plugins.symbolic_memory | Filling register rbx with 8 unconstrained bytes referenced from 0x401062 (phase_5+0x0 in bomb (0x401062))
WARNING | 2020-08-02 20:48:21,579 | angr.state_plugins.symbolic_memory | Filling memory at 0x40000006 with 250 unconstrained bytes referenced from 0x40131b (string_length+0x0 in bomb (0x40131b))
WARNING | 2020-08-02 20:48:21,694 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeffd1 with 7 unconstrained bytes referenced from 0x401092 (phase_5+0x30 in bomb (0x401092))
WARNING | 2020-08-02 20:48:23,609 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff8 with 232 unconstrained bytes referenced from 0x401338 (strings_not_equal+0x0 in bomb (0x401338))
WARNING | 2020-08-02 20:48:23,610 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeffe7 with 1 unconstrained bytes referenced from 0x401338 (strings_not_equal+0x0 in bomb (0x401338))
CRITICAL | 2020-08-02 20:48:24,220 | angr.sim_state | The name state.se is deprecated; please use state.solver.
b'\t\x0f\x0e\x05\x06\x07'
{% endraw %}
{% endhighlight %}

We indeed got a solution, but those are not ASCII printable characters! Of course, we can pipe the input to the binary with something like pwntools, but this seems to not be the point of the assignment. This is where we introduce the new concept of adding constraints to our input.

### Adding Constraints
We want to constrain our input bytes such that they are in the printable range. For simplicity, I will restrict it further to be smallest range that include the alphanumeric range, which includes a few non-alphanumeric characters as well. This will range from '0' (0x30) to 'z' (0x7A), which you can quickly verify by pulling up an ASCII table with `man ascii`. 

We'll add these constraints right before we build the simulation:

{% highlight python linenos %}
{% raw %}
    def constrain_printable(c):
        return claripy.And(ord('0') <= c , c <= ord('z'))

    for i in range(input_len):
        initial_state.solver.add(constrain_printable(phase_5_input.get_byte(i)))
{% endraw %}
{% endhighlight %}

Now, we will either get a solution that is printable, or perhaps no solution at all. Let's try:


{% highlight c linenos %}
{% raw %}
$ python solve.py bomb
WARNING | 2020-08-02 20:54:43,766 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-02 20:54:43,766 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-02 20:54:43,766 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-02 20:54:43,766 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-02 20:54:43,766 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-02 20:54:43,766 | angr.state_plugins.symbolic_memory | Filling register rbx with 8 unconstrained bytes referenced from 0x401062 (phase_5+0x0 in bomb (0x401062))
WARNING | 2020-08-02 20:54:43,796 | angr.state_plugins.symbolic_memory | Filling memory at 0x40000006 with 250 unconstrained bytes referenced from 0x40131b (string_length+0x0 in bomb (0x40131b))
WARNING | 2020-08-02 20:54:43,906 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeffd1 with 7 unconstrained bytes referenced from 0x401092 (phase_5+0x30 in bomb (0x401092))
WARNING | 2020-08-02 20:54:45,753 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff8 with 232 unconstrained bytes referenced from 0x401338 (strings_not_equal+0x0 in bomb (0x401338))
WARNING | 2020-08-02 20:54:45,753 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeffe7 with 1 unconstrained bytes referenced from 0x401338 (strings_not_equal+0x0 in bomb (0x401338))
CRITICAL | 2020-08-02 20:54:46,356 | angr.sim_state | The name state.se is deprecated; please use state.solver.
b'9?>567'
{% endraw %}
{% endhighlight %}

Fantastic! Let's try this input on the bomb:

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
{% endraw %}
{% endhighlight %}

Looks like it worked! Thanks for reading so far, and I hope you enjoyed it! You can continue on to Part 6 [here](breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-6).
