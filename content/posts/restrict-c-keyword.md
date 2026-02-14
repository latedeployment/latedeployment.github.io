---
title: "restrict C keyword for optimizations"
date: 2026-02-13T10:00:00
tags: ["c", "optimization", "x86"]
ShowToc: true
TocOpen: true
---

The `restrict` keyword in _C_ is a forgotten keyword, with only `auto` and `register` more bygone. It is used as a compiler hint, to tell it that pointers does not write on *each other*, otherwise (without it) when multiple pointers are used in a function and some data is written, it has to `reload` the pointer each time because it cannot gurantee the *pointer itself*, or the data it points to was not modified. 

Let's see a simple example: 
```c
void copy_sum(int *dst, int *src, int *val, int n)
{
    for (int i = 0; i < n; i++)
    {
        dst[i] = src[i] + *val;
    }
}
```

The pointers `dst` and `src` could _in theory_ point to overlapping memory, or even equal. The compiler **can't know** they don't overlap. So, inside the loop, after writing to `dst[i]`, the compiler must assume that this write could have changed the memory pointed to by `src` (if `dst` equals `src`), and vice versa.

That means on _every iteration_, the compiler has to:
- **reload** the value of `dst` and `src` from memory, instead of keeping them in registers (for potential aliasing),
- maybe reload `*val` as well, if it could alias to one of the other pointers.

![Potential aliasing problem](/images/restrict-aliasing.svg)


If we look at the *optimized* `x86` assembly generated -

```asm
copy_sum:
        movq    %rdx, %r8
        testl   %ecx, %ecx
        jle     .L1
        movl    %ecx, %ecx
        xorl    %eax, %eax
        salq    $2, %rcx
.L3:
        movl    (%r8), %edx
        addl    (%rsi,%rax), %edx
        movl    %edx, (%rdi,%rax)
        addq    $4, %rax
        cmpq    %rax, %rcx
        jne     .L3
.L1:
        ret
```

Inside the loop, the compiler emits `movl (%r8), %edx` and `addl (%rsi,%rax), %edx` **in every iteration**. This means that every time through the loop, the compiler is reloading from `val` (`*val`) and from `src[i]` (`(%rsi,%rax)`).


Now all we change is this: (adding `restrict`)

```c
void copy_sum_restrict(int *restrict dst, int *restrict src, int *restrict val, int n)
{
    for (int i = 0; i < n; i++)
    {
        dst[i] = src[i] + *val;
    }
}
```

We added `restrict` to every pointer. We basically told the compiler "you know what, addresses do not overlap". Now the compiler *does not have to reload*, and it basically can start generting much more clever code. 

```asm
copy_sum_restrict:
        movl    %ecx, %r8d
        testl   %ecx, %ecx
        jle     .L6
        leal    -1(%rcx), %eax
        movl    (%rdx), %r9d
        cmpl    $2, %eax
        jbe     .L11
        movl    %ecx, %edx
        movd    %r9d, %xmm2
        xorl    %eax, %eax
        shrl    $2, %edx
        pshufd  $0, %xmm2, %xmm1
        movl    %edx, %ecx
        salq    $4, %rcx
.L9:
        movdqu  (%rsi,%rax), %xmm0
        paddd   %xmm1, %xmm0
        movups  %xmm0, (%rdi,%rax)
        addq    $16, %rax
        cmpq    %rcx, %rax
        jne     .L9
        leal    0(,%rdx,4), %eax
        cmpl    %eax, %r8d
        je      .L6
.L10:
        movl    (%rsi,%rax,4), %edx
        addl    %r9d, %edx
        movl    %edx, (%rdi,%rax,4)
        addq    $1, %rax
        cmpl    %eax, %r8d
        jg      .L10
.L6:
        ret
.L11:
        xorl    %eax, %eax
        jmp     .L10
```

So the optimized code looks longer, which is quite odd, but the compiler is taking advantage of `SSE2 vector instructions`, which means it can process several array elements at once instead of one at a time. 

All we did was change the type of the pointer, and the compiler was able to generate much more efficient code.

A benchmark shows that it *does* speedup things: 

```
Array size : 4194304 elements (16 MB per array)
Iterations : 200 (+ 10 warmup)

copy_sum (no restrict)           1.12 ms    28490.2 MB/s
copy_sum_restrict                0.70 ms    45964.6 MB/s
```
