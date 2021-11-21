

# AwdPwnPatcher教程

## 格式化字符串

程序源码：

```C
//gcc fmt.c -o fmt64 -fno-builtin-printf
//gcc fmt.c -o fmt32_nopie -fno-builtin-printf -no-pie -m32
//gcc fmt.c -o fmt32_pie -fno-builtin-printf -m32
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    char * p;
    p = (char *)malloc(0x40);
    read(0, p, 0x40);
    printf(p);
    return 0;
}
```

在AWD比赛中，printf格式化漏洞修复不能简简单单地将printf改为puts，会多一个换行符从而过不了check，一般通过增加"%s"参数进行patch。

### 32位不开PIE

```assembly
08048486 <main>:
 8048486:	8d 4c 24 04          	lea    ecx,[esp+0x4]
 804848a:	83 e4 f0             	and    esp,0xfffffff0
 804848d:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
 8048490:	55                   	push   ebp
 8048491:	89 e5                	mov    ebp,esp
 8048493:	53                   	push   ebx
 8048494:	51                   	push   ecx
 8048495:	83 ec 10             	sub    esp,0x10
 8048498:	e8 23 ff ff ff       	call   80483c0 <__x86.get_pc_thunk.bx>
 804849d:	81 c3 63 1b 00 00    	add    ebx,0x1b63
 80484a3:	83 ec 0c             	sub    esp,0xc
 80484a6:	6a 40                	push   0x40
 80484a8:	e8 93 fe ff ff       	call   8048340 <malloc@plt>
 80484ad:	83 c4 10             	add    esp,0x10
 80484b0:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 80484b3:	83 ec 04             	sub    esp,0x4
 80484b6:	6a 40                	push   0x40
 80484b8:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 80484bb:	6a 00                	push   0x0
 80484bd:	e8 5e fe ff ff       	call   8048320 <read@plt>
 80484c2:	83 c4 10             	add    esp,0x10
 80484c5:	83 ec 0c             	sub    esp,0xc
 80484c8:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 80484cb:	e8 60 fe ff ff       	call   8048330 <printf@plt>
 80484d0:	83 c4 10             	add    esp,0x10
 80484d3:	b8 00 00 00 00       	mov    eax,0x0
 80484d8:	8d 65 f8             	lea    esp,[ebp-0x8]
 80484db:	59                   	pop    ecx
 80484dc:	5b                   	pop    ebx
 80484dd:	5d                   	pop    ebp
 80484de:	8d 61 fc             	lea    esp,[ecx-0x4]
 80484e1:	c3                   	ret
```

使用patch_fmt_by_call函数修补很简单，只需要提供call printf这条指令的地址即可，即0x80484cb：

```python
binary = "./fmt32_nopie"
awd_pwn_patcher = AwdPwnPatcher(binary)
awd_pwn_patcher.patch_fmt_by_call(0x80484cb)
awd_pwn_patcher.save()
```

使用patch_by_jmp函数进行patch，需要将0x80484cb地址之前的一条指令修改为jmp，并且离call printf指令的距离要保证至少有5字节的空间，这里选择从0x80484c5地址开始，patch过程分为三个步骤：

- 在eh_frame添加"%s"字符串
- 在eh_frame添加patch代码
- 调用完printf后对栈进行调整

```python
binary = "./fmt32_nopie"
awd_pwn_patcher = AwdPwnPatcher(binary)
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
assembly = """
sub esp, 0xc
push dword ptr [ebp - 0xc]
lea eax, dword ptr [{}]
push eax
""".format(fmt_addr)
awd_pwn_patcher.patch_by_jmp(0x80484c5, jmp_to=0x80484cb, assembly=assembly)
assembly = "add esp, 0x14"
awd_pwn_patcher.patch_origin(0x80484d0, assembly=assembly)
awd_pwn_patcher.save()
```



### 32位开PIE

```assembly
0000057d <main>:
 57d:	8d 4c 24 04          	lea    ecx,[esp+0x4]
 581:	83 e4 f0             	and    esp,0xfffffff0
 584:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
 587:	55                   	push   ebp
 588:	89 e5                	mov    ebp,esp
 58a:	53                   	push   ebx
 58b:	51                   	push   ecx
 58c:	83 ec 10             	sub    esp,0x10
 58f:	e8 ec fe ff ff       	call   480 <__x86.get_pc_thunk.bx>
 594:	81 c3 3c 1a 00 00    	add    ebx,0x1a3c
 59a:	83 ec 0c             	sub    esp,0xc
 59d:	6a 40                	push   0x40
 59f:	e8 6c fe ff ff       	call   410 <malloc@plt>
 5a4:	83 c4 10             	add    esp,0x10
 5a7:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 5aa:	83 ec 04             	sub    esp,0x4
 5ad:	6a 40                	push   0x40
 5af:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 5b2:	6a 00                	push   0x0
 5b4:	e8 37 fe ff ff       	call   3f0 <read@plt>
 5b9:	83 c4 10             	add    esp,0x10
 5bc:	83 ec 0c             	sub    esp,0xc
 5bf:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 5c2:	e8 39 fe ff ff       	call   400 <printf@plt>
 5c7:	83 c4 10             	add    esp,0x10
 5ca:	b8 00 00 00 00       	mov    eax,0x0
 5cf:	8d 65 f8             	lea    esp,[ebp-0x8]
 5d2:	59                   	pop    ecx
 5d3:	5b                   	pop    ebx
 5d4:	5d                   	pop    ebp
 5d5:	8d 61 fc             	lea    esp,[ecx-0x4]
 5d8:	c3                   	ret
```

用patch_fmt_by_call修补很简单，这里只介绍patch_by_jmp的方式。32位程序无法像64位程序一样通过lea指令取相对地址，所以在开了PIE的情况下，需要先获取程序地址，这里通过call+pop的方式取到程序地址：

```python
binary = "./fmt32_pie"
awd_pwn_patcher = AwdPwnPatcher(binary)
fmt_offset = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
call {0}
pop eax
sub eax, {0}
add eax, {1}
sub esp, 0xc
push dword ptr [ebp - 0xc]
push eax
""".format(hex(patch_start_addr+5), fmt_offset)
awd_pwn_patcher.patch_by_jmp(0x5bc, jmp_to=0x5c2, assembly=assembly)
assembly = "add esp, 0x14"
awd_pwn_patcher.patch_origin(0x5c7, assembly=assembly)
awd_pwn_patcher.save()
```

### 64位

```
00000000000006da <main>:
 6da:	55                   	push   rbp
 6db:	48 89 e5             	mov    rbp,rsp
 6de:	48 83 ec 10          	sub    rsp,0x10
 6e2:	bf 40 00 00 00       	mov    edi,0x40
 6e7:	e8 c4 fe ff ff       	call   5b0 <malloc@plt>
 6ec:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
 6f0:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
 6f4:	ba 40 00 00 00       	mov    edx,0x40
 6f9:	48 89 c6             	mov    rsi,rax
 6fc:	bf 00 00 00 00       	mov    edi,0x0
 701:	e8 9a fe ff ff       	call   5a0 <read@plt>
 706:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
 70a:	48 89 c7             	mov    rdi,rax
 70d:	b8 00 00 00 00       	mov    eax,0x0
 712:	e8 79 fe ff ff       	call   590 <printf@plt>
 717:	b8 00 00 00 00       	mov    eax,0x0
 71c:	c9                   	leave
 71d:	c3                   	ret
```

64位程序通过patch_by_jmp修补的话，还不需要考虑恢复栈平衡的情况，比32位要简单：

```python
binary = "./fmt64"
awd_pwn_patcher = AwdPwnPatcher(binary)
fmt_offset = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
assembly = """
mov rsi, qword ptr [rbp-0x8]
lea rdi, qword ptr [{}]
""".format(hex(fmt_offset))
awd_pwn_patcher.patch_by_jmp(0x706, jmp_to=0x712, assembly=assembly)
awd_pwn_patcher.save()
```

## UAF

程序源码：

```c
//gcc fmt.c -o uaf64
//gcc fmt.c -o uaf32 -no-pie -m32
#include <stdio.h>
#include <stdlib.h>

void * p[10];

int main()
{
    unsigned int index;
    printf("Input index: ");
    scanf("%u", &index);
    if(index<10){
        p[index] = malloc(0x40);
        free(p[index]);
    }
    return 0;
}
```

一般严格的AWD比赛中，都不允许修改call free这条指令，否则直接nop即可，这种情况有两种修复方法：

- 在call free前插入jmp
- 在call free后插入jmp

### 32位

```assembly
08048536 <main>:
 ... ...
 8048597:	e8 44 fe ff ff       	call   80483e0 <malloc@plt>
 804859c:	83 c4 10             	add    esp,0x10
 804859f:	89 c2                	mov    edx,eax
 80485a1:	c7 c0 60 a0 04 08    	mov    eax,0x804a060
 80485a7:	89 14 b0             	mov    DWORD PTR [eax+esi*4],edx
 80485aa:	8b 55 e0             	mov    edx,DWORD PTR [ebp-0x20]
 80485ad:	c7 c0 60 a0 04 08    	mov    eax,0x804a060
 80485b3:	8b 04 90             	mov    eax,DWORD PTR [eax+edx*4]
 80485b6:	83 ec 0c             	sub    esp,0xc
 80485b9:	50                   	push   eax
 80485ba:	e8 01 fe ff ff       	call   80483c0 <free@plt>
 80485bf:	83 c4 10             	add    esp,0x10
 80485c2:	b8 00 00 00 00       	mov    eax,0x0
 80485c7:	8b 4d e4             	mov    ecx,DWORD PTR [ebp-0x1c]
 80485ca:	65 33 0d 14 00 00 00 	xor    ecx,DWORD PTR gs:0x14
 80485d1:	74 05                	je     80485d8 <main+0xa2>
 80485d3:	e8 88 00 00 00       	call   8048660 <__stack_chk_fail_local>
 80485d8:	8d 65 f4             	lea    esp,[ebp-0xc]
 80485db:	59                   	pop    ecx
 80485dc:	5b                   	pop    ebx
 80485dd:	5e                   	pop    esi
 80485de:	5d                   	pop    ebp
 80485df:	8d 61 fc             	lea    esp,[ecx-0x4]
 80485e2:	c3                   	ret
```



这里通过在call free之后插入jmp的方式进行patch，从0x80485bf开始跳转，patch代码结束后再跳回0x80485c7：

```python
binary = "./uaf32"
awd_pwn_patcher = AwdPwnPatcher(binary)
assembly = """
add esp, 0x10
mov eax, 0
mov edx, dword ptr [ebp - 0x20]
mov eax, 0x804a060
lea eax, dword ptr [eax + edx*4]
mov dword ptr [eax], 0
"""
awd_pwn_patcher.patch_by_jmp(0x80485bf, jmp_to=0x80485c7, assembly=assembly)
awd_pwn_patcher.save()
```



### 64位

```assembly
00000000000007aa <main>:
 ... ...
 7fb:	e8 70 fe ff ff       	call   670 <malloc@plt>
 800:	48 89 c1             	mov    rcx,rax
 803:	89 d8                	mov    eax,ebx
 805:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
 80c:	00
 80d:	48 8d 05 2c 08 20 00 	lea    rax,[rip+0x20082c]        # 201040 <p>
 814:	48 89 0c 02          	mov    QWORD PTR [rdx+rax*1],rcx
 818:	8b 45 e4             	mov    eax,DWORD PTR [rbp-0x1c]
 81b:	89 c0                	mov    eax,eax
 81d:	48 8d 14 c5 00 00 00 	lea    rdx,[rax*8+0x0]
 824:	00
 825:	48 8d 05 14 08 20 00 	lea    rax,[rip+0x200814]        # 201040 <p>
 82c:	48 8b 04 02          	mov    rax,QWORD PTR [rdx+rax*1]
 830:	48 89 c7             	mov    rdi,rax
 833:	e8 08 fe ff ff       	call   640 <free@plt>
 838:	b8 00 00 00 00       	mov    eax,0x0
 83d:	48 8b 75 e8          	mov    rsi,QWORD PTR [rbp-0x18]
 841:	64 48 33 34 25 28 00 	xor    rsi,QWORD PTR fs:0x28
 848:	00 00
 84a:	74 05                	je     851 <main+0xa7>
 84c:	e8 ff fd ff ff       	call   650 <__stack_chk_fail@plt>
 851:	48 83 c4 18          	add    rsp,0x18
 855:	5b                   	pop    rbx
 856:	5d                   	pop    rbp
 857:	c3                   	ret
```

在0x838指令出插入jmp，然后再跳回0x83d地址处：

```python
binary = "./uaf64"
awd_pwn_patcher = AwdPwnPatcher(binary)
assembly = """
mov eax, 0
mov eax, dword ptr [rbp - 0x1c]
cdqe
lea rdx, qword ptr [0x201040]
lea rax, qword ptr [rdx + rax*8]
mov qword ptr [rax], 0
"""
awd_pwn_patcher.patch_by_jmp(0x838, jmp_to=0x83d, assembly=assembly)
awd_pwn_patcher.save()
```



## 栈溢出

程序源码：

```C
//gcc overflow.c -o overflow64 -fno-stack-protector
//gcc overflow.c -o overflow32 -fno-stack-protector -no-pie -m32
#include <stdio.h>
#include <unistd.h>

int main()
{
    char a[32];
    read(0, a, 0x100);
    puts(a);
    return 0;
}
```



### 32位

```C
08048456 <main>:
 8048456:	8d 4c 24 04          	lea    ecx,[esp+0x4]
 804845a:	83 e4 f0             	and    esp,0xfffffff0
 804845d:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
 8048460:	55                   	push   ebp
 8048461:	89 e5                	mov    ebp,esp
 8048463:	53                   	push   ebx
 8048464:	51                   	push   ecx
 8048465:	83 ec 20             	sub    esp,0x20
 8048468:	e8 23 ff ff ff       	call   8048390 <__x86.get_pc_thunk.bx>
 804846d:	81 c3 93 1b 00 00    	add    ebx,0x1b93
 8048473:	83 ec 04             	sub    esp,0x4
 8048476:	68 00 01 00 00       	push   0x100
 804847b:	8d 45 d8             	lea    eax,[ebp-0x28]
 804847e:	50                   	push   eax
 804847f:	6a 00                	push   0x0
 8048481:	e8 7a fe ff ff       	call   8048300 <read@plt>
 8048486:	83 c4 10             	add    esp,0x10
 8048489:	83 ec 0c             	sub    esp,0xc
 804848c:	8d 45 d8             	lea    eax,[ebp-0x28]
 804848f:	50                   	push   eax
 8048490:	e8 7b fe ff ff       	call   8048310 <puts@plt>
 8048495:	83 c4 10             	add    esp,0x10
 8048498:	b8 00 00 00 00       	mov    eax,0x0
 804849d:	8d 65 f8             	lea    esp,[ebp-0x8]
 80484a0:	59                   	pop    ecx
 80484a1:	5b                   	pop    ebx
 80484a2:	5d                   	pop    ebp
 80484a3:	8d 61 fc             	lea    esp,[ecx-0x4]
 80484a6:	c3                   	ret
```

将0x8048476地址处的push 0x100改成push 0x20即可：

```python
binary = "./overflow32"
awd_pwn_patcher = AwdPwnPatcher(binary)
assembly = '''
push 0x20
'''
awd_pwn_patcher.patch_origin(0x8048476, end=0x804847b, assembly=assembly)
awd_pwn_patcher.save()
```

### 64位

```C
000000000000068a <main>:
 68a:	55                   	push   rbp
 68b:	48 89 e5             	mov    rbp,rsp
 68e:	48 83 ec 20          	sub    rsp,0x20
 692:	48 8d 45 e0          	lea    rax,[rbp-0x20]
 696:	ba 00 01 00 00       	mov    edx,0x100
 69b:	48 89 c6             	mov    rsi,rax
 69e:	bf 00 00 00 00       	mov    edi,0x0
 6a3:	e8 b8 fe ff ff       	call   560 <read@plt>
 6a8:	48 8d 45 e0          	lea    rax,[rbp-0x20]
 6ac:	48 89 c7             	mov    rdi,rax
 6af:	e8 9c fe ff ff       	call   550 <puts@plt>
 6b4:	b8 00 00 00 00       	mov    eax,0x0
 6b9:	c9                   	leave
 6ba:	c3                   	ret
```

将0x696地址处的mov edx, 0x100改成mov edx, 0x20即可：

```python
binary = "./overflow64"
awd_pwn_patcher = AwdPwnPatcher(binary)
assembly = '''
mov edx, 0x20
'''
awd_pwn_patcher.patch_origin(0x696, end=0x69b, assembly=assembly)
awd_pwn_patcher.save()
```



