# AwdPwnPatcher

AwdPwnPatcher是一款针对CTF AWD比赛中PWN题的半自动化patch工具，有以下几个优点：

- 可以很方便地对补丁做好版本管理
- 适合多人协作patch
- 支持x86、mips、arm三种架构，支持32位、64位以及大小端模式

为什么要写这样一款工具，因为感觉目前用IDA或者lief工具在进行patch的时候，会有以下问题：

- IDA修改原文件，需要通过Edit -> Patch program -> Apply patches to input file才能使修改生效，可能会因为忘记使用该操作而导致修改未生效
- IDA修改原文件时，可以选择将原文件备份成.bak，然后在原文件上进行修改，此时可能产生的影响是，如果多次使用Apply patches to input file，你只会保留前一个修改后的副本，这时你想回退到之前的副本时，几乎不可能。
- 用IDA在patch的时候，如果patch失败了想回退，除非你之前有保存过快照，即View -> Database snapshot manager，否则你只能选择关闭IDA重新打开。
- lief在给程序patch的时候，前后文件改动会比较大，往往很难过check

因此，诞生了AwdPwnPatcher这款工具，该工具基于pwntools+keystone来辅助二进制选手进行patch，你可以将所有的patch代码以汇编的形式写进脚本里然后一键patch，这样如果哪一处patch有问题，直接修改对应的代码即可，而不会造成混乱。

该工具目前适用x86、arm和mips架构，包括32位和64位，该脚本patch的思路主要是通过jmp跳转到eh_frame段执行patch代码，然后再跳回程序原逻辑。当然也支持patch call指令（只针对x86，arm和mips暂未添加），改为调用在eh_frame段添加的函数，但这种方式很有可能在比赛中过不了check，比方UAF漏洞，不允许patch call free。

## 依赖安装

支持python2/python3环境：

```
sudo pip install pwntools
sudo pip install keystone-engine
```

## 使用说明

添加AwdPwnPatcher脚本所在目录至环境变量：

```
export PYTHONPATH=/path/to/AwdPwnPatcher:$PYTHONPATH
```

引用：

```
from AwdPwnPatcher import *
```

加载目标程序：

```
binary = "./test"
awd_pwn_patcher = AwdPwnPatcher(binary)
```

然后通过调用类成员函数，对目标程序进行patch，一些关键函数如下：

**add_patch_in_ehframe(self, assembly="", machine_code=[])**

- 作用：在eh_frame段中添加patch代码
- 参数
  - assembly：要添加的汇编代码，与machine_code二选一
  - machine_code：要添加的机器码，类型为整数列表，与assembly二选一

**patch_origin(self, start, end=0, assembly="", machine_code=[], string="")**

- 作用：主要针对在原地址处修改指令或字符串的patch
- 参数：
  - start：原程序待patch的起始指令地址
  - end：原程序待patch的结束指令地址，如果不为0，则会要求assembly翻译成机器码的长度或者machine_code的长度必须小于等于end-start，小于的时候会用nop指令填充
  - assembly：要添加的汇编代码，与machine_code二选一
  - machine_code：要添加的机器码，类型为整数列表，与assembly二选一
  - string：要修改成的字符串，也可以用来修改整数，整数需要转成字符串，该参数与汇编的两个参数二选一

**patch_by_jmp(self, jmp_from, jmp_to=0, assembly="", machine_code=[])**

- 作用：通过jmp指令修改原程序逻辑，使得跳转到eh_frame段处的patch代码，执行完patch代码后再跳转回去
- 参数
  - jmp_from：地址，表示从原程序哪一条指令jmp到我们的patch代码
  - jmp_to：地址，表示patch代码结束后，需要跳转的目标指令地址，该参数不为0的情况下，patch_by_jmp函数会自动在patch代码的最后添加jmp语句，为0默认表示用户已经在原有的assembly或machine_code中考虑了跳转情况。
  - assembly：要添加的汇编代码，与machine_code二选一
  - machine_code：要添加的机器码，类型为整数列表，与assembly二选一

**patch_by_call(self, call_from, assembly="", machine_code=[])**

- 作用：通过修改call指令，使其调用在eh_frame段添加的函数，目前只适用x86架构
- 参数
  - call_from：要patch的call指令地址
  - assembly：要在eh_frame段插入的汇编代码，记得包含ret，与machine_code二选一
  - machine_code：要添加的机器码，类型为整数列表，与assembly二选一

**add_constant_in_ehframe(self, string)**

- 作用：在eh_frame段中添加常量，如整数、字符串等。
- 参数：
  - string：常量，类型为str，比如添加整数0xffff，则值为'\xff\xff\x00\x00'
- 返回值：常量的起始地址

**get_next_patch_start_addr(self)**

- 作用：获取下一段patch代码的起始地址

**save(self, save_path="")**

- 作用：当执行完所有的patch后，通过save函数将结果保存到二进制文件中，在不提供save_patch参数的时候，默认文件以_patch为后缀名。在保存的时候，会自动修改eh_frame段为可执行。

## 教程样例

程序和代码见example文件夹，详细教程见[Tutorial](./Tutorial.md)。

## 更新日志

### 2022-10-17

- 修复patch_by_jump函数逻辑问题：当同时提供jmp_to和machine_code两个参数时，machine_code不会写入。
- 增加对python3的支持

### 2021-11-19

修复patch_by_jmp针对mips架构的时候，对跳转指令翻译有误问题。keystone在翻译b跳转指令的时候，偏移计算的时候是以ks.asm参数addr作为基准，因此如果此时翻译的指令有好几条汇编，b跳转指令并不是第一条的时候，翻译b指令计算相对偏移的时候，并不会自动以b指令对应的地址作为基准，而是直接以参数addr计算，所以跳转的地址翻译就会有偏差，因此针对这种情况，会重新翻译b指令，把之前的覆盖。

### 2021-11-16

支持mips32、mips64、arm和aarch64，由于arm和mips架构的程序eh_frame的size都比较小，无法直接用，但其实eh_frame后面有一段部分内存是可用的且没有其他数据存在，因此修改prgrame header table将这段内存空间也映射到虚拟空间里来。

### 2021-09-27

save函数自动将ehframe段修改为可执行

### 2021-09-22

- 更新README的使用说明
- 添加样例教程
