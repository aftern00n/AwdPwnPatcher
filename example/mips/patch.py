#!/usr/bin/env python
# coding=utf-8

from AwdPwnPatcher import *

# 32 mips nopie
awd_pwn_patcher = AwdPwnPatcher("./vuln32_nopie")
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
assembly = """
lw $v0, 0($v0)
move $a1, $v0
li $a0, {}
""".format(hex(fmt_addr))
awd_pwn_patcher.patch_by_jmp(0x400E38, jmp_to=0x400E40, assembly=assembly)

assembly = """
li $a2, 0x20
"""
awd_pwn_patcher.patch_origin(0x4009fc, assembly=assembly)

assembly = """
lw $v1, -0x7fd8($gp)
lw $v0, 0x1c($fp)
sll $v0, 2
addu $v0, $v1, $v0
sw $zero, 0($v0)
"""
awd_pwn_patcher.patch_by_jmp(0x400Da0, jmp_to=0x400dc4, assembly=assembly)
awd_pwn_patcher.save()


# 32 mips pie
awd_pwn_patcher = AwdPwnPatcher("./vuln32_pie")
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
save_fmt_addr = awd_pwn_patcher.add_constant_in_ehframe(p32(fmt_addr))
assembly = """
lw $a1, 0($v0)
lw $a0, -{}($gp)
addu $a0, $a0, $gp
subu $a0, $a0, 0x1a030
""".format(hex(0x1a030-save_fmt_addr))
awd_pwn_patcher.patch_by_jmp(0x1004, jmp_to=0x100c, assembly=assembly)

assembly = """
li $a2, 0x20
"""
awd_pwn_patcher.patch_origin(0xb9c, assembly=assembly)

assembly = """
lw $v1, -0x7fc0($gp)
lw $v0, 0x1c($fp)
sll $v0, 2
addu $v0, $v1, $v0
sw $zero, 0($v0)
"""
awd_pwn_patcher.patch_by_jmp(0xf60, jmp_to=0xf84, assembly=assembly)
awd_pwn_patcher.save()

# 64 mips
awd_pwn_patcher = AwdPwnPatcher("./vuln64")
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
assembly = """
ld $a1, 0($v0)
move $a0, $gp
dsubu $a0, 0x8000
dsubu $a0, 0x8000
dsubu $a0, 0x5000
dsubu $a0, 0x5030
daddiu $a0, $a0, {}
""".format(hex(fmt_addr))
awd_pwn_patcher.patch_by_jmp(0x13f0, jmp_to=0x13f8, assembly=assembly)

assembly = """
li $a2, 0x20
"""
awd_pwn_patcher.patch_origin(0xfcc, assembly=assembly)

assembly = """
ld $v1, -0x7f80($gp)
lw $v0, 0xc($fp)
dsll $v0, 3
daddu $v0, $v1, $v0
sw $zero, 0($v0)
"""
awd_pwn_patcher.patch_by_jmp(0x1354, jmp_to=0x1374, assembly=assembly)
awd_pwn_patcher.save()