#!/usr/bin/env python
# coding=utf-8

from AwdPwnPatcher import *

binary = "./vuln64"
awd_pwn_patcher = AwdPwnPatcher(binary)
fmt_offset = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
assembly = """
mov rsi, rax
lea rdi, qword ptr [{}]
""".format(hex(fmt_offset))
awd_pwn_patcher.patch_by_jmp(0xbd4, jmp_to=0xbdc, assembly=assembly)

assembly = """
mov edx, 0x20
"""
awd_pwn_patcher.patch_origin(0x9db, end=0x9e0, assembly=assembly)

assembly = """
lea rax, qword ptr [rdx + rax]
mov rdi, qword ptr [rax]
mov qword ptr [rax], 0
"""
awd_pwn_patcher.patch_by_jmp(0xb7e, jmp_to=0xb85, assembly=assembly)
awd_pwn_patcher.save()