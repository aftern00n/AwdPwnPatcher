#!/usr/bin/env python
# coding=utf-8
from AwdPwnPatcher import *

# arm 32 nopie
awd_pwn_patcher = AwdPwnPatcher("./vuln32_nopie")
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
save_fmt_addr = awd_pwn_patcher.add_constant_in_ehframe(p32(fmt_addr))
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
mov r1, r3
ldr r0, [pc, #{}]
""".format(hex(save_fmt_addr-patch_start_addr-0xc))
awd_pwn_patcher.patch_by_jmp(0x10900, jmp_to=0x10904, assembly=assembly)

assembly = """
mov r2, 0x20
"""
awd_pwn_patcher.patch_origin(0x106cc, assembly=assembly)

book_ptr = awd_pwn_patcher.add_constant_in_ehframe(p32(0x2107C))
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
ldr r2, [pc, #{}]
ldr r3, [r11, #-8]
mov r1, 0
str r1, [r2, r3, LSL#2]
""".format(hex(book_ptr-patch_start_addr-8))
awd_pwn_patcher.patch_by_jmp(0x108B4, jmp_to=0x108c0, assembly=assembly)
awd_pwn_patcher.save()

# arm 32 pie
awd_pwn_patcher = AwdPwnPatcher("./vuln32_pie")
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
save_fmt_addr = awd_pwn_patcher.add_constant_in_ehframe(struct.pack("<i", fmt_addr-0x11000))
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
mov r1, r3
ldr r0, [pc, #{}]
add r0, r4, r0
""".format(hex(save_fmt_addr-patch_start_addr-0xc))
awd_pwn_patcher.patch_by_jmp(0xb14, jmp_to=0xb18, assembly=assembly)

assembly = """
mov r2, 0x20
"""
awd_pwn_patcher.patch_origin(0x82c, assembly=assembly)

book_ptr = awd_pwn_patcher.add_constant_in_ehframe(p32(0x1106c-0x11000))
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
ldr r3, [pc, #{}]
ldr r3, [r4, r3]
ldr r2, [r11, #-0x10]
mov r1, 0
str r1, [r3, r2, LSL#2]
""".format(hex(book_ptr-patch_start_addr-8))
awd_pwn_patcher.patch_by_jmp(0xaa8, jmp_to=0xabc, assembly=assembly)
awd_pwn_patcher.save()

# arm 64
awd_pwn_patcher = AwdPwnPatcher("./vuln64")
fmt_addr = awd_pwn_patcher.add_constant_in_ehframe("%s\x00\x00")
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
ldr x0, [x0,x1,LSL#3]
mov x1, x0
adrp x0, #label
label:
add x0, x0, {}
""".format(hex(fmt_addr&0xfff))
awd_pwn_patcher.patch_by_jmp(0xd50, jmp_to=0xd54, assembly=assembly)

assembly = """
mov x2, 0x20
"""
awd_pwn_patcher.patch_origin(0xb34, assembly=assembly)


book_ptr = awd_pwn_patcher.add_constant_in_ehframe(p64(0x11ff8))
patch_start_addr = awd_pwn_patcher.get_next_patch_start_addr()
assembly = """
adrp x0, #label
label:
add x1, x0, {}
ldr x1, [x1]
ldr x0, [x0, x1]
ldrsw x1, [x29,#0x1c]
mov x2, 0
str x2, [x0, x1, LSL#3]
""".format(book_ptr&0xfff)
awd_pwn_patcher.patch_by_jmp(0xd0c, jmp_to=0xd1c, assembly=assembly)
awd_pwn_patcher.save()