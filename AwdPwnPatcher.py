#!/usr/bin/env python
# coding=utf-8

from pwn import *
import keystone
import ctypes
import shutil
import struct
import sys

PYTHON_VERSION = sys.version_info[0]

class AwdPwnPatcher:
    def __init__(self, path, adjust_eh_frame_size=True):
        self.path = path
        self.save_path = path + "_patch"
        self.binary = ELF(self.path)
        self.bits = self.binary.bits
        self.pie = self.binary.pie
        self.endian = self.binary.endian
        self.arch = self.binary.arch
        if self.bits != 32 and self.bits != 64:
            print("Sorry, the architecture of program is neither 32-bit or 64-bit.")
            quit()
        if self.arch == "arm":
            self.ks_arch = keystone.KS_ARCH_ARM
            self.ks_mode = keystone.KS_MODE_ARM
        elif self.arch == "aarch64":
            self.ks_arch = keystone.KS_ARCH_ARM64
            self.ks_mode = 0
        elif self.arch == "i386" or self.arch == "amd64":
            self.ks_arch = keystone.KS_ARCH_X86
            self.ks_mode = keystone.KS_MODE_32 if self.bits == 32 else keystone.KS_MODE_64
        elif self.arch == "mips" or self.arch == "mips64":
            self.ks_arch = keystone.KS_ARCH_MIPS
            self.ks_mode = keystone.KS_MODE_MIPS32 if self.bits == 32 else keystone.KS_MODE_MIPS64
        else:
            self.ks_mode = 0
            self.ks_arch = 0
        if self.endian == "little":
            self.ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
        else:
            self.ks_mode |= keystone.KS_MODE_BIG_ENDIAN
        if self.ks_arch != 0:
            self.ks = keystone.Ks(self.ks_arch, self.ks_mode)
        self.eh_frame_section = self.binary.get_section_by_name(".eh_frame")
        self.eh_frame_addr = self.eh_frame_section.header.sh_addr
        self.eh_frame_size = self.eh_frame_section.header.sh_size
        self.offset = 0
        if adjust_eh_frame_size:
            self.adjust_eh_frame_size()

    def adjust_eh_frame_size(self):
        if self.arch == "arm" or self.arch == "aarch64" or self.arch == "mips" or self.arch == "mips64":
            PAGE_SIZE = 0x1000
            for i in range(self.binary.num_sections()):
                section = self.binary.get_section(i)
                if self.binary._get_section_name(section) == ".eh_frame":
                    break
            if self.arch == "mips64":
                self.note_section = self.binary.get_section(i+1)
                self.ctors_section = self.binary.get_section(i+2)
                self.offset = self.eh_frame_size + self.note_section.header.sh_size
                self.eh_frame_next_section = self.ctors_section
            else:
                self.eh_frame_next_section = self.binary.get_section(i+1)
            self.eh_frame_section_header_offset = self.binary._section_offset(i)
            actual_size = self.eh_frame_next_section.header.sh_offset - self.eh_frame_section.header.sh_offset
            self.eh_frame_end_addr = self.eh_frame_addr + self.eh_frame_size
            if (self.eh_frame_end_addr % PAGE_SIZE) != 0:
                self.eh_frame_end_addr_align = (self.eh_frame_end_addr + PAGE_SIZE) & ctypes.c_uint32(~PAGE_SIZE + 1).value
            self.old_eh_frame_size = self.eh_frame_size
            if self.eh_frame_addr + actual_size > self.eh_frame_end_addr_align:
                self.eh_frame_size = self.eh_frame_end_addr_align - self.eh_frame_addr
            else:
                self.eh_frame_size = actual_size
            load_segment = self.binary.get_segment_for_address(self.eh_frame_addr)
            for i in range(self.binary.num_segments()):
                segment = self.binary.get_segment(i)
                if segment.header.p_vaddr == load_segment.header.p_vaddr:
                    break
            self.load_segment_header_offset = self.binary._segment_offset(i)
            if self.endian == "little":
                endian_fmt = "<"
            else:
                endian_fmt = ">"
            new_size = self.eh_frame_size - self.old_eh_frame_size + load_segment.header.p_filesz
            shutil.copy2(self.path, self.save_path)
            self.bin_file = open(self.save_path, "rb+")
            if self.bits == 32:
                self.bin_file.seek(self.load_segment_header_offset+16)
                self.bin_file.write(struct.pack(endian_fmt+"I", new_size))
                self.bin_file.write(struct.pack(endian_fmt+"I", new_size))
            else:
                self.bin_file.seek(self.load_segment_header_offset+32)
                self.bin_file.write(struct.pack(endian_fmt+"Q", new_size))
                self.bin_file.write(struct.pack(endian_fmt+"Q", new_size))
            self.bin_file.close()
            self.binary = ELF(self.save_path)

            print("old eh_frame_size: %#x" % self.old_eh_frame_size)
        print("eh_frame_size: %#x" % self.eh_frame_size)

    def patch_file(self, offset, content, save_path=""):
        if len(save_path) != 0:
            shutil.copy2(self.path, save_path)
            self.bin_file = open(save_path, "rb+")
        else:
            shutil.copy2(self.path, self.save_path)
            self.bin_file = open(self.save_path, "rb+")
        self.bin_file.seek(offset)
        self.bin_file.write(content)
        self.bin_file.close()

    def generate_shellcode(self, assembly, base_addr):
        shellcode, count = self.ks.asm(assembly, addr=base_addr)
        shellcode = "".join([chr(x) for x in shellcode])
        return shellcode

    def add_patch_in_ehframe(self, assembly="", machine_code=[]):
        patch_start_addr = self.eh_frame_addr + self.offset
        if len(assembly) != 0 :
            shellcode, count = self.ks.asm(assembly, addr=patch_start_addr)
            shellcode = "".join([chr(x) for x in shellcode])
        elif len(machine_code) != 0:
            shellcode = "".join([chr(x) for x in machine_code])
        else:
            shellcode = ""

        if len(shellcode) == 0:
            return 0

        self.offset += len(shellcode)
        assert(self.offset <= self.eh_frame_size)
        if PYTHON_VERSION == 3:
            shellcode = shellcode.encode("latin-1")
        self.binary.write(patch_start_addr, shellcode)
        return patch_start_addr

    def patch_origin(self, start, end=0, assembly="", machine_code=[], string=""):
        if len(assembly) != 0:
            shellcode, count = self.ks.asm(assembly, addr=start)
            shellcode = "".join([chr(x) for x in shellcode])
        elif len(machine_code) != 0:
            shellcode = "".join([chr(x) for x in machine_code])
        elif len(string) != 0:
            shellcode = string
        else:
            shellcode = ""
        if end != 0:
            assert(len(shellcode) <= (end-start))
            shellcode = shellcode.ljust(end - start, "\x90")
        if PYTHON_VERSION == 3:
            shellcode = shellcode.encode("latin-1")
        self.binary.write(start, shellcode)

    def patch_by_jmp(self, jmp_from, jmp_to=0, assembly="", machine_code=[]):
        if self.arch == "i386" or self.arch == "amd64":
            jmp_ins = "jmp"
        elif self.arch == "arm" or self.arch == "aarch64":
            jmp_ins = "b"
        elif self.arch == "mips" or self.arch =="mips64":
            if self.pie:
                jmp_ins = "b"
            else:
                jmp_ins = "j"
        if jmp_to:
            payload = "{} {}".format(jmp_ins, hex(jmp_to))
            if len(assembly) != 0:
                assembly += "\n" + payload
            else:
                addr = self.get_next_patch_start_addr() + len(machine_code)
                shellcode, count = self.ks.asm(payload, addr=addr)
                machine_code += shellcode
        patch_start_addr = self.add_patch_in_ehframe(assembly=assembly, machine_code=machine_code)
        if jmp_to:
            # fix translation bug of mips jump code: when keystone translates jmp code, it treats the value of argument start as the base address,
            # rather than the address of jump code.
            # FYI: shellcode, count = self.ks.asm(assembly, addr=patch_start_addr)
            if self.arch == "mips" or self.arch == "mips64":
                next_patch_addr = self.get_next_patch_start_addr()
                payload = "{} {}".format(jmp_ins, hex(jmp_to))
                # why - 8? because a nop code will be added automatically after jmp code.
                self.patch_origin(next_patch_addr-8, assembly=payload)

        if patch_start_addr == 0:
            return 0
        payload = "{} {}".format(jmp_ins, hex(patch_start_addr))
        self.patch_origin(jmp_from, assembly=payload)
        return patch_start_addr

    def patch_by_call(self, call_from, assembly="", machine_code=[]):
        if self.arch != "i386" and self.arch != "amd64":
            print("Sorry, patch_by_call only support x86 architecture!")
            quit()
        patch_start_addr = self.add_patch_in_ehframe(assembly=assembly, machine_code=machine_code)
        if patch_start_addr == 0:
            return 0

        payload = "call {}".format(hex(patch_start_addr))
        self.patch_origin(call_from, assembly=payload)
        return patch_start_addr

    def add_constant_in_ehframe(self, string):
        patch_start_addr = self.eh_frame_addr + self.offset
        if PYTHON_VERSION == 3:
            string = string.encode("latin-1")
        self.binary.write(patch_start_addr, string)
        self.offset += len(string)
        return patch_start_addr

    def patch_fmt_by_call(self, call_from):
        if self.arch != "i386" and self.arch != "amd64":
            print("Sorry, patch_fmt_by_call only support x86 architecture!")
            quit()
        fmt_addr = self.add_constant_in_ehframe("%s\x00\x00")
        patch_start_addr = self.eh_frame_addr + self.offset

        printf_addr = (call_from + 5 + u32(self.binary.read(call_from+1, 4))) & 0xffffffff
        if self.bits == 32 and not self.pie:
            assembly = """
            mov eax, dword ptr [esp+4]
            push eax
            lea eax, dword ptr [{0}]
            push eax
            call {1}
            add esp, 0x8
            ret
            """.format(hex(fmt_addr), hex(printf_addr))
        elif self.bits == 32 and self.pie:
            assembly = """
            call {0}
            mov eax, dword ptr [esp+8]
            push eax
            mov eax, dword ptr [esp+4]
            sub eax, {0}
            add eax, {1}
            push eax
            call {2}
            add esp, 0xc
            ret
            """.format(hex(patch_start_addr+5), fmt_addr, hex(printf_addr))
        else:
            assembly = """
            mov rsi, rdi
            lea rdi, qword ptr [{0}]
            call {1}
            ret
            """.format(hex(fmt_addr), hex(printf_addr))
        self.patch_by_call(call_from, assembly=assembly)

            
    def save(self, save_path="", fix_eh_frame_flags=True):
        if fix_eh_frame_flags:
            self.fix_eh_frame_flags()
        if len(save_path) != 0:
            self.binary.save(save_path)
        else:
            self.binary.save(self.save_path)

    def get_next_patch_start_addr(self):
        return self.eh_frame_addr + self.offset

    def fix_eh_frame_flags(self):
        e_phnum = self.binary.header.e_phnum
        e_phoff = self.binary.header.e_phoff
        phdr_size = 32 if self.bits == 32 else 56
        p_flags_offset = 24 if self.bits == 32 else 4
        for i in range(0, e_phnum):
            phdr = self.binary.get_segment(i).header
            page_start = int((phdr.p_vaddr / 0x1000) * 0x1000)
            page_end = phdr.p_vaddr + phdr.p_memsz
            if page_end % 0x1000 != 0:
                page_end = (page_end / 0x1000) * 0x1000 + 0x1000
                page_end = int(page_end)
            if phdr.p_type == "PT_LOAD" and page_start <= self.eh_frame_addr and page_end >= self.eh_frame_addr + self.eh_frame_size:
                print("fix_eh_frame_flags:\npage_start: {} page_end: {} eh_frame_addr: {} eh_frame_size: {} origin phdr.p_flags: {}"
                      .format(hex(page_start), hex(page_end), hex(self.eh_frame_addr), hex(self.eh_frame_size), str(phdr.p_flags)))
                flags = chr(phdr.p_flags | 1)
                if PYTHON_VERSION == 3:
                    flags = flags.encode("latin-1")
                self.binary.write(e_phoff + phdr_size * i + p_flags_offset, flags)

