#!/usr/bin/env python2

class Operands:
    # specially for "ret", none or one operand required
    fields = [
            # data transfer
            "mov", "cmove", "cmovne", "cmova", "cmovae", "cmovb", "cmovbe", "cmovg", "cmovge", "cmovl", "cmovle", "cmovs","cmovp","xchg", "bswap", "xadd", "cmpxchg", "push","pop", "in", "out", "cwde", "cdq", "movsx". "movzx",
            # flag control instuctions
            "stc", "clc", "cmc", "cld", "std", "lahf", "shf", "pushfq", "popfq", "sti", "cli",
            # arithmetic
            "add", "adc", "sub", "sbb", "imul","mul", "idiv", "div", "inc", "dec", "neg", "cmp", "daa", "das", "aaa", "aas", "aam", "aad"
            # control transfer
            "ret", "iret", "int", "into", "enter", "leave", "call", "jmp", "ja", "jae", "jb", "jbe", "jc", "je", "jnc", "jne", "jnp", "jp", "jg", "jge", "jl", "jle", "jno", "jns","jo", "js", 
            # logic
            "and", "or", "xor", "not",
            # shift and rotate
            "sar", "shr", "sal", "shrd", "shld", "ror", "rol", "rcr", "rcl",
            # bit and bytes
            "bt", "bts", "btr", "btc", "bsf", "bsr", "sete", "setne", "seta", "setae", "setb", "setbe", "setg", "setge", "setl", "setle", "sets", "setns", "seto", "setno", "setpe", "setpo", "test",
            # segment 
            "lds", "les", "lfs", "lgs", "lss",
            # others
            "lea", "nop", "xlatb"]


class ROPChain:
    def __init__(self, binary, gadgets):
        self.binary = binary
        self.gadgets = gadgets


    def parse_gadget(self):
        for gadget in gadgets:
            ins = gadget["gadget"].split(" ; ")
            # reg init
            for ins in ins:
                exp = parse_exp(ins)


    def parse_exp(self, string):
        operator = string.split()[0]
        
