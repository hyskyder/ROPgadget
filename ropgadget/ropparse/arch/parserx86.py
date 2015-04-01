#!/usr/bin/env python2
##
##	We define Instrution as two types "Computing instruction" and "Control Transfer instruction"
##		for computing instruction
##			"NAME" : [ Operand_Number , [ Formula_that_modify_reg ], [ FLAG_reg_modified]]
##		for control transfter instruciton
##			"NAME" : [ Operand_Number , [ Formula_that_modify_reg ], [ DST_Addr_on_condition]]
##
from capstone import *
from expression import Exp
from semantic import Semantic
from copy import deepcopy
class X86:
    FLAG = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]
    regs64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
            "r13", "r14", "r15", "CS", "DS", "ES", "FS", "GS", "SS"]
    regs32 = ["eax", "ebx", "ecx", "edx", "CS", "DS", "ES", "FS", "GS", "SS", "esi", "edi", "ebp", "esp", "eip"]
    Tregs64 = {
            "eax" : ["eax = rax $ 0 : 31", "rax = rax & 0xffffffff00000000 | eax"],
            "ax" : ["ax = rax $ 0 : 15", "rax = rax & 0xffffffffffff0000 | ax"],
            "ah" : ["ah = rax $ 8 : 15", "rax = rax & 0xffffffffffff00ff | ah"],
            "al" : ["ah = rax $ 0 : 7", "rax = rax & 0xffffffffffffff00 | al"],
            "ebx" : ["ebx = rbx $ 0 : 31", "rbx = rbx & 0xffffffff00000000 | ebx"],
            "bx" : ["bx = rbx $ 0 : 15", "rbx = rbx & 0xffffffffffff0000 | bx"],
            "bh" : ["bh = rbx $ 8 : 15", "rbx = rbx & 0xffffffffffff00ff | bh"],
            "bl" : ["bh = rbx $ 0 : 7", "rbx = rbx & 0xffffffffffffff00 | bl"],
            "ecx" : ["ecx = rcx $ 0 : 31", "rcx = rcx & 0xffffffff00000000 | ecx"],
            "cx" : ["cx = rcx $ 0 : 15", "rcx = rcx & 0xffffffffffff0000 | cx"],
            "ch" : ["ch = rcx $ 8 : 15", "rcx = rcx & 0xffffffffffff00ff | ch"],
            "cl" : ["ch = rcx $ 0 : 7", "rcx = rcx & 0xffffffffffffff00 | cl"],
            "edx" : ["edx = rdx $ 0 : 31", "rdx = rdx & 0xffffffff00000000 | edx"],
            "dx" : ["dx = rdx $ 0 : 15", "rdx = rdx & 0xffffffffffff0000 | dx"],
            "dh" : ["dh = rdx $ 8 : 15", "rdx = rdx & 0xffffffffffff00ff | dh"],
            "dl" : ["dh = rdx $ 0 : 7", "rdx = rdx & 0xffffffffffffff00 | dl"]
        }
    Tregs32 = {
            "ax" : ["ax = eax $ 0 : 15", "eax = eax & 0xffff0000 | ax"],
            "ah" : ["ah = eax $ 8 : 15", "eax = eax & 0xffff00ff | ah"],
            "al" : ["ah = eax $ 0 : 7", "eax = eax & 0xffffff00 | al"],
            "bx" : ["bx = ebx $ 0 : 15", "ebx = ebx & 0xffff0000 | bx"],
            "bh" : ["bh = ebx $ 8 : 15", "ebx = ebx & 0xffff00ff | bh"],
            "bl" : ["bh = ebx $ 0 : 7", "ebx = ebx & 0xffffff00 | bl"],
            "cx" : ["cx = ecx $ 0 : 15", "ecx = ecx & 0xffff0000 | cx"],
            "ch" : ["ch = ecx $ 8 : 15", "ecx = ecx & 0xffff00ff | ch"],
            "cl" : ["ch = ecx $ 0 : 7", "ecx = ecx & 0xffffff00 | cl"],
            "dx" : ["dx = edx $ 0 : 15", "edx = edx & 0xffff0000 | dx"],
            "dh" : ["dh = edx $ 8 : 15", "edx = edx & 0xffff00ff | dh"],
            "dl" : ["dh = edx $ 0 : 7", "edx = edx & 0xffffff00 | dl"],

    }
    # Instructions that modifty the execution path
    Control = ["ret", "iret", "int", "into", "enter", "leave", "call", "jmp", "ja", "jae", "jb", "jbe", "jc", "je","jnc", "jne", "jnp", "jp", "jg", "jge", "jl", "jle", "jno", "jns", "jo", "js"]
    insn = {
        # data transfer
	    "mov": [2, ["operand1 = operand2"], []],
	    "cmove": [2, ["operand1 = ( ZF == 1 ) ? operand2 : operand1"], []],
	    "cmovne": [2, ["operand1 = ( ZF == 0 ) ? operand2 : operand1"], []],
	    "cmova": [2, ["operand1 = ( ZF == 0 & CF == 0 ) ? operand2 : operand1"], []],
	    "cmovae": [2, ["operand1 = ( CF == 0 ) ? operand2 : operand1"], []],
	    "cmovb": [2, ["operand1 = ( CF == 1 ) ? operand2 : operand1"], []],
	    "cmovbe": [2, ["operand1 = ( ZF == 1 | CF == 1 ) ? operand2 : operand1"], []],
        "cmovg": [2, ["operand1 = ( ZF == 0 & SF == OF ) ? operand2 : operand1 "], []],
	    "cmovge": [2, ["operand1 = ( SF == OF ) ? operand2 : operand1"], []],
	    "cmovl": [2, ["operand1 = ( SF != OF ) ? operand2 : operand1"], []],
	    "cmovle": [2, ["operand1 = ( ZF == 1 & SF != OF ) ? operand2 : operand1"], []],
	    "cmovs": [2, ["operand1 = ( SF == 1 ) ? operand2 : operand1"], []],
	    "cmovp": [2, ["operand1 = ( PF == 1 ) ? operand2 : operand1"], []],

	    "push": [1, ["* ssp = operand1"], []],
	    "pop": [1, ["operand1 = * ssp"], []],

        "movsx": [2, ["operand1 = operand2 > 0 ? operand2 : operand2 & 0xffffffffffffffff"], []],
        "movzx": [2, ["operand1 = 0 & operand2"], []],
        # flag control instuctions
		"stc": [0, [], ["CF = 1"]],
	    "clc": [0, [], ["CF = 0"]],
	    "cmc": [0, [], ["CF = ~ CF"]],
	    "cld": [0, [], ["DF = 0"]],
	    "std": [0, [], ["DF = 1"]],
	    "sti": [0, [], ["IF = 1"]],
	    "cli": [0, [], ["IF = 0"]],
        # arithmetic
        "cmp": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
	    "add": [2, ["operand1 = operand1 + operand2"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
	    "adc": [2, ["operand1 = operand1 + operand2 + CF"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
	    "sub": [2, ["operand1 = operand1 - operand2"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
	    "sbb": [2, ["operand1 = operand1 - operand2 - CF"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
        # FIXME imul need specially atteition
#	    "imul": [3, [""]],
#        "mul": [1, []],
#        "idiv": [1, ["sax = sdx:sax / operand1", "sdx = sdx:sax % operand1"], []],
#        "div": [1, ["sax = sdx:sax / operand1", "sdx = sdx:sax % operand1"], []],

	    "inc": [1, ["operand1 = operand1 + 1"], ["OF", "SF", "ZF", "AF", "PF"]],
	    "dec": [1, ["operand1 = operand1 - 1"], ["OF", "SF", "ZF", "AF", "PF"]],
	    "neg": [1, ["operand1 = - operand1"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        # control transfer
        "ret": [1, [], ["* ssp"]],

        "call": [1, [], ["* operand1"]],

	    "jmp": [1, [], ["* operand1"]],
	    "ja": [1, [], ["CF == 0 & ZF == 0 ? * operand1 : 0"]],
	    "jae": [1, [], ["CF == 0 ? * operand1 : 0"]],
	    "jb": [1, [] , ["CF == 1 ? * operand1 : 0"]],
	    "jbe": [1, [] , ["CF == 1 | ZF == 1 ? * operand1 : 0"]],
	    "jc": [1, [], ["CF == 1 ? * operand1 : 0"]],
	    "je": [1, [], ["ZF == 1 ? * operand1 : 0"]],
	    "jnc": [1, [], ["CF == 0 ? * operand1 : 0"]],
	    "jne": [1, [], ["ZF == 0 ? * operand1 : 0"]],
	    "jnp": [1, [], ["PF == 0 ? * operand1 : 0"]],
	    "jp": [1, [], ["PF == 1 ? * operand1 : 0"]],
	    "jg": [1, [], ["ZF == 0 & SF == OF ? * operand1 : 0"]],
	    "jge": [1, [], ["SF == OF ? * operand1 : 0"]],
	    "jl": [1, [], ["SF != OF ? * operand1 : 0"]],
	    "jle": [1, [], ["ZF == 1 | SF != OF ? * operand1 : 0"]],
	    "jno": [1, [], ["OF == 0 ? * operand1 : 0"]],
	    "jns": [1, [], ["SF == 0 ? * operand1 : 0"]],
	    "jo": [1, [], ["OF == 1 ? * operand1 : 0"]],
	    "js": [1, [], ["SF == 1 ? * operand1 : 0"]],
        # logic
        "and": [2, ["operand1 = operand1 & operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
	    "or": [2, ["operand1 = operand1 | operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
	    "xor": [2, ["operand1 = operand1 ^ operand2"], ["CF","OF", "SF", "ZF", "PF"]],
	    "not": [1, ["operand1 = ~ operand1"], []],
        # shift and rotate
#        "sar": [2, ["operand1 = operand1 >> operand2"] , ["CF", "OF", "SF", "ZF", "PF"]],
#        "shr": [2, ["operand1 = operand1 >> operand2"], ["CF", "OF", "SF", "ZF", "PF"]],

#        "sal": [2, ["operand1 = operand1 << operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
#        "shl": [2, ["operand1 = operand1 << operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
#        "shrd": [2],
#        "shld": [2],
#        "ror": [2],
#        "rol": [2],
#        "rcr": [2],
#        "rcl": [2],
       # bit and bytes
#        "bt": [2, [""], ["CF = "]],
#        "bts": [],
#        "btr": [],
#        "btc": [],
#        "bsf": [],
#        "bsr": [],
        "sete": [1, ["operand1 = ZF == 1 ? 0xff : operand1"], []],
        "setne": [1, ["operand1 = ZF == 0 ? 0xff : operand1"], []],
        "seta": [1, ["operand1 = CF == 0 & ZF == 0 ? 0xff : operand1"],[]],
        "setae": [1, ["operand1 = CF == 0 ? 0xff : operand1"],[]],
        "setb": [1, ["operand1 = CF == 1 ? 0xff : operand1"],[]],
        "setbe": [1, ["operand1 = ZF == 1 | CF == 1 ? 0xff : operand1"], []],
        "setg": [1, ["operand1 = ZF == 0 & SF == OF ? 0xff : operand1"], []],
        "setge": [1, ["operand1 = SF == OF ? 0xff : operand1"], []],
        "setl": [1, ["operand1 = SF != OF ? 0xff : operand1"], []],
        "setle": [1, ["operand1 = ZF == 1 | SF != OF ? 0xff : operand1"], []],
        "sets": [1, ["operand1 = SF == 1 ? 0xff : operand1"], []],
        "setns": [1, ["operand1 = SF == 0 ? 0xff : operand1"], []],
        "seto": [1, ["operand1 = OF == 1 ? 0xff : operand1"], []],
        "setno": [1, ["operand1 = OF == 0 ? 0xff : operand1"], []],
        "setpe": [1, ["operand1 = PF == 1 ? 0xff : operand1"], []],
        "setpo": [1, ["operand1 = PF == 0 ? 0xff : operand1"], []],
        "test": [2, ["temp = operand1 & operand2"], ["OF = 0", "CF = 0", "SF", "ZF", "PF"]],
        # segment
        # others
        "lea": [2, ["operand1 = & operand2"], []],
        "nop": [0, [], []],
        # string operation
        "movsb": [2, ["operand1 = operand2"], []],
        "movsd": [2, ["operand1 = operand2"], []],
        "movsw": [2, ["operand1 = operand2"], []],
        "cmpsb": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "cmpsw": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "cmpsd": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "scasb": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "scasw": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "scasd": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "lodsb": [2, ["temp = operand1 = operand2"], []],
        "lodsw": [2, ["operand1 = operand2"], []],
        "lodsd": [2, ["operand1 = operand2"], []],
        "stosb": [2, ["operand1 = operand2"], []],
        "stosw": [2, ["operand1 = operand2"], []],
        "stosd": [2, ["operand1 = operand2"], []],
}
class ROPParserX86:
    def __init__(self, gadgets, mode):
        self.gadgets = gadgets
        self.mode = mode
        self.aligned = 0
        if mode == CS_MODE_32:
            self.regs = X86.regs32 + X86.FLAG
            self.Tregs = X86.Tregs32
            self.aligned = 4
        else:
            self.regs = X86.regs64 + X86.FLAG
            self.Tregs = X86.Tregs64
            self.aligned = 8

    def parse(self):
        formulas = []
        for gadget in self.gadgets:
            regs = {"ssp": Exp("ssp")}
            regs = self.parseInst(regs, gadget, 0)
            '''
            print "================================="
            print "Gadget string:"
            for inst in gadget:
                print inst["mnemonic"], inst["op_str"]
            print
            print "Gadget semantic:"
            for reg, v in regs.items():
                print reg, "==>", v
            print
            '''
            if len(regs) == 0:
                continue
            formulas.append(Semantic(regs, gadget))
        print "================================="
        print "Unique gadgets parsed ", len(formulas)
        return formulas


    def parseInst(self, regs, insts, i):
        if i == len(insts):
            return regs
        # all control transfer dst must bewteen low and high addr
        addr = insts[i]["vaddr"]
        prefix = insts[i]["mnemonic"]
        op_str = insts[i]["op_str"]
        if prefix not in X86.insn.keys():
            # contains not supported ins
            return {}
        ins = X86.insn.get(prefix)
        if prefix in X86.Control:
            # control transfer ins
            if prefix in ["ret", "call"]:
                operand1 = None
                operand1 = Exp.parseOperand(op_str.split(" ")[0], regs, self.Tregs)
                dst = Exp.parseExp(ins[2][0].split())
                if operand1 is None:
                    dst.binding({"operand1":0})
                else:
                    dst.binding({"operand1":operand1})
                regs.update({"sip":dst})
                # only ret inst can modify ssp
                if prefix == "ret":
                    ssp = regs["ssp"]
                    ssp = Exp(ssp, "-", self.aligned)
                    if operand1 is not None:
                        ssp = Exp(ssp, "-", operand1)
                    regs.update({"ssp":ssp})
                return regs

            # handle jmp
            operand1 = Exp.parseOperand(op_str.split(" ")[0], regs, self.Tregs)
            dst = Exp.parseExp(ins[2][0].split())
            dst.binding({"operand1":operand1})
            regs.update({"sip": dst})
            return regs
        else:
			# computing ins
            operand1 = None
            operand2 = None
            operands = {}
            # handle special cases
            if ins[0] == 1:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                operands.update({"operand1":operand1})
            elif ins[0] == 2:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                operand2 = Exp.parseOperand(op_str.split(", ")[1], regs, self.Tregs)
                operands.update({"operand1":operand1})
                operands.update({"operand2":operand2})
            # contruct all exps based on the instruction
            if len(ins[1]) > 0:
                exps = Exp.parse(ins[1][0], operands)
                for reg, val in exps.items():
                    if reg == "temp":
                        # temp variable, no need to assign
                        continue
                    dst = Exp.parseOperand(op_str.split(", ")[0], {}, self.Tregs)
                    if str(dst) in self.regs:
                        # GPRs
                        regs.update({str(dst):val})
                    elif str(dst) in self.Tregs:
                        # subpart of GPRs
                        temp = Exp.parse(self.Tregs[dst][1], {})
                        for k, v in temp.items():
                            v.binding(regs)
                            v.binding({{str(dst):val}})
                            regs.update({k:v})
                    else:
                        # mem
                        regs.update({str(reg):val})
                if prefix == "push":
                    regs.update({"ssp":Exp(regs["ssp"], "+", self.aligned)})
                if prefix == "pop":
                    regs.update({"ssp":Exp(regs["ssp"], "-", self.aligned)})

            # evaluate flag regs base on exp
            if len(ins[2]) != 0:
                for flag in ins[2]:
                    tokens = flag.split()
                    if len(tokens) == 1:
                        for k, v in exps.items():
                            regs.update({tokens[0]:v})
                    else:
                        f = Exp.parse(flag, {})
                        for k,v in f.items():
                            # "CF = 1" 
                            regs.update({tokens[0]:v})
            i = i + 1
            return self.parseInst(regs, insts, i)


if __name__ == '__main__':
    binarys = [b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\xc3",
               b"\xbb\x01\x00\x00\x00\x29\xd8\x83\xf8\x01\x0f\x84\x0f\xf9\x01\x00\x5a\xc3"]
    gadgets = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for binary in binarys:
        gadget = []
        for decode in md.disasm(binary, 0x1000):
            inst = {}
            inst.update({"mnemonic": decode.mnemonic})
            inst.update({"op_str": decode.op_str})
            inst.update({"vaddr": decode.address})
            gadget.append(inst)
        gadgets.append(gadget)
    p = ROPParserX86(gadgets, CS_MODE_32)
    formulas = p.parse()
