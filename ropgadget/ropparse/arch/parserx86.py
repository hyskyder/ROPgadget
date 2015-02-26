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
	    "xchg": [2, ["operand1 = operand2", "operand2 = operand1"], []],
#	    "bswap": [2, ["operand1"], []], # TODO
	    "xadd": [2, ["operand2 = operand1 + operand2", "operand1 = operand2"], ["CF", "PF", "AF", "SF", "ZF", "OF"]],
        "cmpxchg": [2, ["temp = sax - operand1", "operand1 = sax - operand1 == 0 ? operand2 : operand1", "sax = sax - operand1 != 0 ? operand1 : sax"],["CF", "PF", "AF", "SF", "ZF", "OF"]],
	    "push": [1, ["* ssp = operand1", "ssp = ssp - length"], []],
	    "pop": [1, ["operand1 = * ssp", "ssp = ssp + length"], []],
#	    "in": [2,["operand1 = undefined"], []],
#	    "out": [2, [], []],
#        "cwde": [0, ["dx = ax > 0 ? 0 : 0xffff"], []],
#        "cdq": [0,["edx = eax > 0 ? 0 : 0xffffffff"],[]],
        "movsx": [2, ["operand1 = operand2 > 0 ? operand2 : operand2 & 0xffffffffffffffff"], []],
        "movzx": [2, ["operand1 = 0 & operand2"], []],

#       flag control instuctions
		"stc": [0, [], ["CF = 1"]],
	    "clc": [0, [], ["CF = 0"]],
	    "cmc": [0, [], ["CF = ~ CF"]],
	    "cld": [0, [], ["DF = 0"]],
	    "std": [0, [], ["DF = 1"]],
#	    "lahf": [0],
#	    "shf": [0],
#	    "pushfq": [1],
#	    "popfq": [1],
	    "sti": [0, [], ["IF = 1"]],
	    "cli": [0, [], ["IF = 0"]],
        # arithmetic
        "cmp": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
#	    "daa": [1],
#	    "das": [1],
#	    "aaa": [1],
#	    "aas": [1],
#	    "aam": [1],
#	    "aad":[1],
	    "add": [2, ["operand1 = operand1 + operand2"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
	    "adc": [2, ["operand1 = operand1 + operand2 + CF"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
	    "sub": [2, ["operand1 = operand1 - operand2"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
	    "sbb": [2, ["operand1 = operand1 - operand2 - CF"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
        # FIXME imul need specially atteition
        # NOTE those 4 cases are handled manully
#	    "imul": [3, [""]],
#        "mul": [1, []],
#        "idiv": [1, ["sax = sdx:sax / operand1", "sdx = sdx:sax % operand1"], []],
#        "div": [1, ["sax = sdx:sax / operand1", "sdx = sdx:sax % operand1"], []],

	    "inc": [1, ["operand1 = operand1 + 1"], ["OF", "SF", "ZF", "AF", "PF"]],
	    "dec": [1, ["operand1 = operand1 - 1"], ["OF", "SF", "ZF", "AF", "PF"]],
	    "neg": [1, ["operand1 = - operand1"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        # control transfer
        "ret": [1, ["ssp = ssp + length + operand1"], ["* ssp"]],
        # for call address need to be handle
        "call": [1, [], ["operand1"]],
#        "int": [1, [], ["undefined"]],
#        "into": [0, [], ["OF == 1 ? undefined : next"]],
        # TODO, enter and leave
	    #"enter": [2, ["*sp = bp", "sp = sp + length", ""], []],
	    #"leave": [0, [], ["undefined"]],

	    "jmp": [1, [], ["operand1"]],
	    "ja": [1, [], ["CF == 0 & ZF == 0 ? operand1 : next"]],
	    "jae": [1, [], ["CF == 0 ? operand1 : next"]],
	    "jb": [1, [] , ["CF == 1 ? operand1 : next"]],
	    "jbe": [1, [] , ["CF == 1 | ZF == 1 ? operand1 : next"]],
	    "jc": [1, [], ["CF == 1 ? operand1 : next"]],
	    "je": [1, [], ["ZF == 1 ? operand1 : next"]],
	    "jnc": [1, [], ["CF == 0 ? operand1 : next"]],
	    "jne": [1, [], ["ZF == 0 ? operand1 : next"]],
	    "jnp": [1, [], ["PF == 0 ? operand1 : next"]],
	    "jp": [1, [], ["PF == 1 ? operand1 : next"]],
	    "jg": [1, [], ["ZF == 0 & SF == OF ? operand1 : next"]],
	    "jge": [1, [], ["SF == OF ? operand1 : next"]],
	    "jl": [1, [], ["SF != OF ? operand1 : next"]],
	    "jle": [1, [], ["ZF == 1 | SF != OF ? operand1 : next"]],
	    "jno": [1, [], ["OF == 0 ? operand1 : next"]],
	    "jns": [1, [], ["SF == 0 ? operand1 : next"]],
	    "jo": [1, [], ["OF == 1 ? operand1 : next"]],
	    "js": [1, [], ["SF == 1 ? operand1 : next"]],
        # logic
        "and": [2, ["operand1 = operand1 & operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
	    "or": [2, ["operand1 = operand1 | operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
	    "xor": [2, ["operand1 = operand1 ^ operand2"], ["CF","OF", "SF", "ZF", "PF"]],
	    "not": [1, ["operand1 = ~ operand1"], []],
        # shift and rotate
        # For SAR, the sign bit is taken care by python
        # Ex, -2 >> 4 = -1,  2 >> 4 = 0
        "sar": [2, ["operand1 = operand1 >> operand2"] , ["CF", "OF", "SF", "ZF", "PF"]],
        "shr": [2, ["operand1 = operand1 >> operand2"], ["CF", "OF", "SF", "ZF", "PF"]],

        "sal": [2, ["operand1 = operand1 << operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
        "shl": [2, ["operand1 = operand1 << operand2"], ["CF", "OF", "SF", "ZF", "PF"]],
        #	    "shrd": [2],
        #	    "shld": [2],
        #	    "ror": [2],
        #	    "rol": [2],
        #	    "rcr": [2],
        #	    "rcl": [2],
        #            # bit and bytes
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
        #            "lds": [0],
        #	    "les": [0],
        #	    "lfs": [0],
        #	    "lgs": [0],
        #	    "lss": [0],
        #            # others
        "lea": [2, ["operand1 = & operand2"], []],
        "nop": [0, [], []],
#        "xlatb": [0, ["al = [ sbx + al ]"],[]],
        # string operation
        "movsb": [2, ["operand1 = operand2"], []],
        "movsd": [2, ["operand1 = operand2"], []],
        "movsw": [2, ["operand1 = operand2"], []],
        "cmpsb": [2, ["operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "cmpsw": [2, ["operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "cmpsd": [2, ["operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "scasb": [2, ["operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "scasw": [2, ["operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "scasd": [2, ["operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "lodsb": [2, ["operand1 = operand2"], []],
        "lodsw": [2, ["operand1 = operand2"], []],
        "lodsd": [2, ["operand1 = operand2"], []],
        "stosb": [2, ["operand1 = operand2"], []],
        "stosw": [2, ["operand1 = operand2"], []],
        "stosd": [2, ["operand1 = operand2"], []],
        "rep": [0, [], []],
        "repz": [0, [], []],
        "repnz": [0, [], []],
#        "insb": [2, ["operand1 = undefined"], []],
#        "insw": [2,["operand1 = undefined"], []],
#        "insd": [2,["operand1 = undefined"], []]
#
#        "outsb": [0, [], []],
#        "outsw": [0, [], []],
#        "outsd": [0, [], []],
#        # floating point ins
#        "fld": [],
#        "fst": [],
#        "fstp": [],
#        "fild": [],
#        "fist": [],
#        "fistp": [],
#        "fbld": [],
#        "fbstp": [],
#        "fxch": [],
#        "fcmove": [],
##        "fcmovne": [],
#        "fcmovb": [],
#        "fcmovbe": [],
#        "fcmovnb": [],
#        "fcmovnbe": [],
#        "fcmovu": [],
#        "fcmovnu": [],
#        "fadd": [],
#        "faddp": [],
#        "fiadd": [],
#        "fsub": [],
#        "fsubp": [],
#        "fisub": [],
#        "fsubr": [],
#        "fsubrp": [],
#        "fsubr": [],
#        "fmul": [],
#        "fmulp": [],
#        "fimul": [],
#        "fdiv": [],
#        "fdivp": [],
#        "fidiv": [],
#        "fdivr": [],
#        "fdivrp": [],
#        "fidivr": [],
#        "fprem": [],
#        "fpremi": [],
#        "fabs": [],
#        "fchs": [],
#        "frndint": [],
#        "fscale": [],
#        "fsqrt": [],
#        "fxtract": [],
#        "fcom": [],
#        "fcomp": [],
#        "fcmopp": [],
#        "fucom": [],
#        "fucomp": [],
#        "fucompp": [],
#        "ficom": [],
#        "ficomp": [],
#        "fcomi": [],
#        "fucomi": [],
#        "fcomip": [],
#        "fucomp": [],
#        "ftst": [],
#        "fxam": [],
#        # transcendental
#        "fsin": [],
#        "fcos": [],
#        "fsincos": [],
#        "fptan": [],
#        "fpatan": [],
#        "f2xm1": [],
#        "fyl2x": [],
#        "fyl2xp1": [],
#        # load constant
#        "fld1": [],
#        "fldz": [],
#        "fldpi": [],
#        "fldl2e": [],
#        "fldln2": [],
#        "fldl2t": [],
#        "fldlg2": [],
#        # FPU control
#        "fincstp": [],
#        "fdecstp": [],
#        "ffree": [],
#        "finit": [],
#        "fninit": [],
#        "fclex": [],
#        "fnclex": [],
#        "fstcw": [],
#        "fnstcw": [],
#        "fldcw": [],
#        "fstenv": [],
#        "fnstenv": [],
#        "fldenv": [],
#        "fsave": [],
#        "fnsave": [],
#        "frstor": [],
#        "fstsw": [],
#        "fnstsw": [],
#        "wait": [],
#        "fnop": [],
#        # system instructions
#        "lgdt": [],
#        "sgdt": [],
#        "lldt": [],
#        "sldt": [],
#        "ltr": [],
#        "str": [],
#        "lidt": [],
#        "sidt": [],
#        #"mov": [],
#        "lmsw": [],
#        "smsw": [],
#        "clts": [],
#        "arpl": [],
#        "lar": [],
#        "lsl": [],
#        "verr": [],
#        "verw": [],
#        #"mov": [],
#        "invd": [],
#        "wbinvd": [],
#        "invlpg": [],
#        "lock": [],
#        "hlt": [],
#        "rsm": [],
#        "rdmsr": [],
#        "wrmsr": [],
#        "rdpmc": [],
#        "rdtsc": []
}
class ROPParserX86:
    def __init__(self, gadgets, mode):
        self.gadgets = gadgets
        self.mode = mode
        if mode == CS_MODE_32:
            self.regs = X86.regs32 + X86.FLAG
            self.Tregs = X86.Tregs32
            self.wrap = {"ssp":"esp", "ip":"eip", "length":"4"}
            # wrap the formula with arch_specified regs
            # Ex: update sp with esp , ip with eip, length with 4
            for o, n in self.wrap.items():
                for k, v in X86.insn.items():
                    if len(v) < 3:
                        continue
                    for i, s in enumerate(v[1]):
                        v[1][i] = s.replace(o,n)
                        X86.insn.update({k:v})
                    for i, s in enumerate(v[2]):
                        v[2][i] = s.replace(o,n)
                        X86.insn.update({k:v})
        else:
            self.regs = X86.regs64 + X86.FLAG
            self.Tregs = X86.Tregs64
            self.wrap = {"ssp":"rsp", "ip":"rip", "length":"8"}
            for o, n in self.wrap.items():
                for k, v in X86.insn.items():
                    if len(v) < 3:
                        continue
                    for i, s in enumerate(v[1]):
                        v[1][i] = s.replace(o,n)
                        X86.insn.update({k:v})
                    for i, s in enumerate(v[2]):
                        v[2][i] = s.replace(o,n)
                        X86.insn.update({k:v})


    def parse(self):
        formulas = []
        for gadget in self.gadgets:
            regs = {}
            regs = self.parseInst(regs, gadget, 0)
            print "================================="
            print "Gadget string:"
            for inst in gadget:
                print inst["mnemonic"], inst["op_str"]
            print
            print "Gadget semantic:"
            for reg, v in regs.items():
                if reg in X86.FLAG:
                    continue
                print reg, "==>", v
            print
            formulas.append(regs)
        return formulas


    def parseInst(self, regs, insts, i):
        if i == len(insts):
            return regs
        # all control transfer dst must bewteen low and high addr
        addr = insts[i]["addr"]
        prefix = insts[i]["mnemonic"]
        op_str = insts[i]["op_str"]
        if prefix not in X86.insn.keys():
            # contains not supported ins
            return {}
        ins = X86.insn.get(prefix)
        if prefix in X86.Control:
            # control transfer ins
            operand1 = None
            operands = {}
            if prefix == "call":
                # call reg
                operand1 = Exp.parseOperand(op_str.split(" ")[0], regs, self.Tregs)
                operands.update({"operand1":operand1})
                dst = Exp.parseExp(ins[2][0].split())
                if isinstance(dst, Exp):
                    regs.update({"dst":dst.binding(regs)})
                else:
                    regs.update({"dst":dst})
                return regs
            # only ret inst can modify other regs
            if prefix == "ret":
                operand1 = Exp.parseOperand(op_str.split(" ")[0], regs, self.Tregs)
                if operand1 != None:
                    operands.update({"operand1":operand1})
                else:
                    operands.update({"operand1":"0"})
                exps = Exp.parse(ins[1], operands)
                for k, v in exps.items():
                    regs.update({k:v})
                dst = Exp.parseExp(ins[2][0].split())
                regs.update({"dst":dst})
                return regs
            print prefix
            dst = Exp.parseExp(ins[2][0].split())
            # handle conditional jmp
            if prefix != "jmp":
                # dup all the exps on the condition, then handle the rest
                operand1 = Exp.parseOperand(op_str.split(" ")[0], regs, self.Tregs)
                con = dst.getCondition()
                regs1 = deepcopy(regs)
                index = dst.checkBound(regs, insts, addr, str(operand1))
                if index != -1:
                    regs = self.parseInst(regs, insts, index)
                else:
                    regs.update({"dst": Exp(operand1, "+", addr)})

                index = i + 1
                regs1 = self.parseInst(regs1, insts, index)
                r = {}
                for k,v in regs.items():
                    r[k] = None
                for k,v in regs1.items():
                    r[k] = None;
                for k,v in r.items():
                    left = k
                    if k in regs.keys():
                        left = regs[k]
                    right = k
                    if k in regs1.keys():
                        right = regs1[k]
                    r[k] = Exp(left, "condition", right, con)
                return r
            else:
                # for direct jmp, it depends on the address
                operand1 = Exp.parseOperand(op_str.split(" ")[0], regs, self.Tregs)
                regs.update({"dst":operand1})
                return regs
        else:
			# computing ins
            operand1 = None
            operand2 = None
            # handle special cases
            if prefix == "imul" or prefix == "mul":
                exps = {}
                flags = {}
                if op_str.count(",") == 0:
                    operand1 = Exp.parseOperand(op_str.split(",")[0], regs, self.Tregs)
                    if operand1.OperandSize() == 8:
                        mul = Exp("al", "*", operand1)
                        exp.update({"ax":mul})
                        flags.update({"CF":Exp("1", "condition", "0", Exp("ax", "!=", "al"))})
                        flags.update({"OF":Exp("1", "condition", "0", Exp("ax", "!=", "al"))})
                        if prefix == "imul":
                            flags.update({"SF":Exp("7", "bits", "7", mul)})
                    elif operand1.OperandSize() == 16:
                        mul = Exp("ax", "*", operand1)
                        exp.update({"dx":Exp("16", "bits", "31", mul)})
                        exp.update({"ax":Exp("0", "bits", "15", mul)})
                        flags.update({"CF":Exp("1", "condition", "0", Exp("dx", "!=", "0"))})
                        flags.update({"OF":Exp("1", "condition", "0", Exp("dx", "!=", "0"))})
                        if prefix == "imul":
                            flags.update({"SF":Exp("15", "bits", "15", mul)})
                    elif operand1.OperandSize() == 32:
                        mul = Exp("eax", "*", operand1)
                        exp.update({"edx":Exp("32", "bits", "63", mul)})
                        exp.update({"eax":Exp("0", "bits", "31", mul)})
                        flags.update({"CF":Exp("1", "condition", "0", Exp("edx", "!=", "0"))})
                        flags.update({"OF":Exp("1", "condition", "0", Exp("edx", "!=", "0"))})
                        if prefix == "imul":
                            flags.update({"SF":Exp("31", "bits", "31", mul)})
                    else:
                        mul = Exp("rax", "*", operand1)
                        exp.update({"rdx":Exp("64", "bits", "127", mul)})
                        exp.update({"rax":Exp("0", "bits", "63", mul)})
                        flags.update({"CF":Exp("1", "condition", "0", Exp("rdx", "!=", "0"))})
                        flags.update({"OF":Exp("1", "condition", "0", Exp("rdx", "!=", "0"))})
                        if prefix == "imul":
                            flags.update({"SF":Exp("63", "bits", "63", mul)})
                elif op_str.count(",") == 1:
                    operand1 = Exp.parseOperand(op_str.split(",")[0], regs, self.Tregs)
                    operand2 = Exp.parseOperand(op_str.split(",")[1], regs, self.Tregs)
                    size = operand1.OperandSize()
                    mul = Exp(operand1, "*", operand2)
                    tru = Exp("0", "bits", str(size-1), mul)
                    exp.update({str(operand1):tru})
                    flags.update({"SF":Exp(str(size-1), "bits", str(size-1), mul)})
                    flags.update({"CF":Exp("1", "condition", "0", Exp(mul, "!=", tru))})
                    flags.update({"OF":Exp("1", "condition", "0", Exp(mul, "!=", tru))})
                else:
                    operand1 = Exp.parseOperand(op_str.split(",")[0], regs, self.Tregs)
                    operand2 = Exp.parseOperand(op_str.split(",")[1], regs, self.Tregs)
                    operand3 = Exp.parseOperand(op_str.split(",")[2], regs, self.Tregs)
                    size = operand1.OperandSize()
                    mul = Exp(operand2, "*", operand3)
                    tru = Exp("0", "bits", str(size-1), mul)
                    exp.update({str(operand1):tru})
                    flags.update({"SF":Exp(str(size-1), "bits", str(size-1), mul)})
                    flags.update({"CF":Exp("1", "condition", "0", Exp(mul, "!=", tru))})
                    flags.update({"OF":Exp("1", "condition", "0", Exp(mul, "!=", tru))})
                # TODO
            if ins[0] == 1:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
            elif ins[0] == 2:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                operand2 = Exp.parseOperand(op_str.split(", ")[1], regs, self.Tregs)
                # contruct all exps based on the instruction
            operands = {}
            if operand1 != None:
                operands.update({"operand1":operand1})
            if operand2 != None:
                operands.update({"operand2":operand2})
            flagExp = Exp("flag")
            exps = Exp.parse(ins[1], operands, flagExp)

            # evaluate flag regs base on first exp
            if len(ins[2]) != 0:
                f = Exp.parse(ins[2], operands)
                for k,v in f.items():
                    # exp indicates this flag is directly set instead of depending on the first exp
                    # "CF = 1"  or "CF"
                    if k != str(v):
                        regs.update({k:v})
                    else:
                        regs.update({k:Exp(flagExp,v[0])})
            for k,v in exps.items():
                if k == "temp":
                    continue
                if str(v) == "undefined":
                    del regs[k]
                    continue
                if k in self.Tregs.keys():
                    exp = Exp.parseExp(self.Tregs[k][1].split())
                    exp.binding(k, v)
                    regs.update({exp.getDest():exp.getSrc()})
                else:
                    regs.update({k:v})
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
            inst.update({"addr": decode.address})
            gadget.append(inst)
        gadgets.append(gadget)
    p = ROPParserX86(gadgets, CS_MODE_32)
    formulas = p.parse()
#
#    binarys = [b"\x0F\x42\xD8\xFF\xC3\x83\xD3\x3C\xC3",
#                b"\xF9\x48\x0F\x42\xC3\x48\x83\xE8\x01\xC3"]
#    gadgets = []
#    md = Cs(CS_ARCH_X86, CS_MODE_64)
#    md.detail = True
#    for binary in binarys:
#        gadget = []
#        for decode in md.disasm(binary, 0x1000):
#            inst = {}
#            inst.update({"mnemonic": decode.mnemonic})
#            inst.update({"op_str": decode.op_str})
#            inst.update({"addr": decode.address})
#            gadget.append(inst)
#        gadgets.append(gadget)
#    p = ROPParserX86(gadgets, CS_MODE_64)
#    formulas = p.parse()
#
