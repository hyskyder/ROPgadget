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
              "r13", "r14", "r15", "cs", "ds", "es", "fs", "gs", "ss"]
    regs32 = ["eax", "ebx", "ecx", "edx", "cs", "ds", "es", "fs", "gs", "ss", "esi", "edi", "ebp", "esp", "eip"]
    Tregs64 = {
        "eax": ["rax $ 0 : 31", "rax = ( rax $ 32 : 63 ) # eax", 32],
        "ax": ["rax $ 0 : 15", "rax = ( rax $ 16 : 63 ) # ax", 16],
        "ah": ["rax $ 8 : 15", "rax = ( rax $ 16 : 63 ) # ah # ( rax $ 0 : 7 )", 8],
        "al": ["rax $ 0 : 7", "rax = ( rax $ 8 : 63 ) # al", 8],
        "ebx": ["rbx $ 0 : 31", "rbx = ( rbx $ 32 : 63 ) # ebx", 32],
        "bx": ["rbx $ 0 : 15", "rbx = ( rbx $ 16 : 63 ) # bx", 16],
        "bh": ["rbx $ 8 : 15", "rbx = ( rbx $ 16 : 63 ) # bh # ( rbx $ 0 : 7 )", 8],
        "bl": ["rbx $ 0 : 7", "rbx = ( rbx $ 8 : 63 ) # bl", 8],
        "ecx": ["rcx $ 0 : 31", "rcx = ( rcx $ 32 : 63 ) # ecx", 32],
        "cx": ["rcx $ 0 : 15", "rcx = ( rcx $ 16 : 63 ) # cx", 16],
        "ch": ["rcx $ 8 : 15", "rcx = ( rcx $ 16 : 63 ) # ch # ( rcx $ 0 : 7 )", 8],
        "cl": ["rcx $ 0 : 7", "rcx = ( rcx $ 8 : 63 ) # cl", 8],
        "edx": ["rdx $ 0 : 31", "rdx = ( rdx $ 32 : 63 ) # edx", 32],
        "dx": ["rdx $ 0 : 15", "rdx = ( rdx $ 16 : 63 ) # dx", 16],
        "dh": ["rdx $ 8 : 15", "rdx = ( rdx $ 16 : 63 ) # dh # ( rdx $ 0 : 7 )", 8],
        "dl": ["rdx $ 0 : 7", "rdx = ( rdx $ 8 : 63 ) # dl", 8],
    }
    Tregs32 = {
        "ax": ["eax $ 0 : 15", "eax = ( eax $ 16 : 31 ) # ax", 16],
        "ah": ["eax $ 8 : 15", "eax = ( eax $ 16 : 31 ) # ah # ( eax $ 0 : 7 )", 8],
        "al": ["eax $ 0 : 7", "eax = ( eax $ 8 : 31 ) # al", 8],
        "bx": ["ebx $ 0 : 15", "ebx = ( ebx $ 16 : 31 ) # bx", 16],
        "bh": ["ebx $ 8 : 15", "ebx = ( ebx $ 16 : 31 ) # bh # ( ebx $ 0 : 7 )", 8],
        "bl": ["ebx $ 0 : 7", "ebx = ( ebx $ 8 : 31 ) # bl", 8],
        "cx": ["ecx $ 0 : 15", "ecx = ( ecx $ 16 : 31 ) # cx", 16],
        "ch": ["ecx $ 8 : 15", "ecx = ( ecx $ 16 : 31 ) # ch # ( ecx $ 0 : 7 )", 8],
        "cl": ["ecx $ 0 : 7", "ecx = ( ecx $ 8 : 31 ) # cl", 8],
        "dx": ["edx $ 0 : 15", "edx = ( edx $ 16 : 31 ) # dx", 16],
        "dh": ["edx $ 8 : 15", "edx = ( edx $ 16 : 31 ) # dh # ( edx $ 0 : 7 )", 8],
        "dl": ["edx $ 0 : 7", "edx = ( edx $ 8 : 31 ) # dl", 8],
    }
    # Instructions that will crash the program
    CrashIns = ["in", "insb", "insd", "out", "outsd", "outsb",  "iretd", "retf", "sti"]
    ProblematicIns= ["ljmp", "lcall", "int", "hlt"]
    # Instructions that can be bypassed (no need to parse)
    BypassableIns = ["int1", "nop"]
    # Instructions that modifty the execution path
    Control = ["ret", "iret", "into", "enter", "leave", "call", "jmp", "ljmp"
               "ja", "jae", "jb", "jbe", "jc", "je",
               "jnc", "jne", "jnp", "jp", "jg", "jge", "jl", "jle", "jno", "jns", "jo", "js", "jecxz",
               "loop", "loopne"]
    insn = {
        # data transfer
        "mov": [2, ["operand1 = operand2"], []],
        "cmove": [2, ["operand1 = ( ZF == 1 ) ? operand2 : operand1"], []],
        "cmovne": [2, ["operand1 = ( ZF == 0 ) ? operand2 : operand1"], []],
        "cmova": [2, ["operand1 = ( ( ZF == 0 ) & ( CF == 0 ) ) ? operand2 : operand1"], []],
        "cmovae": [2, ["operand1 = ( CF == 0 ) ? operand2 : operand1"], []],
        "cmovb": [2, ["operand1 = ( CF == 1 ) ? operand2 : operand1"], []],
        "cmovbe": [2, ["operand1 = ( ( ZF == 1 ) | ( CF == 1 ) ) ? operand2 : operand1"], []],
        "cmovg": [2, ["operand1 = ( ( ZF == 0 ) & ( SF == OF ) ) ? operand2 : operand1"], []],
        "cmovge": [2, ["operand1 = ( SF == OF ) ? operand2 : operand1"], []],
        "cmovl": [2, ["operand1 = ( SF != OF ) ? operand2 : operand1"], []],
        "cmovle": [2, ["operand1 = ( ( ZF == 1 ) & ( SF != OF ) ) ? operand2 : operand1"], []],
        "cmovs": [2, ["operand1 = ( SF == 1 ) ? operand2 : operand1"], []],
        "cmovp": [2, ["operand1 = ( PF == 1 ) ? operand2 : operand1"], []],

        "push": [1, ["* ssp = operand1"], []],
        "pop": [1, ["operand1 = * ssp"], []],

        # "movsx": [2, ["operand1 = operand2 > 0 ? operand2 : operand2 & 0xffffffffffffffff"], []],
        # "movzx": [2, ["operand1 = 0 & operand2"], []],
        # flag control instuctions
        "stc": [0, [], ["CF = 1"]],
        "clc": [0, [], ["CF = 0"]],
        "cmc": [0, [], ["CF = ~ CF"]],
        "cld": [0, [], ["DF = 0"]],
        "std": [0, [], ["DF = 1"]],
        "sti": [0, [], ["IF = 1"]],
        "cli": [0, [], ["IF = 0"]],
        # arithmetic
        "xchg": [2, ["FIXME"], []],
        "cmp": [2, ["temp = operand1 - operand2"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        "add": [2, ["operand1 = operand1 + operand2"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
        "adc": [2, ["operand1 = operand1 + operand2 + CF"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
        "sub": [2, ["operand1 = operand1 - operand2"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],
        "sbb": [2, ["operand1 = operand1 - operand2 - CF"], ["OF", "SF", "ZF", "AF", "CF", "PF"]],

        "inc": [1, ["operand1 = operand1 + 1"], ["OF", "SF", "ZF", "AF", "PF"]],
        "dec": [1, ["operand1 = operand1 - 1"], ["OF", "SF", "ZF", "AF", "PF"]],
        "neg": [1, ["operand1 = - operand1"], ["CF", "OF", "SF", "ZF", "AF", "PF"]],
        # control transfer
        "ret": [1, [], ["* ssp"]],

        "call": [1, [], ["operand1"]],

        "jmp": [1, [], ["operand1"]],
        #"ljmp": [1, [], ["operand1"]], #unimplemented
        "ja": [1, [], ["( ( CF == 0 ) & ( ZF == 0 ) ) ? * operand1 : 0"]],
        "jae": [1, [], ["CF == 0 ? * operand1 : 0"]],
        "jb": [1, [], ["CF == 1 ? * operand1 : 0"]],
        "jbe": [1, [], ["( ( CF == 1 ) | ( ZF == 1 ) ) ? * operand1 : 0"]],
        "jc": [1, [], ["CF == 1 ? * operand1 : 0"]],
        "je": [1, [], ["ZF == 1 ? * operand1 : 0"]],
        "jnc": [1, [], ["CF == 0 ? * operand1 : 0"]],
        "jne": [1, [], ["ZF == 0 ? * operand1 : 0"]],
        "jnp": [1, [], ["PF == 0 ? * operand1 : 0"]],
        "jp": [1, [], ["PF == 1 ? * operand1 : 0"]],
        "jg": [1, [], ["( ( ZF == 0 ) & ( SF == OF ) ) ? * operand1 : 0"]],
        "jge": [1, [], ["SF == OF ? * operand1 : 0"]],
        "jl": [1, [], ["SF != OF ? * operand1 : 0"]],
        "jle": [1, [], ["( ( ZF == 1 ) | ( SF != OF ) ) ? * operand1 : 0"]],
        "jno": [1, [], ["OF == 0 ? * operand1 : 0"]],
        "jns": [1, [], ["SF == 0 ? * operand1 : 0"]],
        "jo": [1, [], ["OF == 1 ? * operand1 : 0"]],
        "js": [1, [], ["SF == 1 ? * operand1 : 0"]],
        "loop": [1, ["c = c - 1"], ["( c - 1 ) == 0 ? operand1 : 0"]], #FIXME
        "loopne": [1, ["c = c - 1"], ["( c - 1 ) == 0 ? 0 : operand1"]], #FIXME

        #"hlt": [0, [], [] ], #TODO
        # logic
        "and": [2, ["operand1 = operand1 & operand2"], ["CF = 0", "OF = 0", "SF", "ZF", "PF"]],
        "or": [2, ["operand1 = operand1 | operand2"], ["CF = 0", "OF = 0", "SF", "ZF", "PF"]],
        "xor": [2, ["operand1 = operand1 ^ operand2"], ["CF = 0", "OF = 0", "SF", "ZF", "PF"]],
        "not": [1, ["operand1 = ~ operand1"], []],
        "test": [2, ["temp = operand1 & operand2"], ["OF = 0", "CF = 0", "SF", "ZF", "PF"]],
        # segment
        # others
        "lea": [2, ["operand1 = & operand2"], []],
        "nop": [0, [], []],
        #"int": [0, [], []], #Unsupported
        "int1": [0, [], []]
    }


class ROPParserX86:
    parse_stat={}
    def __init__(self, gadgets, mode):
        self.gadgets = gadgets
        self.addrs = dict()
        self.mode = mode
        self.aligned = 0
        self.memLoc = []
        self.writeMem = {}
        if mode == CS_MODE_32:
            self.regs = X86.regs32 + X86.FLAG
            self.Tregs = X86.Tregs32
            self.aligned = 4
            self.default = 32
            self.sp = "esp"
            self.ip = "eip"
        else:
            self.regs = X86.regs64 + X86.FLAG
            self.Tregs = X86.Tregs64
            self.aligned = 8
            self.default = 64
            self.sp = "rsp"
            self.ip = "rip"

        for k, v in X86.insn.items():
            for i, s in enumerate(v[1]):
                v[1][i] = s.replace("ssp", self.sp)
            for i, s in enumerate(v[2]):
                v[2][i] = s.replace("ssp", self.sp)
            X86.insn.update({k: v})

    def parse(self):
        #self.parse_stat["crash_gadgets"] = 0
        self.parse_stat["failed_gadgets"] = 0
        formulas = []
        for gadget in self.gadgets:
            self.memLoc = []
            self.writeMem = {}
            regs = {self.sp: Exp(self.sp)}
            regs = self.parseInst(regs, gadget["insns"], 0)
            if len(regs) == 0:
                print "[Warn] Parser failed to parse the gadget addr=" + str(hex(gadget["vaddr"]))
                self.parse_stat["failed_gadgets"]=self.parse_stat["failed_gadgets"]+1
                continue
            formulas.append(Semantic(regs, gadget["vaddr"], self.memLoc, self.writeMem))
            self.addrs.update({hex(gadget["vaddr"]).replace("L", ""): gadget["insns"]})
        print "================================="
        print "parsex86: gadgets parsed = ", len(formulas)
        return formulas

    def parseInst(self, regs, insts, i):
        ## Recursive function, insts should be consistent with all iterations
        ## regs : unkonwn
        ## insts : the gadget pool
        ## i : index of the list *insts*
        if i >= len(insts):
            return regs

        prefix = insts[i]["mnemonic"]
        op_str = insts[i]["op_str"].replace("*", " * ")

        if (prefix in X86.CrashIns) or (prefix in X86.ProblematicIns):
            print "(CrashIns)",
            return {}

        if prefix not in X86.insn.keys():
            # unsupported ins
            print "[Warn] Skip Unsupported ins: " + prefix
            return self.parseInst(regs, insts, i + 1)

        if prefix in X86.BypassableIns:
            return self.parseInst(regs, insts, i + 1)

        ins = X86.insn.get(prefix)
        if prefix in X86.Control:
            if (i + 1 != len(insts)):
                print " ("+ prefix +") at middle ! ", # Rest ins are ignored in this gadget."
                return {}
            # control transfer ins, end of gadget
            if prefix in ["ret", "call"]:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                dst = Exp.parseExp(ins[2][0].split())
                if operand1 is None:
                    dst = dst.binding({"operand1": Exp.ExpL(Exp.defaultLength, 0)})
                else:
                    dst = dst.binding({"operand1": operand1})
                dst = dst.binding(regs)  #TODO:this is a bug?
                regs.update({self.ip: dst})
                # only ret inst modifies stackpointer
                if prefix == "ret":
                    ssp = regs[self.sp]
                    ssp = Exp(ssp, "+", Exp(self.aligned))
                    if operand1 is not None:
                        ssp = Exp(ssp, "+", operand1)
                    regs.update({self.sp: ssp})
                return regs
            elif prefix in ["int"]:
                print "(int unsupported)", #TODO
                return {}
            else:
                # handle jmp
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                if operand1 is None :
                    print "[Warn] Something wrong ! when parse: " + prefix + " " + op_str,  #TODO:(Probably multiple memory writes but with different length )
                    return {}
                dst = Exp.parseExp(ins[2][0].split())
                dst = dst.binding({"operand1": operand1})
                # dst = dst.binding(regs) #TODO:this is a bug?
                regs.update({self.ip: dst})
                return regs

            #else:
            #    raise RuntimeError("Program should never get here. [data: prefix="+ prefix+"]")
        else:
            # computing ins
            operand1 = None
            operand2 = None
            operands = {self.sp: regs[self.sp]}
            for flag in X86.FLAG:
                if flag in regs.keys():
                    operands.update({flag: regs[flag]})
            # handle special cases
            if ins[0] == 1:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                if operand1 is None:
                    print "[Warn] Discarded Gadget! @235 Something wrong when parse: " + prefix + " " + op_str
                    return {}
                operands.update({"operand1": operand1})
            elif ins[0] == 2:
                operand1 = Exp.parseOperand(op_str.split(", ")[0], regs, self.Tregs)
                operand2 = Exp.parseOperand(op_str.split(", ")[1], regs, self.Tregs)
                if operand1 is None or operand2 is None:
                    print "[Warn] Something wrong ! when parse: " + prefix + " " + op_str,  #TODO:(Probably multiple memory writes but with different length )
                    return {}
                operands.update({"operand1": operand1})
                operands.update({"operand2": operand2})
            if prefix != "lea" and "ptr" in op_str and (operand1.getCategory() == 3 or operand2.getCategory() == 3):
                if prefix not in ["cmp", "test", "push"] and "ptr" in op_str.split(", ")[0]:
                    self.memLoc.append(operand1)
                    self.writeMem.update({str(operand1): operand1})
                else:
                    self.memLoc.append(operand1 if operand1.getCategory() == 3 else operand2)

            # construct insn operation
            if len(ins[1]) > 0:
                if prefix == "lea":
                    reg = op_str.split(", ")[0]
                    addr = Exp.parseExp(op_str.split("[")[1][:-1].split())
                    addr = addr.binding(regs)
                    addr.length = Exp.defaultLength
                    regs.update({reg: addr})
                    return self.parseInst(regs, insts, i + 1)

                if prefix == "xchg":
                    op1k = op_str.split(", ")[0]
                    op2k = op_str.split(", ")[1]
                    op1v = None
                    op2v = None
                    if op2k in self.Tregs:
                        # subpart of register
                        temp = Exp.parse(self.Tregs[op2k][1], {op2k: operands["operand1"]})
                        for k, v in temp.items():
                            v.length = Exp.defaultLength
                            op2k = k
                            op2v = v
                    elif op2k in self.regs:
                        # register
                        operands["operand1"].length = Exp.defaultLength
                        op2v = operands["operand1"]
                    else:
                        # mem
                        op2k = str(operands["operand2"])
                        op2v = operands["operand1"]

                    if op1k in self.Tregs:
                        temp = Exp.parse(self.Tregs[op1k][1], {op1k: operands["operand2"]})
                        for k, v in temp.items():
                            v.length = Exp.defaultLength
                            op1k = k
                            op1v = v
                    elif op1k in self.regs:
                        operands["operand2"].length = Exp.defaultLength
                        op1v = operands["operand2"]
                    else:
                        op1k = str(operands["operand1"])
                        op1v = operands["operand2"]

                    regs.update({op1k: op1v})
                    regs.update({op2k: op2v})
                    return self.parseInst(regs, insts, i + 1)

                exps = Exp.parse(ins[1][0], operands)

                for reg, val in exps.items():
                    # handle special case of xor, op1 == op2 clear the register
                    if prefix == "xor" and op_str.split(", ")[0] == op_str.split(", ")[1]:
                        val = Exp.ExpL(val.length, 0)
                    # temp variable, no need to assign
                    if reg == "temp":
                        val.length = max(operand1.length, operand2.length)
                        continue
                    if "*" in reg:
                        # this can only be push inst
                        val.length = Exp.defaultLength
                        regs.update({"[ " + str(regs[self.sp]) + " ]": val})
                        continue
                    dst = Exp.parseOperand(op_str.split(", ")[0], {}, {})
                    if str(dst) in self.regs:
                        # general purpose reg
                        val.length = Exp.defaultLength
                        regs.update({str(dst): val})
                    elif str(dst) in self.Tregs:
                        # subpart of GPRs
                        temp = Exp.parse(self.Tregs[str(dst)][1], {})
                        for k, v in temp.items():
                            v = v.binding(regs)
                            v = v.binding({str(dst): val})
                            v.length = Exp.defaultLength
                            regs.update({k: v})
                    else:
                        # mem
                        regs.update({str(operands["operand1"]): val})
                if prefix == "push":
                    regs.update({self.sp: Exp(regs[self.sp], "+", Exp(self.aligned))})
                if prefix == "pop":
                    regs.update({self.sp: Exp(regs[self.sp], "-", Exp(self.aligned))})

            # evaluate flag regs base on exp
            if len(ins[2]) != 0:
                for flag in ins[2]:
                    tokens = flag.split()
                    if len(tokens) == 1:
                        for k, v in exps.items():
                            exp = Exp(v, tokens[0][:-1])
                            exp.length = 1
                            regs.update({tokens[0]: exp})
                    else:
                        f = Exp.parse(flag, {})
                        for k, v in f.items():
                            # "CF = 1" 
                            v.length = 1
                            regs.update({tokens[0]: v})

            return self.parseInst(regs, insts, i + 1)


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
        gadget = {"insns": gadget, "vaddr": len(binary)}
        gadgets.append(gadget)
    p = ROPParserX86(gadgets, CS_MODE_32)
    formulas = p.parse()
    for item in formulas:
        print item
