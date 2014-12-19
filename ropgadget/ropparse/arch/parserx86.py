#!/usr/bin/env python2
from capstone import CS_MODE_32
from expression import Exp
class X86:
    # specially for "ret", none or one operand required
    FLAG = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]
    regs64 = ["rax", "eax", "ax", "ah", "al", "rbx", "ebx", "bh", "bl", "rcx", "cx", "ch", "cl", 
            "rdx", "edx", "dh", "dl" "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
            "r13", "r14", "r15"]
    regs32 = ["eax", "ax", "ah", "al", "ebx", "bx", "bh", "bl", "ecx", "cx", "ch", "cl", "edx", "dx", "dh", "dl" "CS", "DS", "ES", "FS", "GS", "SS", "esi", "edi", "ebp", "esp", "eip"]
    insn = {
            # data transfer
	    "mov": [2, ["operand1 = operand2"]], 
	    "cmove": [2, ["operand1 = ( ZF == 1 ) ? operand2 : operand1"]],
	    "cmovne": [2, ["operand1 = ( ZF == 0 ) ? operand2 : operand1"]], 
	    "cmova": [2, ["operand1 = ( ZF == 0 || CF == 0 ) ? operand2 : operand1"]], 
	    "cmovae": [2, ["operand1 = ( CF == 0 ) ? operand2 : operand1"]], 
	    "cmovb": [2, ["operand1 = ( CF == 1 ) ? operand2 : operand1"]], 
	    "cmovbe": [2, ["operand1 = ( ZF == 1 || CF == 1 ) ? operand2 : operand1"]], 
	    #"cmovg": [2, [""]], 
	    "cmovge": [2, ["operand1 = ( SF == 0 || OF == 0 ) ? operand2 : operand1"]], 
	    "cmovl": [2, ["operand1 = ( SF == 1 || OF == 1 ) ? operand2 : operand1"]], 
	    "cmovle": [2, ["operand1 = ( ( ( SF xor OF ) or ZF ) == 1) ? operand2 : operand1"]], 
	    "cmovs": [2, ["operand1 = ( SF == 1 ) ? operand2 : operand1"]], 
	    "cmovp": [2, ["operand1 = ( PF == 1 ) ? operand2 : operand1"]], 
	    "xchg": [2, ["operand1 = operand2", "operand2 = operand1"]], 
#	    "bswap": [1, ["operand1"]], 
#	    "xadd": [2], 
#	    "cmpxchg": [2], 
	    "push": [1, ["* sp = operand1", "sp = sp - length"]],
	    "pop": [1, ["operand1 = * sp", "sp = sp + length"]], 
#	    "in": [0], 
#	    "out": [0], 
#	    "cwde": [1], 
#	    "cdq": [1], 
#	    "movsx": [2], 
#	    "movzx", [2],
            # flag control instuctions
            "stc": [0, ["CF = 1"]], 
	    "clc": [0, ["CF = 0"]], 
	    "cmc": [0, ["CF = ~ CF"]], 
	    "cld": [0, ["DF = 0"]], 
	    "std": [0, ["DF = 1"]], 
#	    "lahf": [0], 
#	    "shf": [0], 
#	    "pushfq": [1], 
#	    "popfq": [1], 
#	    "sti": [0], 
#	    "cli": [0],
#            # arithmetic
	    "cmp": [2, ["ZF = ( operand1 - operand2 ) == 0 ? 0 : -1", ""], 
#	    "daa": [1],  
#	    "das": [1], 
#	    "aaa": [1], 
#	    "aas": [1], 
#	    "aam": [1], 
#	    "aad":[1],
	    "add": [2, ["operand1 = operand1 + operand2"]], 
	    "adc": [2, ["operand1 = operand1 + operand2 + ( ( CF == 1 ) ? 1 : 0 )"]], 
	    "sub": [2, ["operand1 = operand1 - operand2"]], 
	    "sbb": [2, ["operand1 = operand1 - operand2 - ( ( CF == 1 ) ? 1 : 0 )"]], 
#	    "imul": [1], 
#	    "mul": [1], 
#	    "idiv": [1, "eax = ( edx << 32 + eax ) / operand1", "edx = edx:eax % operand1"], 
#	    "div": [1], 
	    "inc": [1, ["operand1 = operand1 + 1"]], 
	    "dec": [1, ["operand1 = operand1 - 1"]], 
	    "neg": [1, ["operand1 = - operand1"]], 
            # control transfer
            "ret": [1, ["ip = * sp", "sp = sp + length"]], 
#	    "iret": [1], 
#	    "int": [0], 
#	    "into": [0], 
#	    "enter": [0], 
#	    "leave": [0], 
#	    "call": [1], 
#	    "jmp": [1], 
#	    "ja": [1], 
#	    "jae": [1], 
#	    "jb": [1], 
#	    "jbe": [1], 
#	    "jc": [1], 
#	    "je": [1], 
#	    "jnc": [1], 
#	    "jne": [1], 
#	    "jnp": [1], 
#	    "jp": [1], 
#	    "jg": [1], 
#	    "jge": [1], 
#	    "jl": [1], 
#	    "jle": [1], 
#	    "jno": [1], 
#	    "jns": [1], 
#	    "jo": [1], 
#	    "js": [1], 
            # logic
            "and": [2, ["operand1 = operand1 & operand2"]], 
	    "or": [2, ["operand1 = operand2 | operand2"]], 
	    "xor": [2, ["operand1 = operand1 ^ operand2"]], 
	    "not": [2, ["operand1 = ~ operand1"]],
            # shift and rotate
            # For SAR, the sign bit is taken care by python
            # Ex, -2 >> 4 = -1,  2 >> 4 = 0
	    "sar": [2, ["operand1 = operand1 >> operand2", "CF = operand1 $ ( operand2 - 1 )"]], 
	    "shr": [2, ["operand1 = operand1 >> operand2", "CF = operand1 $ ( operand2 - 1 )"]], 
            
	    "sal": [2, ["operand1 = operand1 << operand2", "CF = operand1"]], 
	    "shl": [2, ["operand1 = operand1 << operand2", "CF = operand1"]], 
#	    "shrd": [2], 
#	    "shld": [2], 
#	    "ror": [2], 
#	    "rol": [2],
#	    "rcr": [2], 
#	    "rcl": [2],
#            # bit and bytes
#            "bt", "bts", "btr", "btc", "bsf", "bsr", "sete", "setne", "seta", "setae", "setb", "setbe", "setg", "setge", "setl", "setle", "sets", "setns", "seto", "setno", "setpe", "setpo", "test",
#            # segment 
#            "lds": [0], 
#	    "les": [0], 
#	    "lfs": [0], 
#	    "lgs": [0], 
#	    "lss": [0],
#            # others
            "lea": [2, ["operand1 = & operand2"]], 
	    "nop": [0, []], 
#	    "xlatb": [1]
#	    # TODO: string operation, loop operation, MMX instruction, float point, System instruction
#
}
class ROPParserX86:
	def __init__(self, gadgets, mode):
		self.gadgets = gadget
                self.mode = mode
		if mode == CS_MODE_32:
			self.regs = X86.regs32 + X86.FLAG 	
                        self.wrap = {"sp":"esp", "ip":"eip", "length":"4"}
                        # wrap the formula with arch_specified regs
                        # Ex: update sp with esp , ip with eip, length with 4
			for o, n in self.wrap.items():
				for k, v in X86.insn.items():
					for i, s in enumerate(v[1]):
						v[1][i] = s.replace(o,n)
					X86.insn.update({k:v})
                else:
			self.regs = X86.regs64 + X86.FLAG 	
                        self.wrap = {"sp":"rsp", "ip":"rip", "length":"8"}
			for o, n in self.wrap.items():
				for k, v in X86.insn.items():
					for i, s in enumerate(v[1]):
						v[1][i] = s.replace(o,n)
					X86.insn.update({k:v})
	def parse(self):
		formulas = []
		for gadget in self.gadgets:
			regs = {}
			for s in gadget.split(" ; "):
                            prefix = s.split()[0]
                            ins = X86.insn.get(prefix)

                            # get the operand and dst 
                            operand1 = None
                            operand2 = None
                            if ins[0] == 1:
				# handle ret instruction as we can have "ret" or "ret operand1"
				if prefix == "ret":
					if s.find(" ") == -1:
						operand1 = 0
					else:
						operand1 = Exp.parseOperand(s.split(", ")[0][len(prefix)+1:], self.regs)
				else:
					operand1 = Exp.parseOperand(s.split(", ")[0][len(prefix)+1:], self.regs)
                            elif ins[0] == 2:
                                operand1 = Exp.parseOperand(s.split(", ")[0][len(prefix)+1:], self.regs)
                                operand2 = Exp.parseOperand(s.split(", ")[1], self.regs)
                            # contruct all exps based on the instruction
                            operands = {}
                            if operand1 != None:
                                operands.update({"operand1":operand1})
                            if operand2 != None:
                                operands.update({"operand2":operand2})
                            
                            exps = Exp.parse(ins[1], operands)

                            # bind previous exps with new exp
                            for k,v in exps.items():
                                v = v.binding(regs)

                            # update current regs status
                            for k,v in exps.items():
                                regs.update({k:v})

			formulas.append(regs)
		return formulas
		

if __name__ == '__main__':
    gadget = ["add eax, -0x6f ; mov eax, dword ptr [ecx + eax*4] ; sub eax, edx ; xchg eax, ebx ; ret"]
    p = ROPParserX86(gadget, CS_MODE_32)
    formulas = p.parse()
    print gadget
    for formula in formulas:
	    for reg, exp in formula.items():
		    print reg , " ==> " ,  exp
