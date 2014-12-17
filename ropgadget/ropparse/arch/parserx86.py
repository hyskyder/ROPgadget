#!/usr/bin/env python2

class X86:
    # specially for "ret", none or one operand required
    FLAG = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]
    32bits = ["eax", "ax", "ah", "al", "ebx", "bx", "bh", "bl", "ecx", "cx", "ch", "cl", "edx", "dx", "dh", "dl" "CS", "DS", "ES", "FS", "GS", "SS", "esi", "edi", "ebp", "esp", "eip"]
    64bits = ["rax", "eax", "ax", "ah", "al", "rbx", "ebx", "bh", "bl", "rcx", "cx", "ch", "cl", "rdx", "edx", "dh", "dl" "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    instructions = {
            # data transfer
	    "mov": [2, ["operand1 = operand2"]]
	    "cmove": [2, ["operand1 = (ZF == 1) ? operand2 : operand1"]]
	    "cmovne": [2, ["operand1 = (ZF == 0) ? operand2 : operand1"]], 
	    "cmova": [2, ["operand1 = (ZF == 0 || CF == 0) ? operand2 : operand1"]], 
	    "cmovae": [2, ["operand1 = (CF == 0) ? operand2 : operand1"]], 
	    "cmovb": [2, ["operand1 = (CF == 1) ? operand2 : operand1"]], 
	    "cmovbe": [2, "operand1 = (ZF == 1 || CF == 1) ? operand2 : operand1"]], 
	    "cmovg": [2, ""], 
	    "cmovge": [2, "operand1 = (SF == 0 || OF == 0) ? operand2 : operand1"], 
	    "cmovl": [2, "operand1 = (SF == 1 || OF == 1) ? operand2 : operand1"], 
	    "cmovle": [2, "operand1 = (((SF xor OF) or ZF) == 1) ? operand2 : operand1"], 
	    "cmovs": [2, "operand1 = (SF == 1) ? operand2 : operand1"], 
	    "cmovp": [2, "operand1 = (PF == 1) ? operand2 : operand1"], 
	    "xchg": [2], 
	    "bswap": [2], 
	    "xadd": [2], 
	    "cmpxchg": [2], 
	    "push": [1, "[esp] = operand1", "esp = esp - 4"]
	    "pop": [1, "operand1 = [esp]", "esp = esp + 4"], 
	    "in": [0], 
	    "out": [0], 
	    "cwde": [1], 
	    "cdq": [1], 
	    "movsx": [2], 
	    "movzx", [2],
            # flag control instuctions
            "stc": [0, "CF = 1"], 
	    "clc": [0, "CF = 0"], 
	    "cmc": [0, "CF = not CF"], 
	    "cld": [0, "DF = 0"], 
	    "std": [0, "DF = 1"], 
	    "lahf": [0], 
	    "shf": [0], 
	    "pushfq": [1], 
	    "popfq": [1], 
	    "sti": [0], 
	    "cli": [0],
            # arithmetic
	    "cmp": [2, ], 
	    "daa": [1],  
	    "das": [1], 
	    "aaa": [1], 
	    "aas": [1], 
	    "aam": [1], 
	    "aad":[1],
	    "add": [2, "operand1 = operand1 + operand2"], 
	    "adc": [2, "operand1 = operand1 + operand2 + ((CF == 1) ? 1 : 0)"], 
	    "sub": [2, "operand1 = operand1 - operand2"], 
	    "sbb": [2, "operand1 = operand1 - operand2 - ((CF == 1) ? 1 : 0)"], 
	    "imul": [1], 
	    "mul": [1], 
	    "idiv": [1, "eax = edx:eax / operand1", "edx = edx:eax % operand1"], 
	    "div": [1], 
	    "inc": [1, "operand1 = operand1 + 1"], 
	    "dec": [1, "operand1 = operand1 - 1"], 
	    "neg": [1, "operand1 = - operand1"], 
            # control transfer
            "ret": [1, "eip = esp", "esp = esp + 4"], 
	    "iret": [1], 
	    "int": [0], 
	    "into": [0], 
	    "enter": [0], 
	    "leave": [0], 
	    "call": [1], 
	    "jmp": [1], 
	    "ja": [1], 
	    "jae": [1], 
	    "jb": [1], 
	    "jbe": [1], 
	    "jc": [1], 
	    "je": [1], 
	    "jnc": [1], 
	    "jne": [1], 
	    "jnp": [1], 
	    "jp": [1], 
	    "jg": [1], 
	    "jge": [1], 
	    "jl": [1], 
	    "jle": [1], 
	    "jno": [1], 
	    "jns": [1], 
	    "jo": [1], 
	    "js": [1], 
            # logic
            "and": [2, "operand1 = operand1 & operand2"], 
	    "or": [2, "operand1 = operand2 | operand2"], 
	    "xor": [2, "operand1 = operand1 ^ operand2"], 
	    "not": [2], "operand1 = not operand1",
            # shift and rotate
            "sar": [2], 
	    "shr": [2], 
	    "sal": [2], 
	    "shrd": [2], 
	    "shld": [2], 
	    "ror": [2], 
	    "rol": [2],
	    "rcr": [2], 
	    "rcl": [2],
            # bit and bytes
            "bt", "bts", "btr", "btc", "bsf", "bsr", "sete", "setne", "seta", "setae", "setb", "setbe", "setg", "setge", "setl", "setle", "sets", "setns", "seto", "setno", "setpe", "setpo", "test",
            # segment 
            "lds": [0], 
	    "les": [0], 
	    "lfs": [0], 
	    "lgs": [0], 
	    "lss": [0],
            # others
            "lea": [2, "operand1 = & operand2"], 
	    "nop": [0, ""], 
	    "xlatb": [1]
	    # TODO: string operation, loop operation, MMX instruction, float point, System instruction
	    }

class ROPParserX86:
	def __init__(self, gadgets, mode):
		self.gadgets = gadget
		if mode == CS_MODE_32:
			self.regs = X86.32bits + X86.FLAG 	
		else:
			self.regs = X86.64bits + X86.FLAG 	

	
	def parse(self):
		formulats = []
		for gadget in self.gadgets:
			regs = {}
			for s in gadget.split(" ; "):
                            prefix = s.split()[0]
                            ins = X86.instructions.get(prefix)
                            oprand1 = None
                            oprand2 = None
                            if ins[0] == 1:
                                operand1 = Exp.parseOperand(s.split(",")[0][len(prefix)+1:])
                            elif ins[1] == 2:
                                operand1 = Exp.parseOperand(s.split(",")[0][len(prefix)+1:])
                                operand2 = Exp.parseOperand(s.split(",")[1])
                            # contruct all exps based on the instruction
                            exps = Exp.parse(ins[1], oprand1, oprand2)

                            # bind previous exps with new exp
                            for k,v in exps.items():
                                if k in regs:
                                    v.binding(regs.get(k))
                                regs.update({k, v})
			formulats.append(regs)
		return formulats
		

if __name__ == '__main__':
    
