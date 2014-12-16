#!/usr/bin/env python2

class X86:
    # specially for "ret", none or one operand required
    FLAG = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]
    32bits = ["eax", "ebx", "ecx", "edx", "CS", "DS", "ES", "FS", "GS", "SS", "esi", "edi", "ebp", "esp", "eip"]
    64bits = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    instructions = {
            # data transfer
	    "mov": [2, Expression("operand1", "=", "operand2")], 
	    "cmove": [2, Expression("")], 
	    "cmovne": [2], 
	    ["cmova", 2], 
	    ["cmovae", 2], 
	    ["cmovb", 2], 
	    ["cmovbe", 2], 
	    ["cmovg", 2], 
	    ["cmovge", 2], 
	    ["cmovl", 2], 
	    ["cmovle", 2], 
	    ["cmovs", 2], 
	    ["cmovp", 2], 
	    ["xchg", 2], 
	    ["bswap", 2], 
	    ["xadd", 2], 
	    ["cmpxchg", 2], 
	    ["push", 1], 
	    ["pop", 1], 
	    ["in", 0], 
	    ["out", 0], 
	    ["cwde", 1], 
	    ["cdq", 1], 
	    ["movsx", 2], 
	    ["movzx", 2],
            # flag control instuctions
            ["stc", 0], 
	    ["clc", 0], 
	    ["cmc", 0], 
	    ["cld", 0], 
	    ["std", 0], 
	    ["lahf", 0], 
	    ["shf", 0], 
	    ["pushfq", 1], 
	    ["popfq", 1], 
	    ["sti", 0], 
	    ["cli", 0],
            # arithmetic
	    ["cmp", 2], 
	    ["daa", 1],  
	    ["das", 1], 
	    ["aaa", 1], 
	    ["aas", 1], 
	    ["aam", 1], 
	    ["aad",1],
	    ["add", 2], 
	    ["adc", 2], 
	    ["sub", 2], 
	    ["sbb", 2], 
	    ["imul", 1], 
	    ["mul", 1], 
	    ["idiv", 1], 
	    ["div", 1], 
	    ["inc", 1], 
	    ["dec", 1], 
	    ["neg", 1], 
            # control transfer
            ["ret", 1], 
	    ["iret", 1], 
	    ["int", 0], 
	    ["into", 0], 
	    ["enter", 0], 
	    ["leave", 0], 
	    ["call", 1], 
	    ["jmp", 1], 
	    ["ja", 1], 
	    ["jae", 1], 
	    ["jb", 1], 
	    ["jbe",1], 
	    ["jc", 1], 
	    ["je", 1], 
	    ["jnc", 1], 
	    ["jne", 1], 
	    ["jnp", 1], 
	    ["jp", 1], 
	    ["jg", 1], 
	    ["jge", 1], 
	    ["jl", 1], 
	    ["jle", 1], 
	    ["jno", 1], 
	    ["jns", 1], 
	    ["jo", 1], 
	    ["js", 1], 
            # logic
            ["and", 2], 
	    ["or", 2], 
	    ["xor", 2], 
	    ["not", 2],
            # shift and rotate
            ["sar", 2], 
	    ["shr", 2], 
	    ["sal", 2], 
	    ["shrd", 2], 
	    ["shld", 2], 
	    ["ror", 2], 
	    ["rol", 2],
	    ["rcr", 2], 
	    ["rcl", 2],
            # bit and bytes
            "bt", "bts", "btr", "btc", "bsf", "bsr", "sete", "setne", "seta", "setae", "setb", "setbe", "setg", "setge", "setl", "setle", "sets", "setns", "seto", "setno", "setpe", "setpo", "test",
            # segment 
            ["lds", 0], 
	    ["les", 0], 
	    ["lfs", 0], 
	    ["lgs", 0], 
	    ["lss", 0],
            # others
            ["lea", 2], 
	    ["nop", 0], 
	    ["xlatb", 1]
	    # TODO: string operation, loop operation, MMX instruction, float point, System instruction
	    }

class ROPParserX86:
	def __init__(self, gadgets, mode):
		self.gadgets = gadget
		if mode == CS_MODE_32:
			self.regs = X86.32bits + X86.FLAG 	
		else:
			self.regs = X86.64bits + X86.FLAG 	

	
	def parseGadget(self):
		formulats = []
		for gadget in self.gadgets:
			regs = []
			for ins in gadget.split(" ; ")
				expr = parseExp(ins)
			formulats.append(regs)
		return formulats
		
