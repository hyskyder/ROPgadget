#!/usr/bin/env python2
from arch.parserx86 import ROPParserX86
from capstone import *

class ROPChain:
    def __init__(self, binary, gadgets):
        self.binary = binary
        self.gadgets = gadgets
        self.categories = {}
        if self.binary.getArch() == CS_ARCH_X86:
            self.parser = ROPParserX86(self.gadgets, self.binary.getArchMode())
            self.formulas = self.parser.parse()
            for reg in self.parser.regs:
                self.categories.update({reg:[]})

            for formula in self.formulas:
                for reg in self.parser.regs:
                    if reg in formula.keys():
                        self.categories[reg].append(formula)
            print "Gadget Categories"
            print "===================="
            for k, v in self.categories.items():
                print  len(v), " gadgets modify ", k

    def Chain():
        while True:
            string = raw_input("Please Specify the status of registers:")
            if string == "quit" or string == "q":
                break
            tokens = string.split()
            regs = {}
            while len(tokens) != 0:
                regs.update({tokens.pop(0): Exp(tokens.pop(0))})

