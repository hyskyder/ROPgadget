#!/usr/bin/env python2
from arch.parserx86 import ROPParserX86
from arch.parserx86 import X86
from arch.semantic import Semantic
from arch.expression import Exp
from capstone import *
from copy import deepcopy
from z3 import *
import sys, traceback

class ROPChain:
    def __init__(self, binary, gadgets):
        self.binary = binary
        self.gadgets = gadgets
        # all the gadgets store by { reg : { cat : [] } }
        self.categories = {}
        # gadgets writes to mem
        self.mems = []
        self.semantics = []
        self.deepth = 1
        self.solver = Solver()
        self.z3Regs= {}
        self.cond = {}
        if self.binary is not None and self.binary.getArch() == CS_ARCH_X86:
            self.parser = ROPParserX86(self.gadgets, self.binary.getArchMode())
            self.semantics = self.parser.parse()
            if self.binary.getArchMode() == CS_MODE_32:
                for reg in X86.regs32:
                    ref = BitVec(reg, 32)
                    self.z3Regs.update({reg:ref})
            else:
                for reg in X86.regs64:
                    ref = BitVec(reg, 64)
                    self.z3Regs.update({reg:ref})
        self.Category()
        self.Core()

    def Convert(self, exp):
        if not isinstance(exp, Exp):
            if exp in self.z3Regs.keys():
                return self.z3Regs[exp]
            else:
                return exp
        reg = None
        if exp.condition is not None:
            return If(self.Convert(exp.condition), self.Convert(exp.left), self.Convert(exp.right))
        else:
            if exp.right is not None:
                if exp.op == '+':
                    return self.Convert(exp.left) + self.Convert(exp.right)
                elif exp.op == '-':
                    return self.Convert(exp.left) - self.Convert(exp.right)
                elif exp.op == '*':
                    return self.Convert(exp.left) * self.Convert(exp.right)
                elif exp.op == '%':
                    return self.Convert(exp.left) % self.Convert(exp.right)
                elif exp.op == '&':
                    return self.Convert(exp.left) & self.Convert(exp.right)
                elif exp.op == '|':
                    return self.Convert(exp.left) | self.Convert(exp.right)
                elif exp.op == '^':
                    return self.Convert(exp.left) ^ self.Convert(exp.right)
                elif exp.op == '$':
                    return Extract(self.Convert(exp.right), self.Convert(exp.left), self.Convert(exp.condition))
                else:
                    pass
            else:
                if exp.op is not None:
                    if exp.op == '+':
                        return self.Convert(exp.left)
                    elif exp.op == '-':
                        return -self.Convert(exp.left)
                    else:
                        # TODO & and *
                        pass
                return self.Convert(exp.left) 

    # check whether a set of regs is sat to the targets
    def CheckRegsSat(self, regs, targets):
        for k in targets.keys():
            if k not in regs.keys():
                self.solver.pop()
                return False
            if targets[k].getCategory() == 0:
                if regs[k].getCategory() == 3 and regs[k].isControl():
                    continue
                elif regs[k].getCategory() == 0:
                    if str(simplify(IntVal(self.Convert(targets[k]() == IntVal(self.Convert(regs[k])))) == "True":
                        continue
                    return False
                else:
                    return False
            elif regs[k].getCategory() == 3:
                return False  
            else:
                temp = targets[k].getRegs()
                for s in temp:
                    if s not in regs[k].getRegs():
                        return False
                if str(simplify(self.Convert(targets[k]) == self.Convert(regs[k]))) == "True":
                    continue
                return False
        return True
        '''
        if str(self.solver.check()) == "sat":
            res = self.solver.model()
            for r in res:
                if not str(r) in defined and r != "dst":
                    self.solver.pop()
                    return False
            self.solver.pop()
            return True
        else:
            self.solver.pop()
            return False
        '''

    def Core(self):
        while True:
            print "================================================\n"
            string = raw_input("Please Specify the status of registers:")
            if string == "quit" or string == "q":
                break
            regs = {}
            exps = string.split(';')
            for exp in exps:
                tokens = exp.split()
                reg = tokens.pop(0)
                val = Exp.parseExp(tokens)
                if not isinstance(val, Exp):
                    val = Exp(val)
                regs.update({reg:val})
            self.cond = regs

            reserve = set()
            chained = set([None])
            for reg, val in regs.items():
                temp = set()
                for semantic in chained:
                    if semantic is not None and self.CheckRegsSat({reg:semantic.regs[reg]}, {reg:val}):
                        temp.add(semantic)
                        continue
                    nex = self.Chain(reserve, reg, val, [reg], 5, None)
                    for s in nex:
                        c = deepcopy(s)
                        c.chain(semantic)
                        temp.add(c)
                reserve.add(reg)
                chained = deepcopy(temp)
            print  len(chained), "unique gadgets found"
            for s in chained:
                print s

    def Overlap(self, reserve, regs):
        for reg in regs.keys():
            if reg in reserve:
                return True
        return False

    def Chain(self, reserve, reg, val, targets, cat, nex):
        chained = set()
        target = targets.pop(0)
        print "searching for ", reg, " ==> ", val , " throught ", target
        if len(targets) != 0:
            # DFS, only works for regs + regs
            if target in self.categories.keys()  and 2 in self.categories[target].keys():
                for semantic in self.categories[target][2]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    temp = targets.pop(0)
                    reserve.add(temp)
                    chained.update(self.Chain(reserve, reg, val, targets, c))
                    reserve.remove(temp)
                    targets.insert(temp)
            return chained

        # check for gadget that modify mem
        if cat == -1:
            for semantic in self.mems:
                if self.Overlap(reserve, semantic.regs):
                    continue
                c = deepcopy(nex)
                c.chain(semantic)
                if target in semantic.keys():
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    chained.update(self.Chain(reserve, reg, val, c.regs[reg], 5, c))
            return chained

        # check mem location 
        if cat == 5 or cat == 3:
            if target in self.categories.keys() and 3 in self.categories[target].keys():
                for semantic in self.categories[target][3]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    else:
                        chained.update(self.Chain(reserve, reg, val,[str(c.regs[reg])], -1, c))

        # check constant based
        if cat == 5 or cat == 0:
            if target in self.categories.keys() and 0 in self.categories[target].keys():
                for semantic in self.categories[target][0]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)

        # check reg based
        if cat == 5 or cat == 1:
            if target in self.categories.keys() and 1 in self.categories[target].keys():
                for semantic in self.categories[target][1]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    print semantic.regs[target], " == ", val
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    chained.update(self.Chain(reserve, reg, val, semantic.regs[target].getRegs(), 5, c))

        # check regs based if needed
        if cat == 5 or cat == 2:
            if target in self.categories.keys()  and 2 in self.categories[target].keys():
                for semantic in self.categories[target][2]:
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    else:
                        chained.update(self.Chain(reserve, reg, val, semantic.regs[reg].getRegs(), 2, c))

        # TODO check Mem + Regs
        targets.insert(0, target)
        return chained
    def AddGadget(self, reg, val, semantic):
        if reg not in self.categories.keys():
            self.categories.update({reg:{}})
        if val.getCategory() not in self.categories[reg].keys():
            self.categories[reg].update({val.getCategory():[]})
        self.categories[reg][val.getCategory()].append(semantic)

    def Category(self):
        temp = []
        for semantic in self.semantics:
            if semantic.regs["dst"].isControl():
                # return address is somewhere in esp
                for reg, val in semantic.regs.items():
                    if not reg in self.z3Regs:
                        self.mems.append(semantic)
                        continue
                    self.AddGadget(reg, val, semantic)
            else:
                temp.append(semantic)
        # fix dst
        for semantic in temp:
            regs = semantic.regs["dst"].getRegs()
            if len(regs) == 1:
                for chain in self.categories[regs[0]][0]:
                    dup = deepcopy(chain)
                    dup.chain(semantic)
                    for reg, val in dup.regs.items():
                        self.categories[reg][val.getCategory()].append(val)
            else:
                # TODO for multiple regs
                pass
        # prechain
        print "prechaining with deepth = ", self.deepth
        for i in range(self.deepth):
            for reg1 in self.categories.keys():
                # replace all regs that can be mapped to constant or reg
                for t1 in [ 0, 1 ]:
                    if t1 not in self.categories[reg1].keys():
                        continue
                    for semantic in self.categories[reg1][t1]:
                        for reg2 in self.categories.keys():
                            if reg1 == reg2:
                                continue
                            for t2 in [1, 2, 3]:
                                if t2 in self.categories[reg2].keys():
                                    temp = []
                                    for s in self.categories[reg2][t2]:
                                        if reg1 not in s.regs[reg2].getRegs():
                                            continue
                                        c = deepcopy(s)
                                        c.chain(semantic)
                                        temp.append(c)
                                    for s in temp:
                                        self.AddGadget(reg2, s.regs[reg2], s)
        # category
        print "Category as follows:"
        for reg in self.categories.keys():
            for k in self.categories[reg]:
                print reg, " ======> ", k , " with ", len(self.categories[reg][k])
                for s in self.categories[reg][k]:
                    print s

if __name__ == '__main__':
    regs = {"dst":Exp("esp", "*"), "eax": Exp("1")}
    s1 = Semantic(regs, {"vaddr":0x1})
    regs2 = {"dst":Exp("esp", "*"), "ebx": Exp("eax")}
    s2 = Semantic(regs2, {"vaddr":0x2})
    exp = Exp("eax", "+", "ebx")
    regs3 = {"dst":Exp(Exp("esp", "+", 4), "*"), "ecx": exp}
    s3 = Semantic(regs3, {"vaddr":0x3})
    regs4 = {"dst":Exp("esp", "*"), "ebx": Exp("1")}
    s4 = Semantic(regs4, None)
    s = [s1, s2, s3]
    r = ROPChain(None, None)
    r.semantics = s
    r.Category()
    r.Core()

