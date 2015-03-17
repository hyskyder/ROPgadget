#!/usr/bin/env python2
from arch.parserx86 import ROPParserX86
from arch.semantic import Semantic
from arch.expression import Exp
from capstone import *
from copy import deepcopy

class ROPChain:
    def __init__(self, binary, gadgets):
        self.binary = binary
        self.gadgets = gadgets
        self.categories = {}
        self.semantics = []
        if self.binary is not None and self.binary.getArch() == CS_ARCH_X86:
            self.parser = ROPParserX86(self.gadgets, self.binary.getArchMode())
            self.semantics = self.parser.parse()
	
    def Core(self):
        while True:
            string = raw_input("Please Specify the status of registers:")
            if string == "quit" or string == "q":
                break
            tokens = string.split()
            regs = {}
            while len(tokens) != 0:
                val = Exp(tokens.pop())
                reg = tokens.pop()
                regs.update({reg:val})

            reserve = []
            chained = []
            temp = [None]
            for reg, val in regs.items():
                chained = temp
                temp = []
                for semantic in chained:
                    temp.extend(self.Chain(reserve, reg, val, semantic))
                reserve.append(reg)
            for s in temp:
                print s
            print  len(temp), " unique gadgets found"

    def Overlap(self, reserve, regs):
        for reg in regs.keys():
            if reg in reserve:
                return True
        return False
    
    def Search(self, reserve, stats):
        for semantic in self.semantics:
            flag = True
            if self.Overlap(reserve, semantic.regs):
                continue
            for reg, val in stats.items():
                if not semantic.regs[reg].equals(val):
                    flag = False
            if flag:
                return semantic
        return None

    # reutrn: gadgets that set exp of regs to val, else None
    def SearchAddup(self, reverse, exp, val, prev):
        for semantic in self.semantics:
            if self.Overlap(reserve, semantic.regs):
                continue
        for reg in regs:
            if reg in self.categories.keys() and 
    
    # return: gadgets that set all regs to constant, else None
    def SearchConstant(self, reverse, regs):
        if len(regs) == 0 or regs[0] not in self.categories.keys() or 0 not in self.categories[regs[0]].keys():
            return None
        for semantic in self.categories[regs[0]][0]:
            if self.Overlap(reserve, semantic.regs):
                continue
            flag = True
            for reg in regs:
                if reg not in semantic.regs.keys() or not semantic.regs[reg].isConstant():
                    flag = False
            if flag:
                return semantic 
        return None



    def Chain(self, reserve, reg, val, prev):
        print "searching for ", reg, " ==> ", val
        chained = []
        if val.isConstant():
            # check esp based
            if reg in self.categories.keys() and 2 in self.categories[reg].keys():
                for semantic in self.categories[reg][2]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    chained.append(deepcopy(semantic).chain(prev))

            # check constant based
            if reg in self.categories.keys() and 0 in self.categories[reg].keys():
                for semantic in self.categories[reg][0]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    if semantic.regs[reg].equals(val):
                        chained.append(deepcopy(semantic).chain(prev))
                    else:
                        # TODO using z3 to generate new condition 
                        pass


            # check reg based
            if reg in self.categories.keys() and 3 in self.categories[reg].keys():
                for semantic in self.categories[reg][3]:
                    print semantic.regs[reg], " == ", val
                    # TODO using z3 to generate new condition 
                    nval = val
                    temp = deepcopy(semantic)
                    if prev is not None:
                        temp.chain(prev)
                    follow = self.Chain(reserve, str(semantic.regs[reg]), nval, temp)
                    chained.extend(follow)

            if reg in self.categories.keys()  and 4 in self.categories[reg].keys():
                # check regs based if needed
                # a) one of regs esp-based, others are constant
                # b) all regs are constant and added up to val
                regs = semantic.regs[reg].getRegs()
                for temp in regs:
                    if temp in self.categories.keys() and 2 in self.categories[temp].keys():
                        for semantic in self.categories[temp][2]:
                            if self.Overlap(reserve, semantic.regs):
                                continue
                            reserve.append(temp)
                            ga = self.SearchConstant(reserve, regs - temp)
                            reserve.pop_back()
                            if ga is not None:
                                chained.append(deepcopy(ga).chain(semantic).chain(prev))
                ga = self.SearchAddup(reserve, semantic.regs[reg], val, deepcopy(semantic).chain(prev))
                if ga is not None:
                    chained.append(deepcopy(ga).chain(prev))
                
        else:
            # check reg based first
            if reg in self.categories.keys() and 3 in self.categories[reg].keys():
                for semantic in self.categories[reg][3]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    if semantic.regs[reg].equals(val):
                        chained.append(deepcopy(semantic).chain(prev))
                    else:
                        nval = val.reduce(semantic.regs[reg])
                        temp = deepcopy(semantic)
                        if prev is not None:
                            temp.chain(prev)
                        follow = self.Chain(reserve, str(semantic.regs[reg]), nval, temp)
                        chained.extend(follow)

            if 10 and reg in self.categories.keys()  and 4 in self.categories[reg].keys():
                # check regs based if needed
                # one of reg is val based, others add up to constant val 
                regs = semantic.regs[reg].getRegs()
                for semantic in self.categories[reg][3]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    follow = self.SearchAddup(reserve, semantic.regs[reg], val, deepcopy(semantic).chain(prev))
                    if follow is not None:
                        follow.chain(temp)
                        chained.append(follow)
        return chained

    def Category(self):
        temp = []
        for semantic in self.semantics:
            # if the dst cannot be controlled, abandon
            if semantic.regs["dst"].getCategory() == 0:
                continue
            regs = semantic.regs["dst"].getRegs()
            if len(regs) == 1 and ( regs[0] == "esp" or resgs[0] == "rsp"):
                # category gadgets baseed on the regs and type
                for reg, val in semantic.regs.items():
                    if reg not in self.categories.keys():
                        self.categories.update({reg:{}})
                    if val.getCategory() not in self.categories[reg].keys():
                        self.categories[reg].update({val.getCategory():[]})
                    self.categories[reg][val.getCategory()].append(semantic)
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
        # TODO prechain
        print "categories as follows:"
        for k, v in self.categories.items():
            print k
            for i, j in v.items():
                print i, type(i), j

if __name__ == '__main__':
    regs = {"dst":Exp("esp"), "eax": Exp("1")}
    s1 = Semantic(regs, None)
    regs2 = {"dst":Exp("esp"), "ebx": Exp("eax")}
    s2 = Semantic(regs2, None)
    s = [s1, s2]
    r = ROPChain(None, None)
    r.semantics = s
    r.Category()
    r.Core()

