#!/usr/bin/env python2
from arch.parserx86 import ROPParserX86
from arch.parserx86 import X86
from arch.semantic import Semantic
from arch.expression import Exp
from capstone import *
from copy import deepcopy
from z3 import *

class ROPChain:
    def __init__(self, binary, gadgets, opt, deepth = 0):
        self.binary = binary
        self.gadgets = gadgets
        # all the gadgets store by { reg : { cat : [] } }
        self.categories = {}
        # gadgets writes to mem
        self.mems = []
        self.semantics = []
        self.deepth = deepth
        self.solver = Solver()
        self.z3Regs= {}
        self.optimized = opt
        if self.binary is not None and self.binary.getArch() == CS_ARCH_X86:
            self.parser = ROPParserX86(self.gadgets, self.binary.getArchMode())
            self.semantics = self.parser.parse()
            if self.binary.getArchMode() == CS_MODE_32:
                Exp.defaultLength = 32
                for reg in X86.regs32:
                    ref = BitVec(reg, 32)
                    self.z3Regs.update({reg:ref})
            else:
                Exp.defaultLength = 64
                for reg in X86.regs64:
                    ref = BitVec(reg, 64)
                    self.z3Regs.update({reg:ref})
            for reg in X86.FLAG:
                ref = BitVec(reg, 1)
                self.z3Regs.update({reg:ref})
        self.Category()

    def Convert(self, exp):
        if not isinstance(exp.left, Exp):
            if exp.left == "ssp":
                if self.binary.getArchMode() == CS_MODE_32:
                    return self.z3Regs["esp"]
                else:
                    return self.z3Regs["rsp"]
            elif exp.left in self.z3Regs.keys():
                return self.z3Regs[exp.left]
            elif isinstance(exp.left, str) and "0x" in exp.left:
                return int(exp.left, 16)
            else:
                return int(exp.left)
        reg = None
        if exp.op is not None and exp.op == "condition":
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
                elif exp.op == '==':
                    return self.Convert(exp.left) == self.Convert(exp.right)
                elif exp.op == '>':
                    return self.Convert(exp.left) > self.Convert(exp.right)
                elif exp.op == '<':
                    return self.Convert(exp.left) < self.Convert(exp.right)
                elif exp.op == '!=':
                    return self.Convert(exp.left) != self.Convert(exp.right)
                elif exp.op == '#':
                    left = self.Convert(exp.left)
                    right = self.Convert(exp.right)
                    print exp
                    if not is_bv(left):
                        left = BitVecVal(left, exp.left.length)
                    if not is_bv(right):
                        right = BitVecVal(right, exp.right.length)
                    return Concat(left, right)
                else:
                    pass
            else:
                if exp.op is not None:
                    if exp.op == '+':
                        return self.Convert(exp.left)
                    elif exp.op == '-':
                        return -self.Convert(exp.left)
                    elif exp.op == 'O':
                        self.z3Regs["OF"] = If(self.Overflow(self.Convert(exp.left), 1, 0))
                        return self.z3Regs["OF"]
                    elif exp.op == 'Z':
                        self.z3Regs["ZF"] = If(self.Convert(exp.left) == 0, 1, 0)
                        return self.z3Regs["ZF"]
                    elif exp.op == 'S':
                        self.z3Regs["SF"] = If(self.Convert(exp.left) > 0, 1, 0)
                        return self.z3Regs["SF"]
                    elif exp.op == 'C':
                        self.z3Regs["CF"] = If(self.Carry(exp.left), 1, 0)
                        return self.z3Regs["CF"]
                    elif exp.op == 'P':
                        self.z3Regs["PF"] = If(self.Parity(self.Convert(exp.left)) % 2 == 0, 1, 0)
                        return self.z3Regs["PF"]
                    elif exp.op == 'A':
                        self.z3Regs["AF"] = If(self.Adjust(self.Convert(exp.left)), 1, 0)
                        return self.z3Regs["AF"]
                    else:
                        # TODO & and *
                        pass
                return self.Convert(exp.left) 

    def Adjust(self, exp):
        # TODO
        return True

    def Overflow(self, exp):
        if exp.right is None:
            # unary exp, i.e. -op
            left = self.Convert(exp.left)
            return Extract(exp.size, exp.size, left) == Extract(exp.size, exp.size, -left)
        else:
            left = self.Convert(exp.left)
            right = self.Convert(exp.right)
            if not is_bv(left):
                left = BitVecVal(exp.size)
            if not is_bv(right):
                right = BitVecVal(exp.size)
            if is_bv(right) and right.size() == 1:
                # bin exp, e.g. op1 + op2 + CF
                if self.op == '+':
                    return Or((self.Overflow(exp.left), And(Extract(exp.size-1, exp.size-1, left) == Extract(exp.size-1, exp.size-1, right), Extract(exp.size-1, exp.size-1, left + right) != Extract(exp.size-1, exp.size-1, left))))
                if self.op == '-':
                    return Or((self.Overflow(exp.left), And(Extract(exp.size-1, exp.size-1, left) == Extract(exp.size-1, exp.size-1, right), Extract(exp.size-1, exp.size-1, left - right) != Extract(exp.size-1, exp.size-1, left))))
            else:
                # bin exp, e.g. op1 + op2
                if exp.op == '+':
                    return And(Extract(exp.size-1, exp.size-1, left) == Extract(exp.size-1, exp.size-1, right), Extract(exp.size-1, exp.size-1, left + right) != Extract(exp.size-1, exp.size-1, left))
                elif exp.op == '-':
                    return And(Extract(exp.size-1, exp.size-1, left) != Extract(exp.size-1, exp.size-1, right), Extract(exp.size-1, exp.size-1, left - right) != Extract(exp.size-1, exp.size-1, left))

    def Carry(self, exp):
        if exp.right is None:
            # unary exp, i.e. - op
            return self.Convert(exp) != 0 
        else:
            left = self.Convert(exp.left)
            right = self.Convert(exp.right)
            if not is_bv(left):
                left = BitVecVal(left, exp.size)
            if not is_bv(right):
                right = BitVecVal(right, exp.size)
            if is_bv(right) and right.size() == 1:
                # bin exp, e.g. op1 + op2 + CF
                if exp.op == '+':
                    return Or((self.Carry(exp.left), Extract(exp.size - 1, exp.size - 1, left + right)) == 1)
                if exp.op == '-':
                    return Or((self.Carry(exp.left), Extract(exp.size, exp.size, left - right)) == 1)
            else:
                # bin exp, e.g. op1 + op2
                if exp.op == '+':
                    return (Extract(exp.size - 1, exp.size - 1, left + right) == 1)
                elif exp.op == '-':
                    return (Extract(exp.size - 1, exp.size - 1, left - right) == 1)

    def Parity(self, reg):
        count = 0    
        for i in range(reg.size()):
            if Extract(i, i, reg) == 1:
                count = count + 1
        return count

    # check whether a set of regs is sat to the targets
    def CheckRegsSat(self, regs, targets):
        for k in targets.keys():
            if k not in regs.keys():
                return False
            if targets[k].getCategory() == 0:
                if regs[k].getCategory() == 3 and regs[k].isControl():
                    continue
                if regs[k].getCategory() == 0:
                    if str(simplify( IntVal(self.Convert(targets[k])) == IntVal(self.Convert(regs[k])))) == "True":
                        continue
                else:
                    print (regs[k])
                    if str(simplify( (self.Convert(targets[k])) == (self.Convert(regs[k])))) == "True":
                        continue
                return False
            elif regs[k].getCategory() == 3:
                return False  
            else:
                temp = targets[k].getRegs()
                for s in temp:
                    if s not in regs[k].getRegs():
                        return False
                if str(simplify(self.Convert(targets[k]) == self.Convert(regs[k]))) != "True":
                    return False
        return True
        '''
        if str(self.solver.check()) == "sat":
            res = self.solver.model()
            for r in res:
                if not str(r) in defined and r != "sip":
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
            self.Start(regs)

    def Start(self, regs):
        reserve = set()
        chained = set([None])
        # TODO, sort the regs order first
        for reg, val in regs.items():
            temp = set()
            for semantic in chained:
                prev = None
                if semantic is not None:
                    prev = semantic.regs
                if semantic is not None and reg in semantic.regs.keys() and self.CheckRegsSat({reg:semantic.regs[reg]}, {reg:val}):
                    temp.add(semantic)
                    continue
                nex = self.Chain(reserve, reg, val, [reg], val.getCategory(), prev, None, 0)
                if len(nex) == 0:
                    nex.update(self.Chain(reserve, reg, val, [reg], 6, prev, None, 0))
                for s in nex:
                    c = deepcopy(s)
                    c.chain(semantic)
                    temp.add(c)
            reserve.add(reg)
            chained = deepcopy(temp)
        final = []
        for t in chained:
            if self.CheckRegsSat(t.regs, regs):
                final.append(t)

        if len(chained) <= 1:
            print  len(final), "unique gadget found"
        else:
            print  len(final), "unique gadgets found"
        for s in final:
            print s
        return final 

    def Overlap(self, reserve, regs):
        for reg in regs.keys():
            if reg in reserve:
                return True
        return False

    def Chain(self, reserve, reg, val, targets, cat, prev, nex, deepth):
        chained = set()
        print "searching for ", reg, " ==> ", val , " throught ", targets, " category ", cat, " deepth ", deepth, " limit ", self.deepth
        if len(targets) == 0 or deepth > self.deepth:
            return chained
        target = targets.pop(0)
        print nex
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
                    c.binding(prev)
                    temp = targets.pop(0)
                    reserve.add(temp)
                    chained.update(self.Chain(reserve, reg, val, targets, cat, prev, c, deepth+1))
                    reserve.remove(temp)
                    targets.insert(0, temp)
            return chained

        # checks for gadget that modify mem, or checks for gadgets to control this mem location
        if cat == -1:
            for semantic in self.mems:
                if self.Overlap(reserve, semantic.regs):
                    continue
                c = deepcopy(nex)
                c.chain(semantic)
                c.binding(prev)
                if target in semantic.regs.keys():
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    chained.update(self.Chain(reserve, reg, val, c.regs[reg], 6, prev, c, deepth+1))
            chained.update(self.ChainRetGadget(c.regs[reg], prev, nex, deepth+1))
            return chained

        # checks mem location 
        if cat == 6 or cat == 3:
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
                    c.binding(prev)
                    print "checking ", c.regs[reg], " == ", val
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    else:
                        chained.update(self.Chain(reserve, reg, val,[str(c.regs[reg])], -1, prev, c, deepth+1))

        # checks constant based
        if cat == 6 or cat == 0:
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
                    c.binding(prev)
                    print "checking ", c.regs[reg], " == ", val
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)

        # checks reg based
        if cat == 6 or cat == 1:
            if target in self.categories.keys() and 1 in self.categories[target].keys():
                for semantic in self.categories[target][1]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    c.binding(prev)
                    print "checking ", c.regs[reg], " == ", val
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    else:
                        chained.update(self.Chain(reserve, reg, val, semantic.regs[target].getRegs(), cat, prev, c, deepth+1))

        # checks regs based if needed
        if cat == 6 or cat == 2:
            if target in self.categories.keys()  and 2 in self.categories[target].keys():
                for semantic in self.categories[target][2]:
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    c.binding(prev)
                    print "checking ", c.regs[reg], " == ", val
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    else:
                        chained.update(self.Chain(reserve, reg, val, semantic.regs[reg].getRegs(), cat, prev, c, deepth+1))

        # checks condition based if needed
        if cat == 6 or cat == 5:
            if target in self.categories.keys()  and 5 in self.categories[target].keys():
                for semantic in self.categories[target][5]:
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = semantic
                    c.binding(prev)
                    print "checking ", c.regs[reg], " == ", val
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}):
                        chained.add(c)
                    else:
                        chained.update(self.Chain(reserve, reg, val, semantic.regs[reg].getCondition().getRegs(), cat, prev, c, deepth+1))

        # TODO checks Mem + Regs
        targets.insert(0, target)
        return chained

    def AddToCat(self, reg, val, semantic):
        if reg not in self.categories.keys():
            self.categories.update({reg:{}})
        if val.getCategory() not in self.categories[reg].keys():
            self.categories[reg].update({val.getCategory():[]})
        self.categories[reg][val.getCategory()].append(semantic)

    def ChainRetGadget(self, sip, prev, nex, deepth):
        # sip must be a mem location
        print "chaing esp val", nex
        fixed = set()
        if deepth > self.deepth:
            return fixed
        if not isinstance(sip.left, Exp) or sip.left.getCategory() == 1:
            # the location is only determined by one reg 
            reg = str(sip.left)
            if isinstance(sip.left, Exp):
                reg = sip.left.getRegs()[0]
            if reg in self.categories.keys() and 1 in self.categories[reg].keys():
                for semantic in self.categories[reg][1]:
                    if semantic.regs[reg].getCategory() == 1 and semantic.regs[reg].getRegs()[0] == "ssp":
                        c = deepcopy(nex)
                        c.chain(semantic)
                        c.binding(prev)
                        fixed.add(c)
                        # TODO, we can return after find one perfect ret gadget
            if reg in self.categories.keys() and 3 in self.categories[reg].keys():
                for semantic in self.categories[reg][3]:
                    if semantic.regs[reg].isControl():
                        c = deepcopy(nex)
                        c.chain(semantic)
                        c.binding(prev)
                        fixed.add(c)

        elif sip.left.getCategory() == 2:
            regs = sip.left.getRegs()
            for reg in regs:
                # one reg is esp, others are constant, TODO
                pass

        elif sip.left.getCategory() == 3:
            if sip.left.isControl():
                # if mem location is from esp
                nex.binding(prev)
                fixed.add(nex)
            else:
                # otherwise, chain another mem location gadget
                temp = self.ChainRetGadget(sip.left.left, prev, nex, deepth+1)
                for jop in temp:
                    fixed.add(jop)
        return fixed 

    def ChainCondGadget(self, targets, nex):
        fixed = set()
        reg = targets.pop(0)
        if len(targets) == 0:
            if reg in self.categories.keys() and 0 in self.categories[reg].keys():
                for semantic in self.categories[reg][0]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    if self.Convert(c.regs["sip"].getCondition()) or simplify(self.Convert(c.regs["sip"].getCondition())) == "True":
                        c.regs.update({"sip":c.regs["sip"].meetCondition()})
                        fixed.add(c)

            if reg in self.categories.keys() and 1 in self.categories[reg].keys():
                for semantic in self.categories[reg][1]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    if self.Convert(c.regs["sip"].getCondition()) or simplify(self.Convert(c.regs["sip"].getCondition())) == "True":
                        c.regs.update({"sip":c.regs["sip"].meetCondition()})
                        fixed.add(c)
        else:
            if reg in self.categories.keys() and 0 in self.categories[reg].keys():
                for semantic in self.categories[reg][0]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    fixed.update(self.ChainCondGadget(targets, c))

            if reg in self.categories.keys() and 1 in self.categories[reg].keys():
                for semantic in self.categories[reg][1]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    fixed.update(self.ChainCondGadget(targets, c))
        targets.append(reg)
        return fixed

    def Category(self):
        cond = []
        rets = []
        for semantic in self.semantics:
            if semantic.regs["sip"].isControl():
                # return address is somewhere in esp
                print semantic
                for reg, val in semantic.regs.items():
                    if not reg in self.z3Regs:
                        self.mems.append(semantic)
                        continue
                    self.AddToCat(reg, val, semantic)
            else:
                if semantic.regs["sip"].isCond():
                    cond.append(semantic)
                else:
                    rets.append(semantic)
        print "gadgets with condition ", len(cond)
        print "gadgets with destination not specified ", len(rets)
        print "gadgets can be directly used", len(self.semantics) - len(rets)
        for semantic in cond:
            # fix cond 
            rets.extend(self.ChainCondGadget(semantic.regs["sip"].getCondition().getRegs(), semantic))
        
        for semantic in rets:
            fixed = [semantic]
            if not semantic.regs["sip"].isControl():
                fixed = self.ChainRetGadget(semantic.regs["sip"], None, semantic, 0)
            for jop in fixed:
                for reg, val in jop.regs.items():
                    if not reg in self.z3Regs:
                        self.mems.append(jop)
                        continue
                    self.AddToCat(reg, val, jop)

        # prechain
        if self.optimized:
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
                                            self.AddToCat(reg2, s.regs[reg2], s)
        # category
        print "Category as follows:"
        for reg in self.categories.keys():
            for k in self.categories[reg]:
                print reg, "\t======>\t", k , " with ", len(self.categories[reg][k])
                for s in self.categories[reg][k]:
                    pass

if __name__ == '__main__':
    regs = {"sip":Exp("ssp", "*"), "eax": Exp("1")}
    s1 = Semantic(regs, {"vaddr":0x1})
    regs2 = {"sip":Exp("ssp", "*"), "ebx": Exp("eax")}
    s2 = Semantic(regs2, {"vaddr":0x2})
    exp = Exp("eax", "+", "ebx")
    regs3 = {"sip":Exp(Exp("ssp", "+", 4), "*"), "ecx": exp}
    s3 = Semantic(regs3, {"vaddr":0x3})
    regs4 = {"sip":Exp("ssp", "*"), "ebx": Exp("1")}
    s4 = Semantic(regs4, None)
    s = [s1, s2, s3]
    r = ROPChain(None, None, False)
    r.semantics = s

