#!/usr/bin/env python2
from arch.parserx86 import ROPParserX86
from arch.parserx86 import X86
from arch.semantic import Semantic
from arch.expression import Exp
from capstone import *
from copy import deepcopy
from z3 import *
import random
import math
import sys

class ROPChain:
    def __init__(self, binary, gadgets, opt, deepth = 1):
        self.binary = binary
        self.gadgets = gadgets
        # all the gadgets store by { reg : { cat : [] } }
        self.categories = {}
        # gadgets writes to mem
        self.mems = []
        self.chained = set()
        self.semantics = []
        self.deepth = deepth
        self.default = 5
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

    def Compare(self, left, right=None):
        le = self.Convert(left)
        if right is None:
            return simplify(le)
        re = self.Convert(right)

        if isinstance(le, int):
            le = BitVecVal(le, left.length)
        elif le.sort() == IntSort():
            le = BitVecRef( Z3_mk_int2bv(le.ctx_ref(), left.length, le.as_ast()), le.ctx)

        if isinstance(re, int):
            re = BitVecVal(re, right.length)
        elif re.sort() == IntSort():
            re = BitVecRef( Z3_mk_int2bv(re.ctx_ref(), right.length, re.as_ast()), re.ctx) 
        return simplify(le == re)

    def Convert(self, exp):
        if not isinstance(exp.left, Exp):
            if exp.left == "ssp":
                if self.binary.getArchMode() == CS_MODE_32:
                    return self.z3Regs["esp"]
                else:
                    return self.z3Regs["rsp"]
            elif exp.left in self.z3Regs.keys():
                return self.z3Regs[exp.left]
            elif "0x" in str(exp.left):
                if exp.length == 0:
                    return (int(exp.left, 16))
                else:
                    return BitVecVal(int(exp.left, 16), exp.length)
            else:
                if exp.length == 0:
                    return (int(exp.left))
                else:
                    return BitVecVal(int(exp.left), exp.length)
        if exp.op is not None and exp.op == "condition":
            return If(self.Convert(exp.condition), self.Convert(exp.left), self.Convert(exp.right))
        else:
            if exp.right is not None:
                left = self.Convert(exp.left)
                right = self.Convert(exp.right)
                if is_bv(left) and is_bv(right):
                    # this only hanlde for Flag regs and GPR
                    if left.size() < right.size() and left.size() == 1:
                        left = ZeroExt(right.size() - left.size(), left)
                    elif right.size() < left.size() and right.size() == 1:
                        right = ZeroExt(left.size() - right.size(), right)
                elif isinstance(left, int) or isinstance(right, int) or left.sort() == right.sort():
                    pass
                else:
                    if is_int(left) and is_bv(right):
                        left = BitVecRef(Z3_mk_int2bv(left.ctx_ref(), right.size(), left.as_ast()), left.ctx)
                    elif is_int(right) and is_bv(left):
                        right = BitVecRef(Z3_mk_int2bv(right.ctx_ref(), left.size(), right.as_ast()), right.ctx)

                if exp.op == '+':
                    return left + right
                elif exp.op == '-':
                    return left - right
                elif exp.op == '*':
                    return left * right
                elif exp.op == '%':
                    return left % right
                elif exp.op == '&':
                    if is_bool(left) and is_bool(right):
                        return And(left, right)
                    return left & right
                elif exp.op == '|':
                    if is_bool(left) and is_bool(right):
                        return Or(left, right)
                    return left | right
                elif exp.op == '^':
                    if is_bool(left) and is_bool(right):
                        return Xor(left, right)
                    return left ^ right
                elif exp.op == '$':
                    return Extract(right, left, self.Convert(exp.condition))
                elif exp.op == '==':
                    return left == right
                elif exp.op == '>':
                    return left > right
                elif exp.op == '<':
                    return left < right
                elif exp.op == '!=':
                    return left != right
                elif exp.op == '#':
                    return Concat(left, right)
                else:
                    pass
            else:
                if exp.op is not None:
                    if exp.op == '~':
                        if is_bool(self.Convert(exp.left)):
                            return Not(self.Convert(exp.left))
                        return ~ self.Convert(exp.left)
                    elif exp.op == '+':
                        return self.Convert(exp.left)
                    elif exp.op == '-':
                        return -self.Convert(exp.left)
                    elif exp.op == 'O':
                        self.z3Regs["OF"] = If(self.Overflow(exp.left), 1, 0)
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
                        # TODO for & and *, won't goto this branch in any case
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

            if is_int(left):
                left = BitVecRef(Z3_mk_int2bv(left.ctx_ref(), right.size(), left.as_ast()), left.ctx)
            elif isinstance(left, int):
                left = BitVecVal(left, exp.length) 

            if is_int(right):
                right = BitVecRef(Z3_mk_int2bv(right.ctx_ref(), left.size(), right.as_ast()), right.ctx)
            elif isinstance(right, int):
                right = BitVecVal(right, exp.length)

            if is_bv(right) and right.size() == 1:
                # bin exp, e.g. op1 + op2 + CF
                if self.op == '+':
                    return Or((self.Overflow(exp.left), And(Extract(exp.length-1, exp.length-1, left) == Extract(exp.length-1, exp.length-1, right), Extract(exp.length-1, exp.length-1, left + right) != Extract(exp.length-1, exp.length-1, left))))
                if self.op == '-':
                    return Or((self.Overflow(exp.left), And(Extract(exp.length-1, exp.length-1, left) == Extract(exp.length-1, exp.length-1, right), Extract(exp.length-1, exp.length-1, left - right) != Extract(exp.length-1, exp.length-1, left))))
            else:
                # bin exp, e.g. op1 + op2
                if exp.op == '+':
                    return And(Extract(exp.length-1, exp.length-1, left) == Extract(exp.length-1, exp.length-1, right), Extract(exp.length-1, exp.length-1, left + right) != Extract(exp.length-1, exp.length-1, left))
                elif exp.op == '-':
                    return And(Extract(exp.length-1, exp.length-1, left) != Extract(exp.length-1, exp.length-1, right), Extract(exp.length-1, exp.length-1, left - right) != Extract(exp.length-1, exp.length-1, left))

    def Carry(self, exp):
        if exp.right is None:
            # unary exp, i.e. - op
            return self.Convert(exp) != 0 
        else:
            left = self.Convert(exp.left)
            right = self.Convert(exp.right)
            size = exp.length
            if is_int(left):
                left = BitVecRef(Z3_mk_int2bv(left.ctx_ref(), size, left.as_ast()), left.ctx)
            elif isinstance(left, int):
                left = BitVecVal(left, size) 

            if is_int(right):
                right = BitVecRef(Z3_mk_int2bv(right.ctx_ref(), size, right.as_ast()), right.ctx)
            elif isinstance(right, int):
                right = BitVecVal(right, size)
            if is_bv(right) and right.size() == 1:
                # bin exp, e.g. op1 + op2 + CF
                if exp.op == '+':
                    return Or((self.Carry(exp.left), Extract(exp.size - 1, exp.size - 1, left + right)) == 1)
                if exp.op == '-':
                    return Or((self.Carry(exp.left), Extract(exp.size, exp.size, left - right)) == 1)
            else:
                # bin exp, e.g. op1 + op2
                if exp.op == '+':
                    return (Extract(exp.length - 1, exp.length- 1, left + right) == 1)
                elif exp.op == '-':
                    return (Extract(exp.length - 1, exp.length- 1, left - right) == 1)

    def Parity(self, reg):
        count = 0    
        for i in range(reg.size()):
            if Extract(i, i, reg) == 1:
                count = count + 1
        return count

    # check whether a set of regs is sat to the targets
    def CheckRegsSat(self, regs, targets, semantic):
        for k in targets.keys():
            if k not in regs.keys():
                return False
            #print regs[k] , " == ", targets[k]
            if targets[k].getCategory() == 0:
                if regs[k].getCategory() == 3:
                    if regs[k].isControl():
                        # FIXME: should record this mem in case of conflicts
                        continue
                elif is_true(self.Compare(regs[k], targets[k])):
                    continue
                return False
            elif regs[k].getCategory() == 3:
                return False  
            else:
                temp = targets[k].getRegs()
                for s in temp:
                    if s not in regs[k].getRegs():
                        return False
                if not is_true(self.Compare(regs[k], targets[k])):
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
                val.length = Exp.defaultLength
                regs.update({reg:val})
            self.Start(regs)

    def Start(self, regs):
        # TODO, sort the regs order first
        self.chained = set()
        for i in range(math.factorial(len(regs))):
            if self.Chain([], None, None, [], 6, None, None, 0, regs):
                break
        if len(self.chained) <= 1:
            print  len(self.chained), "unique gadget found"
        else:
            print  len(self.chained), "unique gadgets found"
        for s in self.chained:
            print s

        return self.chained

    def Overlap(self, reserve, regs):
        for reg in regs.keys():
            if reg in reserve:
                return True
        return False

    def Chain(self, reserve, reg, val, targets, cat, prev, nex, deepth, constraints):
        if deepth > self.deepth:
            return False 
        if reg is None and val is None:
            if len(constraints) == 0:
                print "all done"
                print prev
                if prev is not None:
                    self.chained.add(prev)
                return len(self.chained) >= self.default
            k = random.choice(constraints.keys())
            v = constraints.pop(k)
            print "Now looking for gadget with ", k , " == ", v
            res = self.Chain(reserve, k, v, [k], 6, prev, None, deepth, constraints)
            constraints.update({k:v})
            return res
        target = targets.pop(0)
        print "searching for ", reg, " ==> ", val , " throught ", target, " category ", cat, " deepth ", deepth, " limit ", self.deepth
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
                        c = deepcopy(semantic)
                    c.chain(prev)
                    temp = targets.pop(0)
                    reserve.append(temp)
                    if self.Chain(reserve, reg, val, targets, cat, prev, c, deepth+1, constraints):
                        return True
                    reserve.pop()
                    targets.insert(0, temp)
            return False

        # checks for gadget that modify mem
        if cat == -1:
            if isinstance(target, list):
                #TODO, for multi regs
                pass
            else:
                for semantic in self.mems:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    c = deepcopy(nex)
                    c.chain(semantic)
                    c.chain(prev)
                    if target in semantic.regs.keys():
                        if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}, c):
                            c.regs[reg] = val
                            reserve.append(reg)
                            if self.Chain(reserve, None, None, None, 0, c, None, deepth+1, constraints):
                                return True
                            reserve.pop()
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
                        c = deepcopy(semantic)
                    c.chain(prev)
                    print "checking gadget that set constant", c.regs[target]
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}, c):
                        c.regs[reg] = val
                        reserve.append(reg)
                        if self.Chain(reserve, None, None, None, 0, c, None, deepth+1, constraints):
                            return True
                        reserve.pop()

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
                        c = deepcopy(semantic)
                    c.chain(prev)
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}, c):
                        c.regs[reg] = val
                        reserve.append(reg)
                        if self.Chain(reserve, None, None, None, 0, c, None, deepth+1, constraints):
                            return True
                        reserve.pop()
                    else:
                        # either we control the addr of this mem location or we control the value of this mem location
                        print "checking gadget that set mem ", c.regs[target]
                        if len(c.regs[reg].getRegs()) != 0:
                            r = self.ChainRetGadget(reserve, c.regs[target], prev, c, deepth+1)
                            if r is not None:
                                if self.CheckRegsSat({reg:r.regs[reg]}, {reg:val}, r):
                                    if self.Chain(reserve, None, None, None, 0,  r, None, deepth+1, constraints):
                                        return True
                        elif self.Chain(reserve, reg, val,[str(c.regs[reg])], -1, prev, c, deepth+1, constraints):
                            return True

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
                        c = deepcopy(semantic)
                    c.chain(prev)
                    print "checking gadget that set to another reg", c.regs[target]
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}, c):
                        c.regs[reg] = val
                        reserve.append(reg)
                        if self.Chain(reserve, None, None, None, 0, c, None, deepth+1, constraints):
                            return True
                        reserve.pop()
                    else:
                        if self.Chain(reserve, reg, val, semantic.regs[target].getRegs(), cat, prev, c, deepth+1, constraints):
                            return True

        # checks regs based if needed
        if cat == 6 or cat == 2:
            if target in self.categories.keys()  and 2 in self.categories[target].keys():
                for semantic in self.categories[target][2]:
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = deepcopy(semantic)
                    c.chain(prev)
                    print "checking gadget that set to regs", c.regs[target]
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}, c):
                        c.regs[reg] = val
                        reserve.append(reg)
                        if self.Chain(reserve, None, None, None, 0, c, None, deepth+1, constraints):
                            return True
                        reserve.pop()
                    else:
                        if self.Chain(reserve, reg, val, semantic.regs[target].getRegs(), cat, prev, c, deepth+1, constraints):
                            return True

        # checks condition based if needed
        if cat == 6 or cat == 5:
            if target in self.categories.keys()  and 5 in self.categories[target].keys():
                for semantic in self.categories[target][5]:
                    c = None
                    if nex is not None:
                        c = deepcopy(nex)
                        c.chain(semantic)
                    else:
                        c = deepcopy(semantic)
                    c.chain(prev)
                    print "checking gadget that set based on condition", c.regs[target]
                    if self.CheckRegsSat({reg:c.regs[reg]}, {reg:val}, c):
                        c.regs[reg] = val
                        reserve.append(reg)
                        if self.Chain(reserve, None, None, None, 0, c, None, deepth+1, constraints):
                            return True
                        reserve.pop()
                    else:
                        if self.Chain(reserve, reg, val, semantic.regs[target].getCondition().getRegs(), cat, prev, c, deepth+1):
                            return True
        # TODO checks Mem + Regs
        targets.insert(0, target)
        return False

    def AddToCat(self, reg, val, semantic):
        if reg not in self.categories.keys():
            self.categories.update({reg:{}})
        if val.getCategory() not in self.categories[reg].keys():
            self.categories[reg].update({val.getCategory():[]})
        self.categories[reg][val.getCategory()].append(semantic)

    def ChainRetGadget(self, reserve, sip, prev, nex, deepth):
        # sip must be a mem location, make sure this mem determined only by esp
        if deepth > self.deepth:
            return None
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
                        return c
                        # TODO, we can return after find one perfect ret gadget
            if reg in self.categories.keys() and 3 in self.categories[reg].keys():
                for semantic in self.categories[reg][3]:
                    if semantic.regs[reg].isControl():
                        c = deepcopy(nex)
                        c.chain(semantic)
                        c.binding(prev)
                        return c

        elif sip.left.getCategory() == 2:
            regs = sip.left.getRegs()
            for reg in regs:
                # one reg is esp, others are constant, TODO
                pass

        elif sip.left.getCategory() == 3:
            if sip.left.isControl():
                # if mem location is from esp
                nex.binding(prev)
                return nex
            else:
                # otherwise, chain another mem location gadget
                return self.ChainRetGadget(reserve, sip.left.left, prev, nex, deepth+1)
        return None 

    def ChainCondGadget(self, targets, nex, deepth):
        if deepth > self.deepth:
            return None
        reg = targets.pop(0)
        if len(targets) == 0:
            if reg in self.categories.keys() and 0 in self.categories[reg].keys():
                for semantic in self.categories[reg][0]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    if ((c.regs["sip"].getCondition().getCategory() < 3 and is_true(self.Compare(c.regs["sip"].getCondition())))
                            or c.regs["sip"].getCondition().isControl()):
                        c.regs.update({"sip":c.regs["sip"].meetCondition()})
                        return c 

            if reg in self.categories.keys() and 1 in self.categories[reg].keys():
                for semantic in self.categories[reg][1]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    if ((c.regs["sip"].getCondition().getCategory() < 3 and is_true(self.Compare(c.regs["sip"].getCondition())))
                            or c.regs["sip"].getCondition().isControl()):
                        c.regs.update({"sip":c.regs["sip"].meetCondition()})
                        return c 
        else:
            if reg in self.categories.keys() and 0 in self.categories[reg].keys():
                for semantic in self.categories[reg][0]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    return (self.ChainCondGadget(targets, c, deepth+1))

            if reg in self.categories.keys() and 1 in self.categories[reg].keys():
                for semantic in self.categories[reg][1]:
                    c = deepcopy(nex)
                    c.chain(semantic)
                    return (self.ChainCondGadget(targets, c, deepth+1))
        targets.append(reg)
        return None 

    def Category(self):
        cond = []
        rets = []
        for semantic in self.semantics:
            if semantic.regs["sip"].isControl():
                # return address is somewhere in esp
                for reg, val in semantic.regs.items():
                    if reg != "sip" and reg != "ssp" and reg not in self.z3Regs:
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
            # fix gadget with condition here
            # if the mem location can't be control, abandon this
            if len(semantic.regs["sip"].meetCondition().getRegs()) == 0:
                continue
            arr = self.ChainCondGadget(semantic.regs["sip"].getCondition().getRegs(), semantic, 0)
            if arr is not None:
                print "for cond gadget fixed", arr.getAddress()
                rets.append(arr)
        print "extend cond gadgets done"
        for semantic in rets:
            fixed = [semantic]
            if not semantic.regs["sip"].isControl():
                jop = self.ChainRetGadget([], semantic.regs["sip"], None, semantic, 0)
            if jop is not None:
                for reg, val in jop.regs.items():
                    if not reg in self.z3Regs:
                        self.mems.append(jop)
                        continue
                    self.AddToCat(reg, val, jop)
        print "extend ret gadgets done"

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
                    #print s
