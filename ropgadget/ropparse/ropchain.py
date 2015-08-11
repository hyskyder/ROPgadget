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
import time
import sys
import os.path
import logging

class ROPChain:
    def __init__(self, binary, gadgets, opt, deepth = 0):
        self.binary = binary
        # gadgets seperate into [ ROP, COP/JOP ]
        # ROP and COP/JOP are categories as { reg : { cat : [] } } 
        self.rop = [{}, {}]
        # register dependency graph, { reg: { reg : [] } }
        self.dependency = [{}, {}]
        # gadgets that should be discarded
        self.aba = []
        # gadgets that read undefined mem, should be careful
        self.readMem = {}
        # gadgets that write to mem { mem: [] }
        self.writeMem = []
        # result
        self.chained = []
        # hashmap ( addr ==> gadget )
        self.semantics = {}
        # search deepth
        self.deepth = deepth
        # number of gadgets chains before return
        self.default = 5
        # z3 solver
        self.solver = Solver()
        # z3 Regs
        self.z3Regs = {}
        self.gadgets = gadgets
        logging.basicConfig(level=logging.DEBUG)

        if self.binary is not None and self.binary.getArch() == CS_ARCH_X86:
            self.parser = ROPParserX86(self.gadgets, self.binary.getArchMode())
            semantics = self.parser.parse()
            for s in semantics:
                self.semantics.update({s.getAddress()[0]:s})
            if self.binary.getArchMode() == CS_MODE_32:
                Exp.defaultLength = 32
                self.z3Mem = Array('Mem', BitVecSort(32), BitVecSort(8))
                self.sp = "esp"
                self.ip = "eip"
                for reg in X86.regs32:
                    ref = BitVec(reg, 32)
                    self.z3Regs.update({reg:ref})
            else:
                Exp.defaultLength = 64
                self.z3Mem = Array('Mem', BitVecSort(64), BitVecSort(8))
                self.sp = "rsp"
                self.ip = "rip"
                for reg in X86.regs64:
                    ref = BitVec(reg, 64)
                    self.z3Regs.update({reg:ref})
            for reg in X86.FLAG:
                ref = BitVec(reg, 1)
                self.z3Regs.update({reg:ref})
        self.Category()

    def timing(f):
        def wrap(*args):
            time1 = time.time()
            ret = f(*args)
            time2 = time.time()
            print '%s function took %0.3f s' % (f.func_name, (time2-time1)*1.0)
            return ret
        return wrap

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

    def Select(self, size, i):
        if size == 8:
            return Select(self.z3Mem, i)
        elif size == 16:
            return Concat(self.Select(8, i + 1), self.Select(8, i))
        elif size == 32:
            return Concat(self.Select(16, i + 2), self.Select(16, i))
        elif size == 64:
            return Concat(self.Select(32, i + 4), self.Select(32, i))

    def Convert(self, exp):
        if not isinstance(exp.left, Exp):
            if exp.left in self.z3Regs.keys():
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
                    elif exp.op == '*':
                        return self.Select(exp.length, self.Convert(exp.left))
                    elif exp.op == '&':
                        # in this case, exp.left must be mem
                        return self.Convert(exp.left.left)
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
                right = ZeroExt(left.size() - right.size(), right)
                # bin exp, e.g. op1 + op2 + CF
                if exp.op == '+':
                    return Or((self.Carry(exp.left), Extract(size - 1, size - 1, left + right)) == 1)
                if exp.op == '-':
                    return Or((self.Carry(exp.left), Extract(size - 1, size - 1, left - right)) == 1)
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
                return "unsat" 
            #print semantic.regs[k]
            try:
                exp = self.Compare(regs[k], targets[k])
            except:
                print regs[k].showLength(regs[k])
                self.printGadgets(semantic.getAddress())
                return "unsat"
            if is_true(exp):
                return "true"
            if targets[k].getCategory() != 0:
                return "sat"
            self.solver.push()
            self.solver.add(exp)
            sat = str(self.solver.check())
            self.solver.pop()
            return sat
        return True

    def Core(self):
        while True:
            print "================================================\n"
            string = raw_input("Please enter command or specify the status of registers:")
            if string.split()[0] == "set":
                if string.split()[1] == "length":
                    self.deepth = int(string.split()[2])
                    print "set searching deepth to ", self.deepth
                elif string.split()[1] == "number":
                    self.default = int(string.split()[2])
                    print "set wanted gadget number to ", self.default
                continue
            elif string.split()[0] == "addr":
                if "0x" in string.split()[1]:
                    addr = (string.split()[1].lower())
                else:
                    addr = (hex(int(string.split()[1])))
                if not addr in self.parser.addrs.keys():
                    print "gadget of this address doesn't exist"
                else:
                    self.printGadget(addr)
                continue
            elif string == "help":
                print "usage: "
                print "  set length <integer>\t\t\tMaximum length of gadgets chain"
                print "  set number <integer>\t\t\tDesired number of gadgets chain before stop searching"
                print "  addr <hexaddr>\t\t\tPrint semantic and instructions of gadget at this address"
                print "  print cop\t\t\tPrint semantic and instructions of all COP/JOP gadgets"
                print "  print mem\t\t\tPrint semantic and instructions of all gadgets that read/write memory"
                print "  print <register>\t\t\tPrint semantic and instructions of all gadgets that modify this register"
                print "  search <register> <expression>\t\t\tSearching gadgets chain that set register to expression"
                print "  search <register> stack\t\t\tSearching gadgets chains that pop value from stack to this register"
                print "  search mem <register>\t\t\tSearching gadgets chains that write to memory address of this register"
                print "  quit \t\t\tQuit"
                print ""
                print "examples:"
                print "  "
                continue
            elif string == "quit":
                break
            elif string.split()[0] == "print" or string.split()[0] == "p":
                reg = string.split()[1]
                continue
            elif string.split()[0] == "search":
                regs = {}
                reg = string.split()[1] 
                tokens = string.split()[2:]
                if reg == "mem":
                    val = tokens[0]
                elif len(tokens) == 0:
                    val = None
                elif len(tokens) == 1 and tokens[0] == "stack":
                    val = "stack"
                else:
                    val = Exp.parseExp(tokens)
                    if not isinstance(val, Exp):
                        val = Exp(val)
                    val.length = Exp.defaultLength
                regs.update({reg:val})
                self.start(regs)
            else:
                print "what are you doing........"
                continue
    @timing
    def start(self, regs):
        self.chained = []
        before = []
        after = []
        for reg, val in regs.items():
            if reg == "mem":
                self.SearchWriteMem(set(), val[0], val[1], before, after, self.chained)
            elif val == "stack":
                self.SearchStack(set(), reg, before, after, self.chained)
            elif val.getCategory() == 0:
                self.SearchConstant(set(), reg, val.left, before, after, self.chained)
            elif val.getCategory() == 1:
                self.SearchReg(set(), reg, self.Convert(val), before, after, self.chained)
            elif val.getCategory() == 2:
                self.SearchRegs(set(), reg, val, before, after, self.chained)
            elif val.getCategory() == 3:
                self.SearchReadMem(set(), reg, val, before, after, self.chained)
            else:
                print "invalid expression"
                return self.chained

        for each in self.chained:
            self.printGadgets(each)
        return self.chained

    def printGadgets(self, addrs):
        for addr in addrs:
            self.printGadget(addr)

    def printGadget(self, addr):
        print addr
        print self.parser.addrs[addr]
        print self.semantics[addr]

    def CheckSat(self, val1, val2):
        f1 = self.Convert(val1)
        self.solver.reset()
        self.solver.add(f1 == val2)
        if str(self.solver.check()) == "sat":
            return True
        return False

    def FindConstant(self, reserve, reg):
        number = set()
        constants = []
        if reg in self.rop[0].keys():
            if 0 in self.rop[0][reg].keys():
                for semantic in self.rop[0][reg][0]:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    val = semantic.regs[reg]
                    if int(str(val)) not in number:
                        number.add(int(str(val)))
                        constants.append(semantic)
        return constants

    def SearchStack(self, reserve, reg, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        for rop in self.rop:
            if reg in rop.keys():
                if 3 in rop[reg].keys():
                    for semantic in rop[reg][3]:
                        if self.Overlap(reserve, semantic.regs):
                            continue
                        if not semantic.regs[self.ip].isControl():
                            # COP/JOP TODO
                            pass
                            '''
                            reserve.add(reg)
                            semantic = self.ChainRetGadget(reserve, semantic.regs["sip"], None, semantic, deepth+1)
                            reserve.remove(reg)
                            if semantic is None:
                                continue
                            '''
                        if semantic.regs[reg].isControl():
                            # done
                            temp = semantic.getAddress()
                            temp.extend(after)
                            before.extend(temp)
                            chains.append(temp)
                            return len(chains) >= self.default
                        else:
                            # map the address to esp,TODO
                            pass

        if reg in self.dependency[0].keys():
            for k, v in self.dependency[0].items():
                for semantic in v:
                    if self.Overlap(reserve, semantic.regs):
                        continue
                    temp = semantic.getAddress()
                    temp.extend(after)
                    if self.SearchStack(self, reserve, k, before, after, chains):
                        return True
            '''
            for k, v in self.dependency[1].items():
                for semantic in v:
                    if self.Overlap(reserve, semantic.regs):
                        continue
            '''

    def SearchConstant(self, reserve, reg, desired, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        indent = (len(before) + len(after)) * "\t"
        logging.debug(indent + "constant search: " + str(reg) + " => "+ str(desired))
        for rop in self.rop:
            if reg in rop.keys():
                if 0 in rop[reg].keys():
                    for semantic in rop[reg][0]:
                        if self.Overlap(reserve, semantic.regs):
                            continue
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                        if str(semantic.regs[reg]) == str(desired):
                            if not semantic.regs[self.ip].isControl():
                                # COP/JOP gadgets, TODO
                                continue 
                                '''
                                if reg in semantic.regs["sip"].getRegs() or desired in semantic.regs["sip"].getRegs():
                                    continue
                                reserve.add(reg)
                                semantic = self.ChainRetGadget(reserve, semantic.regs["sip"], None, semantic, deepth+1)
                                reserve.remove(reg)
                                if semantic is None:
                                    continue
                                '''
                            temp = deepcopy(before)
                            temp.extend(semantic.getAddress())
                            temp.extend(after)
                            chains.append(temp)
                            logging.debug(indent + reg + " => " + str(desired) + " done " + ", ".join(temp))
                            if len(chains) >= self.default:
                                return True
                if 1 in rop[reg].keys():
                    for semantic in rop[reg][1]:
                        if self.Overlap(reserve, semantic.regs):
                            continue
                        nreg = semantic.regs[reg].getRegs()[0]
                        if nreg == self.sp:
                            continue
                        if not semantic.regs[self.ip].isControl():
                            # COP/JOP gadgets, TODO
                            continue 
                            '''
                            if reg in semantic.regs[self.ip].getRegs() or desired in semantic.regs[self.ip].getRegs():
                                continue
                            reserve.add(nreg)
                            semantic = self.ChainRetGadget(reserve, semantic.regs["sip"], None, semantic, deepth+1)
                            reserve.remove(nreg)
                            if semantic is None:
                                continue
                            '''
                        if not self.CheckSat(semantic.regs[reg], desired):
                            logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + " unsat")
                            continue
                        res = self.solver.model()
                        ndesired = res[self.z3Regs[nreg]]
                        temp = semantic.getAddress()
                        temp.extend(after)
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + " sat")
                        if self.SearchConstant(reserve, nreg, int(str(ndesired)), before, temp, chains):
                            return True

                if 2 in rop[reg].keys():
                    for semantic in rop[reg][2]:
                        continue
                    regs = semantic.regs[reg].getRegs()
                    logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + " sat")
                    constants = []
                    for i in range(len(regs) - 1):
                        # set other regs to constant, and search regs[i] to satisfies this
                        constants.append(self.FindConstant(reserve, regs[i]))
                        reserve.add(regs[i])

                    temp = semantic.getAddress()
                    temp.extend(after)
                    coms = [(self.Convert(semantic.regs[reg]) == desired)]
                    if self.Combination(reserve, constants, 0, coms, semantic.regs[reg], regs, before, temp, chains):
                        return True

    def Combination(self, reserve, constants, index, coms, val, regs, before, after, chains):
        indent = (len(before) + len(after)) * "\t"
        if index == len(constants):
            # map regs[j] to new val in z3
            self.solver.reset()
            for com in coms:
                self.solver.add(com)
            if not str(self.solver.check()) == "sat":
                logging.debug(indent + " unsat")
                return False
            res = self.solver.model()
            ndesired = res[self.z3Regs[regs[index]]]
            logging.debug(indent + str(res) + " sat")
            if self.SearchConstant(reserve, regs[index], int(str(ndesired)), before, after, chains):
                return True
            return False
        if len(constants[index]) == 0:
            return False

        for constant in constants[index]:
            before.extend(constant.getAddress())
            coms.append(self.z3Regs[regs[index]] == self.Convert(constant.regs[regs[index]]))
            logging.debug(indent + regs[index] + " => " + str(constant.regs[regs[index]]) + " sat")
            if self.Combination(reserve, constants, index+1, coms, val, regs, before, after, chains):
                return True
            before.pop()
            coms.pop()

    def SearchRegs(self, reserve, reg, desired, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        
        for rop in self.dependency:
            if reg in rop.keys():
                if 1 in rop[reg].keys():
                    for semantic in rop[reg][1]:
                        if self.Overlap(reserve, semantic.regs):
                            continue
                        if not semantic.regs[self.ip].isControl():
                            #TODO
                            continue 

                if 2 in rop[reg].keys():
                    for semantic in rop[reg][2]:
                        if self.Overlap(reserve, semantic.regs):
                            continue
                        if not semantic.regs[self.ip].isControl():
                            #TODO
                            continue 
                        if is_true(simplify(desired == self.Convert(semantic.regs[reg]))):
                            temp = deepcopy(before)
                            temp.extend(semantic.getAddress())
                            temp.extend(after)
                            chains.append(temp)
                            if len(chains) >= self.default:
                                return True
                        else:
                            regs = semantic.regs[reg].getRegs()


    def SearchReg(self, reserve, reg, desired, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False

        indent = (len(before) + len(after)) * "\t"
        regs = str(desired).split()
        for i in regs:
            if i in self.z3Regs.keys():
                target = i 

        logging.debug(indent + "reg search: " + str(reg) + " => "+ str(desired) + ", " + target)
        for rop in self.rop:
            if reg in rop.keys():
                if 1 in rop[reg].keys():
                    for semantic in rop[reg][1]:
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]) )
                        if self.Overlap(reserve, semantic.regs):
                            continue
                        if not semantic.regs[self.ip].isControl():
                            # TODO, COP
                            continue
                            '''
                            if reg in semantic.regs["sip"].getRegs() or desired in semantic.regs["sip"].getRegs():
                                continue
                            reserve.add(desired)
                            semantic = self.ChainRetGadget(reserve, semantic.regs["sip"], None, semantic, deepth+1)
                            reserve.remove(desired)
                            if semantic is None:
                                continue
                            '''
                        if is_true(simplify(desired == self.Convert(semantic.regs[reg]))):
                            temp = deepcopy(before)
                            temp.extend(semantic.getAddress())
                            temp.extend(after)
                            chains.append(temp)
                            if len(chains) >= self.default:
                                return True
                        else:
                            exp = simplify(desired == self.Convert(semantic.regs[reg]))
                            ntarget = semantic.regs[reg].getRegs()[0]
                            ndesired = self.reduct(exp, ntarget)
                            temp = semantic.getAddress()
                            temp.extend(after)
                            logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                            if self.SearchReg(reserve, ntarget, ndesired, before, after, chains):
                                return True
                if 2 in rop[reg].keys():
                    for semantic in rop[reg][2]:
                            if self.Overlap(reserve, semantic.regs):
                                continue
                            regs = semantic.regs[reg].getRegs()
                            if len(regs) > 2:
                                # TODO, multiple regs 
                                continue
                            elif target in regs:
                                ntarget = regs[0] if target == regs[1] else regs[1]
                                self.solver.push()
                                self.solver.add(ForAll(self.z3Regs[target], desired == self.Convert(semantic.regs[reg])))
                                sat = self.solver.check()
                                if not str(sat) == "sat":
                                    continue
                                ndesired = self.solver.model()[self.z3Regs[ntarget]]
                                self.solver.pop()
                                temp = semantic.getAddress()
                                temp.extend(after)
                                logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + ", " + ntarget + ": " + str(ndesired))
                                if self.SearchConstant(reserve, ntarget, ndesired, before, temp, chains):
                                    return True
                            else:
                                temp = semantic.getAddress()
                                temp.extend(after)
                                exp = simplify(desired == self.Convert(semantic.regs[reg]))
                                logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                                indent += "\t"
                                for i in regs:
                                    for semantic in self.dependency[0][i][target]:
                                        sexp = substitute(exp, (self.z3Regs[i], semantic.regs[i]))
                                        ntarget = regs[0] if target == regs[1] else regs[1]
                                        self.solver.push()
                                        self.solver.add(ForAll(self.z3Regs[reg], desired == self.Convert(semantic.regs[reg])))
                                        ndesired = self.solver.model()[self.z3Regs[ntarget]]
                                        self.solver.pop()
                                        temp1 = semantic.getAddress()
                                        temp1.extend(temp)
                                        if self.SearchConstant(reserve, ntarget, ndesired, before, temp1, chains):
                                            return True

    def SearchWriteMem(self, reserve, reg, addrs, chains, deepth):
        for semantic in self.undefinedMem:
            if self.Overlap(reserve, semantic.regs):
                continue

            for k, v in semantic.regs.items():
                if k not in self.z3Regs.keys():
                    if len(k) != 7:
                        continue
                    use = k.split()[1]
                    if not semantic.regs["sip"].isControl():
                        if use in semantic.regs["sip"].getRegs() or reg in semantic.regs["sip"].getRegs():
                            continue
                        reserve.add(use)
                        c = self.ChainRetGadget(reserve, semantic.regs["sip"], None, semantic, deepth+1)
                        reserve.remove(use)
                        if c is None:
                            continue
                    if use == reg:
                        chains.append(semantic.getAddress())
                        return True
                    if self.SearchReg(set(), use, reg, semantic.getAddress(), chains, deepth+1):
                        return True
        
        '''
        self.chained = set()
        self.Chain([], None, None, [], 6, None, None, 0, regs)
        if len(self.chained) <= 1:
            print  len(self.chained), "unique gadget found"
        else:
            print  len(self.chained), "unique gadgets found"
        for s in self.chained:
            self.printGadgets(s.getAddress())
            for k, v in s.regs.items():
                print k, " ===> ", v

        return self.chained
        '''

    def Overlap(self, reserve, regs):
        for reg in regs.keys():
            if reg in reserve:
                return True
        return False

    def addToCat(self, cat, reg, val, semantic):
        if reg not in cat.keys():
            cat.update({reg:{}})
        if val not in cat[reg].keys():
            cat[reg].update({val:[]})
        cat[reg][val].append(semantic)

    def Category(self):
        cond = []
        for addr, semantic in self.semantics.items():
            if semantic.touchUndefinedMem:
                for reg, val in semantic.regs.items():
                    if reg not in self.z3Regs.keys():
                        # write to mem
                        self.writeMem.append(semantic)
                    else:
                        # read from mem
                        self.addToCat(self.readMem, reg, val.getCategory(), semantic)
                continue

            logging.debug(str(addr) + str(semantic.regs[self.ip]))
            if semantic.regs[self.ip].getCategory() == 0:
                # constant return address, discard
                self.aba.append(semantic)
                continue
            elif not semantic.regs[self.ip].isControl():
                # COP/JOP gadgets
                for reg, val in semantic.regs.items():
                    self.addToCat(self.rop[1], reg, val.getCategory(), semantic)
                    # build register dependency graph
                    '''
                    if val.getCategory() == 1 and self.checkDependency(reg, val.getRegs()[0], val):
                        self.addToCat(self.dependency[1], reg, val.getRegs()[0], semantic)
                    elif val.getCategory() == 2:
                        for target in val.getRegs():
                            if self.checkDependency(reg, target, val):
                                self.addToCat(self.dependency[0], reg, target, semantic)
                    '''
                continue
            elif semantic.regs[self.ip].isCond():
                # conditional jmp 
                cond.append(semantic)
                continue
            else:
                # ROP gadgets
                for reg, val in semantic.regs.items():
                    # build register dependency graph
                    self.addToCat(self.rop[0], reg, val.getCategory(), semantic)
                    logging.debug("category: " + reg + " => " + str(val.getCategory()))
                    if val.getCategory() == 1 and self.checkDependency(reg, val.getRegs()[0], val):
                        logging.debug("register dep: " + str(reg) + " => " + str(val))
                        self.addToCat(self.dependency[0], reg, val.getRegs()[0], semantic)
                    elif val.getCategory() == 2:
                        for target in val.getRegs():
                            if self.checkDependency(reg, target, val):
                                self.addToCat(self.dependency[1], reg, target, semantic)

    def checkDependency(self, reg, target, val):
        # return True if there is register dependency from reg to target register 
        # Ex eax = ebx + 1  eax ==> ebx, eax = ebx & 1 there is no such dependency
        #    eax = ebx - ecx, eax depends on ebx True, eax depends on ecx True
        #    eax = ebx ^ ecx, eax depends on ebx True, eax depends on ecx True
        #    eax = ebx & ecx, eax depends on ebx False, eax depends on ecx False 
        if len(reg) == 2 or len(target) == 2:
            return False
        if val.getCategory() == 1:
            exp = self.Convert(val)

            exp1 = substitute(exp, (self.z3Regs[target], self.z3Regs[reg]))
            exp2 = substitute(exp, (self.z3Regs[target], -self.z3Regs[reg]))

            res1 = simplify(exp1 == self.z3Regs[reg])
            res2 = simplify(exp2 == self.z3Regs[reg])
            if is_true(res1) or is_false(res1) or is_true(res2) or is_false(res2):
                return True
            return False
        else:
            exp = self.Convert(val)
            self.solver.push()
            self.solver.add(ForAll(self.z3Regs[target], exp == self.z3Regs[target]))
            sat = self.solver.check()
            if str(sat) == "sat":
                ndesired = self.solver.model()
                logging.debug("register dep: " + str(reg) + " => " + str(target) + ", " + str(val) + str(ndesired))
                self.solver.pop()
                return True
            else:
                self.solver.pop()
                return False

    def reduct(self, exp, target):
        childrens = exp.children()
        rexp = childrens[1]
        lexp = childrens[0]
        for s in lexp.children():
            if not str(s).contains(target):
                rexp = rexp - s
        logging.debug("reduct: " + str(target) + ", "+ str(exp) + " => " + str(rexp))
        return rexp

