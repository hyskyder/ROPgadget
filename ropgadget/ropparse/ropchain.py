#!/usr/bin/env python2
from arch.parserx86 import ROPParserX86
from arch.parserx86 import X86
from arch.semantic import Semantic
from arch.expression import Exp
from capstone import *
from copy import deepcopy
from z3.z3 import *
import time
import logging


class ROPChain:
    def __init__(self, binary, gadgets, opt, deepth=0):
        self.binary = binary
        # gadgets is categories as { reg : { cat : [] } }
        self.rop = {}
        # register dependency graph, { reg: { reg : [] } }
        self.dependency = {}
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
        # reserved register
        self.reserve = set()
        # search deepth
        self.deepth = deepth
        # number of gadgets chains before return
        self.default = 5
        # z3 solver
        self.solver = None
        # z3 Regs
        self.z3Regs = {}
        self.gadgets = gadgets
        logging.basicConfig(level=logging.ERROR)

        if self.binary is not None and self.binary.getArch() == CS_ARCH_X86:
            self.parser = ROPParserX86(self.gadgets, self.binary.getArchMode())
            semantics = self.parser.parse()
            for s in semantics:
                self.semantics.update({s.getAddress()[0]: s})
            if self.binary.getArchMode() == CS_MODE_32:
                Exp.defaultLength = 32
                self.z3Mem = Array('Mem', BitVecSort(32), BitVecSort(8))
                self.sp = "esp"
                self.ip = "eip"
                for reg in X86.regs32:
                    ref = BitVec(reg, 32)
                    self.z3Regs.update({reg: ref})
            else:
                Exp.defaultLength = 64
                self.z3Mem = Array('Mem', BitVecSort(64), BitVecSort(8))
                self.sp = "rsp"
                self.ip = "rip"
                for reg in X86.regs64:
                    ref = BitVec(reg, 64)
                    self.z3Regs.update({reg: ref})
            for reg in X86.FLAG:
                ref = BitVec(reg, 1)
                self.z3Regs.update({reg: ref})
        self.category()

    def timing(f):
        def wrap(*args):
            time1 = time.time()
            ret = f(*args)
            time2 = time.time()
            print 'Search took %0.3f s' % ((time2 - time1) * 1.0)
            return ret

        return wrap

    def compare(self, left, right=None):
        le = self.convert(left)
        if right is None:
            return simplify(le)
        re = self.convert(right)

        if isinstance(le, int):
            le = BitVecVal(le, left.length)
        elif le.sort() == IntSort():
            le = BitVecRef(Z3_mk_int2bv(le.ctx_ref(), left.length, le.as_ast()), le.ctx)

        if isinstance(re, int):
            re = BitVecVal(re, right.length)
        elif re.sort() == IntSort():
            re = BitVecRef(Z3_mk_int2bv(re.ctx_ref(), right.length, re.as_ast()), re.ctx)
        return simplify(le == re)

    def select(self, size, i):
        if size == 8:
            return Select(self.z3Mem, i)
        elif size == 16:
            return Concat(self.select(8, i + 1), self.select(8, i))
        elif size == 32:
            return Concat(self.select(16, i + 2), self.select(16, i))
        elif size == 64:
            return Concat(self.select(32, i + 4), self.select(32, i))

    def convert(self, exp):
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
            return If(self.convert(exp.condition), self.convert(exp.left), self.convert(exp.right))
        else:
            if exp.right is not None:
                left = self.convert(exp.left)
                right = self.convert(exp.right)
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
                    return Extract(right, left, self.convert(exp.condition))
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
                        if is_bool(self.convert(exp.left)):
                            return Not(self.convert(exp.left))
                        return ~ self.convert(exp.left)
                    elif exp.op == '+':
                        return self.convert(exp.left)
                    elif exp.op == '-':
                        return -self.convert(exp.left)
                    elif exp.op == 'O':
                        return If(self.overflow(exp.left), BitVecVal(1, 1), BitVecVal(0,1))
                    elif exp.op == 'Z':
                        return If(self.convert(exp.left) == 0, BitVecVal(1, 1), BitVecVal(0,1))
                    elif exp.op == 'S':
                        return If(self.convert(exp.left) > 0, BitVecVal(1, 1), BitVecVal(0,1))
                    elif exp.op == 'C':
                        return If(self.carry(exp.left), BitVecVal(1, 1), BitVecVal(0,1))
                    elif exp.op == 'P':
                        return If(self.parity(self.convert(exp.left)) % 2 == 0, BitVecVal(1, 1), BitVecVal(0,1))
                    elif exp.op == 'A':
                        return If(self.adjust(self.convert(exp.left)), BitVecVal(1, 1), BitVecVal(0,1))
                    elif exp.op == '*':
                        return self.select(exp.length, self.convert(exp.left))
                    elif exp.op == '&':
                        # in this case, exp.left must be mem
                        return self.convert(exp.left.left)
                return self.convert(exp.left)

    def adjust(self, exp):
        # TODO
        return True

    def overflow(self, exp):
        if exp.right is None:
            # unary exp, i.e. -op
            left = self.convert(exp.left)
            return Extract(exp.size, exp.size, left) == Extract(exp.size, exp.size, -left)
        else:
            left = self.convert(exp.left)
            right = self.convert(exp.right)

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
                    return Or((self.overflow(exp.left), And(
                        Extract(exp.length - 1, exp.length - 1, left) == Extract(exp.length - 1, exp.length - 1, right),
                        Extract(exp.length - 1, exp.length - 1, left + right) != Extract(exp.length - 1, exp.length - 1,
                                                                                         left))))
                if self.op == '-':
                    return Or((self.overflow(exp.left), And(
                        Extract(exp.length - 1, exp.length - 1, left) == Extract(exp.length - 1, exp.length - 1, right),
                        Extract(exp.length - 1, exp.length - 1, left - right) != Extract(exp.length - 1, exp.length - 1,
                                                                                         left))))
            else:
                # bin exp, e.g. op1 + op2
                if exp.op == '+':
                    return And(
                        Extract(exp.length - 1, exp.length - 1, left) == Extract(exp.length - 1, exp.length - 1, right),
                        Extract(exp.length - 1, exp.length - 1, left + right) != Extract(exp.length - 1, exp.length - 1,
                                                                                         left))
                elif exp.op == '-':
                    return And(
                        Extract(exp.length - 1, exp.length - 1, left) != Extract(exp.length - 1, exp.length - 1, right),
                        Extract(exp.length - 1, exp.length - 1, left - right) != Extract(exp.length - 1, exp.length - 1,
                                                                                         left))

    def carry(self, exp):
        if exp.right is None:
            # unary exp, i.e. - op
            return self.convert(exp) != 0
        else:
            left = self.convert(exp.left)
            right = self.convert(exp.right)
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
                    return Or((self.carry(exp.left), Extract(size - 1, size - 1, left + right)) == 1)
                if exp.op == '-':
                    return Or((self.carry(exp.left), Extract(size - 1, size - 1, left - right)) == 1)
            else:
                # bin exp, e.g. op1 + op2
                if exp.op == '+':
                    return (Extract(exp.length - 1, exp.length - 1, left + right) == 1)
                elif exp.op == '-':
                    return (Extract(exp.length - 1, exp.length - 1, left - right) == 1)

    def parity(self, reg):
        count = 0
        for i in range(reg.size()):
            if Extract(i, i, reg) == 1:
                count = count + 1
        return count

    def help(self):
        print "usage: "
        print "  set length <integer>\t\t\tMaximum length of gadgets chain (defualt 1, should not be larger than 3)"
        print "  set number <integer>\t\t\tDesired number of gadgets chain before stop searching (default 5)"
        print "  addr <hexaddr>\t\t\tPrint semantic and instructions of gadget at this address"
        print "  search <register> <expression>\tSearching gadgets chain that set register to arithmetic expression"
        print "  search <register> stack\t\tSearching gadgets chains that pop value from stack to this register"
        print "  search mem <address> <register>\tSearching gadgets chains that write to memory address with this register"
        print "  reserve <register> <register>\t\tReserve registers for searching next time (reset automatically after each search)"
        print "  print \t\t\tPrint gadgets (??)"
        print "  quit \t\t\t\t\tQuit"
        print ""
        print "examples:"
        print "  search eax 4"
        print "  search eax eax - 4"
        print "  search eax eax + ebx"
        print "  search eax stack"
        print "  search mem eax ebx"

    def core(self):
        #self.help()
        print "[Hello] ROPChain: input 'help' to get help."
        while True:
            print "================================================\n"
            cmd = raw_input("Please enter command (help for usage):")
            res=process_cmd(cmd)
            if (res): break


    def process_cmd(self,string):
        if string.split()[0] == "set":
            if string.split()[1] == "length":
                self.deepth = int(string.split()[2])
                print "set searching deepth to ", self.deepth
            elif string.split()[1] == "number":
                self.default = int(string.split()[2])
                print "set wanted gadget number to ", self.default
            return 0
        elif string.split()[0] == "addr":
            if "0x" in string.split()[1]:
                addr = (string.split()[1].lower())
            else:
                addr = (hex(int(string.split()[1])))
            if not addr in self.parser.addrs.keys():
                print "gadget of this address doesn't exist"
            else:
                self.printGadget(addr)
            return 0
        elif string == "help":
            self.help()
            return 0
        elif string.split()[0] == "reserve":
            self.reserve = set(string.split()[1:])
            return 0
        elif string == "quit":
            return 1
        elif string.split()[0] == "print" or string.split()[0] == "p":
            reg = string.split()[1]
            if reg == "mem":
                print "[Warn] Unimplemented yet."
                return 0
            elif reg == "cop":
                print "[Warn] Unimplemented yet."
                return 0
            else:
                if reg in self.rop.keys():
                    for cat in self.rop[reg].keys():
                        for s in self.rop[reg][cat]:
                            print s.getAddress()[0], reg, " => ", str(s.regs[reg])

        elif string.split()[0] == "search":
            regs = {}
            reg = string.split()[1]
            tokens = string.split()[2:]
            if reg == "mem":
                val = tokens
            elif len(tokens) == 0:
                val = None
            elif len(tokens) == 1 and tokens[0] == "stack":
                val = "stack"
            else:
                val = Exp.parseExp(tokens)
                if not isinstance(val, Exp):
                    val = Exp(val)
                val.length = Exp.defaultLength
            regs.update({reg: val})
            self.start(regs)
            self.reserve.clear()
        else:
            print "[ERROR] Unrecognized Command."
            self.help()
            return 0
        return 0

    @timing
    def start(self, regs):
        self.chained = []
        before = []
        after = []
        for reg, val in regs.items():
            if reg == "mem":
                self.searchWriteMem(self.reserve, val[0], val[1], before, after, self.chained)
            elif val == "stack":
                self.searchStack(self.reserve, reg, before, after, self.chained)
            elif val.getCategory() == 0:
                self.searchConstant(self.reserve, reg, val.left, before, after, self.chained)
            elif val.getCategory() == 1:
                self.searchReg(self.reserve, reg, self.convert(val), before, after, self.chained)
            elif val.getCategory() == 2:
                self.searchRegs(self.reserve, reg, self.convert(val), before, after, self.chained)
            elif val.getCategory() == 3:
                self.searchReadMem(self.reserve, reg, val, before, after, self.chained)
            else:
                print "invalid expression"
                return self.chained
        print "[in ROPChain.start()]---------------"
        if len(self.chained) < 2:
            print len(self.chained), " gadget chain found"
        else:
            print len(self.chained), " gadget chains found"

        for i, each in enumerate(self.chained):
            print "+ Gadget chain No. ", i, ":"
            self.printGadgets(each)
        return self.chained

    def printGadgets(self, addrs):
        for addr in addrs:
            self.printGadget(addr)

    def printGadget(self, addr):
        #print "addr=", addr
        print str(self.semantics[addr]) + ":"
        print self.parser.addrs[addr]
        

    def findConstant(self, reserve, reg):
        number = set()
        constants = []
        if reg in self.rop.keys():
            if 0 in self.rop[reg].keys():
                for semantic in self.rop[reg][0]:
                    if self.overlap(reserve, semantic.regs.keys()) or not semantic.regs[self.ip].isControl():
                        continue
                    val = semantic.regs[reg]
                    v = self.convert(val)
                    if str(v) not in number:
                        number.add(str(v))
                        constants.append(semantic)
        return constants

    def searchStack(self, reserve, reg, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        indent = (len(before) + len(after)) * "\t"
        logging.debug(indent + "stack search: " + str(reg))
        r = deepcopy(reserve)
        r.add(reg)
        if reg in self.rop.keys():
            if 3 in self.rop[reg].keys():
                for semantic in self.rop[reg][3]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    logging.debug(indent + "stack search done " + str(semantic.regs[reg]))
                    temp = self.addToChain(before, after, semantic, reg, self.deepth, r)
                    if temp is None:
                        continue
                    chains.append(temp)
                    if len(chains) >= self.default:
                        return True

        if reg in self.readMem.keys():
            if 3 in self.readMem[reg].keys():
                for semantic in self.readMem[reg][3]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    if semantic.regs[reg].isControl():
                        # done
                        logging.debug(indent + "stack search done " + str(semantic.regs[reg]))
                        temp = self.addToChain(before, after, semantic, regs, self.deepth, r)
                        if temp is None:
                            continue
                        chains.append(temp)
                        if len(chains) >= self.default:
                            return True
                    else:
                        # map the address to esp
                        logging.debug(indent + "stack search address: " + str(semantic.regs[reg]))
                        regs = semantic.regs[reg].getRegs()
                        if len(regs) > 1:
                            # TODO, multi regs
                            continue
                        temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), r)
                        if temp is None:
                            continue
                        if reg in self.dependency.keys() and self.sp in self.dependency[reg].keys():
                            for semantic in self.dependency[reg][self.sp]:
                                if self.overlap(reserve, semantic.regs.keys()):
                                    continue
                                temp = self.addToChain(before, temp, semantic, reg, self.deepth, r)
                                chains.append(temp)
                                if len(chains) >= self.default:
                                    return True

        if reg in self.dependency.keys():
            for k, v in self.dependency[reg].items():
                for semantic in v:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), r)
                    if temp is None:
                        continue
                    logging.debug(indent + reg + " => " + k + ", " + str(semantic.regs[reg]))
                    if self.searchStack(reserve, k, before, temp, chains):
                        return True

    def searchConstant(self, reserve, reg, desired, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        dup = set()
        indent = (len(before) + len(after)) * "\t"
        logging.debug(indent + "constant search: " + str(reg) + " => " + str(desired))
        if reg in self.rop.keys():
            if 0 in self.rop[reg].keys():
                for semantic in self.rop[reg][0]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                    if str(semantic.regs[reg]) == str(desired):
                        temp = self.addToChain(before, after, semantic, reg, self.deepth, reserve)
                        if temp is None:
                            continue
                        chains.append(temp)
                        logging.debug(indent + reg + " => " + str(desired) + " done " + ", ".join(temp))
                        if len(chains) >= self.default:
                            return True
            if len(before) + len(after) > self.deepth:
                return False
            if 1 in self.rop[reg].keys():
                for semantic in self.rop[reg][1]:
                    if self.overlap(reserve, semantic.regs.keys()) or str(semantic.regs[reg]) in dup:
                        continue
                    nreg = semantic.regs[reg].getRegs()[0]
                    if nreg == self.sp:
                        continue
                    self.solver = Solver()
                    self.solver.add(desired == self.convert(semantic.regs[reg]))
                    if not str(self.solver.check()) == "sat":
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + " unsat")
                        dup.add(semantic.regs[reg])
                        continue
                    res = self.solver.model()
                    ndesired = res[self.z3Regs[nreg]]
                    temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                    if temp is None:
                        continue
                    logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + " sat")
                    l = len(chains)
                    if self.searchConstant(reserve, nreg, int(str(ndesired)), before, temp, chains):
                        return True
                    if l == len(chains):
                        dup.add(str(semantic.regs[reg]))

            if len(before) + len(after) > self.deepth:
                return False
            if 2 in self.rop[reg].keys():
                for semantic in self.rop[reg][2]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    regs = semantic.regs[reg].getRegs()
                    if len(before) + len(after) + len(regs) >= self.deepth:
                        continue
                    logging.debug(indent + reg + " => " + str(semantic.regs[reg]) + " sat")
                    constants = []
                    nreserve = deepcopy(reserve)
                    for i in range(len(regs) - 1):
                        # set other regs to constant, and search regs[i] to satisfies this
                        constants.append(self.findConstant(reserve, regs[i]))
                        nreserve.add(regs[i])

                    temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                    if temp is None:
                        continue
                    coms = [(self.convert(semantic.regs[reg]) == desired)]
                    if self.combination(nreserve, constants, 0, coms, semantic.regs[reg], regs, before, temp,
                                        chains):
                        return True

    def combination(self, reserve, constants, index, coms, val, regs, before, after, chains):
        indent = (len(before) + len(after)) * "\t"
        if index == len(constants):
            # map regs[j] to new val in z3
            self.solver = Solver()
            for com in coms:
                self.solver.add(com)
            if not str(self.solver.check()) == "sat":
                logging.debug(indent + " unsat")
                return False
            res = self.solver.model()
            ndesired = res[self.z3Regs[regs[index]]]
            logging.debug(indent + str(res) + " sat")
            if self.searchConstant(reserve, regs[index], int(str(ndesired)), before, after, chains):
                return True
            return False
        if len(constants[index]) == 0:
            return False

        for constant in constants[index]:
            before.extend(constant.getAddress())
            coms.append(self.z3Regs[regs[index]] == self.convert(constant.regs[regs[index]]))
            logging.debug(indent + regs[index] + " => " + str(constant.regs[regs[index]]) + " sat")
            if self.combination(reserve, constants, index + 1, coms, val, regs, before, after, chains):
                return True
            before.pop()
            coms.pop()


    def searchRegs(self, reserve, reg, desired, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        indent = (len(before) + len(after)) * "\t"
        logging.debug(indent + "regs search: " + str(reg) + " => " + str(desired))
        if reg in self.rop.keys():
            if 1 in self.rop[reg].keys():
                for semantic in self.rop[reg][1]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    exp = simplify(desired == self.convert(semantic.regs[reg]))
                    ntarget = semantic.regs[reg].getRegs()[0]
                    ndesired = self.reduce(self.convert(semantic.regs[reg]), desired, ntarget)
                    if ndesired is None:
                        continue
                    temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                    if temp is None:
                        continue
                    logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                    if self.searchRegs(reserve, ntarget, ndesired, before, temp, chains):
                        return True

            if 2 in self.rop[reg].keys():
                for semantic in self.rop[reg][2]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    if is_true(simplify(desired == self.convert(semantic.regs[reg]))):
                        temp = self.addToChain(before, after, semantic, reg, self.deepth, reserve)
                        if temp is None:
                            continue
                        chains.append(temp)
                        if len(chains) >= self.default:
                            return True
                    else:
                        vregs = self.getRegs(desired)
                        kregs = semantic.regs[reg].getRegs()
                        if len(before) + len(after) + 1 >= self.deepth:
                            continue
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                        if len(kregs) > 2:
                            # For now, this method is designed for two registers expression
                            continue
                        exp = self.convert(semantic.regs[reg])
                        if self.overlap(kregs, vregs):
                            ntarget = kregs[0] if kregs[1] in vregs else kregs[0]
                            ndesired = self.reduce(exp, desired, ntarget)
                            if len(self.getRegs(ndesired)) == 1:
                                temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                                if temp is None:
                                    continue
                                if self.searchReg(reserve, ntarget, ndesired, before, temp, chains):
                                    return True
                        # eliminate one of regs to constant
                        for k in kregs:
                            for s in self.findConstant(reserve, k):
                                logging.debug(indent + "\t" + str(semantic.regs[reg]) + " sub: " + k + " => " + str(s.regs[k]))
                                ntarget = kregs[0] if k == kregs[1] else kregs[1]
                                #try:
                                if isinstance(s.regs[k].left, Exp):
                                    nexp = substitute(exp, (self.z3Regs[k], self.convert(s.regs[k])))
                                else:
                                    nexp = substitute(exp, (self.z3Regs[k], BitVecVal(s.regs[k].left, s.regs[k].length)))
                                #except:
                                #    print exp, k, self.convert(s.regs[k])
                                #    print s.regs[k].getCategory()
                                #    print "Unexpected error:", sys.exc_info()[0]
                                #    self.printGadgets(s.getAddress())
                                #    exit()
                                ndesired = self.reduce(nexp, desired, ntarget)
                                if ndesired is None:
                                    continue
                                nbefore = deepcopy(before)
                                nbefore.extend(s.getAddress())
                                nafter = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                                if nafter is None:
                                    continue
                                logging.debug(
                                    indent + "\t" + k + " => " + str(s.regs[k]) + ", " + ntarget + " == " + str(
                                        ndesired))
                                if self.searchRegs(reserve, ntarget, ndesired, nbefore, nafter, chains):
                                    return True
                        # based on the reg dep
                        for k in vregs:
                            if kregs[0] not in self.dependency.keys() or k not in self.dependency[kregs[0]].keys():
                                continue
                            for s in self.dependency[kregs[0]][k]:
                                ntarget = kregs[1]
                                logging.debug(indent + "\t" + kregs[0] + " => " + str(exp) + ", " + ntarget)
                                left = substitute(exp, (self.z3Regs[kregs[0]], BitVecVal(0, self.z3Regs[kregs[0]].size())))
                                right = substitute(exp, (self.z3Regs[ntarget], BitVecVal(0, self.z3Regs[ntarget].size())))
                                right = substitute(right,
                                                   (self.z3Regs[kregs[0]], self.convert(s.regs[kregs[0]])))
                                ndesired = self.reduce(left, desired - right, ntarget)
                                if ndesired is None:
                                    continue
                                logging.debug(indent + "\t" + kregs[0] + " => " + str(
                                    s.regs[kregs[0]]) + ", " + ntarget + " == " + str(ndesired))
                                tempb = deepcopy(before)
                                tempb.extend(s.getAddress())
                                tempa = semantic.getAddress()
                                tempa.extend(after)
                                if self.searchRegs(reserve, ntarget, ndesired, tempb, tempa, chains):
                                    return True

        return False

    def searchReg(self, reserve, reg, desired, before, after, chains):
        if len(before) + len(after) >= self.deepth:
            return False
        dup = set()
        indent = (len(before) + len(after)) * "\t"
        logging.debug(indent + "reg search: " + str(reg) + " => " + str(desired) + ", ")
        target = self.getRegs(desired)[0]

        if reg in self.rop.keys():
            if 1 in self.rop[reg].keys():
                for semantic in self.rop[reg][1]:
                    logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                    if self.overlap(reserve, semantic.regs.keys()) or str(semantic.regs[reg]) in dup:
                        continue
                    if is_true(simplify(desired == self.convert(semantic.regs[reg]))):
                        temp = self.addToChain(before, after, semantic, reg, self.deepth, reserve)
                        if temp is None:
                            continue
                        chains.append(temp)
                        if len(chains) >= self.default:
                            return True
                    else:
                        ntarget = semantic.regs[reg].getRegs()[0]
                        ndesired = self.reduce(self.convert(semantic.regs[reg]), desired, ntarget)
                        if ndesired is None:
                            continue
                        temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                        if temp is None:
                            continue
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                        l = len(chains)
                        if self.searchReg(reserve, ntarget, ndesired, before, temp, chains):
                            return True
                        if l == len(chains):
                            dup.add(str(semantic.regs[reg]))
            if 2 in self.rop[reg].keys():
                for semantic in self.rop[reg][2]:
                    if self.overlap(reserve, semantic.regs.keys()):
                        continue
                    regs = semantic.regs[reg].getRegs()
                    if len(regs) > 2:
                        # TODO, multiple regs
                        continue
                    self.solver = Solver()
                    self.solver.set("timeout", 1000)
                    self.solver.add(ForAll(self.z3Regs[target], desired == self.convert(semantic.regs[reg])))
                    sat = self.solver.check()
                    if str(sat) == "sat":
                        # target reg appears in this expression
                        if len(before) + len(after) + len(regs) - 1 >= self.deepth:
                            continue
                        # eliminate the other register by set it to constant
                        ntarget = regs[0] if target == regs[1] else regs[1]
                        ndesired = self.solver.model()[self.z3Regs[ntarget]]
                        temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                        if temp is None:
                            continue
                        logging.debug(
                            indent + reg + " => " + str(semantic.regs[reg]) + ", " + ntarget + ": " + str(ndesired))
                        if self.searchConstant(reserve, ntarget, ndesired, before, temp, chains):
                            return True
                        # eliminate the other register by minus itself
                        ndesired = self.reduce(self.convert(semantic.regs[reg]), desired, target)
                        if ndesired is None:
                            continue
                        temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                        if temp is None:
                            continue
                        logging.debug(
                            indent + reg + " => " + str(semantic.regs[reg]) + ", " + target + ": " + str(ndesired))
                        if self.searchRegs(reserve, target, ndesired, before, temp, chains):
                            return True
                    else:
                        # use reg dependency to locate target reg
                        if len(before) + len(after) + len(regs) >= self.deepth:
                            continue
                        temp = self.addToChain([], after, semantic, reg, self.deepth - len(before), reserve)
                        if temp is None:
                            continue
                        exp = simplify(desired == self.convert(semantic.regs[reg]))
                        logging.debug(indent + reg + " => " + str(semantic.regs[reg]))
                        for i in regs:
                            if not i in self.dependency.keys() or not target in self.dependency[i].keys():
                                continue
                            for semantic in self.dependency[i][target]:
                                sexp = substitute(exp, (self.z3Regs[i], self.convert(semantic.regs[i])))
                                ntarget = regs[0] if target == regs[1] else regs[1]
                                self.solver = Solver()
                                self.solver.set("timeout", 1000)
                                self.solver.add(ForAll(self.z3Regs[reg], desired == self.convert(semantic.regs[i])))
                                if str(self.solver.check()) != "sat":
                                    break
                                ndesired = self.solver.model()[self.z3Regs[ntarget]]
                                temp1 = self.addToChain([], temp, semantic, reg, self.deepth - len(before), reserve)
                                if temp1 is None:
                                    continue
                                if self.searchConstant(reserve, ntarget, ndesired, before, temp1, chains):
                                    return True
        return False

    def searchWriteMem(self, reserve, addr, reg, before, after, chain):
        indent = (len(before) + len(after)) * "\t"
        logging.debug(indent + "searching writeMem [" + addr + "] => " + str(reg))
        default = self.default
        self.default = 1
        for semantic in self.writeMem:
            if self.overlap(reserve, semantic.regs.keys()):
                continue
            for k, v in semantic.regs.items():
                if k in semantic.writeMem.keys() and v.getCategory() in [1,2]:
                    logging.debug(indent + k + " => " + str(v))
                    nbefore = deepcopy(before)
                    exp = semantic.writeMem[k]
                    regs = exp.getRegs()
                    exp = self.convert(exp.left)
                    val = self.convert(v)
                    if len(regs) == 1:
                        if regs[0] == self.sp or val.size() != Exp.defaultLength:
                            continue
                        if not is_true(simplify(exp == self.z3Regs[addr])):
                            temp = []
                            desired = self.reduce(exp, self.z3Regs[addr], regs[0])
                            if desired is None or len(nbefore) + len(after) + 1 >= self.deepth:
                                continue
                            if not self.searchReg(reserve, regs[0], desired, nbefore, [], temp):
                                continue
                            nbefore = temp[0]
                        if is_true(simplify(val == self.z3Regs[reg])):
                            pass
                        elif len(v.getRegs()) == 0:
                            continue
                        elif len(v.getRegs()) == 1:
                            desired = self.reduce(val, self.z3Regs[reg], v.getRegs()[0])
                            if desired is None or len(nbefore) + len(after) + 1 >= self.deepth:
                                continue
                            logging.debug(indent + " content: " + v.getRegs()[0] + " => " + str(desired))
                            temp = []
                            deepth = self.deepth
                            self.deepth = self.deepth - 1 - len(nbefore)
                            if not self.searchReg(reserve, v.getRegs()[0], desired, nbefore, [], temp):
                                self.deepth = deepth
                                break
                            self.deepth = deepth
                            nbefore = temp[0]
                        else:
                            temp = []
                            if not reg in v.getRegs():
                                desired = self.reduce(self.convert(v), self.z3Regs[reg], v.getRegs()[0])
                                if desired is None or len(nbefore) + len(after) + 1 >= self.deepth:
                                    continue
                                deepth = self.deepth
                                self.deepth = self.deepth - 1 - len(nbefore)
                                if not self.searchRegs(reserve, reg, desired, nbefore, [], temp):
                                    self.deepth = deepth
                                    break
                                self.deepth = deepth
                            else:
                                left = simplify(self.convert(v) - self.z3Regs[reg])
                                nreg = v.getRegs()[0] if reg == v.getRegs()[1] else v.getRegs()[0]
                                desired = self.reduce(left, BitVecVal(0, left.size()), nreg)
                                if desired is None:
                                    continue
                                deepth = self.deepth
                                self.deepth = self.deepth - 1 - len(nbefore)
                                if not self.searchReg(reserve, nreg, desired, nbefore, [], temp):
                                    self.deepth = deepth
                                    break
                                self.deepth = deepth
                            nbefore = temp[0]
                        temp = self.addToChain(nbefore, after, semantic, "", self.deepth, reserve, addr)
                        if temp is not None:
                            chain.append(temp)
                            break
                    else:
                        # TODO, mem address determined by multi regs
                        continue
            if len(chain) >= default:
                break
        self.default = default

    def overlap(self, reserve, regs):
        for reg in regs:
            if reg in reserve:
                return True
        return False

    def addToCat(self, cat, reg, val, semantic):
        if reg not in cat.keys():
            cat.update({reg: {}})
        if val not in cat[reg].keys():
            cat[reg].update({val: []})
        cat[reg][val].append(semantic)

    def category(self):
        cond = []
        read = set()
        write = set()
        for addr, semantic in self.semantics.items():
            if len(semantic.regs[self.ip].getRegs()) == 0:
                # constant return address, discard
                self.aba.append(semantic)
                continue
            elif semantic.regs[self.ip].isCond():
                # conditional jmp
                cond.append(semantic)
                continue

            if len(semantic.memLoc) > 0:
                for mem in semantic.memLoc:
                    if str(mem) not in semantic.writeMem.keys():
                        # read from mem
                        # logging.debug("category, readMem: " + reg + " => " + str(val.getCategory()))
                        if semantic.getAddress()[0] not in read:
                            for k, v in semantic.regs.items():
                                if str(v) == str(mem):
                                    self.addToCat(self.readMem, k, v.getCategory(), semantic)
                                    read.add(semantic.getAddress()[0])
                                    break
                    else:
                        # write to mem by only regs
                        # logging.debug("category, writeMem: " + reg + " => " + str(val.getCategory()))
                        if semantic.getAddress()[0] not in write and semantic.regs[str(mem)].getCategory() in [1, 2] and semantic.regs[str(mem)].length == Exp.defaultLength:
                            self.writeMem.append(semantic)
                            write.add(semantic.getAddress()[0])
            # ROP gadgets
            for reg, val in semantic.regs.items():
                # build register dependency graph
                #logging.debug("category: " + reg + " => " + str(val))
                if reg not in self.z3Regs.keys():
                    continue
                if val.getCategory() in [0, 3]:
                    self.addToCat(self.rop, reg, val.getCategory(), semantic)
                elif val.getCategory() == 1 and "F" not in val.getRegs()[0] and self.checkDependency(reg, val.getRegs()[0], val):
                    # logging.debug("register dep: " + str(reg) + " => " + str(val))
                    self.addToCat(self.dependency, reg, val.getRegs()[0], semantic)
                    self.addToCat(self.rop, reg, val.getCategory(), semantic)
                elif val.getCategory() == 2:
                    dep = True
                    for target in val.getRegs():
                        if "F" in target:
                            continue
                        if self.checkDependency(reg, target, val):
                            self.addToCat(self.dependency, reg, target, semantic)
                        else:
                            dep = False
                    if dep:
                        #logging.debug("registers dep: " + str(reg) + " => " + str(val))
                        self.addToCat(self.rop, reg, val.getCategory(), semantic)

    def checkDependency(self, reg, target, val):
        # return True if there is register dependency from reg to target register 
        # Ex eax = ebx + 1  eax ==> ebx, eax = ebx & 1 there is no such dependency
        #    eax = ebx - ecx, eax depends on ebx True, eax depends on ecx True
        #    eax = ebx ^ ecx, eax depends on ebx True, eax depends on ecx True
        #    eax = ebx & ecx, eax depends on ebx False, eax depends on ecx False
        if len(reg) == 2 or len(target) == 2:
            return False
        if val.getCategory() == 1:
            exp = self.convert(val)

            exp1 = substitute(exp, (self.z3Regs[target], self.z3Regs[reg]))
            exp2 = substitute(exp, (self.z3Regs[target], -self.z3Regs[reg]))

            res1 = simplify(exp1 == self.z3Regs[reg])
            res2 = simplify(exp2 == self.z3Regs[reg])
            if is_true(res1) or is_false(res1) or is_true(res2) or is_false(res2):
                return True
            return False
        else:
            exp = self.convert(val)
            self.solver = Solver()
            self.solver.set("timeout", 1000)
            self.solver.add(ForAll(self.z3Regs[target], exp == self.z3Regs[target]))
            sat = self.solver.check()
            if str(sat) == "sat":
                return True
            self.solver = Solver()
            self.solver.set("timeout", 1000)
            self.solver.add(ForAll(self.z3Regs[target], exp == -self.z3Regs[target]))
            sat = self.solver.check()
            return str(sat) == "sat"

    def reduce(self, left, right, target):
        # reduce the expression
        # Ex. eax' + ebx == eax   ==>  eax' == eax - ebx
        if len(target) == 2:
            return None
        left = simplify(left)
        ret = right
        sign = True
        #logging.debug("reduct: " + str(left) + " == " + str(right) + ", "+ str(target))
        for i in left.children():
            if len(i.children()) != 0 and target in str(i):
                sign = False
            elif str(i) != target:
                if i.size() != right.size():
                    return None
                ret = ret - i
        return simplify(ret) if sign else simplify(-1 * ret)

    def getRegs(self, exp):
        regs = []
        exp = simplify(exp)
        if len(exp.children()) == 0:
            return [str(exp)]
        for i in exp.children():
            if len(i.children()) > 1:
                for j in i.children():
                    if str(j) in self.z3Regs.keys():
                        regs.append(str(j))
            elif str(i) in self.z3Regs.keys():
                regs.append(str(i))
        return regs

    def addToChain(self, before, after, cur, dst, d, r, used = ''):
        regs = set()
        for mem in cur.memLoc:
            # fix all mem location, For now only deal with one register
            if len(mem.getRegs()) != 1 or (dst != "" and dst in mem.getRegs()):
                return None
            if used == mem.getRegs()[0]:
                continue
            regs |= set(mem.getRegs())

        if not cur.regs[self.ip].isControl():
            # COP/JOP, fix ret addr
            if used in cur.regs[self.ip].getRegs() or (dst != "" and dst in cur.regs[self.ip].getRegs()):
                return None
            regs |= set(cur.regs[self.ip].getRegs())

        if self.overlap(r, regs) or len(regs) + len(before) + len(after) + 1 > d:
            return None

        temp = deepcopy(before)
        reserve = deepcopy(r)
        default = self.default
        deepth = self.deepth
        self.default = 1
        self.deepth = d - len(after) - 1
        for reg in regs:
            fixStack = []
            if not self.searchStack(reserve, reg, temp, [], fixStack):
                self.default = default
                self.deepth = deepth
                return None
            reserve.add(reg)
            temp = fixStack[0]
        temp.extend(cur.getAddress())
        temp.extend(after)
        self.default = default
        self.deepth = deepth
        return temp
