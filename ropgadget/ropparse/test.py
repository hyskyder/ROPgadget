import unittest
from capstone import *
from arch.parserx86 import *
from arch.expression import *
from arch.semantic import *
from ROPChain import *

class BinaryStub():
    def __init__(self):
        pass
        
    def getArch(self):
        return CS_ARCH_X86

    def getArchMode(self):
        return CS_MODE_32

class ROPChainTestCase1(unittest.TestCase):
    def setUp(self):
        gadget1 = [{"mnemonic":"mov", "op_str":"eax, 1", "vaddr":1}, {"mnemonic":"ret", "op_str": "", "vaddr": "1"}]
        gadget2 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":2},    {"mnemonic":"ret", "op_str": "", "vaddr": "2"}]
        gadget3 = [{"mnemonic":"mov", "op_str":"ebx, eax", "vaddr":3}, {"mnemonic":"ret", "op_str": "", "vaddr": "3"}]

        gadget4 = [{"mnemonic":"mov", "op_str":"edx, esp", "vaddr":4}, {"mnemonic":"add", "op_str":"esp, 4", "vaddr":"4"}, {"mnemonic":"ret", "op_str": "", "vaddr": "4"}]
        gadget5 = [{"mnemonic":"add", "op_str":"ecx, byte ptr [edx]", "vaddr":5}, {"mnemonic":"ret", "op_str": "", "vaddr": "5"}]


        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5]
        self.rop = ROPChain(BinaryStub(), gadgets, 0)

    def testMultiConds(self):
        print "Testing with multi regs..............................."
        # TODO need to sort the multi regs first, for now it is empty
        res = list(self.rop.Start({"ebx":Exp("eax"), "eax": Exp(1)}))
        assert len(res) == 0

        res = list(self.rop.Start({"eax": Exp(1), "ebx": Exp(1)}))
        assert len(res) == 1 and len(res[0].gadgets) == 2 and res[0].getAddress() == [1, 3]


    def testOneCond(self):
        print "Testing with one reg..............................."
        res = list(self.rop.Start({"eax": Exp(1)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 1

        res = list(self.rop.Start({"eax": Exp(21213)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 2

        res = list(self.rop.Start({"eax": Exp(-21213)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 2

        res = list(self.rop.Start({"ebx": Exp("eax")}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 3

        res = list(self.rop.Start({"edx": Exp("ssp")}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 4

        # TODO, Mem + regs
        # res = list(self.rop.Start({"ecx": Exp("ecx", "+", Exp("edx", "*"))}))
        # assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 5

        # res = list(self.rop.Start({"ecx": Exp("ecx", "+", "1")}))
        # assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [4, 5] 

        res = list(self.rop.Start({"ebx": Exp("1")}))
        assert len(res) == 2 and len(res[0].gadgets) == 2 and len(res[1].gadgets) == 2 and ( (res[0].getAddress() == [1, 3] and res[1].getAddress() == [2, 3])  or ( res[1].getAddress() == [1, 3] and res[2].getAddress() == [2, 3]) )

        res = list(self.rop.Start({"ebx": Exp("1111")}))
        assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [2, 3] 


        res = list(self.rop.Start({"edx": Exp("1111")}))
        assert len(res) == 0



class ROPChainTestCase2(unittest.TestCase):

    def setUp(self):
        gadget6 = [{"mnemonic":"stc", "op_str":"", "vaddr":6},      {"mnemonic":"ret", "op_str": "", "vaddr":"6"}]
        gadget7 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":7},  {"mnemonic":"ret", "op_str":"", "vaddr":7}]
        gadget9 = [{"mnemonic":"cmovb", "op_str":"edx, ecx", "vaddr":9},  {"mnemonic":"jc", "op_str":"eax", "vaddr":9}]

        gadgets = [gadget6, gadget9, gadget7]
        self.rop = ROPChain(BinaryStub(), gadgets, 0)

    def testJOP(self):
        print "Testing JOP gadgets..........................................."

        res = list(self.rop.Start({"edx": Exp("ecx")}))
        assert len(res) == 1 and ( res[0].getAddress() == [7, 6, 9] or res[0].getAddress() == [6, 7 , 9])

class ROPChainTestCase3(unittest.TestCase):

    def setUp(self):
        gadget1 = [{"mnemonic":"mov", "op_str":"al, 1", "vaddr":1},      {"mnemonic":"ret", "op_str": "", "vaddr":"1"}]
    #    gadget2 = [{"mnemonic":"mov", "op_str":"ah, 1", "vaddr":2},  {"mnemonic":"ret", "op_str":"", "vaddr":2}]
        gadget3 = [{"mnemonic":"mov", "op_str":"eax, 0", "vaddr":3},  {"mnemonic":"ret", "op_str":"", "vaddr":3}]

        gadgets = [gadget1, gadget3]
        self.rop = ROPChain(BinaryStub(), gadgets, 0)

    def testSubRegs(self):
        print "Testing sub regs gadgets..........................................."

        res = list(self.rop.Start({"eax": Exp(1)}))
        assert len(res) == 1 and res[0].getAddress() == [3, 1]

        #res = list(self.rop.Start({"eax": Exp(257)}))
        #assert len(res) == 1 and res[0].getAddress() == [3, 1, 2]

if __name__ == "__main__":
    unittest.main()
