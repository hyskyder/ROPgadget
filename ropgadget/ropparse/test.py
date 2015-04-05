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

class ROPChainTestCase(unittest.TestCase):
    def setUp(self):
        gadget1 = [{"mnemonic":"mov", "op_str":"eax, 1", "vaddr":1}, {"mnemonic":"ret", "op_str": "", "vaddr": "1"}]
        gadget2 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":2},    {"mnemonic":"ret", "op_str": "", "vaddr": "2"}]
        gadget3 = [{"mnemonic":"mov", "op_str":"ebx, eax", "vaddr":3}, {"mnemonic":"ret", "op_str": "", "vaddr": "3"}]

        gadget4 = [{"mnemonic":"mov", "op_str":"edx, esp", "vaddr":4}, {"mnemonic":"ret", "op_str": "", "vaddr": "4"}]
        gadget5 = [{"mnemonic":"add", "op_str":"ecx, byte ptr [edx]", "vaddr":5}, {"mnemonic":"ret", "op_str": "", "vaddr": "5"}]

        gadget6 = [{"mnemonic":"stc", "op_str":"", "vaddr":6},      {"mnemonic":"ret", "op_str": "", "vaddr":"6"}]
        gadget7 = [{"mnemonic":"cmovb", "op_str":"edx, 1", "vaddr":7},      {"mnemonic":"ret", "op_str": "", "vaddr":"6"}]
        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5, gadget6, gadget7]
        self.rop = ROPChain(BinaryStub(), gadgets, 0)

    def testOneCond(self):
        res = list(self.rop.Start({"eax": Exp(1)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 1

        res = list(self.rop.Start({"eax": Exp(21213)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 2

        res = list(self.rop.Start({"eax": Exp(-21213)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 2

        res = list(self.rop.Start({"ebx": Exp("eax")}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 3

        res = list(self.rop.Start({"edx": Exp("esp")}))
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

        res = list(self.rop.Start({"edx": Exp("1")}))
        assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [6, 7] 

'''
    def testTwoConds(self):
        pass

    def testJOP(self):
        pass

    def testSubReg(self):
        pass
'''

if __name__ == "__main__":
    unittest.main()
