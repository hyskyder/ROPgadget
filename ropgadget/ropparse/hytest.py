import unittest
from capstone import *
from arch.parserx86 import *
from arch.expression import *
from arch.semantic import *
from ropchain import *
#import cProfile, pstats, StringIO

class BinaryStub():
    def __init__(self):
        pass
        
    def getArch(self):
        return CS_ARCH_X86

    def getArchMode(self):
        return CS_MODE_32


class ParserX86TestCase2(unittest.TestCase):
    def setUp(self):
        gadget1 = {"insns":[{"mnemonic":"mov", "op_str":"eax, 1"}], "vaddr":1}
        gadget2 = {"insns":[{"mnemonic":"cmove", "op_str":"ebx, eax"}], "vaddr":2}
        gadget3 = {"insns":[{"mnemonic":"push", "op_str":"eax"}], "vaddr":3}
        gadget4 = {"insns":[{"mnemonic":"pop", "op_str":"eax"}], "vaddr":4}
        gadget5 = {"insns":[{"mnemonic":"stc", "op_str":""}], "vaddr":5}
        gadget6 = {"insns":[{"mnemonic":"adc", "op_str":"ecx, byte ptr [edx]"}], "vaddr":6}
        gadget7 = {"insns":[{"mnemonic":"sub", "op_str":"ecx, byte ptr [edx]"}], "vaddr":7}
        gadget8 = {"insns":[{"mnemonic":"cmp", "op_str":"ecx, byte ptr [edx]"}], "vaddr":8}
        gadget9 = {"insns":[{"mnemonic":"inc", "op_str":"ecx"}], "vaddr":9}
        gadget10 = {"insns":[{"mnemonic":"dec", "op_str":"ecx"}], "vaddr":10}
        gadget11 = {"insns":[{"mnemonic":"neg", "op_str":"ecx"}], "vaddr":11}
        gadget12 = {"insns":[{"mnemonic":"call", "op_str": "eax"}], "vaddr":12}
        gadget13 = {"insns":[{"mnemonic":"jmp", "op_str": "eax"}], "vaddr":13}
        gadget14 = {"insns":[{"mnemonic":"je", "op_str": "eax"}], "vaddr":14}
        gadget15 = {"insns":[{"mnemonic":"and", "op_str":"ecx, edx"}], "vaddr":15}
        gadget16 = {"insns":[{"mnemonic":"or", "op_str":"ecx, edx"}], "vaddr":16}
        gadget17 = {"insns":[{"mnemonic":"xor", "op_str":"ecx, edx"}], "vaddr":17}
        gadget18 = {"insns":[{"mnemonic":"not", "op_str":"ecx"}], "vaddr":18}
        gadget19 = {"insns":[{"mnemonic":"test", "op_str":"ecx, byte ptr [edx]"}], "vaddr":19}
        gadget20 = {"insns":[{"mnemonic":"lea", "op_str":"ecx, byte ptr [edx]"}], "vaddr":20}
        gadget21 = {"insns":[{"mnemonic":"pop", "op_str":"eax"}, {"mnemonic":"pop", "op_str":"eax"}], "vaddr":21}
        gadget22 = {"insns":[{"mnemonic":"push", "op_str":"eax"}, {"mnemonic":"push", "op_str":"eax"}], "vaddr":22}
        gadget23 = {"insns":[{"mnemonic":"add", "op_str":"esp, 4"}], "vaddr":23}
        gadget24 = {"insns":[{"mnemonic":"xchg", "op_str":"eax, ebx"}], "vaddr":24}
        gadget25 = {"insns":[{"mnemonic":"xchg", "op_str":"ax, bx"}], "vaddr":25}
        gadget26 = {"insns":[{"mnemonic":"add", "op_str":"byte ptr [ecx], edx"}], "vaddr":26}

        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5, gadget6, gadget7, gadget8, gadget9, gadget10, gadget11, gadget12, gadget13, gadget14, gadget15, gadget16, gadget17, gadget18, gadget19, gadget20, gadget21, gadget22, gadget23, gadget24, gadget25, gadget26]
        self.parser = ROPParserX86(gadgets, BinaryStub().getArchMode()) 
        self.formula = self.parser.parse()

    def test_ParseInst(self):
        assert len(self.formula[0].regs) == 2 and str(self.formula[0].regs["eax"]) == "1" and str(self.formula[0].regs["esp"]) == "esp"
        assert len(self.formula[1].regs) == 2 and str(self.formula[1].regs["ebx"]) == "( ( ZF == 1 ) ? eax : ebx )"
        assert len(self.formula[2].regs) == 2 and str(self.formula[2].regs["esp"]) == "( esp + 4 )" and str(self.formula[2].regs["[ esp ]"]) == "eax"
        assert len(self.formula[3].regs) == 2 and str(self.formula[3].regs["esp"]) == "( esp - 4 )" and str(self.formula[3].regs["eax"]) == "[ esp ]"
        assert len(self.formula[4].regs) == 2 and str(self.formula[4].regs["CF"]) == "1" and str(self.formula[4].regs["esp"]) == "esp"
        assert set(self.formula[5].regs.keys()) == set(["esp", "ecx", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[5].regs["ecx"]) == "( ( ecx + [ edx ] ) + CF )"
        assert set(self.formula[6].regs.keys()) == set(["esp", "ecx", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[6].regs["ecx"]) == "( ecx - [ edx ] )"
        assert set(self.formula[7].regs.keys()) == set(["esp", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[7].regs["CF"]) == "( C ( ecx - [ edx ] ) )"
        assert set(self.formula[8].regs.keys()) == set(["esp", "AF", "ZF", "OF", "SF","PF", "ecx"]) and str(self.formula[8].regs["ecx"]) == "( ecx + 1 )"
        assert set(self.formula[9].regs.keys()) == set(["esp", "AF", "ZF", "OF", "SF","PF", "ecx"]) and str(self.formula[9].regs["ecx"]) == "( ecx - 1 )"
        assert set(self.formula[10].regs.keys()) == set(["esp", "AF", "CF", "ZF", "OF", "SF","PF", "ecx"]) and str(self.formula[10].regs["ecx"]) == "( - ecx )"
        assert len(self.formula[11].regs) == 2 and str(self.formula[11].regs["eip"]) == "[ eax ]" and str(self.formula[11].regs["esp"]) == "esp"
        assert len(self.formula[12].regs) == 2 and str(self.formula[12].regs["eip"]) == "[ eax ]" and str(self.formula[12].regs["esp"]) == "esp"
        assert len(self.formula[13].regs) == 2 and str(self.formula[13].regs["eip"]) == "( ( ZF == 1 ) ? [ eax ] : 0 )" and str(self.formula[13].regs["esp"]) == "esp"
        assert set(self.formula[14].regs.keys()) == set(["CF", "ZF", "OF", "SF","PF", "ecx", "esp"]) and str(self.formula[14].regs["ecx"]) == "( ecx & edx )" and str(self.formula[14].regs["CF"]) == "0" and str(self.formula[14].regs["OF"]) == "0"
        assert set(self.formula[15].regs.keys()) == set(["CF", "ZF", "OF", "SF","PF", "ecx", "esp"]) and str(self.formula[15].regs["ecx"]) == "( ecx | edx )" and str(self.formula[15].regs["CF"]) == "0" and str(self.formula[16].regs["OF"]) == "0"
        assert set(self.formula[16].regs.keys()) == set(["CF", "ZF", "OF", "SF","PF", "ecx", "esp"]) and str(self.formula[16].regs["ecx"]) == "( ecx ^ edx )" and str(self.formula[16].regs["CF"]) == "0" and str(self.formula[16].regs["OF"]) == "0"
        assert len(self.formula[17].regs) == 2 and str(self.formula[17].regs["ecx"]) == "( ~ ecx )"
        assert set(self.formula[18].regs.keys()) == set(["esp", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[18].regs["CF"]) == "0" and str(self.formula[18].regs["OF"]) == "0"
        assert len(self.formula[19].regs) == 2 and str(self.formula[19].regs["ecx"]) == "edx"
        assert len(self.formula[20].regs) == 2 and str(self.formula[20].regs["esp"]) == "( ( esp - 4 ) - 4 )" and str(self.formula[20].regs["eax"]) == "[ ( esp - 4 ) ]"
        assert len(self.formula[21].regs) == 3 and str(self.formula[21].regs["esp"]) == "( ( esp + 4 ) + 4 )" and str(self.formula[21].regs["[ esp ]"]) == "eax" and str(self.formula[21].regs["[ ( esp + 4 ) ]"]) == "eax"
        assert set(self.formula[22].regs) == set(['PF', 'CF', 'AF', 'OF', 'ZF', 'esp', 'SF']) and str(self.formula[22].regs["esp"]) == "( esp + 4 )" 
        assert set(self.formula[23].regs) == set(['esp', 'eax', 'ebx']) and str(self.formula[23].regs["eax"]) == "ebx" and str(self.formula[23].regs["ebx"]) == "eax" 
        assert set(self.formula[24].regs) == set(['esp', 'eax', 'ebx']) and str(self.formula[24].regs["eax"]) == "( ( eax $ 16 : 31 ) # ( ebx $ 0 : 15 ) )" and str(self.formula[24].regs["ebx"]) == "( ( ebx $ 16 : 31 ) # ( eax $ 0 : 15 ) )" 
        assert set(self.formula[25].regs.keys()) == set(["esp", "[ ecx ]", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[25].regs["[ ecx ]"]) == "( [ ecx ] + edx )"

class ROPChainTestCase1(unittest.TestCase):
    def setUp(self):
        gadget1 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, eax"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":1}
        gadget2 = {"insns":[{"mnemonic":"mov", "op_str":"eax, 1"},    {"mnemonic":"ret", "op_str": ""}], "vaddr":2}

        gadget3 = {"insns":[{"mnemonic":"add", "op_str":"ebx, eax"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":3}
        gadget4 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, 0"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":4}

        gadget5 = {"insns":[{"mnemonic":"mov", "op_str":"eax, dword ptr [eax]"},    {"mnemonic":"ret", "op_str": ""}], "vaddr":5}
        gadget6 = {"insns":[{"mnemonic":"mov", "op_str":"eax, esp"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":6}

        gadget7 = {"insns":[{"mnemonic":"mov", "op_str":"dword ptr [ebx], ecx"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":7}
        gadget8 = {"insns":[{"mnemonic":"mov", "op_str":"ecx, dword ptr [ebx]"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":8}

        gadget9 = {"insns":[{"mnemonic":"inc", "op_str":"ebx"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":9}

        gadget10 = {"insns":[{"mnemonic":"xor", "op_str":"ebx, eax"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":10}

        gadget11 = {"insns":[{"mnemonic":"and", "op_str":"ebx, eax"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":11}

        gadget12 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, 0xffffffff"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":12}

        gadget13 = {"insns":[{"mnemonic":"pop", "op_str":"eax"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":13}

        gadget14 = {"insns":[{"mnemonic":"add", "op_str":"eax, ebx"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":14}
        gadget15 = {"insns":[{"mnemonic":"sub", "op_str":"eax, ebx"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":15}
        gadget16 = {"insns":[{"mnemonic":"add", "op_str":"ebx, ecx"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":16}

        gadget17 = {"insns":[{"mnemonic":"mov", "op_str":"dword ptr [edi], esi"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":17}
        gadget18 = {"insns":[{"mnemonic":"xchg", "op_str":"eax, esi"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":18}

        gadget19 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, 1"}, {"mnemonic":"call", "op_str": "eax"}], "vaddr":19}
        gadget20 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, ecx"}, {"mnemonic":"call", "op_str": "eax"}], "vaddr":20}
        gadget21 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, eax"}, {"mnemonic":"call", "op_str": "eax"}], "vaddr":21}
        gadget22 = {"insns":[{"mnemonic":"mov", "op_str":"dword ptr [eax], ebx"}, {"mnemonic":"mov", "op_str": "ebx, ecx"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":22}

        gadget23 = {"insns":[{'mnemonic': u'xchg', 'op_str': u'eax, ebp', 'vaddr': 134715832L}, {'mnemonic': u'ret', 'op_str': u'-0x3fcf', 'vaddr': 134715833L}], "vaddr":1}
        gadget24 = {"insns":[{'mnemonic': u'add', 'op_str': u'ebx, ebp', 'vaddr': 135004340L}, {'mnemonic': u'ret', 'op_str': u'', 'vaddr': 135004342L}], "vaddr": 2}

        gadget25 = {"insns":[{'mnemonic': u'xchg', 'op_str': u'eax, ebx', 'vaddr': 829972L}, {'mnemonic': u'and', 'op_str': u'edx, dword ptr [eax + 0x440ffffd]', 'vaddr': 829973L}, {'mnemonic': u'ret', 'op_str': u'0x4489', 'vaddr': 829979L}], "vaddr":1}
        self.gadgets1 = [gadget1, gadget2]
        self.gadgets2 = [gadget2, gadget3, gadget4]
        self.gadgets3 = [gadget3, gadget4]
        self.gadgets4 = [gadget2, gadget3]
        self.gadgets5 = [gadget9]
        self.gadgets6 = [gadget4, gadget10]
        self.gadgets7 = [gadget4, gadget11]
        self.gadgets8 = [gadget11, gadget12]
        self.gadgets9 = [gadget5, gadget6]
        self.gadgets10 = [gadget13]
        self.gadgets11 = [gadget1, gadget13]
        self.gadgets12 = [gadget14]
        self.gadgets13 = [gadget14, gadget15, gadget16]
        self.gadgets14 = [gadget1, gadget14]
        self.gadgets15 = [gadget3, gadget15]
        self.gadgets16 = [gadget17, gadget18]
        self.gadgets17 = [gadget13, gadget19]
        self.gadgets18 = [gadget13, gadget20]
        self.gadgets19 = [gadget13, gadget21]
        self.gadgets20 = [gadget13, gadget22]
        self.gadgets21 = [gadget23, gadget24]
        self.gadgets22 = [gadget25]

    def testCOP(self):

        self.rop = ROPChain(BinaryStub(), self.gadgets17, False, 2)
        res = list(self.rop.start({"ebx": Exp.ExpL(32, 1)}))
        assert len(res) == 1 and res[0] == ["0xd", "0x13"]
        print "res=" + str(res)	


        self.rop = ROPChain(BinaryStub(), self.gadgets18, False, 2)
        res = list(self.rop.start({"ebx": Exp("ecx")}))
        assert len(res) == 1 and res[0] == ["0xd", "0x14"]

        self.rop = ROPChain(BinaryStub(), self.gadgets20, False, 2)
        res = list(self.rop.start({"ebx": Exp("ecx")}))
        assert len(res) == 1 and res[0] == ["0xd", "0x16"]

if __name__ == "__main__":
    unittest.main(verbosity=10)