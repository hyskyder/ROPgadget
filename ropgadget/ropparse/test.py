import unittest
from capstone import *
from arch.parserx86 import *
from arch.expression import *
from arch.semantic import *
from ROPChain import *
import cProfile, pstats, StringIO

class BinaryStub():
    def __init__(self):
        pass
        
    def getArch(self):
        return CS_ARCH_X86

    def getArchMode(self):
        return CS_MODE_32
'''
class ExpTestCase(unittest.TestCase):
    def testGetCat(self):
        print "Test Exp binding...................................."
        assert Exp("1").getCategory() == 0
        assert Exp("eax").getCategory() == 1
        assert Exp(Exp("eax"), "+", Exp("ebx")).getCategory() == 2
        assert Exp(Exp("1"),"*").getCategory() == 3
        assert Exp(Exp(Exp("eax"),"*"), "+", Exp("ebx")).getCategory() == 4
        assert Exp("1","condition", Exp("eax"), Exp("ebx")).getCategory() == 5
        operand1 = Exp.parseOperand("byte ptr [0x15]", {}, {})
        assert operand1.getCategory() == 3
        operands = {}
        operands.update({"operand1":operand1})
        exp = Exp.parse("operand1 = operand1 ^ operand1", operands)
        for key, val in exp.items():
            print key, val.getCategory()
            assert val.getCategory() == 3 and key == "operand1"

        operand1 = Exp.parseOperand("al", {"eax":Exp("eax")}, {"al":["eax $ 0 : 7", "eax = ( eax $ 8 : 31 ) # al", 8]})
        assert operand1.getCategory() == 1

    def testExpBinding(self):
        print "Test Exp binding...................................."
        exp = Exp("eax")
        exp = exp.binding({"eax":Exp(1)})
        assert str(exp) == "1"
        exp2 = Exp(Exp("eax"), "+", Exp("1"))
        exp2 = exp2.binding({"eax":exp})
        assert str(exp2) == "( 1 + 1 )"


    def testExpParsing(self):
        print "Test Exp parsing...................................."
        exp = Exp.parseOperand("byte ptr [rax + 0x15]", {}, {})
        assert str(exp) == "[ ( rax + 0x15 ) ]"
        exp = Exp.parseOperand("eax", {"eax":Exp(1)},{})
        assert str(exp) == "1"
        exp = Exp.parse("operand1 = operand2", { "operand1":Exp("eax"), "operand2":Exp("ebx")})
        for key, val in exp.items():
            assert key == "operand1" and str(val) == "ebx"
        exp = Exp.parse("operand1 = operand1 + operand2", {"operand1":Exp("eax"), "operand2":Exp(4)})
        for key, val in exp.items():
            assert key == "operand1" and str(val) == "( eax + 4 )"
        exp = Exp.parse("operand1 = ( operand2 - 1 ) $ 0 : 15", {"operand1":Exp("ax"), "operand2":Exp("eax")})
        for key, val in exp.items():
            assert key == "operand1" and str(val) == "( ( eax - 1 ) $ 0 : 15 )"
        exp = Exp.parse("operand1 = ( operand1 $ 16 : 31 ) # operand2", {"operand1":Exp("eax"), "operand2":Exp("ax")})
        for key, val in exp.items():
            assert key == "operand1" and str(val) == "( ( eax $ 16 : 31 ) # ax )"

    def testExpLength(self):
        print "Test Exp length...................................."
        operand = Exp.parseOperand("eax", {}, {})
        assert operand.length == 32

        operand = Exp.parseOperand("al", {"eax":operand}, {"al":["eax $ 0 : 7", "eax = ( eax $ 8 : 31 ) # al", 8]})
        assert operand.length == 8 

        operand1 = Exp.parseOperand("eax", {}, {})
        assert operand1.length == 32

        operand2 = Exp.parseOperand("1", {}, {})
        assert operand2.length == 0

        operands = {}
        operands.update({"operand1":operand1})
        operands.update({"operand2":operand2})
        exp = Exp.parse("operand1 = operand1 + operand2", operands)
        assert len(exp) == 1
        for key, val in exp.items():
            assert key == "operand1" and str(val) == "( eax + 1 )" and val.length == 32

        operands = {}
        operand1 = Exp.parseOperand("al", {"eax":exp["operand1"]}, {"al":["eax $ 0 : 7", "eax = ( eax $ 8 : 31 ) # al", 8]})
        assert str(operand1) == "( ( eax + 1 ) $ 0 : 7 )" and operand1.length == 8
        operands.update({"operand1":operand1})
        operands.update({"operand2":Exp("1")})
        exp2 = Exp.parse("operand1 = operand1 + operand2", operands)
        assert len(exp2) == 1
        for key, val in exp2.items():
            assert key == "operand1" and str(val) == "( ( ( eax + 1 ) $ 0 : 7 ) + 1 )" and val.length == 8
            # concat al back to eax
            temp = Exp.parse("eax = ( eax $ 8 : 31 ) # al", {"al":val, "eax":exp["operand1"]})
            for k, v in temp.items():
                v = v.binding({"al":val})
                assert v.length == 32 and str(v) == "( ( ( eax + 1 ) $ 8 : 31 ) # ( ( ( eax + 1 ) $ 0 : 7 ) + 1 ) )"

        operand1 = Exp.parseOperand("eax", {}, {})
        assert operand1.length == 32

        operand2 = Exp.parseOperand("1", {}, {})
        assert operand2.length == 0

        operands = {}
        operands.update({"operand1":operand1})
        operands.update({"operand2":operand2})
        exp = Exp.parse("operand1 = operand2", operands)
        assert len(exp) == 1
        for key, val in exp.items():
            assert key == "operand1" and str(val) == "1" and val.length == 32

        operands = {}
        operand1 = Exp.parseOperand("al", {"eax":exp["operand1"]}, {"al":["eax $ 0 : 7", "eax = ( eax $ 8 : 31 ) # al", 8]})
        assert str(operand1) == "( 1 $ 0 : 7 )" and operand1.length == 8 and operand1.condition.length == 32
        operands.update({"operand1":operand1})
        operands.update({"operand2":Exp("1")})
        exp2 = Exp.parse("operand1 = operand1 + operand2", operands)
        assert len(exp2) == 1
        for key, val in exp2.items():
            assert key == "operand1" and str(val) == "( ( 1 $ 0 : 7 ) + 1 )" and val.length == 8
            # concat al back to eax
            temp = Exp.parse("eax = ( eax $ 8 : 31 ) # al", {"al":val, "eax":exp["operand1"]})
            for k, v in temp.items():
                v = v.binding({"al":val})
                assert v.length == 32 and str(v) == "( ( 1 $ 8 : 31 ) # ( ( 1 $ 0 : 7 ) + 1 ) )"

class ParserX86TestCase1(unittest.TestCase):
    def setUp(self):
        gadget1 = {"insns": [{"mnemonic":"adc", "op_str":"al, 0x41"} , {"mnemonic":"xor", "op_str":"eax, eax"}, {"mnemonic":"adc", "op_str":"al, -2"}, {"mnemonic":"jbe", "op_str":"0x123123"}], "vaddr":1 }
        gadget2 = {"insns":[{"mnemonic":"cmove", "op_str":"ebx, eax"}], "vaddr":2}
        gadget3 = {"insns":[{"mnemonic":"add", "op_str":"eax, ebx"},  {"mnemonic":"ret", "op_str":""}], "vaddr":3}
        gadget4 = {"insns":[{"mnemonic":"adc", "op_str":"al, 0x41"}], "vaddr":4}
        gadget5 = {"insns":[{"mnemonic":"mov", "op_str":"eax, 0x123123"}, {"mnemonic":"ret", "op_str":"4"}], "vaddr":5}
        gadget6 = {"insns":[{"mnemonic":"cmp", "op_str":"eax, 2"}, {"mnemonic":"jle", "op_str":"0x123123"}], "vaddr":6}
        gadget7 = {"insns":[{"mnemonic":"ja", "op_str":"0x123123"}], "vaddr":7}
        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5, gadget6, gadget7]
        self.parser = ROPParserX86(gadgets, BinaryStub().getArchMode()) 
        self.formula = self.parser.parse()
        self.rop = ROPChain(BinaryStub(), [], False, 2)

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

    def testParseInst(self):
        print "Testing parsing instruction"
        assert len(self.formula[0].regs) == 2 and str(self.formula[0].regs["eax"]) == "1" and str(self.formula[0].regs["ssp"]) == "ssp"
        assert len(self.formula[1].regs) == 2 and str(self.formula[1].regs["ebx"]) == "( ( ZF == 1 ) ? eax : ebx )"
        assert len(self.formula[2].regs) == 2 and str(self.formula[2].regs["ssp"]) == "( ssp + 4 )" and str(self.formula[2].regs["[ ssp ]"]) == "eax"
        assert len(self.formula[3].regs) == 2 and str(self.formula[3].regs["ssp"]) == "( ssp - 4 )" and str(self.formula[3].regs["eax"]) == "[ ssp ]"
        assert len(self.formula[4].regs) == 2 and str(self.formula[4].regs["CF"]) == "1" and str(self.formula[4].regs["ssp"]) == "ssp"
        assert set(self.formula[5].regs.keys()) == set(["ssp", "ecx", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[5].regs["ecx"]) == "( ( ecx + [ edx ] ) + CF )"
        assert set(self.formula[6].regs.keys()) == set(["ssp", "ecx", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[6].regs["ecx"]) == "( ecx - [ edx ] )"
        assert set(self.formula[7].regs.keys()) == set(["ssp", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[7].regs["CF"]) == "( C ( ecx - [ edx ] ) )"
        assert set(self.formula[8].regs.keys()) == set(["ssp", "AF", "ZF", "OF", "SF","PF", "ecx"]) and str(self.formula[8].regs["ecx"]) == "( ecx + 1 )"
        assert set(self.formula[9].regs.keys()) == set(["ssp", "AF", "ZF", "OF", "SF","PF", "ecx"]) and str(self.formula[9].regs["ecx"]) == "( ecx - 1 )"
        assert set(self.formula[10].regs.keys()) == set(["ssp", "AF", "CF", "ZF", "OF", "SF","PF", "ecx"]) and str(self.formula[10].regs["ecx"]) == "( - ecx )"
        assert len(self.formula[11].regs) == 2 and str(self.formula[11].regs["sip"]) == "[ eax ]" and str(self.formula[11].regs["ssp"]) == "ssp"
        assert len(self.formula[12].regs) == 2 and str(self.formula[12].regs["sip"]) == "[ eax ]" and str(self.formula[12].regs["ssp"]) == "ssp"
        assert len(self.formula[13].regs) == 2 and str(self.formula[13].regs["sip"]) == "( ( ZF == 1 ) ? [ eax ] : 0 )" and str(self.formula[13].regs["ssp"]) == "ssp"
        assert set(self.formula[14].regs.keys()) == set(["CF", "ZF", "OF", "SF","PF", "ecx", "ssp"]) and str(self.formula[14].regs["ecx"]) == "( ecx & edx )" and str(self.formula[14].regs["CF"]) == "0" and str(self.formula[14].regs["OF"]) == "0"
        assert set(self.formula[15].regs.keys()) == set(["CF", "ZF", "OF", "SF","PF", "ecx", "ssp"]) and str(self.formula[15].regs["ecx"]) == "( ecx | edx )" and str(self.formula[15].regs["CF"]) == "0" and str(self.formula[16].regs["OF"]) == "0"
        assert set(self.formula[16].regs.keys()) == set(["CF", "ZF", "OF", "SF","PF", "ecx", "ssp"]) and str(self.formula[16].regs["ecx"]) == "( ecx ^ edx )" and str(self.formula[16].regs["CF"]) == "0" and str(self.formula[16].regs["OF"]) == "0"
        assert len(self.formula[17].regs) == 2 and str(self.formula[17].regs["ecx"]) == "( ~ ecx )"
        assert set(self.formula[18].regs.keys()) == set(["ssp", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[18].regs["CF"]) == "0" and str(self.formula[18].regs["OF"]) == "0"
        assert len(self.formula[19].regs) == 2 and str(self.formula[19].regs["ecx"]) == "( & [ edx ] )"
        assert len(self.formula[20].regs) == 2 and str(self.formula[20].regs["ssp"]) == "( ( ssp - 4 ) - 4 )" and str(self.formula[20].regs["eax"]) == "[ ( ssp - 4 ) ]"
        assert len(self.formula[21].regs) == 3 and str(self.formula[21].regs["ssp"]) == "( ( ssp + 4 ) + 4 )" and str(self.formula[21].regs["[ ssp ]"]) == "eax" and str(self.formula[21].regs["[ ( ssp + 4 ) ]"]) == "eax"
        assert set(self.formula[22].regs) == set(['PF', 'CF', 'AF', 'OF', 'ZF', 'ssp', 'SF']) and str(self.formula[22].regs["ssp"]) == "( ssp + 4 )" 
        assert set(self.formula[23].regs) == set(['ssp', 'eax', 'ebx']) and str(self.formula[23].regs["eax"]) == "ebx" and str(self.formula[23].regs["ebx"]) == "eax" 
        assert set(self.formula[24].regs) == set(['ssp', 'eax', 'ebx']) and str(self.formula[24].regs["eax"]) == "( ( eax $ 16 : 31 ) # ( ebx $ 0 : 15 ) )" and str(self.formula[24].regs["ebx"]) == "( ( ebx $ 16 : 31 ) # ( eax $ 0 : 15 ) )" 
        assert set(self.formula[25].regs.keys()) == set(["ssp", "[ ecx ]", "AF", "CF", "ZF", "OF", "SF","PF"]) and str(self.formula[25].regs["[ ecx ]"]) == "( [ ecx ] + edx )"

class ROPChainTestCase1(unittest.TestCase):
    def setUp(self):
        gadget1 = {"insns":[{"mnemonic":"mov", "op_str":"eax, 1"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":1}
        gadget2 = {"insns":[{"mnemonic":"pop", "op_str":"eax"},    {"mnemonic":"ret", "op_str": ""}], "vaddr":2}
        gadget3 = {"insns":[{"mnemonic":"mov", "op_str":"ebx, eax"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":3}
        gadget4 = {"insns":[{"mnemonic":"mov", "op_str":"edx, esp"}, {"mnemonic":"add", "op_str":"esp, 4"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":4}
        gadget5 = {"insns":[{"mnemonic":"mov", "op_str":"ecx, byte ptr [edx]"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":5}

        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 2)

    def testMultiConds(self):
        print "Testing with multi regs..............................."
        res = list(self.rop.Start({"eax": Exp.ExpL(32, 1), "ebx": Exp.ExpL(32, 1)}))
        for r in res:
            assert r.getAddress() == ["0x2", "0x3"] or r.getAddress() == ["0x1", "0x3"]

        self.rop.deepth = 4
        res = list(self.rop.Start({"eax": Exp.ExpL(32, 10), "ebx": Exp.ExpL(32, 1)}))
        for r in res:
            print r
            assert r.getAddress() == ["0x1", "0x3", "0x2"] or r.getAddress() == ["0x2", "0x3", "0x2"]


    def testOneCond(self):
        print "Testing with one reg..............................."
        res = list(self.rop.Start({"ebx": Exp("eax")}))
        assert len(res) == 1 and res[0].getAddress() == ["0x3"]

        res = list(self.rop.Start({"edx": Exp("ssp")}))
        assert len(res) == 1 and res[0].getAddress() == ["0x4"]

        # TODO, Mem + regs
        # res = list(self.rop.Start({"ecx": Exp("ecx", "+", Exp("edx", "*"))}))
        # assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 5

        # res = list(self.rop.Start({"ecx": Exp("ecx", "+", "1")}))
        # assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [4, 5] 

        res = list(self.rop.Start({"ebx": Exp.ExpL(32, "1")}))
        for r in res:
            assert r.getAddress() == ["0x2", "0x3"] or r.getAddress() == ["0x1", "0x3"]

class ROPChainTestCase2(unittest.TestCase):

    def setUp(self):
        gadget7 = {"insns":[{"mnemonic":"pop", "op_str":"eax"},  {"mnemonic":"ret", "op_str":""}], "vaddr":7}
        gadget1 = {"insns":[{"mnemonic":"mov", "op_str":"ecx, ebx"},  {"mnemonic":"call", "op_str":"eax"}], "vaddr":1}

        gadgets = [gadget1, gadget7]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 4)
    
    def testCOP(self):
        print "Testing COP gadgets..........................................."

        res = list(self.rop.Start({"ecx": Exp("ebx")}))
        assert len(res) == 1 and ( res[0].getAddress() == ["0x7", "0x1"])

class ROPChainTestCase3(unittest.TestCase):

    def setUp(self):
        gadget6 = {"insns":[{"mnemonic":"stc", "op_str":""},      {"mnemonic":"ret", "op_str": ""}], "vaddr":6}
        gadget7 = {"insns":[{"mnemonic":"pop", "op_str":"eax"},  {"mnemonic":"ret", "op_str":""}], "vaddr":7}
        gadget9 = {"insns":[{"mnemonic":"cmovb", "op_str":"edx, ecx"},  {"mnemonic":"jmp", "op_str":"eax"}], "vaddr":9}

        gadgets = [gadget6, gadget9, gadget7]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 3)

    def testJOP(self):
        print "Testing JOP gadgets..........................................."

        res = list(self.rop.Start({"edx": Exp("ecx")}))
        assert len(res) == 1 and ( res[0].getAddress() == ["0x7", "0x6", "0x9"] or res[0].getAddress() == ["0x6", "0x7" , "0x9"])

class ROPChainTestCase4(unittest.TestCase):

    def setUp(self):
        gadget1 = {"insns":[{"mnemonic":"mov", "op_str":"al, 1"},      {"mnemonic":"ret", "op_str": ""}], "vaddr":1}
        gadget2 = {"insns":[{"mnemonic":"mov", "op_str":"ah, 1"},  {"mnemonic":"ret", "op_str":""}], "vaddr":2}
        gadget3 = {"insns":[{"mnemonic":"mov", "op_str":"eax, 0"},  {"mnemonic":"ret", "op_str":""}], "vaddr":3}

        gadgets = [gadget1, gadget2, gadget3]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 2)

    def testSubRegs(self):
        print "Testing sub regs gadgets..........................................."
        res = list(self.rop.Start({"eax": Exp.ExpL(32, 1)}))
        print res[0].getAddress()
        assert len(res) == 1 and res[0].getAddress() == ["0x3", "0x1"]

        self.rop.deepth = 3
        res = list(self.rop.Start({"eax": Exp.ExpL(32, 257)}))
        for r in res:
            assert (r.getAddress() == ["0x3", "0x1", "0x2"] or r.getAddress() == ["0x3", "0x2", "0x1"]) 

class ROPChainTestCase5(unittest.TestCase):
    def setUp(self):
        gadget1 = {"insns":[{"mnemonic":"pop", "op_str":"eax"},      {"mnemonic":"ret", "op_str": ""}], "vaddr":1}
        gadget2 = {"insns":[{"mnemonic":"pop", "op_str":"ebx"},  {"mnemonic":"ret", "op_str":""}], "vaddr":2}
        gadget3 = {"insns":[{"mnemonic":"add", "op_str":"eax, ebx"},  {"mnemonic":"ret", "op_str":""}], "vaddr":3}
        gadget4 = {"insns":[{"mnemonic":"mov", "op_str":"ecx, byte ptr [eax]"},  {"mnemonic":"ret", "op_str":""}], "vaddr":4}

        gadgets = [gadget1, gadget2, gadget3, gadget4]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 1)

    def testComplexMem(self):
        print "Testing complex mem location for reg sat..........................................."
'''
class ROPChainTestCase6(unittest.TestCase):
    def setUp(self):
        gadget1 = {"insns":[{"mnemonic":"add", "op_str":"esp, 6"}, {"mnemonic":"ret", "op_str": ""}], "vaddr":1}
        gadgets = [gadget1]
        self.parser = ROPParserX86(gadgets, BinaryStub().getArchMode()) 
        self.formula = self.parser.parse()

    def testDebug(self):
        for k,v in (self.formula[0].regs).items():
            print k, v
        
if __name__ == "__main__":
    unittest.main()
