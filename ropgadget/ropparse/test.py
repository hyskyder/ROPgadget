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

class ExpTestCase(unittest.TestCase):
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

class ParserX86TestCase(unittest.TestCase):
    def setUp(self):
        gadget1 = [{"mnemonic":"mov", "op_str":"eax, 1", "vaddr":1}]
        gadget2 = [{"mnemonic":"cmove", "op_str":"ebx, eax", "vaddr":3}]
        gadget3 = [{"mnemonic":"push", "op_str":"eax", "vaddr":2}]
        gadget4 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":2}]
        gadget5 = [{"mnemonic":"stc", "op_str":"", "vaddr":4}]
        gadget6 = [{"mnemonic":"adc", "op_str":"ecx, byte ptr [edx]", "vaddr":5}]
        gadget7 = [{"mnemonic":"sub", "op_str":"ecx, byte ptr [edx]", "vaddr":5}]
        gadget8 = [{"mnemonic":"cmp", "op_str":"ecx, byte ptr [edx]", "vaddr":5}]
        gadget9 = [{"mnemonic":"inc", "op_str":"ecx", "vaddr":5}]
        gadget10 = [{"mnemonic":"dec", "op_str":"ecx", "vaddr":5}]
        gadget11 = [{"mnemonic":"neg", "op_str":"ecx", "vaddr":5}]
        gadget12 = [{"mnemonic":"call", "op_str": "eax", "vaddr": "5"}]
        gadget13 = [{"mnemonic":"jmp", "op_str": "eax", "vaddr": "5"}]
        gadget14 = [{"mnemonic":"je", "op_str": "eax", "vaddr": "5"}]
        gadget15 = [{"mnemonic":"and", "op_str":"ecx, edx", "vaddr":5}]
        gadget16 = [{"mnemonic":"or", "op_str":"ecx, edx", "vaddr":5}]
        gadget17 = [{"mnemonic":"xor", "op_str":"ecx, edx", "vaddr":5}]
        gadget18 = [{"mnemonic":"not", "op_str":"ecx", "vaddr":5}]
        gadget19 = [{"mnemonic":"test", "op_str":"ecx, byte ptr [edx]", "vaddr":5}]
        gadget20 = [{"mnemonic":"lea", "op_str":"ecx, byte ptr [edx]", "vaddr":5}]
        gadget21 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":2}, {"mnemonic":"pop", "op_str":"eax", "vaddr":3}]
        gadget22 = [{"mnemonic":"push", "op_str":"eax", "vaddr":2}, {"mnemonic":"push", "op_str":"eax", "vaddr":3}]
        gadget23 = [{"mnemonic":"add", "op_str":"esp, 4", "vaddr":5}]

        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5, gadget6, gadget7, gadget8, gadget9, gadget10, gadget11, gadget12, gadget13, gadget14, gadget15, gadget16, gadget17, gadget18, gadget19, gadget20, gadget21, gadget22, gadget23]
        self.parser = ROPParserX86(gadgets, BinaryStub().getArchMode()) 
        self.formula = self.parser.parse()

    def testParseInst(self):
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

class ROPChainTestCase1(unittest.TestCase):
    def setUp(self):
        gadget1 = [{"mnemonic":"mov", "op_str":"eax, 1", "vaddr":1}, {"mnemonic":"ret", "op_str": "", "vaddr": "1"}]
        gadget2 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":2},    {"mnemonic":"ret", "op_str": "", "vaddr": "2"}]
        gadget3 = [{"mnemonic":"mov", "op_str":"ebx, eax", "vaddr":3}, {"mnemonic":"ret", "op_str": "", "vaddr": "3"}]

        gadget4 = [{"mnemonic":"mov", "op_str":"edx, esp", "vaddr":4}, {"mnemonic":"add", "op_str":"esp, 4", "vaddr":"4"}, {"mnemonic":"ret", "op_str": "", "vaddr": "4"}]
        gadget5 = [{"mnemonic":"mov", "op_str":"ecx, byte ptr [edx]", "vaddr":5}, {"mnemonic":"ret", "op_str": "", "vaddr": "5"}]


        gadgets = [gadget1, gadget2, gadget3, gadget4, gadget5]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 4)

    def testMultiConds(self):
        print "Testing with multi regs..............................."
        res = list(self.rop.Start({"eax": Exp(1), "ebx": Exp(1)}))
        assert len(res) == 1 and len(res[0].gadgets) == 2 and res[0].getAddress() == [1, 3]
        # TODO need to sort the multi regs first, for now it is empty
        res = list(self.rop.Start({"ebx":Exp("eax"), "eax": Exp(1)}))
        assert len(res) == 0



    def testOneCond(self):
        print "Testing with one reg..............................."
        res = list(self.rop.Start({"eax": Exp(1)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress() == [1]

        res = list(self.rop.Start({"eax": Exp(21213)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress() == [2]

        res = list(self.rop.Start({"eax": Exp(-21213)}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress() == [2]

        res = list(self.rop.Start({"ebx": Exp("eax")}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress() == [3]

        res = list(self.rop.Start({"edx": Exp("ssp")}))
        assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress() == [4]

        # TODO, Mem + regs
        # res = list(self.rop.Start({"ecx": Exp("ecx", "+", Exp("edx", "*"))}))
        # assert len(res) == 1 and len(res[0].gadgets) == 1 and res[0].getAddress()[0] == 5

        # res = list(self.rop.Start({"ecx": Exp("ecx", "+", "1")}))
        # assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [4, 5] 

        res = list(self.rop.Start({"ebx": Exp("1111")}))
        print res
        assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [2, 3] 

        res = list(self.rop.Start({"edx": Exp("1111")}))
        assert len(res) == 0

        res = list(self.rop.Start({"ecx": Exp("1111")}))
        assert len(res) == 1 and len(res[0].gadgets) == 2  and res[0].getAddress() == [4, 5] 

        res = list(self.rop.Start({"ebx": Exp("1")}))
        assert len(res) == 2 and len(res[0].gadgets) == 2 and len(res[1].gadgets) == 2 and ( (res[0].getAddress() == [1, 3] and res[1].getAddress() == [2, 3])  or ( res[1].getAddress() == [1, 3] and res[2].getAddress() == [2, 3]) )

class ROPChainTestCase2(unittest.TestCase):

    def setUp(self):
        gadget7 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":7},  {"mnemonic":"ret", "op_str":"", "vaddr":7}]
        gadget1 = [{"mnemonic":"mov", "op_str":"ecx, ebx", "vaddr":1},  {"mnemonic":"call", "op_str":"eax", "vaddr":9}]

        gadgets = [gadget1, gadget7]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 4)
    
    def testCOP(self):
        print "Testing COP gadgets..........................................."

        res = list(self.rop.Start({"ecx": Exp("ebx")}))
        assert len(res) == 1 and ( res[0].getAddress() == [7, 1])

class ROPChainTestCase3(unittest.TestCase):

    def setUp(self):
        gadget6 = [{"mnemonic":"stc", "op_str":"", "vaddr":6},      {"mnemonic":"ret", "op_str": "", "vaddr":"6"}]
        gadget7 = [{"mnemonic":"pop", "op_str":"eax", "vaddr":7},  {"mnemonic":"ret", "op_str":"", "vaddr":7}]
        gadget9 = [{"mnemonic":"cmovb", "op_str":"edx, ecx", "vaddr":9},  {"mnemonic":"jc", "op_str":"eax", "vaddr":9}]

        gadgets = [gadget6, gadget9, gadget7]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 4)

    def testJOP(self):
        print "Testing JOP gadgets..........................................."

        res = list(self.rop.Start({"edx": Exp("ecx")}))
        assert len(res) == 1 and ( res[0].getAddress() == [7, 6, 9] or res[0].getAddress() == [6, 7 , 9])

class ROPChainTestCase4(unittest.TestCase):

    def setUp(self):
        gadget1 = [{"mnemonic":"mov", "op_str":"al, 1", "vaddr":1},      {"mnemonic":"ret", "op_str": "", "vaddr":"1"}]
        gadget2 = [{"mnemonic":"mov", "op_str":"ah, 1", "vaddr":2},  {"mnemonic":"ret", "op_str":"", "vaddr":2}]
        gadget3 = [{"mnemonic":"mov", "op_str":"eax, 0", "vaddr":3},  {"mnemonic":"ret", "op_str":"", "vaddr":3}]

        gadgets = [gadget1, gadget2, gadget3]
        self.rop = ROPChain(BinaryStub(), gadgets, False, 1)

    def testSubRegs(self):
        print "Testing sub regs gadgets..........................................."
        exp = Exp(1)
        exp.length = 32
        res = list(self.rop.Start({"eax": exp}))
        assert len(res) == 1 and res[0].getAddress() == [3, 1]

        self.rop.deepth = 2
        exp = Exp(257)
        exp.length = 32
        res = list(self.rop.Start({"eax": exp}))
        assert len(res) == 2 and ( (res[0].getAddress() == [3, 1, 2] and res[1].getAddress() == [3, 2, 1]) or (res[0].getAddress() == [3, 2, 1] and res[1].getAddress() == [3, 1, 2]))

if __name__ == "__main__":
    unittest.main()
