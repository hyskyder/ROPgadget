#!/usr/bin/env python2
from copy import deepcopy
'''
		Primary-Expression:
			Register
			Constant
			Address

		Unary-Expression:
			unary-op Expression
			unary-op Expression

		Unary-op:
			* & + - ~

		Binary-Expression:
			Expression Binary-op Expression

		Binary-op:
			&& || + - % & | ^ >> << == != > >= < <= $ #

		Conditional-Expression:
			Expression ? Expression : Expression;

                A $ B : C is defined as take the Bth bit to Cth bit of A  #( Note: range: right-MSB 31 : 0 left-LSB  ; z3 also uses 31:0 )
                A # B is defined as concat A and B
'''
class Exp:
    unaryOp = ["-", "*", "+", "&", "~", "C", "A", "P", "Z", "I", "O", "D", "S"]
    binOp = {"*":1, "%":1, "/":1, "+":2, "-":2, ">>":3, "<<":3, "<":4, "<=":4, ">":4, ">=":4, "==":5, "!=":5, "&":6, "^":7, "|":8, "&&":9, "||":10, "?":11, "$":11, "#":11, "=":12}
    defaultLength = 32
    def __init__(self, left, op=None, right=None, condition=None):
        if isinstance(left, unicode) and ( left == u"esp" or left == u"rsp") and op is not None:
            self.left = Exp(left)
            self.right = right		
            self.condition = condition			
            self.op = op		
        elif condition != None:			
            self.left = left			
            self.right = right		
            self.condition = condition			
            self.op = op		
        else:			
            self.op = op			
            self.left = left			
            self.right = right			
            self.condition = condition            
        
        # default size for constant
        self.length = 0
        if len(str(left)) == 3 and "r" in str(left):
            self.length = 64
        elif len(str(left)) == 3 and "e" in str(left):
            self.length = 32
        elif len(str(left)) == 2 and "x" in str(left):
            self.length = 16
        elif len(str(left)) == 2 and ( "h" in str(left) or "l" in str(left)):
            self.length = 8
        elif len(str(left)) == 2 and "F" in str(left):
            self.length = 1
        elif self.op == '$':
            self.length = int(str(right)) - int(str(left)) + 1
        elif self.op == '#':
            self.length = left.length + right.length
        else:
            if isinstance(left, Exp):
                self.length = max(left.length, self.length)
            if isinstance(right, Exp):
                self.length = max(right.length, self.length)

        '''
        if isinstance(left, Exp):
            self.size = max(self.size, left.size)
        elif not isinstance(left, str):
            pass
        elif left[0] == 'e':
            self.size = max(self.size, 32)
        elif left[0] == 'r':
            self.size = max(self.size, 64)
        '''

    def showLength(self, exp):
        if not isinstance(exp, Exp):
            return str(exp)
        elif exp.condition is not None and exp.op == "condition":
            return "( " + self.showLength(exp.condition)  + " ? " + self.showLength(exp.left) + " : " + self.showLength(exp.right) + " )-" + str(exp.length)
        elif exp.condition is not None:
            return "( " + self.showLength(exp.condition)  + " $ " + self.showLength(exp.left) + " : " + self.showLength(exp.right) + " )-" + str(exp.length)
        elif exp.right is not None:
            return "( " + self.showLength(exp.left) + " " + exp.op + " " + self.showLength(exp.right) + " )"
        elif exp.op is not None:
            if exp.op == '*':
                return "[ " + self.showLength(exp.left) + " ]-" + str(exp.length)
            return exp.op +"( " + self.showLength(exp.left) + " " + " )-" + str(exp.length)
        return self.showLength(exp.left) +"-" + str(exp.length)

    def __str__(self):
        if self.condition is not None:
            if self.op == "condition":
                return "( "+str(self.condition)+" ? " + str(self.left) + " : " + str(self.right)+" )"
            else:
                return "( "+str(self.condition)+" $ " + str(self.left) + " : " + str(self.right)+" )"
        else:
            if self.right is not None:
                return "( " + str(self.left) + " " + self.op + " " + str(self.right) + " )"
            elif self.op is not None:
                if self.op == "*":
                    return "[ " + str(self.left) + " ]"
                return  "( " + self.op + " " + str(self.left) + " )"
            else:
                return str(self.left)

    # return True if this is conditional exp
    def isCond(self):
        if self.op is not None and self.op == "condition":
            return True
        cond = False
        if isinstance(self.left, Exp):
            cond |= self.left.isCond()
        if isinstance(self.right, Exp):
            cond |= self.right.isCond()
        return cond

    # return True if exp is Mem determined by esp only
    def isControl(self):
        if self.op is not None and self.op == "condition":
            return self.condition.isControl() 

        if self.getCategory() != 3:
            return False

        if self.right is None:
            if self.op is not None and self.op == "*":
                return len(self.getRegs()) == 1 and ( self.getRegs()[0] == "esp" or self.getRegs()[0] == "rsp")
            else:
                return isinstance(self.left, Exp) and self.left.isControl()
        else:
            if isinstance(self.left, Exp) and isinstance(self.right, Exp):
                return self.left.isControl() and self.right.isControl()
            elif isinstance(self.left, Exp):
                return self.left.isControl() and self.isInt(self.right)
            elif isinstance(self.right, Exp):
                return self.right.isControl() and self.isInt(self.left)

    # expr category is defined as follows:
    # 0 == Constant, 1 == Reg, 2 == Regs, 3 == Mem, 4 == Mem + Regs, 5 == condition (TO BE DETERMINED)
    def getCategory(self):
        # TODO: for conditional val
        if self.isCond():
            return 5
        if self.condition is not None and self.op == '$':
            return self.condition.getCategory()

        left = 0
        right = 0
        if not isinstance(self.left, Exp):
            if not self.isInt(self.left):
                left = 1
        else:
            left = self.left.getCategory()

        if not isinstance(self.right, Exp):
            if not self.isInt(self.right):
                right = 1
        else:
            right = self.right.getCategory()

        if self.right is None:
            if self.op == '&':
                return left
            elif self.op == '*':
                return 3

        if left < 3 and right < 3:
            if left == 1 and right == 1 and self.left.getRegs() != self.right.getRegs():
                return 2
            return max(left, right)
        if left == 3 and right == 3:
            return 3
        return min(4, left + right)

    def getRegs(self):
        regs = set()
        s = str(self).split()
        for reg in s:
            if u"s" in reg or u"r" in reg or (u"e" in reg and "0x" not in reg)  or u"F" in reg:
                regs.add(reg)
        return list(regs)
    
    def isConstant(self):
        constant = True
        if isinstance(self.left, Exp):
            constant &= self.left.isConstant()
        elif not self.isInt(self.left):
            constant = False

        if isinstance(self.right, Exp):
            constant &= self.right.isConstant()
        elif not self.isInt(self.right):
            constant = False

        if isinstance(self.condition, Exp):
            constant &= self.condition.isConstant()
        elif not self.isInt(self.condition):
            constant = False

        return constant
    
    def equals(self, exp):
        equal = True
        if not isinstance(exp, Exp):
            return False
        if isinstance(self.left, Exp):
            equal &= self.left.equals(exp.left)
        else:
            equal &= self.left == exp.left

        if isinstance(self.right, Exp):
            equal &= self.right.equals(exp.right)
        else:
            equal &= self.right == exp.right

        if isinstance(self.condition, Exp):
            equal &= self.condition.equals(exp.condition)
        else:
            equal &= self.condition == exp.condition
        return equal

    def isInt(self, string):
        if string is None:
            return True 
        try:
            if (isinstance(string, str) or isinstance(string, unicode))and u"0x" in string:
                int(string, 16)
            else:
                int(string)
            return True
        except ValueError:
            return False

    def getCondition(self):
        # return the first condition we encounter
        if self.op is not None and self.op == "condition":
            return self.condition
        if isinstance(self.left, Exp) and self.left.isCond():
            return self.left.getCondition()
        if isinstance(self.right, Exp) and self.right.isCond():
            return self.right.getCondition()
        return None
    
    def meetCondition(self):
        # return new exp with the first condition meet
        if self.condition is not None:
            if self.op == "condition":
                return self.left
            else:
                self.condition = self.condition.meetCondition()
                return self
        if isinstance(self.left, Exp) and self.left.isCond():
            self.left = self.left.meetCondition()
            return self
        if isinstance(self.right, Exp) and self.right.isCond():
            self.right = self.right.meetCondition()
            return self
        return self

    def __repr__(self):
        return '<%s.%s object at %s>' % (
                self.__class__.__module__,
                self.__class__.__name__,
                hex(id(self))
                )

    def binding(self, mapping):
        if ( self.getCategory() == 3 and str(self) in mapping.keys() ) or (not isinstance(self.left, Exp) and self.left in mapping.keys()):
            exp = deepcopy(mapping[str(self)])
            exp.length = max(self.length, mapping[str(self)].length)
            return exp
        '''
        left = True 
        right = True
        condition = True
        for k,v in mapping.items():
            if k == str(self.left):
                self.left = deepcopy(v)
                left = False
            if k == str(self.right):
                self.right = deepcopy(v)
                right = False
            if k == str(self.condition):
                self.condition = deepcopy(v)
                condition = False
        '''
        if isinstance(self.left, Exp):
            self.left = self.left.binding(mapping)
        if isinstance(self.right, Exp):
            self.right = self.right.binding(mapping)
        if isinstance(self.condition, Exp):
            self.condition = self.condition.binding(mapping)

        if self.op is not None and (self.op == '$' or self.op == '#') :
            pass
        else:
            if isinstance(self.left, Exp) and self.length == 0:
                self.length = max(self.length, self.left.length)
            if isinstance(self.right, Exp) and self.length == 0:
                self.length = max(self.length, self.right.length)
            if self.condition is not None and isinstance(self.condition, Exp) and self.length == 0:
                self.length = max(self.length, self.condition.length)
        return self

    @staticmethod
    def parseOperand(string, regs, Tregs):
        # Operand can be immediate val or reg or memory location
        if len(string) == 0:
            return None
        if string.find("[") == -1:
            try:
                # constant
                return Exp(int(string, 16))
            except ValueError:
                # sub register
                if string in Tregs.keys():
                    exp = Exp.parseExp(Tregs[string][0].split())
                    exp = exp.binding(regs)
                    exp.length = Tregs[string][2]
                    return exp
                exp = Exp(string)
                if string in regs.keys():
                    exp = exp.binding(regs)
                return exp
        else:
            # mem
            byte = string.split(" ptr ")[0]
            size = 0
            if byte == "qword":
                size = 64
            elif byte == "dword":
                size = 32
            elif byte == "word":
                size = 16
            elif byte == "byte":
                size = 8
            s = string.split("[")[1][:-1]
            s = s.replace("*", " * ")
            exp = Exp(Exp.parseExp(s.split()), "*")
            if str(exp) in regs.keys():
                if isinstance(regs[str(exp)], Exp) and regs[str(exp)].length != size:
                    return None
                exp = regs[str(exp)]
            exp.length = size
            return exp

    @staticmethod
    def parseExp(tokens):
        exp = Exp.parseUnaryExp(tokens)
        if len(tokens) == 0:
            return exp
        exp = Exp.parseBinExp(exp, tokens, 12)
        return exp

    @staticmethod
    def parseUnaryExp(tokens):
        if tokens[0] in Exp.unaryOp:
            op = tokens.pop(0)
            return Exp(Exp.parseUnaryExp(tokens),op)

        if tokens[0] == "(":
            tokens.pop(0)
            exp = Exp.parseExp(tokens)
            tokens.pop(0)
            return exp

        left = tokens.pop(0)
        return Exp(left)

    @staticmethod
    def parseBinExp(left, tokens, prec):
        while len(tokens) != 0:
            if tokens[0] == "?":
                tokens.pop(0)
                mid = Exp.parseExp(tokens)
                tokens.pop(0)
                right = Exp.parseExp(tokens)
                left = Exp(mid, "condition", right, left)
            elif tokens[0] == "$":
                tokens.pop(0)
                mid = Exp.parseExp(tokens)
                tokens.pop(0)
                right = Exp.parseExp(tokens)
                left = Exp(mid, "$", right, left)
            elif tokens[0] in Exp.binOp.keys():
                op = tokens.pop(0)
                right = Exp.parseUnaryExp(tokens)
                nextOp = None
                if len(tokens) != 0:
                    nextOp = tokens[0]

                if nextOp == None or nextOp == ")" or Exp.binOp.get(op) <= Exp.binOp.get(nextOp):
                    left = Exp(left, op, right)
                else:
                    right = Exp.parseBinExp(right, tokens, Exp.binOp.get(op))
                    left = Exp(left, op, right)
            else:
                break

        return left

    @staticmethod
    def parse(string, operands):
        # dst is either the operand, regs or memory location
        # Ex: operand1 = operand1 + operand2 or [esp] = operand1 
        reg = string.split(" = ")[0]
        val = string.split(" = ")[1]
        exp = Exp.parseExp(val.split()[:])

        if operands != None and reg in operands.keys():
            exp.length = operands[reg].length

        if operands != None:
            if isinstance(exp, Exp):
                exp = exp.binding(operands)
            elif exp in operands.keys():
                exp = operands[exp]

        if not isinstance(exp, Exp):
            exp = Exp(exp)
        if operands is not None and "operand1" in operands.keys():
            exp.length = operands["operand1"].length
        return {reg:exp}

    @staticmethod
    def ExpL(size, left, op=None, right=None, condition=None):
        exp = Exp(left, op, right, condition)
        exp.length = size
        return exp
