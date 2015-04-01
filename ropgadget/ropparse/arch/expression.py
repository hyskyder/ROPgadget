#!/usr/bin/env python2
class Exp:

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
			&& || + - % & | ^ >> << == != > >= < <= $

		Conditional-Expression:
			Expression ? Expression : Expression;

                A $ B : C is defined as take the Bth bit to Cth bit of A
	'''
	# operator precedence, unary always first
	unaryOp = ["-", "*", "+", "&", "~"]
	binOp = {"*":1, "%":1, "/":1, "+":2, "-":2, ">>":3, "<<":3, "<":4, "<=":4, ">":4, ">=":4, "==":5, "!=":5, "&":6, "^":7, "|":8, "&&":9, "||":10, "?":11, "$":11, "=":12}
	def __init__(self, left, op=None, right=None, condition=None):
			if condition != None:
				self.left = left
				self.right = right
				self.condition = condition
				self.op = op
			else:
				self.op = op
				self.left = left
				self.right = right
				self.condition = condition

        def __str__(self):
            if self.condition is not None:
                if self.op == "condition":
                    return "("+str(self.condition)+"?" + str(self.left) + ":" + str(self.right)+")"
                else:
                    return "("+str(self.condition)+"$" + str(self.left) + ":" + str(self.right)+")"
            else:
                if self.right is not None:
                    return "(" + str(self.left)+ self.op + str(self.right) + ")"
                elif self.op is not None:
                    if self.op == "*":
                        return "[" + str(self.left) + "]"
                    return  "(" + self.op + str(self.left) + ")"
                else:
                    return str(self.left)

    	def checkBound(self, regs, insts, addr, operand):
            try:
                naddr = addr + int(operand)
                for index in range(len(insts)):
                    if insts[index]["vaddr"] == naddr:
                        return index
                return -1
            except ValueError:
                return -1

        # return True if exp is Mem determined by esp only
        def isControl(self):
            if self.condition is not None:
                return self.condition.isControl()

            if self.getCategory() != 3:
                return False

            if self.right is None:
                if self.op is not None and self.op == "*":
                    return len(self.getRegs()) == 1 and self.getRegs()[0] == "ssp"
                else:
                    return self.left.isControl()
            else:
                return (exp.left.isControl() and exp.right.getCategory() == 0 ) or (exp.right.isControl() and exp.left.getCategory() == 0)

        # expr category is defined as follows:
        # 0 == Constant, 1 == Reg, 2 == Regs, 3 == Mem, 4 == Mem + Regs
        def getCategory(self):
            if self.condition is not None:
                if isinstance(self.condition, Exp):
                    return self.condition.getCategory()
                elif not self.isInt(self.condition):
                    return 1
                else:
                    return 0

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
                if left == 1 and right == 1:
                    return 2
                return max(left, right)
            return max(4, left + right)

        def getRegs(self):
            regs = []
            if self.left == None:
                pass
            elif isinstance(self.left, Exp):
                regs.extend(self.left.getRegs())
            elif not self.isInt(self.left):
                regs.append(self.left)

            if self.right == None:
                pass
            elif isinstance(self.right, Exp):
                regs.extend(self.right.getRegs())
            elif not self.isInt(self.right):
                regs.append(self.right)

            if self.condition== None:
                pass
            elif isinstance(self.condition, Exp):
                regs.extend(self.condition.getRegs())
            elif not self.isInt(self.condition):
                regs.append(self.condition)
            return list(set(regs))
        
    	def getDest(self):
            if self.op == "=":
                if isinstance(self.left, Exp):
                    return self.left.getOperand1()
                else:
                    return self.left
            return ""

        def isAssign(self):
            return self.op == "="
        
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
                int(string)
                return True
            except ValueError:
                return False

        def getSrc(self):
            return self.right

    	def getCondition(self):
		return self.condition

        def getOperand1(self):
            return self.left

        def getOperand2(self):
            return self.right


        def binding(self, mapping):
            left = True 
            right = True
            condition = True
            for k,v in mapping.items():
                if k == self.left:
                    self.left = v
                    left = False
                if k == self.right:
                    self.right = v
                    right = False
                if k == self.condition:
                    self.condition = v
                    condition = False

            if left and isinstance(self.left, Exp):
                self.left.binding(mapping)
            if right and isinstance(self.right, Exp):
                self.right.binding(mapping)
            if condition and isinstance(self.condition, Exp):
                self.condition.binding(mapping)

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
                    # register
                    if string in Tregs.keys():
                        exp = Exp.parseExp(Tregs[string][0].split()).getSrc()
                        exp.binding(regs)
                        return exp
                    exp = Exp(string)
                    if string in regs.keys():
                        exp.binding(regs)
                    return exp
            else:
                # mem
                s = string.split("[")[1][:-1]
                s = s.replace("*", " * ")
                exp = Exp(Exp.parseExp(s.split()), "*")
                if str(exp) in regs.keys():
                    exp = regs[str(exp)]
                return exp

        @staticmethod
        def parseExp(tokens):
            exp = Exp.parseUnaryExp(tokens)
            if len(tokens) == 0:
                return exp
            exp = Exp.parseBinExp(exp, tokens, 12)
            if isinstance(exp, Exp):
                return exp
            return Exp(exp)

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
            return left

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
                    left = Exp(mid, "bits", right, left)
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
                reg = str(operands[reg])

            if operands != None:
                if isinstance(exp, Exp):
                    exp.binding(operands)
                elif exp in operands.keys():
                    exp = operands[exp]

            return {reg:exp}



if __name__ == '__main__':
    a = Exp(1,"-")
    b = Exp("EAX")
    b.binding({"EAX":Exp("EAX", "+", 4)})
    print b
    c = Exp("EBX", "==", 4)
    print c
    d = Exp(a, "condition", b, c)
    print d
    print Exp(4, "+" , 1)
    print Exp(a, "^" , 1)
    print Exp("esp", "*")
    e = Exp("b", "&" , 0xffff)
    print e
    e.binding({"b":b})
    print e
    print Exp( Exp("EAX", ">>" , d ) , "+" , Exp("c", "-" ,1) )
    print Exp.parseOperand("byte ptr [rax + 0x15]", {}, {})
    print Exp.parseOperand("byte ptr [rax + 0xffffffffffffff83]", {}, {})
    print Exp.parseOperand("cl",{"cl":1},{})
    exps = Exp.parse(["operand1 = operand2"], { "operand1":Exp("eax"), "operand2":Exp("ebx")})
    for k,v in exps.items():
        print k, "==>", v
    exps = Exp.parse(["operand1 = operand1 + operand2 + ( CF == 0 ) ? 1 : 0"], {"operand1":Exp("eax"), "operand2":Exp(4)})
    for k,v in exps.items():
        print k, "==>", v
    exps = Exp.parse(["operand1 = ( operand2 - 1 ) $ 8 : 15", "esp = esp + 4"], {"operand1":Exp("ax"), "operand2":Exp("ecx")})
    for k,v in exps.items():
        print k, "==>", v
    exps = Exp.parse(["operand1 = operand2 $ 0 : 15"], {"operand1":Exp("ax"), "operand2":Exp("eax")})
    for k,v in exps.items():
        print k, "==>", v

