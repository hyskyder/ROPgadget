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
			&& || + - % & | ^ >> << == != > >= < <= 

		Conditional-Expression:
			Expression ? Expression : Expression;
	'''
        # operator precedence, unary always first
        unaryOp = ["-", "*", "+", "&", "~"]
        binOp = {"*":1, "%":1, "/":1, "+":2, "-":2, ">>":3, "<<":3, "<":4, "<=":4, ">":4, ">=":4, "==":5, "!=":5, "&":6, "^":7, "|":8, "&&":9, "||":10, "?":11, "=":12}

	def __init__(self, left, op=None, right=None, condition=None):
		if condition != None:
			self.left = left
			self.right = right
			self.condition = condition
		else:
                        self.op = op
			self.left = left
                        self.right = right
                        self.condition = condition 

        def __str__(self):
            if self.condition is not None:
                return "("+str(self.condition)+"?" + str(self.left) + ":" + str(self.right)+")"
            else:
                if self.right is not None:
                    return "(" + str(self.left)+ self.op + str(self.right) + ")"
                elif self.op is not None:
                    if self.op == "*":
                        return "[" + str(self.left) + "]"
                    return  "(" + self.op + str(self.left) + ")" 
                else:
                    return str(self.left)

	def reduce(self):
            pass

        def binding(self, mapping):
            if isinstance(self.left, Exp):
                self.left.binding(mapping)
            if isinstance(self.right, Exp):
                self.right.binding(mapping)
            if isinstance(self.condition, Exp):
                self.condition.binding(mapping)
            
            for k,v in mapping.items():
                if k == self.left:
                    self.left = v
                if k == self.right:
                    self.right = v
                if k == self.condition:
                    self.condition = v

        @staticmethod
        def parseOperand(string, regs):
            # Operand can be immediate val or reg or memory location
	    # Ex: mov eax, 1 	mov ebx, [eax + edi*4 + 0x14]
            if string.find("[") == -1:
                if string in regs:
                    return Exp(string)
                else:
                    return Exp(int(string, 16))
            else:
                s = string.split("[")[1][:-1]
                s = s.replace("*", " * ")

		# convert string to exp class
		# here we only can have operator like '*' or '+'
                rpn = []
                oprator = []
                for val in s.split():
                    if val != "+" and val != "*":
                        if val in regs:
                            rpn.append(Exp(val))
                        else:
                            rpn.append(int(val,16))
                    elif len(oprator) == 0:
                        oprator.append(val)
                    elif oprator[-1] == "+"  and val == "*":
                        oprator.append(val)
                    else:
                        exp = Exp(rpn.pop(), oprator.pop(), rpn.pop())
                        rpn.append(exp)

                while len(oprator) != 0:
                    exp = Exp(rpn.pop(), oprator.pop(), rpn.pop())
                    rpn.append(exp)
                exp = Exp(exp, "*")
                return exp
        @staticmethod
        def parseExp(tokens):
            exp = Exp.parseUnaryExp(tokens)
            if len(tokens) == 0:
                return exp
            return Exp.parseBinExp(exp, tokens, 12) 

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
            exps = {}
            for s in string:
                # dst is either the operand1, regs or memory location
                # Ex: operand1 = operand1 + operand2 or [esp] = operand1 or esp = esp + length
                dst = s.split()[0]
                if dst == "operand1":
                    dst = str(operands["operand1"])

		# parse string into Exp
		# Ex: operand1 = operand1 + operand2 + (CF == 1) ? 1 : 0
                exp = Exp.parseExp(s.split()[2:])
                for k,v in operands.items():
                    if isinstance(exp, Exp):
                        exp.binding({k:v})
                    elif exp == k:
                        exp = v

                exps.update({dst:exp})
            return exps



if __name__ == '__main__':
    a = Exp(1,"-")
    b = Exp("EAX")
    b.binding({"EAX":Exp("EAX", "+", 4)})
    print b
    c = Exp("EBX", "==", 4)
    print c
    d = Exp(a, "conditon", b, c)
    print d
    print Exp(4, "+" , 1)
    print Exp(a, "^" , 1)
    print Exp("esp", "*")
    e = Exp("b", "&" , 0xffff)
    print e
    e.binding({"b":b})
    print e
    print Exp( Exp("EAX", ">>" , d ) , "+" , Exp("c", "-" ,1) )
    print Exp.parseOperand("byte ptr [rax + 0x15]", ["rax"])
    print Exp.parseOperand("byte ptr [rax + 0xffffffffffffff83]", ["rax"])
    print Exp.parseOperand("cl",["cl"])
    print Exp.parseOperand("1",["cl"])
    print Exp.parseOperand("dword ptr [rdx + r12*4]",["rdx", "r12"])
    exps = Exp.parse(["operand1 = operand2"], { "operand1":Exp("eax"), "operand2":Exp("ebx")})
    for k,v in exps.items():
        print k
        print v
    exps = Exp.parse(["operand1 = operand1 + operand2 + ( CF == 0 ) ? 1 : 0"], {"operand1":Exp("eax"), "operand2":Exp(4)})
    for k,v in exps.items():
        print k
        print v


