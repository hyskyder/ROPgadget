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
			^ & + - ~ ! *

		Binary-Expression:
			Expression Binary-op Expression

		Binary-op:
			&& || + - % & |  ~ ^ >> << == != > >= < <= = 

		Conditional-Expression:
			Expression ? Expression : Expression;
			
	'''

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
                    return  self.op + str(self.left) 
                else:
                    return str(self.left)

        def binding(self, mapping):
            if type(self.left) is Exp:
                self.left.binding(mapping)
            if type(self.right) is Exp:
                self.right.binding(mapping)
            if type(self.condition) is Exp:
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
            if string.find(" ") == -1:
                # immediate val or reg
                if string in regs:
                    return Exp(string)
                else:
                    return Exp(int(string, 16))
            else:
                # memory location
                s = string.split("[")[1][:-1]
                # NOTE: the format is [rax + rbx*4 + 0x199]
                s = s.replace("*", " * ")

                # convert this by reverse polish notation
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
        def parse(string, mapping):
            exps = {}
            for s in string:
                # dst is either the operand1, regs or memory location
                # Ex: operand1 = operand1 + operand2 or [esp] = operand1 or esp = esp + 4
                dst = s.split()[0]
                if dst == "operand1":
                    dst = str(mapping["operand1"])

                rpn = []
                oprator = []
                for e in s.split()[2:]:
                    if s == 
                
                exps.update({dst:exp})
            return exps


	def reduce(self):
            pass

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
    print Exp.parseOperand("byte ptr [rax + 0xffffffffffffff83]" ,"rax")
    print Exp.parseOperand("cl","cl")
    print Exp.parseOperand("1","cl")
    print Exp.parseOperand("dword ptr [rdx + r12*4]",["rdx", "r12"])
    print Exp.parse("operand1 = operand2", { "operand1":Exp("eax"), "operand2":Exp("ebx")})
    print Exp.parse("operand1 = operand1 + operand2", {"operand1":Exp("eax"), "operand2":Exp(4)})


