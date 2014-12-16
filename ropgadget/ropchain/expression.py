#!/usr/bin/env python2

class Expression:

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
                    return  self.op + str(self.left) 
                else:
                    return str(self.left)

        def binding(self, mapping):
            if type(self.left) is Expression:
                self.left.binding(mapping)
            if type(self.right) is Expression:
                self.right.binding(mapping)
            if type(self.condition) is Expression:
                self.condition.binding(mapping)
            
            for k,v in mapping.items():
                if k == self.left:
                    self.left = v
                if k == self.right:
                    self.right = v
                if k == self.condition:
                    self.condition = v

	def reduce(self):
            pass

if __name__ == '__main__':
    a = Expression(1,"-")
    b = Expression("EAX")
    b.binding({"EAX":Expression("EAX", "+", 4)})
    print b
    c = Expression("EBX", "==", 4)
    print c
    d = Expression(a, "conditon", b, c)
    print d
    print Expression(4, "+" , 1)
    print Expression(a, "^" , 1)
    e = Expression("b", "&" , 0xffff)
    print e
    e.binding({"b":b})
    print e
    print Expression( Expression("EAX", ">>" , d ) , "+" , Expression("c", "-" ,1) )
