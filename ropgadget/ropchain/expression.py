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
			&& || + - % & |  ~ ^ >> << == != > >= < <=

		Conditional-Expression:
			Expression ? Expression : Expression;
			
	'''
	def __init__(self, left, op=None, right=None, condition=None):
		if conditon != None:
			self.__left = left
			self.__right = right
			self.__condition = condition
		else:
			self.__left = left
			if op != None:
				self.__right = right
				self.__op = op
	
	def reduce(self):
		pass






