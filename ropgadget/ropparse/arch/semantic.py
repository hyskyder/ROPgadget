#!/usr/bin/env python2

class Semantic:
    def __init__(self, regs, gadget):
        self.gadgets = []
        self.gadgets.append(gadget)
        self.regs = regs
        self.deepth = 0

    def chain(self, semantic): 
        for gadget in semantic.gadgets: 
            self.gadgets.append(gadget) 
        for k,v in semantic.regs.items(): 
            v.binding(self.regs) 
        self.deepth = self.deepth + 1

    def __str__(self):
        for k,v in self.regs.items():
            print k, v

