#!/usr/bin/env python2
import sys, traceback

class Semantic:
    def __init__(self, regs, gadget):
        self.gadgets = []
        self.gadgets.append(gadget)
        self.regs = regs
        self.deepth = 1

    def chain(self, semantic): 
        #print "chaing two semantic ........................."
        #print self, semantic
        if semantic is None:
            return
        temp = []
        temp.extend(semantic.gadgets)
        temp.extend(self.gadgets)
        self.gadgets = temp
        for k,v in self.regs.items(): 
            v.binding(semantic.regs)
        for k,v in semantic.regs.items():
            if k not in self.regs.keys():
                self.regs.update({k:v})
        self.deepth = self.deepth + semantic.deepth
        #print self

    def __str__(self):
        string = "length:" + str(self.deepth) + "\n"
        for g in self.gadgets:
            string += str(g[0]["vaddr"]) + "\t" 
        string += "\n"
        for k,v in self.regs.items():
            string += k + " ==> " + str(v) + "\t"
        string += "\n"
        return string

    def __eq__(self, other):
        if self.deepth != other.deepth:
            return False
        for i in range(self.deepth):
            if self.gadgets[i]["vaddr"] != other.gadgets[i]["vaddr"]:
                return False
        return True
    
    def __hash__(self):
        return hash(str(self.gadgets))

