#!/usr/bin/env python2
import sys, traceback
from copy import deepcopy

class Semantic:
    def __init__(self, regs, gadget):
        self.gadgets = []
        self.gadgets.append(gadget)
        self.regs = regs
        self.deepth = 1

    def binding(self, prev):
        if prev is None:
            return 
        for k, v in self.regs.items():
            v.binding(prev)
            self.regs.update({k:v})

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
            t = deepcopy(v)
            t.binding(semantic.regs)
            self.regs.update({k:t})
        for k,v in semantic.regs.items():
            if k not in self.regs.keys():
                self.regs.update({k:v})
        self.deepth = self.deepth + semantic.deepth
    
    def getAddress(self):
        addrs = []
        for g in self.gadgets:
            addrs.append(g[0]["vaddr"])
        return addrs

    def __str__(self):
        string = "length:" + str(self.deepth) + "\n"
        for g in self.gadgets:
            string += hex(g[0]["vaddr"]) + "\n" 
            temp = ""
            for inst in g:
                temp += inst["mnemonic"] + ", " + inst["op_str"] + "\n"
            string += temp

        for reg, val in self.regs.items():
            string += str(reg) + "\t======>\t" + str(val) + "\n"
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

