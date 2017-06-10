#!/usr/bin/env python2
import sys, traceback
from copy import deepcopy

class Semantic:
    def __init__(self, regs, addr, memLoc=[], writeMem={}):
        self.addrs = []
        self.addrs.append(hex(int(addr)))
        self.rets = []
        if "sip" in regs.keys():
            self.rets.append(regs["sip"])
        self.regs = regs
        self.deepth = 1
        self.stack = {}
        self.memLoc = memLoc
        self.writeMem = writeMem

    def binding(self, prev):
        if prev is None:
            return 
        for k, v in self.regs.items():
            v = v.binding(prev.regs)
            self.regs.update({k:v})

    def chain(self, semantic): 
        #print self, semantic
        if semantic is None:
            return
        
        ####### Replacing the following
        #temp = []
        #temp.extend(semantic.addrs)
        #temp.extend(self.addrs)
        #self.addrs = temp
        ####### By:
        self.addrs = semantic.addrs + self.addrs
        # all the gadgets addrs

        for k,v in self.regs.items(): 
            t = deepcopy(v)
            t = t.binding(semantic.regs)
            self.regs.update({k:t})
        for k,v in semantic.regs.items():
            if k not in self.regs.keys():
                self.regs.update({k:v})

        # all the ret addrs in stack of gadgets
        temp = []
        ssp = semantic.regs["ssp"]
        temp.extend(semantic.rets)
        for ret in self.rets:
            temp.append(ret.binding(semantic.regs))
        self.rets = temp
        self.deepth = self.deepth + semantic.deepth
    
    def getAddress(self):
        return deepcopy(self.addrs)

    def __str__(self):
        #string = ""
        #for i in range(len(self.addrs)):
        #    string += (self.addrs[i]) + "\n"
        return " -> ".join(self.addrs)

    def __eq__(self, other):
        if self.deepth != other.deepth:
            return False
        for i in range(self.deepth):
            if self.addrs[i] != other.addrs[i]:
                return False
        return True
    
    def __hash__(self):
        return hash(str(self.addrs))

