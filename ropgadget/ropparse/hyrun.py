from ropchain import *


class BinaryStub():
    def __init__(self):
        pass
        
    def getArch(self):
        return CS_ARCH_X86

    def getArchMode(self):
        return CS_MODE_32

def gen_gadget(addr_hex,inst_list):
    insnslist=[]
    for inst_str in inst_list:
        splt = inst_str.split(" ", 1)
        item={"mnemonic": splt[0], "op_str": splt[1] if len(splt)>1 else ""}
        insnslist.append(item)
    gdt={"insns": insnslist, "vaddr": int(addr_hex,16)}
    return gdt

def ReadGdtFile(gdt_pool):
    with open('libc.BBB-CFI-pass.log') as fp:
        line_conut=0;
        for line in fp:
            addr=line[0:10]
            inst_list=(line[13:-1]).split(" ; ")
            gdt_pool.append(gen_gadget(addr,inst_list))
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(gdt_pool)
    print "Num loaded Gadgets = " + str(len(gdt_pool))


if __name__ == "__main__":
    gdt_pool=[]
    ReadGdtFile(gdt_pool)
    chaintool = ROPChain(BinaryStub(), gdt_pool, False, 1)
    """
    chaintool.process_cmd("set length 1")
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
        print "\n ===============================  " + reg
        chaintool.start({reg: Exp.ExpL(32, 1)})

    chaintool.process_cmd("set length 2")
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
        print "\n ===============================  " + reg
        chaintool.start({reg: Exp.ExpL(32, 1)})

    chaintool.process_cmd("set length 3")
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
        print "\n ===============================  " + reg
        chaintool.start({reg: Exp.ExpL(32, 1)})
    """
    chaintool.process_cmd("set length 1")
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
        print "\n ===============================  " + reg
        chaintool.start({reg: Exp(Exp(reg), "+", Exp.ExpL(32, 1))})

    chaintool.process_cmd("set length 2")
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
        print "\n ===============================  " + reg
        chaintool.start({reg: Exp(Exp(reg), "+", Exp.ExpL(32, 1))})

    chaintool.process_cmd("set length 3")
    for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
        print "\n ===============================  " + reg
        chaintool.start({reg: Exp(Exp(reg), "+", Exp.ExpL(32, 1))})