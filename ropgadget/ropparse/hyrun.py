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

    if 1:
        for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
            print "\n === Search Stack =================  " + reg
            for length in ["1","2","3","4","5","6"]:
                chaintool.process_cmd("set length "+length)
                chaintool.process_cmd("search "+reg+" stack")

    #for reg in ["al", "bl", "cl", "dl"]:
    #for reg in ["(eax $ 8 : 1)", "(ebx $ 8 : 1)"]:#, "ecx $ 8 : 1", "edx $ 8 : 1

    for regstr in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:

        for arithm in ["+", '-']:
            for length in ["1", "2", "3", "4", "5", "6"]:
                chaintool.process_cmd("set length " + length)
                print "\n === ", regstr, " = ", regstr, " ", arithm, " const =================  "
                chaintool.process_cmd("search {0} {0} {1} 1".format(regstr,arithm))
                chaintool.process_cmd("search {0} {0} {1} 2".format(regstr, arithm))

        for regstr2 in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:

            if regstr==regstr2:
                continue

            for length in ["1","2","3","4","5","6"]:
                chaintool.process_cmd("set length "+length)
                print "\n === " + regstr + " = " + regstr2 + " =================  "
                chaintool.start({regstr: Exp(regstr2) })

            for arithm in ["+", '-']:
                for length in ["1", "2", "3", "4", "5", "6"]:
                    chaintool.process_cmd("set length " + length)
                    print "\n === ", regstr + " = " + regstr + " " + arithm + " " + regstr2, " =================  "
                    chaintool.process_cmd("search {0} {0} {1} {2}".format(regstr, arithm, regstr2))
                    #chaintool.start({regstr: Exp(Exp(regstr), arithm, Exp(regstr2))})

            for length in ["1", "2", "3", "4", "5", "6"]:
                chaintool.process_cmd("set length " + length)
                print "\n === [" + regstr + "] = " + regstr2 + " =================  "
                chaintool.process_cmd("search mem {addr} {reg}".format(addr=regstr,reg=regstr2))

#search mem eax ebx