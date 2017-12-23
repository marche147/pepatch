
import capstone
import keystone

class Assembler(object):
    def __init__(self):
        self.cs = capstone.Cs(self.csmode[0], self.csmode[1])
        self.ks = keystone.Ks(self.ksmode[0], self.ksmode[1])
        return

    def asm(self, *args, **kwargs):
        return self.ks.asm(*args, **kwargs)

    def disasm(self, *args, **kwargs):
        return self.cs.disasm(*args, **kwargs)

class X86Assembler(Assembler):
    csmode = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ksmode = (keystone.KS_ARCH_X86, keystone.KS_MODE_32)

class X64Assembler(Assembler):
    csmode = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ksmode = (keystone.KS_ARCH_X86, keystone.KS_MODE_64)

class ARMAssembler(Assembler):
    csmode = (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    ksmode = (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)

def assembler(arch='x86'):
    asmdict = {
            'x86': X86Assembler,
            'amd64': X64Assembler,
            'arm': ARMAssembler
            }
    if arch in asmdict:
        return asmdict[arch]()
    raise NotImplementedError("Support for arch {} is not implemented atm".format(arch))

__all__ = ["assembler"]
