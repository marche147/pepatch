
import capstone
import keystone

class Assembler(object):
    def __init__(self):
        self.cs = capstone.Cs(self.csmode[0], self.csmode[1])
        self.ks = keystone.Ks(self.ksmode[0], self.ksmode[1])
        return

    @staticmethod
    def _flatten(x):
        return ''.join(map(chr, x))

    def asm(self, *args, **kwargs):
        return self._flatten(self.ks.asm(*args, **kwargs)[0])

    def disasm(self, *args, **kwargs):
        return self.cs.disasm(*args, **kwargs)

    def jmp(self, target, *args, **kwargs):
        raise NotImplementedError("Abstract class")

    def call(self, target, *args, **kwargs):
        raise NotImplementedError("Abstract class")

class X86Assembler(Assembler):
    csmode = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ksmode = (keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    def jmp(self, target, *args, **kwargs):
        return self.asm("jmp {}".format(target), *args, **kwargs)

    def call(self, target, *args, **kwargs):
        return self.asm("call {}".format(target), *args, **kwargs)

class X64Assembler(X86Assembler):
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
