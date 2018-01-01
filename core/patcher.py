
from binary import *
from assemble import *
from linker import *
import util
import compiler
import log

class Patcher(object):

    def __init__(self, filename, cflags=[]):
        self.binary = Binary(filename)
        self.linker = Linker(self.binary.arch, self, cflags)

        util.declare(self.linker)
        return

    def save(self, filename):
        return self.binary.save(filename)

    def _compile(self, *args, **kwargs):
        data = ""
        baseaddr = self.binary.next_alloc
        if kwargs.has_key("base"):
            baseaddr = kwargs["base"]

        if kwargs.has_key("asm"):
            code = self.linker.preasm(kwargs['asm'])
            if not kwargs.has_key("base"): baseaddr = self.binary.next_alloc    # if we don't specify a base addr, we need to update baseaddr after linker preasm
            data = self.linker.assembler.asm(code, addr=baseaddr)
        elif kwargs.has_key("hex"):
            data = kwargs["hex"].decode('hex')
        elif kwargs.has_key("raw"):
            data = kwargs["raw"]
        elif kwargs.has_key("jmp"):
            data = self.linker.assembler.jmp(kwargs["jmp"], addr=baseaddr)
        elif kwargs.has_key("call"):
            data = self.linker.assembler.call(kwargs["call"], addr=baseaddr)
        elif kwargs.has_key("c"):
            code = kwargs["c"]
            asm = self.linker.compile(code)
            if not kwargs.has_key("base"): baseaddr = self.binary.next_alloc
            data = self.linker.assembler.asm(asm, addr=baseaddr)

        return bytes(data)

    def inject(self, *args, **kwargs):
        data = self._compile(*args, **kwargs)
        nextva = self.binary.alloc(len(data))
        self.binary.writeva(nextva, data)
        log.success("Injected @ 0x%x"%(nextva))
        return nextva

    def patch(self, va, *args, **kwargs):
        log.info("Patching @ 0x%x"%(va))
        data = self._compile(base=va, *args, **kwargs)
        self.binary.writeva(va, data)
        return True

    def define(self, symbol, va):
        log.info("Defined %s @ 0x%x"%(symbol, va))
        self.linker.addsym(symbol, va)
        return True

    def declare(self, ccodes, header):
        return self.linker.decl(ccodes, header)

