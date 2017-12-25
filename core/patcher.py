
from binary import *
from assemble import *
from linker import *
import log

class Patcher(object):

    def __init__(self, filename):
        self.binary = Binary(filename)
        self.assembler = assembler(self.binary.arch)
        self.linker = Linker()
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
            data = self.assembler.asm(code, addr=baseaddr)
        elif kwargs.has_key("hex"):
            data = kwargs["hex"].decode('hex')
        elif kwargs.has_key("raw"):
            data = kwargs["raw"]
        elif kwargs.has_key("jmp"):
            data = self.assembler.jmp(kwargs["jmp"], addr=baseaddr)
        elif kwargs.has_key("call"):
            data = self.assembler.call(kwargs["call"], addr=baseaddr)
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

