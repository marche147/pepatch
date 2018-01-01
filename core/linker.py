
import re
import compiler
import log
from assemble import *

funcdef_re = r'^(?P<all>(?P<desc>[^\s].+?(?P<name>%s)(?P<args>\(.*?\)))\s*{(?P<body>(.|\n)+?)^})$'

class Linker(object):

    def __init__(self, arch, patcher, cflags=[]):
        self.symtable = {}  # dict (key: function name, value: function address)
        self.header = []
        self.declare = {}   # declared c functions, [name] = code
        self.arch = arch
        self.assembler = assembler(arch)
        self.extra_cflags = cflags
        self.patcher = patcher
        return

    def addsym(self, sym, addr):
        self.symtable[sym] = addr
        return

    def resolve(self, sym):
        if sym in self.symtable:
            return self.symtable[sym]
        if sym in self.declare:
            return self.compile_dependecy(sym, self.declare[sym])
        return None

    def preasm(self, asmcode):
        # search for direct jmp/call
        # e.g. jmp _exit -> (looks for symbol exit)
        refs = []
        jmp_ref = re.compile(r'\b(j|J)[a-zA-Z]+\s+_(\w+)\b')
        call_ref = re.compile(r'\b(call|CALL)\s+_(\w+)\b')
        for line in asmcode.split('\n'):
            line = line.strip()
            match = jmp_ref.match(line)
            if match:
                refs.append(match.groups()[1])
            else:
                match = call_ref.match(line)
                if match:
                    refs.append(match.groups()[1])

        for ref in refs:
            find_ref = r'\b_%s\b' % (re.escape(ref))
            addr = self.resolve(ref)
            if not addr:
                raise Exception("Symbol %s not found!".format(ref))

            if re.search(find_ref, asmcode):
                asmcode = re.sub(find_ref, '0x%x' % addr, asmcode)
        
        return asmcode

    def prec(self, ccode):
        result = []
        for line in ccode.split('\n'):
            line = line.strip()
            result.append(line)
        return '\n'.join(result)

    def compile_dependecy(self, sym, code):
        code = self.prec(code)
        match = re.search(funcdef_re % sym, code, re.MULTILINE)
        if not match:
            raise Exception("Function definition not found!")
        
        result = match.groupdict()
        code = result["all"]
        ccode = "\n".join(self.header) + code
        asm = self.preasm(compiler.compile(ccode, self.arch, self.extra_cflags))
        bincode = self.assembler.asm(asm, addr=self.patcher.binary.next_alloc)
        addr = self.patcher.inject(raw=bincode)
        self.addsym(sym, addr)
        log.success("Resolved %s @ 0x%x" % (sym, addr))
        return addr

    def compile(self, code):
        code = self.prec(code)
        match = re.search(funcdef_re % '\w+', code, re.MULTILINE)
        if not match:
            raise Exception("Function definition not found!")
        
        result = match.groupdict()
        code = result["all"]
        ccode = '\n'.join(self.header) + code
        asm = self.preasm(compiler.compile(ccode, self.arch, self.extra_cflags))
        return asm

    def decl(self, ccodes, header=''):
        if header: self.addheader(header)
        matches = re.findall(funcdef_re % '\w+', ccodes, re.MULTILINE)
        for match in matches:
            code = match[0]
            name = match[2]
            self.declare[name] = code
        return

    def addheader(self, header):
        return self.header.append(header)

__all__ = ["Linker"]
