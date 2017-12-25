
import re

class Linker(object):

    def __init__(self):
        self.symtable = {}  # dict (key: function name, value: function address)
        return

    def addsym(self, sym, addr):
        self.symtable[sym] = addr
        return

    def resolve(self, sym):
        if sym in self.symtable:
            return self.symtable[sym]
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
            find_ref = r'\b_%s\n' % (re.escape(ref))
            addr = self.resolve(ref)
            if not addr:
                raise Exception("Symbol %s not found!".format(ref))

            if re.search(find_ref, asmcode):
                asmcode = re.sub(find_ref, '0x%x' % addr, asmcode)
        
        return asmcode

__all__ = ["Linker"]
