
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

__all__ = ["Linker"]
