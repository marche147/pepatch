from ctypes import *
from dependency import pefile

class Binary(object):

    PAGE_SIZE = 0x1000
    DEFAULT_AMPLIFY_SIZE = 0x2000 

    def __init__(self, filename):
        self.pefile = pefile.PE(filename)

        # HACK: there's currently certain ways to inject code into PE
        # 1. adding a section (requires gaps between section header and the first section)
        # 2. append code to the last section
        # ...
        # each method has it's own drawbacks
        result, section = self._valid()
        if not result:
            raise Exception("Malformed PE that's not valid for patching")

        # remap the pefile
        filesize = len(self.pefile)
        filedata = str(self.pefile.data)
        newsize = filesize + self.roundup(self.DEFAULT_AMPLIFY_SIZE, self.file_alignment)
        filedata = filedata.ljust(newsize, "\x00")
        self.pefile.close()
        self.pefile = pefile.PE(data=filedata)
        result, section = self._valid(second=True)
        if not result:
            raise Exception("????!!!!dafuq")

        # make the section rwx and expand it
        section.Characteristics |= (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] + pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] + pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])
        self.patch_foffset = section.SizeOfRawData + section.PointerToRawData
        section.SizeOfRawData += self.roundup(self.DEFAULT_AMPLIFY_SIZE, self.file_alignment)
        self.patch_alloc = self.patch_foffset

        return

    @property
    def file_alignment(self):
        return self.pefile.OPTIONAL_HEADER.FileAlignment

    @property
    def section_alignment(self):
        return self.pefile.OPTIONAL_HEADER.SectionAlignment

    @property
    def sections(self):
        return self.pefile.sections

    @staticmethod
    def roundup(x, align):
        return ((x + align - 1) // align) * align

    @staticmethod
    def rounddown(x, align):
        return (x // align) * align

    def save(self, filename):
        return self.pefile.write(filename)

    def alloc(self, size):
        r = self.patch_alloc
        self.patch_alloc += size
        return r

    def close(self):
        self.pefile.close()
        return

    @property
    def next_alloc(self):
        return self.patch_alloc

    def _valid(self, second=False):
        """
        Checks if the PE file is valid for patching
        Several situations not available for patching : 
        1. When appending data will cause section overlapping

        params:
        @second - if this is the second validate operation, where binary got amplified so that we dont need the last check
        """

        last_section = None
        last_mem_section = None
        foffset = 0
        voffset = 0
        for section in self.sections:
            print section
            if section.PointerToRawData > foffset:
                last_section = section
                foffset  = section.PointerToRawData
            if section.VirtualAddress > voffset:
                last_mem_section = section
                voffset = section.VirtualAddress

        # no overlapping!
        if last_mem_section != last_section:
            return False, None
        if not second and last_section.PointerToRawData + last_section.SizeOfRawData != len(self.pefile):
            return False, None

        return True, last_section

__all__ = ["Binary"]
