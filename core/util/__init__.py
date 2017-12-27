
import os

def readrelative(filename):
    directory = os.path.dirname(os.path.realpath(__file__))
    return open(directory + os.sep + filename, 'r').read()

def declare(linker):
    linker.addheader(readrelative('windows.h'))

    linker.decl(readrelative('stdlib.c'), readrelative('stdlib.h'))
    return
