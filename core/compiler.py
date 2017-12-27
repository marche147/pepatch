
import log
import subprocess
import os

compiler_version = ''
DEVNULL = open(os.devnull, 'w')

def clean(asm):
    strip = (
        '.macosx_version_min',
        '.subsections_via_symbols',
        '.align',
        '.globl',
        '.weak_definition',
        '.p2align',
        '.cfi',
        '.file',
        '.section',
        '.intel_syntax',
        '#',
    )
    asmcode = []
    for line in asm.split('\n'):
        line = line.strip()
        if line.startswith(strip):
            continue
        asmcode.append(line)
    return '\n'.join(asmcode)

def compile(code, arch='x86', extra_cflags=[]):
    global compiler_version
    cflags = ['-nostdlib', '-mno-sse', '-masm=intel', '-std=c99', '-fno-stack-protector', '-fno-jump-tables', '-fno-pic', '-fno-asynchronous-unwind-tables', '-Wno-incompatible-library-redeclaration']

    if not compiler_version:
        p = subprocess.Popen(["gcc", "--version"], stdout=subprocess.PIPE, stderr=DEVNULL)
        compiler_version, _ = p.communicate()

    if 'gcc' in compiler_version and not 'clang' in compiler_version:
        cflags += ['-fleading-underscore', '-fno-toplevel-reorder']

    if arch == 'x86':
        cflags.append('-m32')

    if extra_cflags:
        cflags += extra_cflags
    p = subprocess.Popen(['gcc', '-xc', '-S', '-o-', '-'] + cflags, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    asm, err = p.communicate(code)
    if 'error:' in err.lower():
        raise Exception(err)
    elif err:
        log.warn("Compiler warning: " + err)
    
    return clean(asm)


