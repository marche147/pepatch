
# hello.exe is compiled by vs2017
# ../patch.py hello.exe hello.py

def patch(pt):

    addr = pt.inject(asm='''
    call getstr
    .byte 0x41
    .byte 0
    getstr:
    pop rcx
    call 0x140001030
    jmp 0x0000000140001010
    ''')
    pt.patch(0x014000100B, jmp=addr)
    return
