# 0

KJECTOR - Linux kernel injector

# Usage

Build the project using the following command:

~~~
$ git submodule update --init # first time only
$ [DEBUG=1] [PAYLOAD=<ldr|idle|idle-trap>] make
~~~

`ldr` is a payload which loads shared object library (default)

`idle` is a payload which does nothing but continues process execution

`idle-trap` is a payload which traps process execution (DO NOT USE IN PRODUCTION)

Once built use the following command to load the module:

~~~
$ sudo insmod kj_mod/kjector.ko
~~~

Default build injects `kj_lib/libkjector.so` to every [ping](kj_mod/module.c#L45) process.

Once injected `libkjector.so` sends `UDP` datagram with a string to `127.0.0.1:6666`.

To catch it run nc-like listener like follows:

~~~
$ nc -ludk 127.0.0.1 6666
~~~

# Features

- x86_64 only
- 2.6.18+ kernels
- able to inject shared object

# How it works

Injection happens in `sys_close` syscall hanlder.

Injection is done using `vm_mmap` / `copy_to_user` / `mprotect` sequence.

Target process state is modifyed by changing instruction pointer register (`pt_regs->ip`).

# Related

KHOOK hooking engine:
 - [KHOOK](https://github.com/milabs/khook)

Kernel mode to user mode so injection:
 - [linux-kernel-so-injector](https://github.com/Rhydon1337/linux-kernel-so-injector)

# Disclaimer

Education purposes. Only.

# License

This software is licensed under the GPL.

# Author

[Ilya V. Matveychikov](https://github.com/milabs)

2023
