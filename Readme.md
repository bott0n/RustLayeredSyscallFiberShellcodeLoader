# RustLayeredSyscallFiberShellcodeLoader
Read byte from `tmp.dat` and decrypted with key `DarklabHK` and execute shellcode through Fiber
## Techniques
- `Rust`
- `Layered Syscall`
- `Fiber shellcode execution`
-  `RC4 Decryption`
## Compile
`cargo build --release`
## References
RustVEHSYscalls - https://github.com/safedv/RustVEHSyscalls/tree/master

RustEatNETLoader - https://github.com/alexlee820/RustEatNETLoader/tree/main

Fiber execute shellcode - https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber

Rust create fiber - https://github.com/b1nhack/rust-shellcode