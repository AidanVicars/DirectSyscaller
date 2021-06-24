# DirectSyscaller
Performs syscalls without using ntdll's exports which may be hooked by an anti-cheat.
This utilises some shellcode that can be seen below. It's put into a byte array then casted to our function prototype
then called.
```asm
mov r10, rcx ; Save register
mov rax, 0x123 ; Move the syscall index into the rax register
syscall ; Perform syscall
ret ; Go back to where we called
```
