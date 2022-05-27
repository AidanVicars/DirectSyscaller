#include <iostream>
#include <Windows.h>
#include "Syscalls.h"

using NtWriteVirtualMemory_T = NTSTATUS(*)(HANDLE, PVOID, PVOID, ULONG, PULONG);

template <typename T, typename ... Args>
PVOID Syscall(const char* syscall_name, Args ... args)
{

    //Shellcode that just replicates how ntdll does syscall
    BYTE syscall_shellcode[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xC3 };
    //Stores the system index
    int8_t system_idx{ 0 };

    //Iterate through map and find the syscall's index
    for (const auto& current_pair : syscall_indices)
        if (current_pair.first == syscall_name)
            system_idx = current_pair.second;

    //Allocate memory for our shellcode
    uint64_t syscall = reinterpret_cast<uint64_t>(VirtualAlloc(0, sizeof(syscall_shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    //Copy our shellcode to the allocated memory
    memcpy((PVOID)syscall, syscall_shellcode, sizeof(syscall_shellcode));
    //Write the syscall index to the shellcode
    *reinterpret_cast<uint32_t*>(syscall + 0x4) = system_idx;
    //Cast our function before we call it
    T syscall_function = (T)syscall;
    //Call the function and return the values
    return (PVOID)syscall_function(args...);

}

int main()
{
    
    int x = 0;
    int y = 1;

    Syscall<NtWriteVirtualMemory_T>("NtWriteVirtualMemory", GetCurrentProcess(), &x, &y, sizeof(x), nullptr);

}
