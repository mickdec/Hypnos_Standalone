'''
Library made for editing the values of a ELF class.
-void AddSection(Elf, sectionname: str, rawdata: str)
-void ModifyEntryPoint(Elf, entrypoint: str)
'''
from SRC.Core import Globals
from SRC.Libs import LibDebug
from SRC.Libs import LibElfAnnalyzer
from SRC.Libs import LibByteEditor

import time
from datetime import datetime


def AddSection(Elf, sectionname: str, rawdata: str):
    '''
    Adding a new section to a specified ELF object.
    -return: void
    '''
   
    #Elf.Elfheader.entrynumber_programheader = LibDebug.AdaptStringToHex(str(hex(int(Elf.Elfheader.entrynumber_programheader, 16) + 1))[2:], Elf.Elfheader.sizeof_entrynumber_programheader)
    Elf.Elfheader.entrynumber_sectionheader = LibDebug.AdaptStringToHex(str(hex(int(Elf.Elfheader.entrynumber_sectionheader, 16) + 1))[2:], Elf.Elfheader.sizeof_entrynumber_sectionheader)
    

    content = ""
    content += Elf.Elfheader.ToHex()
    content += Elf.Programheadertable.ToHex()
    content += Elf.Dummy.ToHex()
    content += Elf.Sectionheadertable.ToHex()

    print("Size of elfheader : ", hex(int(len(Elf.Elfheader.ToHex())/2)))
    print("Size of programheadertable : ", hex(int(len(Elf.Programheadertable.ToHex())/2)))

    print(Elf.Elfheader.elfheadersize)

    LibByteEditor.CreateBinFromHex("ELFx64_EDITED_printf.out", content)
    exit()


def addSectionToHeaderTable(Elf, sectionname: str, addr: str, size: str):
    print("======")
    print(Elf.Sectionheadertable.sectiontable[28].Print())
    print("======")
    print("addr : " + addr)
    exit()
    section = LibElfAnnalyzer.SECTIONHEADER()
    section.name = "00000011"
    section.type = "00000003"
    section.flags = "0000000000000004"
    section.addr = "0000000000000000"
    section.offset = addr
    section.size = size
    section.link = "00000000"
    section.info = "00000000"
    section.addralign = "0000000000000001"
    section.entsize = "0000000000000000"
    return section.ToHex()


def ModifyEntryPoint(Elf, entrypoint: str):
    '''
    Edit the entrypoint (e_entry) of a ELF
    return: void
    '''
