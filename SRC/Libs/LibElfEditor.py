'''
Library made for editing the values of a ELF class.
-void AddSection(Elf, sectionname: str, rawdata: str)
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

    if Elf.Elfheader.struct == "01":
        Elf.Elfheader.entrypoint =  LibDebug.AdaptStringToHex(str(hex(int((int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].offset,16) + int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].size,16)))))[2:], Elf.Elfheader.x32_sizeof_entrypoint)
        Elf.Elfheader.offset_sectionsheader = LibDebug.AdaptStringToHex(str(hex(int(int(int(Elf.Elfheader.entrypoint,16)*2 + int(len(rawdata)))/2)))[2:], Elf.Elfheader.x32_sizeof_offset_sectionsheader)
    elif Elf.Elfheader.struct == "02":
        Elf.Elfheader.entrypoint =  LibDebug.AdaptStringToHex(str(hex(int((int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].offset,16) + int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].size,16)))))[2:], Elf.Elfheader.x64_sizeof_entrypoint)
        Elf.Elfheader.offset_sectionsheader = LibDebug.AdaptStringToHex(str(hex(int(int(int(Elf.Elfheader.entrypoint,16)*2 + int(len(rawdata)))/2)))[2:], Elf.Elfheader.x64_sizeof_offset_sectionsheader)


    print(int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].offset,16))
    index = int(int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].offset,16)/2)
    index2 = int(int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-2].size,16)/2)

    

    lastsectionindex = int(int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-3].name,16)/2)
    print(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-4].name)

    namtable = ""
    namtable += Elf.ToHex()[index:index+lastsectionindex]
    namtable += "002E76616C"
    namtable += Elf.ToHex()[index+lastsectionindex:index+index2]


    section = LibElfAnnalyzer.SECTIONHEADER()
    section.name = lastsectionindex

    for nm in Elf.Sectionheadertable.sectiontable:
        name = int(nm.name,16)
        if name > int(section.name):
            name += len("002E76616C")
            nm.name = LibDebug.AdaptStringToHex(str(hex(name))[2:], 4*2)
        print(nm.name)

    section.type = "00000001"
    section.offset = Elf.Elfheader.entrypoint

    if Elf.Elfheader.struct == "01":
        section.flags = "00000004"
        section.addr = "00000000"
        section.size = LibDebug.AdaptStringToHex(hex(int(len(rawdata)/2))[2:], 4*2)
    elif Elf.Elfheader.struct == "02":
        section.flags = "0000000000000004"
        section.addr = "0000000000000000"
        section.size = LibDebug.AdaptStringToHex(hex(int(len(rawdata)/2))[2:], 8*2)

    section.link = "00000000"
    section.info = "00000000"
    section.addralign = "0000000000000001"
    section.entsize = "0000000000000000"

    content += Elf.Elfheader.ToHex()
    content += Elf.Programheadertable.ToHex()
    content += Elf.Dummy.ToHex()
    content += Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)-4].ToHex()
    content += Elf.Sectionheadertable.ToHex()

    LibByteEditor.CreateBinFromHex("ELFx64_EDITED_printf.out", content)

    Elf.PrintSectionHeaderTable()
    HexContent = LibByteEditor.GetHexFromFile("ELFx64_EDITED_printf.out")
    ElfInput = LibElfAnnalyzer.Extract(HexContent)
    ElfInput.PrintSectionHeaderTable()

    exit()