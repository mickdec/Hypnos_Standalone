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
    toto = Elf.Elfheader.entrypoint
    index = int(LibByteEditor.RevertBytes(
        Elf.Elfheader.offset_sectionsheader), 16)*2
    #print("index", LibByteEditor.RevertBytes(
    #    Elf.Elfheader.offset_sectionsheader))
    # print("adresse to jump :", Elf.Elfheader.offset_sectionsheader)
    # print("adresse to jump :", LibByteEditor.RevertBytes(
    #     Elf.Elfheader.offset_sectionsheader))
   
    Elf.Elfheader.entrynumber_programheader = LibDebug.AdaptStringToHex(str(hex(int(
        Elf.Elfheader.entrynumber_programheader, 16) + 1))[2:], Elf.Elfheader.sizeof_entrynumber_programheader)
    Elf.Elfheader.entrynumber_sectionheader = LibDebug.AdaptStringToHex(str(hex(int(
        Elf.Elfheader.entrynumber_sectionheader, 16) + 1))[2:], Elf.Elfheader.sizeof_entrynumber_sectionheader)
    
    content = ""
    content += Elf.Elfheader.ToHex()
    content += Elf.Programheadertable.ToHex()

    print("Size of elfheader : ", hex(int(len(Elf.Elfheader.ToHex())/2)))
    print("Size of programheadertable : ", hex(int(len(Elf.Programheadertable.ToHex())/2)))

    print(Elf.Elfheader.elfheadersize)
    print(Elf.Elfheader.pr)
    # # content += Elf.Dummy.ToHex()

    # index = int(Elf.Sectionheadertable.sectiontable[1].offset,16)*2
    # index2 = int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.sectionnames_sectiontable_index,16)].offset,16)*2
    # index3 = int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.sectionnames_sectiontable_index,16)].size,16)*2
    # content += Elf.ToHex()[index:index2+index3]

    # print(len(Elf.ToHex()[index:index+index2]))

    LibByteEditor.CreateBinFromHex("ELFx64_EDITED_printf.out", content)
    exit()


    # index = int(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)]].offset)
    # print(Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.sectionnames_sectiontable_index,16)].offset)
    
    print(index2)
    # index = index *2
    print(Elf.ToHex()[index:index+index2])


    
    # strs = "abcdef"
    # print(strs[2:-2])
    
    
    exit()
    # print(Elf.ToHex()[:Elf.Elfheader.entrysize_sectionheader)

    # content += Elf.ToHex()[Elf.Sectionheadertable.sectiontable[int(Elf.Elfheader.entrynumber_sectionheader,16)]]
    
    exit()

    #print("content :",str(hex(int(str(len(content)), 16))))
    # print("index:",index)
    # print("Elf.Elfheader.offset_sectionsheader:",Elf.Elfheader.offset_sectionsheader)
    # print("LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader):",LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader))
    #print("int(LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader), 16):",int(LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader), 16))
    #print("int(LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader), 16)*2:",int(LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader), 16)*2)
    #index = 4100
    #rawdata="eb "+toto+" "
    # rawdata="6666666666666666"
    #content +=rawdata
    # if 64 bit
    #size=LibDebug.AdaptStringToHex(str(hex(len(rawdata)))[2:], Elf.Sectionheadertable.sectiontable[0].x64_sizeof_addr)
    #print(" size : ",size)

    newentrypoint=LibDebug.AdaptStringToHex(str(hex(int(len(content)/2)))[2:],Elf.Elfheader.x64_sizeof_entrypoint)
    print("NEW ENTRY POINT :",newentrypoint)

    #Elf.Elfheader.entrypoint = newentrypoint
    
    content = ""
    content += Elf.Elfheader.ToHex()
    content += Elf.Programheadertable.ToHex()
    # Elf.Elfheader.entrypoint = LibByteEditor.RevertBytes(
    #     Elf.Elfheader.offset_sectionsheader)
    # print("content")
    content += "eb "+toto+" "
    print("toto :",toto)
   # content += "66666666666666666666666666666666666666666666666666666666"

    content += Elf.Sectionheadertable.ToHex()

    size=LibDebug.AdaptStringToHex(str(hex(len(rawdata)))[2:], Elf.Sectionheadertable.sectiontable[0].x64_sizeof_addr)


    content += addSectionToHeaderTable(Elf,"titi",Elf.Elfheader.offset_sectionsheader,size)

    LibByteEditor.CreateBinFromHex("ELFx64_EDITED_printf.out", content)
    # sizeof(rawdata)=len(shellcode)


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
