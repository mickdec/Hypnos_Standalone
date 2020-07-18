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
    print("index", LibByteEditor.RevertBytes(
        Elf.Elfheader.offset_sectionsheader))
    print("adresse to jump :", Elf.Elfheader.offset_sectionsheader)
    print("adresse to jump :", LibByteEditor.RevertBytes(
        Elf.Elfheader.offset_sectionsheader))
   
    Elf.Elfheader.entrynumber_programheader = LibDebug.AdaptStringToHex(str(hex(int(
        Elf.Elfheader.entrynumber_programheader, 16) + 1))[2:], Elf.Elfheader.sizeof_entrynumber_programheader)
    Elf.Elfheader.entrynumber_sectionheader = LibDebug.AdaptStringToHex(str(hex(int(
        Elf.Elfheader.entrynumber_sectionheader, 16) + 1))[2:], Elf.Elfheader.sizeof_entrynumber_sectionheader)

    content = ""
    content += Elf.Elfheader.ToHex()
    content += Elf.Programheadertable.ToHex()
    #content += Elf.Dummy.ToHex()
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
    content = ""
    content += "6666"  # LibByteEditor.RevertBytes(self.name)
    content += "0001"  # type = program data
    # if 32 = 4 if 64 = 8:
    content += "0000000000000004"  # flags = EXECUTABLE
    content += addr  # LibByteEditor.RevertBytes(self.addr)
    content += "0000000000000000"  # LibByteEditor.RevertBytes(self.offset)
    content += size  # LibByteEditor.RevertBytes(self.size)
    # if32
    #   content += LibByteEditor.RevertBytes(self.link)
    #    content += LibByteEditor.RevertBytes(self.info)
    content += "0000000000000000"  # LibByteEditor.RevertBytes(self.addralign)
    content += "0000000000000000"  # LibByteEditor.RevertBytes(self.entsize)
    return content


def ModifyEntryPoint(Elf, entrypoint: str):
    '''
    Edit the entrypoint (e_entry) of a ELF
    return: void
    '''
