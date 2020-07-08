'''
Library made for editing the values of a PE class.
-LibPeAnnalyzer.PE ChangeCOFFTimestamp(Pe: LibPeAnnalyzer.PE, date: str)
-void AddSection(Pe, sectionname: str, shellcode: str)
-void ModifyEntryPoint(Pe, entrypoint:str)
'''
from SRC.Core import Globals
from SRC.Libs import LibDebug
from SRC.Libs import LibPeAnnalyzer
from SRC.Libs import LibByteEditor
import time
from datetime import datetime


def ChangeCOFFTimestamp(Pe: LibPeAnnalyzer.PE, date: str):
    '''
    Change the timestamp of the COFF Header.
    -return: LibPeAnnalyzer.PE
    '''
    LibDebug.Log("WORK", "Changing timestamp..")
    try:
        LibDebug.Log("WORK", "Before : " +
                     str(datetime.fromtimestamp(int(Pe.Coffheader.timedatestamp, 16))))
        Pe.Coffheader.timedatestamp = str(
            hex(int(time.mktime(datetime.strptime(date, "%d/%m/%Y").timetuple()))))[2:]
        LibDebug.Log("WORK", "After : " +
                     str(datetime.fromtimestamp(int(Pe.Coffheader.timedatestamp, 16))))
    except:
        LibDebug.Log("ERROR", "Failed to change the timestamp.")
        exit()
    return Pe


def AddSection(Pe, sectionname: str, rawdata: str):
    '''
    Adding a new section to a specified PE object.
    -return: void
    '''
    Pe.Coffheader.numberofsections = LibDebug.AdaptStringToHex(str(hex(int(
        Pe.Coffheader.numberofsections, 16) + 1))[2:], Pe.Coffheader.sizeof_numberofsections)
    NewSection = LibPeAnnalyzer.IMAGESECTIONHEADER()
    NewSection.name = LibByteEditor.RevertBytes(LibDebug.AdaptStringToHex(
        LibByteEditor.RevertBytes(LibDebug.StringToHex(sectionname)), NewSection.sizeof_name))
    NewSection.virtualsize = LibDebug.AdaptStringToHex(LibByteEditor.AlignData(len(rawdata)/2, int(
        Pe.Optionalpeheader.sectionalignment, 16), 0), NewSection.sizeof_virtualsize)
    NewSection.virtualaddress = LibDebug.AdaptStringToHex(
        LibByteEditor.AlignData(
            int(Pe.SectionTable.sections[int(
                Pe.Coffheader.numberofsections, 16)-2].virtualsize, 16),
            int(Pe.Optionalpeheader.sectionalignment, 16),
            int(Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections,
                                             16)-2].virtualaddress, 16)
        ), NewSection.sizeof_virtualaddress
    )
    NewSection.sizeofrawdata = LibDebug.AdaptStringToHex(LibByteEditor.AlignData(len(rawdata), int(
        Pe.Optionalpeheader.filealignment, 16), 0), NewSection.sizeof_sizeofrawdata)
    ptr = LibByteEditor.AlignData(int(Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections, 16)-2].sizeofrawdata, 16), int(
        Pe.Optionalpeheader.filealignment, 16), int(Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections, 16)-2].pointertorawdata, 16))
    NewSection.pointertorawdata = LibDebug.AdaptStringToHex(
        ptr, NewSection.sizeof_pointertorawdata)
    NewSection.pointertorelocations = "00000000"
    NewSection.pointertolinenumbers = "00000000"
    NewSection.numberofrelocations = "0000"
    NewSection.numberoflinenumbers = "0000"

    if Globals.Env.ARCH == "AMD64":
        NewSection.characteristics = "60000000"
    else:
        NewSection.characteristics = "c0000000"

    Pe.SectionTable.sections.append(NewSection)
    Pe.Optionalpeheader.sizeofimage = LibDebug.AdaptStringToHex(str(hex(int(Pe.Optionalpeheader.sizeofimage, 16)+int(
        Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections, 16)-1].virtualsize, 16))[2:]), Pe.Optionalpeheader.sizeof_sizeofimage)
    for _ in range(len(rawdata)*2):
        rawdata += "00"
    NewHex = str(Pe.ToHex()[:int(2*int(Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections, 16)-1].pointertorawdata, 16))])
    NewHex += str("0"*len(NewSection.ToHex())) + rawdata
    NewHex += str(Pe.ToHex()[int(2*int(int(Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections, 16)-1].pointertorawdata,
                                           16)+int(Pe.SectionTable.sections[int(Pe.Coffheader.numberofsections, 16)-1].sizeofrawdata, 16))):])
    Pe.Dummy.dum01 = NewHex[Pe.Dummy.dummyindex+(len(NewSection.ToHex())*2):]


def ModifyEntryPoint(Pe, entrypoint: str):
    '''
    Edit the entrypoint of a PE
    return: void
    '''
    Pe.Optionalpeheader.addressofentrypoint = entrypoint
