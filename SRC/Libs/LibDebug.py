'''
Library made for all the debuging purpose.
-class ENV
-string RevertString(content:str)
-void Log(status: "WORK:SUCCESS:ERROR", info: str)
-void CheckPreReq()
-string CheckEnv()
-int CheckArgs(argv: list)
-void CheckFile(input_file: str)
-string StringToHex(content: str)
-string IpToHex(content: str)
-string PortToHex(content: str)
-string AdaptStringToHex(content: str, size: int)
-void ComparePe(Pe1: LibPeAnnalyzer.PE, Pe2: LibPeAnnalyzer.PE)
'''
from SRC.Libs import LibDebug
from SRC.Libs import LibPeAnnalyzer
from SRC.Libs import LibByteEditor
import sys
import os
import platform
import subprocess

class ENV:
      def __init__(self):
            self.SYSTEM = platform.uname().system
            self.ARCH = platform.uname().machine


def RevertString(content: str):
      '''
      Revert the specified string
      -return: string
      '''
      return content[::-1]


def Log(status: "INFO:WORK:SUCCESS:ERROR", info: str):
    '''
    Print prettier informations logs.
    INFO, WORK, SUCCESS, ERROR
    -return: void
    '''
    if status == "WORK":
        print("[-] " + info)
    elif status == "SUCCESS":
        print("[+] " + info)
    elif status == "ERROR":
        print("[X] " + info)
    elif status == "INFO":
        print("[i] " + info)


def CheckEnv():
    '''
    Check the environment, and all the ressources to run Andros.
    -return: void
    '''
    try:
      env = ENV()
      return env
    except:
      Log("ERROR", "Error while trying to get system informations.")
      exit()

def CheckHephaistosReq():
      '''
      Check the prerequistes for using Hephaistos.
      -return: void
      '''
      error = False
      if error:
            sys.exit(0)

def CheckHypnosReq():
      '''
      Check the prerequistes for using Hypnos CoreModule.
      -return: void
      '''
      error = False
      try:
            process = subprocess.Popen(['gcc'])
            process.terminate()
            LibDebug.Log("SUCCESS", "GCC ok.")
      except:
            LibDebug.Log("ERROR", "gcc is not FOUND (install or edit your system vars) on your system. Hypnos need it. https://www.cygwin.com/")
            error = True
      try:
            process = subprocess.Popen(['python3'])
            process.terminate()
            LibDebug.Log("SUCCESS", "Python ok.")
      except:
            LibDebug.Log("ERROR", "Python3 can't be invoqued with 'python3' please considering reinstalling Python3. Hypnos need it.")
            error = True
      try:
            process = subprocess.Popen(['nasm'])
            process.terminate()
            LibDebug.Log("SUCCESS", "NASM ok.")
      except:
            LibDebug.Log("ERROR", "NASM is not FOUND (install or edit your system vars) on your system. Hypnos need it. https://www.nasm.us/")
            error = True
      if error:
            sys.exit(0)

def CheckJanusReq():
      '''
      Check the prerequistes for using Janus CoreModule.
      -return: void
      '''
      error = False
      try:
            process = subprocess.Popen(['nmap'])
            process.terminate()
            LibDebug.Log("SUCCESS", "NMAP ok.")
      except:
            LibDebug.Log("ERROR", "NMAP is not FOUND on your system. Janus need it. https://nmap.org/")
            error = True
      if error:
            sys.exit(0)


def CheckArgs(argv: list):
    '''
    Check if the arguments are corrects to start the program.
    -return: int
    '''
    if argv[1] == "":
          return 0
    try:
      CheckFile(argv[1])
      return 1
    except:
      return 0


def CheckFile(input_file: str):
    '''
    Check if the specified file exist.
    -return: void
    '''
    if not os.path.isfile(input_file):
        Log("ERROR", "Specified file \"" + input_file + "\" didn't exist. Exiting.")
        exit()


def StringToHex(content: str):
      '''
      Convert a string to an Hex string
      -return: string
      '''
      return str(content.encode('utf-8').hex())


def IpToHex(content: str):
      '''
      Convert an IP to an Hex string
      -return: string
      '''
      content = content.split(".")
      HexIp = ""
      for i in range(0, len(content)):
            hx = str(hex(int(content[i])))[2:]
            if len(hx) == 1:
                  hx = '0' + hx
            HexIp += hx
      return LibByteEditor.RevertBytes(HexIp)


def PortToHex(content: str):
      '''
      Convert a PORT to an Hex string
      -return: string
      '''
      content = str(hex(int(content)))[2:]
      return LibByteEditor.RevertBytes(content)


def AdaptStringToHex(content: str, size: int):
      '''
      Adapt the specified Hex string into a 00 minimum specified BYTE size.
      -return: string
      '''
      for _ in range(0, size*2):
            if len(content) > size:
                  Log("ERROR", content + " size is superior than the " +
                      str(size) + " BYTE specified size.")
                  exit()
            elif len(content) == size:
                  return content
            elif len(content) < size:
                  tmp = "0" + content
                  content = tmp


def ComparePe(Pe1: LibPeAnnalyzer.PE, Pe2: LibPeAnnalyzer.PE):
      '''
      Compare two PE object together and print the differences.
      -return: void
      '''
      if Pe1.Msdosheader.ToHex() != Pe2.Msdosheader.ToHex():
            if Pe2.Msdosheader.signature != Pe1.Msdosheader.signature:
                  print("signature Pe1 : " + Pe1.Msdosheader.signature)
                  print("signature Pe2 : " + Pe2.Msdosheader.signature)
            if Pe2.Msdosheader.lastsize != Pe1.Msdosheader.lastsize:
                  print("lastsize Pe1 : " + Pe1.Msdosheader.lastsize)
                  print("lastsize Pe2 : " + Pe2.Msdosheader.lastsize)
            if Pe2.Msdosheader.nblocks != Pe1.Msdosheader.nblocks:
                  print("nblocks Pe1 : " + Pe1.Msdosheader.nblocks)
                  print("nblocks Pe2 : " + Pe2.Msdosheader.nblocks)
            if Pe2.Msdosheader.nreloc != Pe1.Msdosheader.nreloc:
                  print("nreloc Pe1 : " + Pe1.Msdosheader.nreloc)
                  print("nreloc Pe2 : " + Pe2.Msdosheader.nreloc)
            if Pe2.Msdosheader.hdrsize != Pe1.Msdosheader.hdrsize:
                  print("hdrsize Pe1 : " + Pe1.Msdosheader.hdrsize)
                  print("hdrsize Pe2 : " + Pe2.Msdosheader.hdrsize)
            if Pe2.Msdosheader.minalloc != Pe1.Msdosheader.minalloc:
                  print("minalloc Pe1 : " + Pe1.Msdosheader.minalloc)
                  print("minalloc Pe2 : " + Pe2.Msdosheader.minalloc)
            if Pe2.Msdosheader.maxalloc != Pe1.Msdosheader.maxalloc:
                  print("maxalloc Pe1 : " + Pe1.Msdosheader.maxalloc)
                  print("maxalloc Pe2 : " + Pe2.Msdosheader.maxalloc)
            if Pe2.Msdosheader.ss != Pe1.Msdosheader.ss:
                  print("ss Pe1 : " + Pe1.Msdosheader.ss)
                  print("ss Pe2 : " + Pe2.Msdosheader.ss)
            if Pe2.Msdosheader.sp != Pe1.Msdosheader.sp:
                  print("sp Pe1 : " + Pe1.Msdosheader.sp)
                  print("sp Pe2 : " + Pe2.Msdosheader.sp)
            if Pe2.Msdosheader.checksum != Pe1.Msdosheader.checksum:
                  print("checksum Pe1 : " + Pe1.Msdosheader.checksum)
                  print("checksum Pe2 : " + Pe2.Msdosheader.checksum)
            if Pe2.Msdosheader.ip != Pe1.Msdosheader.ip:
                  print("ip Pe1 : " + Pe1.Msdosheader.ip)
                  print("ip Pe2 : " + Pe2.Msdosheader.ip)
            if Pe2.Msdosheader.cs != Pe1.Msdosheader.cs:
                  print("cs Pe1 : " + Pe1.Msdosheader.cs)
                  print("cs Pe2 : " + Pe2.Msdosheader.cs)
            if Pe2.Msdosheader.relocpos != Pe1.Msdosheader.relocpos:
                  print("relocpos Pe1 : " + Pe1.Msdosheader.relocpos)
                  print("relocpos Pe2 : " + Pe2.Msdosheader.relocpos)
            if Pe2.Msdosheader.noverlay != Pe1.Msdosheader.noverlay:
                  print("noverlay Pe1 : " + Pe1.Msdosheader.noverlay)
                  print("noverlay Pe2 : " + Pe2.Msdosheader.noverlay)
            if Pe2.Msdosheader.reserved1 != Pe1.Msdosheader.reserved1:
                  print("reserved1 Pe1 : " + Pe1.Msdosheader.reserved1)
                  print("reserved1 Pe2 : " + Pe2.Msdosheader.reserved1)
            if Pe2.Msdosheader.oem_id != Pe1.Msdosheader.oem_id:
                  print("oem_id Pe1 : " + Pe1.Msdosheader.oem_id)
                  print("oem_id Pe2 : " + Pe2.Msdosheader.oem_id)
            if Pe2.Msdosheader.oem_info != Pe1.Msdosheader.oem_info:
                  print("oem_info Pe1 : " + Pe1.Msdosheader.oem_info)
                  print("oem_info Pe2 : " + Pe2.Msdosheader.oem_info)
            if Pe2.Msdosheader.reserved2 != Pe1.Msdosheader.reserved2:
                  print("reserved2 Pe1 : " + Pe1.Msdosheader.reserved2)
                  print("reserved2 Pe2 : " + Pe2.Msdosheader.reserved2)
            if Pe2.Msdosheader.e_lfanew != Pe1.Msdosheader.e_lfanew:
                  print("e_lfanew Pe1 : " + Pe1.Msdosheader.e_lfanew)
                  print("e_lfanew Pe2 : " + Pe2.Msdosheader.e_lfanew)
      if Pe1.Stubprogram.ToHex() != Pe2.Stubprogram.ToHex():
            if Pe1.Stubprogram.stub != Pe2.Stubprogram.stub:
                  print("stub Pe1 : " + Pe1.Stubprogram.stub)
                  print("stub Pe2 : " + Pe2.Stubprogram.stub)
      if Pe1.Signature.ToHex() != Pe2.Signature.ToHex():
            if Pe1.Signature.signature != Pe2.Signature.signature:
                  print("signature Pe1 : " + Pe1.Signature.signature)
                  print("signature Pe2 : " + Pe2.Signature.signature)
      if Pe1.Coffheader.ToHex() != Pe2.Coffheader.ToHex():
            if Pe2.Coffheader.machine != Pe1.Coffheader.machine:
                  print("Machine Pe1 : " + Pe1.Coffheader.machine)
                  print("Machine Pe2 : " + Pe2.Coffheader.machine)
            if Pe2.Coffheader.numberofsections != Pe1.Coffheader.numberofsections:
                  print("Numberofsections Pe1 : " +
                        Pe1.Coffheader.numberofsections)
                  print("Numberofsections Pe2 : " +
                        Pe2.Coffheader.numberofsections)
            if Pe2.Coffheader.timedatestamp != Pe1.Coffheader.timedatestamp:
                  print("Timedatestamp Pe1 : " + Pe1.Coffheader.timedatestamp)
                  print("Timedatestamp Pe2 : " + Pe2.Coffheader.timedatestamp)
            if Pe2.Coffheader.pointertosymboltable != Pe1.Coffheader.pointertosymboltable:
                  print("Pointertosymboltable Pe1 : " +
                        Pe1.Coffheader.pointertosymboltable)
                  print("Pointertosymboltable Pe2 : " +
                        Pe2.Coffheader.pointertosymboltable)
            if Pe2.Coffheader.numberofsymbols != Pe1.Coffheader.numberofsymbols:
                  print("Numberofsymbols Pe1 : " +
                        Pe1.Coffheader.numberofsymbols)
                  print("Numberofsymbols Pe2 : " +
                        Pe2.Coffheader.numberofsymbols)
            if Pe2.Coffheader.sizeofoptionalheader != Pe1.Coffheader.sizeofoptionalheader:
                  print("Sizeofoptionalheader Pe1 : " +
                        Pe1.Coffheader.sizeofoptionalheader)
                  print("Sizeofoptionalheader Pe2 : " +
                        Pe2.Coffheader.sizeofoptionalheader)
            if Pe2.Coffheader.characteristics != Pe1.Coffheader.characteristics:
                  print("Characteristics Pe1 : " +
                        Pe1.Coffheader.characteristics)
                  print("Characteristics Pe2 : " +
                        Pe2.Coffheader.characteristics)
      if Pe1.Optionalpeheader.ToHex() != Pe2.Optionalpeheader.ToHex():
            if Pe2.Optionalpeheader.signature != Pe1.Optionalpeheader.signature:
                  print("signature Pe1 :" + Pe1.signature)
                  print("signature Pe2 :" + Pe2.signature)
            if Pe2.Optionalpeheader.majorlinkerversion != Pe1.Optionalpeheader.majorlinkerversion:
                  print("majorlinkerversioe Pe1 : " +
                        Pe1.Optionalpeheader.majorlinkerversion)
                  print("majorlinkerversioe Pe2 : " +
                        Pe2.Optionalpeheader.majorlinkerversion)
            if Pe2.Optionalpeheader.minorlinkerversion != Pe1.Optionalpeheader.minorlinkerversion:
                  print("minorlinkerversioe Pe1 : " +
                        Pe1.Optionalpeheader.minorlinkerversion)
                  print("minorlinkerversioe Pe2 : " +
                        Pe2.Optionalpeheader.minorlinkerversion)
            if Pe2.Optionalpeheader.sizeofcode != Pe1.Optionalpeheader.sizeofcode:
                  print("sizeofcode Pe1 : " + Pe1.Optionalpeheader.sizeofcode)
                  print("sizeofcode Pe2 : " + Pe2.Optionalpeheader.sizeofcode)
            if Pe2.Optionalpeheader.sizeofinitializeddata != Pe1.Optionalpeheader.sizeofinitializeddata:
                  print("sizeofinitializeddate Pe1 : " +
                        Pe1.Optionalpeheader.sizeofinitializeddata)
                  print("sizeofinitializeddate Pe2 : " +
                        Pe2.Optionalpeheader.sizeofinitializeddata)
            if Pe2.Optionalpeheader.sizeofuninitializeddata != Pe1.Optionalpeheader.sizeofuninitializeddata:
                  print("sizeofuninitializeddate Pe1 : " +
                        Pe1.Optionalpeheader.sizeofuninitializeddata)
                  print("sizeofuninitializeddate Pe2 : " +
                        Pe2.Optionalpeheader.sizeofuninitializeddata)
            if Pe2.Optionalpeheader.addressofentrypoint != Pe1.Optionalpeheader.addressofentrypoint:
                  print("addressofEntryPoint Pe1 : " +
                        Pe1.Optionalpeheader.addressofentrypoint)
                  print("addressofEntryPoint Pe2 : " +
                        Pe2.Optionalpeheader.addressofentrypoint)
            if Pe2.Optionalpeheader.baseofcode != Pe1.Optionalpeheader.baseofcode:
                  print("baseofcode Pe1 : " + Pe1.Optionalpeheader.baseofcode)
                  print("baseofcode Pe2 : " + Pe2.Optionalpeheader.baseofcode)
            if Pe2.Optionalpeheader.baseofdata != Pe1.Optionalpeheader.baseofdata:
                  print("baseofdate Pe1 : " + Pe1.Optionalpeheader.baseofdata)
                  print("baseofdate Pe2 : " + Pe2.Optionalpeheader.baseofdata)
            if Pe2.Optionalpeheader.imagebase != Pe1.Optionalpeheader.imagebase:
                  print("imagebase Pe1 : " + Pe1.Optionalpeheader.imagebase)
                  print("imagebase Pe2 : " + Pe2.Optionalpeheader.imagebase)
            if Pe2.Optionalpeheader.sectionalignment != Pe1.Optionalpeheader.sectionalignment:
                  print("sectionalignmene Pe1 : " +
                        Pe1.Optionalpeheader.sectionalignment)
                  print("sectionalignmene Pe2 : " +
                        Pe2.Optionalpeheader.sectionalignment)
            if Pe2.Optionalpeheader.filealignment != Pe1.Optionalpeheader.filealignment:
                  print("filealignmene Pe1 : " +
                        Pe1.Optionalpeheader.filealignment)
                  print("filealignmene Pe2 : " +
                        Pe2.Optionalpeheader.filealignment)
            if Pe2.Optionalpeheader.majorosversion != Pe1.Optionalpeheader.majorosversion:
                  print("majorosversioe Pe1 : " +
                        Pe1.Optionalpeheader.majorosversion)
                  print("majorosversioe Pe2 : " +
                        Pe2.Optionalpeheader.majorosversion)
            if Pe2.Optionalpeheader.minorosversion != Pe1.Optionalpeheader.minorosversion:
                  print("minorosversioe Pe1 : " +
                        Pe1.Optionalpeheader.minorosversion)
                  print("minorosversioe Pe2 : " +
                        Pe2.Optionalpeheader.minorosversion)
            if Pe2.Optionalpeheader.majorimageversion != Pe1.Optionalpeheader.majorimageversion:
                  print("majorimageversioe Pe1 : " +
                        Pe1.Optionalpeheader.majorimageversion)
                  print("majorimageversioe Pe2 : " +
                        Pe2.Optionalpeheader.majorimageversion)
            if Pe2.Optionalpeheader.minorimageversion != Pe1.Optionalpeheader.minorimageversion:
                  print("minorimageversioe Pe1 : " +
                        Pe1.Optionalpeheader.minorimageversion)
                  print("minorimageversioe Pe2 : " +
                        Pe2.Optionalpeheader.minorimageversion)
            if Pe2.Optionalpeheader.majorsubsystemversion != Pe1.Optionalpeheader.majorsubsystemversion:
                  print("majorsubsystemversioe Pe1 : " +
                        Pe1.Optionalpeheader.majorsubsystemversion)
                  print("majorsubsystemversioe Pe2 : " +
                        Pe2.Optionalpeheader.majorsubsystemversion)
            if Pe2.Optionalpeheader.minorsubsystemversion != Pe1.Optionalpeheader.minorsubsystemversion:
                  print("minorsubsystemversioe Pe1 : " +
                        Pe1.Optionalpeheader.minorsubsystemversion)
                  print("minorsubsystemversioe Pe2 : " +
                        Pe2.Optionalpeheader.minorsubsystemversion)
            if Pe2.Optionalpeheader.win32versionvalue != Pe1.Optionalpeheader.win32versionvalue:
                  print("win32versionvalue Pe1 : " +
                        Pe1.Optionalpeheader.win32versionvalue)
                  print("win32versionvalue Pe2 : " +
                        Pe2.Optionalpeheader.win32versionvalue)
            if Pe2.Optionalpeheader.sizeofimage != Pe1.Optionalpeheader.sizeofimage:
                  print("sizeofimage Pe1 : " + Pe1.Optionalpeheader.sizeofimage)
                  print("sizeofimage Pe2 : " + Pe2.Optionalpeheader.sizeofimage)
            if Pe2.Optionalpeheader.sizeofheaders != Pe1.Optionalpeheader.sizeofheaders:
                  print("sizeofheadere Pe1 : " +
                        Pe1.Optionalpeheader.sizeofheaders)
                  print("sizeofheadere Pe2 : " +
                        Pe2.Optionalpeheader.sizeofheaders)
            if Pe2.Optionalpeheader.checksum != Pe1.Optionalpeheader.checksum:
                  print("checksue Pe1 : " + Pe1.Optionalpeheader.checksum)
                  print("checksue Pe2 : " + Pe2.Optionalpeheader.checksum)
            if Pe2.Optionalpeheader.subsystem != Pe1.Optionalpeheader.subsystem:
                  print("subsystee Pe1 : " + Pe1.Optionalpeheader.subsystem)
                  print("subsystee Pe2 : " + Pe2.Optionalpeheader.subsystem)
            if Pe2.Optionalpeheader.dllcharacteristics != Pe1.Optionalpeheader.dllcharacteristics:
                  print("dllcharacteristice Pe1 : " +
                        Pe1.Optionalpeheader.dllcharacteristics)
                  print("dllcharacteristice Pe2 : " +
                        Pe2.Optionalpeheader.dllcharacteristics)
            if Pe2.Optionalpeheader.sizeofstackreserve != Pe1.Optionalpeheader.sizeofstackreserve:
                  print("sizeofstackreserve Pe1 : " +
                        Pe1.Optionalpeheader.sizeofstackreserve)
                  print("sizeofstackreserve Pe2 : " +
                        Pe2.Optionalpeheader.sizeofstackreserve)
            if Pe2.Optionalpeheader.sizeofstackcommit != Pe1.Optionalpeheader.sizeofstackcommit:
                  print("sizeofstackcommie Pe1 : " +
                        Pe1.Optionalpeheader.sizeofstackcommit)
                  print("sizeofstackcommie Pe2 : " +
                        Pe2.Optionalpeheader.sizeofstackcommit)
            if Pe2.Optionalpeheader.sizeofheapreserve != Pe1.Optionalpeheader.sizeofheapreserve:
                  print("sizeofheapreserve Pe1 : " +
                        Pe1.Optionalpeheader.sizeofheapreserve)
                  print("sizeofheapreserve Pe2 : " +
                        Pe2.Optionalpeheader.sizeofheapreserve)
            if Pe2.Optionalpeheader.sizeofheapcommit != Pe1.Optionalpeheader.sizeofheapcommit:
                  print("sizeofheapcommie Pe1 : " +
                        Pe1.Optionalpeheader.sizeofheapcommit)
                  print("sizeofheapcommie Pe2 : " +
                        Pe2.Optionalpeheader.sizeofheapcommit)
            if Pe2.Optionalpeheader.loaderflags != Pe1.Optionalpeheader.loaderflags:
                  print("loaderflage Pe1 : " + Pe1.Optionalpeheader.loaderflags)
                  print("loaderflage Pe2 : " + Pe2.Optionalpeheader.loaderflags)
            if Pe2.Optionalpeheader.numberofrvaandsizes != Pe1.Optionalpeheader.numberofrvaandsizes:
                  print("numberofrvaandsizee Pe1 : " +
                        Pe1.Optionalpeheader.numberofrvaandsizes)
                  print("numberofrvaandsizee Pe2 : " +
                        Pe2.Optionalpeheader.numberofrvaandsizes)
      if Pe1.SectionTable.ToHex() != Pe2.SectionTable.ToHex():
            if int(Pe1.Coffheader.numberofsections, 16) < int(Pe2.Coffheader.numberofsections, 16):
                  Log("ERROR", "Pe2 have more sections.")
                  for i in range(0, int(Pe1.Coffheader.numberofsections, 16)):
                        print("Section " + str(i) + " : ")
                        if Pe1.SectionTable.sections[i].name != Pe2.SectionTable.sections[i].name:
                              print("Pe1 name : " + Pe1.SectionTable.sections[i].name + " // " + str(
                                    bytearray.fromhex(Pe1.SectionTable.sections[i].name).decode()))
                              print("Pe2 name : " + Pe2.SectionTable.sections[i].name + " // " + str(
                                    bytearray.fromhex(Pe2.SectionTable.sections[i].name).decode()))
                        if Pe1.SectionTable.sections[i].virtualsize != Pe2.SectionTable.sections[i].virtualsize:
                              print("Pe1 virtualsize : " +
                                    Pe1.SectionTable.sections[i].virtualsize)
                              print("Pe2 virtualsize : " +
                                    Pe2.SectionTable.sections[i].virtualsize)
                        if Pe1.SectionTable.sections[i].virtualaddress != Pe2.SectionTable.sections[i].virtualaddress:
                              print("Pe1 virtualaddress : " +
                                    Pe1.SectionTable.sections[i].virtualaddress)
                              print("Pe2 virtualaddress : " +
                                    Pe2.SectionTable.sections[i].virtualaddress)
                        if Pe1.SectionTable.sections[i].sizeofrawdata != Pe2.SectionTable.sections[i].sizeofrawdata:
                              print("Pe1 sizeofrawdata : " +
                                    Pe1.SectionTable.sections[i].sizeofrawdata)
                              print("Pe2 sizeofrawdata : " +
                                    Pe2.SectionTable.sections[i].sizeofrawdata)
                        if Pe1.SectionTable.sections[i].pointertorawdata != Pe2.SectionTable.sections[i].pointertorawdata:
                              print("Pe1 pointertorawdata : " +
                                    Pe1.SectionTable.sections[i].pointertorawdata)
                              print("Pe2 pointertorawdata : " +
                                    Pe2.SectionTable.sections[i].pointertorawdata)
                        if Pe1.SectionTable.sections[i].pointertorelocations != Pe2.SectionTable.sections[i].pointertorelocations:
                              print("Pe1 pointertorelocations : " +
                                    Pe1.SectionTable.sections[i].pointertorelocations)
                              print("Pe2 pointertorelocations : " +
                                    Pe2.SectionTable.sections[i].pointertorelocations)
                        if Pe1.SectionTable.sections[i].pointertolinenumbers != Pe2.SectionTable.sections[i].pointertolinenumbers:
                              print("Pe1 pointertolinenumbers : " +
                                    Pe1.SectionTable.sections[i].pointertolinenumbers)
                              print("Pe2 pointertolinenumbers : " +
                                    Pe2.SectionTable.sections[i].pointertolinenumbers)
                        if Pe1.SectionTable.sections[i].numberofrelocations != Pe2.SectionTable.sections[i].numberofrelocations:
                              print("Pe1 numberofrelocations : " +
                                    Pe1.SectionTable.sections[i].numberofrelocations)
                              print("Pe2 numberofrelocations : " +
                                    Pe2.SectionTable.sections[i].numberofrelocations)
                        if Pe1.SectionTable.sections[i].numberoflinenumbers != Pe2.SectionTable.sections[i].numberoflinenumbers:
                              print("Pe1 numberoflinenumbers : " +
                                    Pe1.SectionTable.sections[i].numberoflinenumbers)
                              print("Pe2 numberoflinenumbers : " +
                                    Pe2.SectionTable.sections[i].numberoflinenumbers)
                        if Pe1.SectionTable.sections[i].characteristics != Pe2.SectionTable.sections[i].characteristics:
                              print("Pe1 characteristics : " +
                                    Pe1.SectionTable.sections[i].characteristics)
                              print("Pe2 characteristics : " +
                                    Pe2.SectionTable.sections[i].characteristics)
                  for i in range(int(Pe1.Coffheader.numberofsections, 16), int(Pe2.Coffheader.numberofsections, 16)):
                        print("Pe 2 Section " + str(i) + " : ")
                        print("     name : " + Pe2.SectionTable.sections[i].name + " // " + str(
                              bytearray.fromhex(Pe2.SectionTable.sections[i].name).decode()))
                        print("     virtualsize : " +
                              Pe2.SectionTable.sections[i].virtualsize)
                        print("     virtualaddress : " +
                              Pe2.SectionTable.sections[i].virtualaddress)
                        print("     sizeofrawdata : " +
                              Pe2.SectionTable.sections[i].sizeofrawdata)
                        print("     pointertorawdata : " +
                              Pe2.SectionTable.sections[i].pointertorawdata)
                        print("     pointertorelocations : " +
                              Pe2.SectionTable.sections[i].pointertorelocations)
                        print("     pointertolinenumbers : " +
                              Pe2.SectionTable.sections[i].pointertolinenumbers)
                        print("     numberofrelocations : " +
                              Pe2.SectionTable.sections[i].numberofrelocations)
                        print("     numberoflinenumbers : " +
                              Pe2.SectionTable.sections[i].numberoflinenumbers)
                        print("     characteristics : " +
                              Pe2.SectionTable.sections[i].characteristics)
            elif int(Pe1.Coffheader.numberofsections, 16) > int(Pe2.Coffheader.numberofsections, 16):
                  for i in range(0, int(Pe2.Coffheader.numberofsections, 16)):
                        Log("ERROR", "Pe1 have more sections.")
                        print("Section " + str(i) + " : ")
                        if Pe1.SectionTable.sections[i].name != Pe2.SectionTable.sections[i].name:
                              print("Pe1 name : " + Pe1.SectionTable.sections[i].name + " // " + str(
                                    bytearray.fromhex(Pe1.SectionTable.sections[i].name).decode()))
                              print("Pe2 name : " + Pe2.SectionTable.sections[i].name + " // " + str(
                                    bytearray.fromhex(Pe2.SectionTable.sections[i].name).decode()))
                        if Pe1.SectionTable.sections[i].virtualsize != Pe2.SectionTable.sections[i].virtualsize:
                              print("Pe1 virtualsize : " +
                                    Pe1.SectionTable.sections[i].virtualsize)
                              print("Pe2 virtualsize : " +
                                    Pe2.SectionTable.sections[i].virtualsize)
                        if Pe1.SectionTable.sections[i].virtualaddress != Pe2.SectionTable.sections[i].virtualaddress:
                              print("Pe1 virtualaddress : " +
                                    Pe1.SectionTable.sections[i].virtualaddress)
                              print("Pe2 virtualaddress : " +
                                    Pe2.SectionTable.sections[i].virtualaddress)
                        if Pe1.SectionTable.sections[i].sizeofrawdata != Pe2.SectionTable.sections[i].sizeofrawdata:
                              print("Pe1 sizeofrawdata : " +
                                    Pe1.SectionTable.sections[i].sizeofrawdata)
                              print("Pe2 sizeofrawdata : " +
                                    Pe2.SectionTable.sections[i].sizeofrawdata)
                        if Pe1.SectionTable.sections[i].pointertorawdata != Pe2.SectionTable.sections[i].pointertorawdata:
                              print("Pe1 pointertorawdata : " +
                                    Pe1.SectionTable.sections[i].pointertorawdata)
                              print("Pe2 pointertorawdata : " +
                                    Pe2.SectionTable.sections[i].pointertorawdata)
                        if Pe1.SectionTable.sections[i].pointertorelocations != Pe2.SectionTable.sections[i].pointertorelocations:
                              print("Pe1 pointertorelocations : " +
                                    Pe1.SectionTable.sections[i].pointertorelocations)
                              print("Pe2 pointertorelocations : " +
                                    Pe2.SectionTable.sections[i].pointertorelocations)
                        if Pe1.SectionTable.sections[i].pointertolinenumbers != Pe2.SectionTable.sections[i].pointertolinenumbers:
                              print("Pe1 pointertolinenumbers : " +
                                    Pe1.SectionTable.sections[i].pointertolinenumbers)
                              print("Pe2 pointertolinenumbers : " +
                                    Pe2.SectionTable.sections[i].pointertolinenumbers)
                        if Pe1.SectionTable.sections[i].numberofrelocations != Pe2.SectionTable.sections[i].numberofrelocations:
                              print("Pe1 numberofrelocations : " +
                                    Pe1.SectionTable.sections[i].numberofrelocations)
                              print("Pe2 numberofrelocations : " +
                                    Pe2.SectionTable.sections[i].numberofrelocations)
                        if Pe1.SectionTable.sections[i].numberoflinenumbers != Pe2.SectionTable.sections[i].numberoflinenumbers:
                              print("Pe1 numberoflinenumbers : " +
                                    Pe1.SectionTable.sections[i].numberoflinenumbers)
                              print("Pe2 numberoflinenumbers : " +
                                    Pe2.SectionTable.sections[i].numberoflinenumbers)
                        if Pe1.SectionTable.sections[i].characteristics != Pe2.SectionTable.sections[i].characteristics:
                              print("Pe1 characteristics : " +
                                    Pe1.SectionTable.sections[i].characteristics)
                              print("Pe2 characteristics : " +
                                    Pe2.SectionTable.sections[i].characteristics)
                  for i in range(int(Pe2.Coffheader.numberofsections, 16), int(Pe1.Coffheader.numberofsections, 16)):
                        print("Pe 1 Section " + str(i) + " : ")
                        print("     name : " + Pe1.SectionTable.sections[i].name + " // " + str(
                              bytearray.fromhex(Pe1.SectionTable.sections[i].name).decode()))
                        print("     virtualsize : " +
                              Pe1.SectionTable.sections[i].virtualsize)
                        print("     virtualaddress : " +
                              Pe1.SectionTable.sections[i].virtualaddress)
                        print("     sizeofrawdata : " +
                              Pe1.SectionTable.sections[i].sizeofrawdata)
                        print("     pointertorawdata : " +
                              Pe1.SectionTable.sections[i].pointertorawdata)
                        print("     pointertorelocations : " +
                              Pe1.SectionTable.sections[i].pointertorelocations)
                        print("     pointertolinenumbers : " +
                              Pe1.SectionTable.sections[i].pointertolinenumbers)
                        print("     numberofrelocations : " +
                              Pe1.SectionTable.sections[i].numberofrelocations)
                        print("     numberoflinenumbers : " +
                              Pe1.SectionTable.sections[i].numberoflinenumbers)
                        print("     characteristics : " +
                              Pe1.SectionTable.sections[i].characteristics)
            else:
                  Log("SUCCESS", "Same section number.")
                  for i in range(0, int(Pe1.Coffheader.numberofsections, 16)):
                        print("Section " + str(i) + " : ")
                        if Pe1.SectionTable.sections[i].name != Pe2.SectionTable.sections[i].name:
                              print("Pe1 name : " + Pe1.SectionTable.sections[i].name + " // " + str(
                                    bytearray.fromhex(Pe1.SectionTable.sections[i].name).decode()))
                              print("Pe2 name : " + Pe2.SectionTable.sections[i].name + " // " + str(
                                    bytearray.fromhex(Pe2.SectionTable.sections[i].name).decode()))
                        if Pe1.SectionTable.sections[i].virtualsize != Pe2.SectionTable.sections[i].virtualsize:
                              print("Pe1 virtualsize : " +
                                    Pe1.SectionTable.sections[i].virtualsize)
                              print("Pe2 virtualsize : " +
                                    Pe2.SectionTable.sections[i].virtualsize)
                        if Pe1.SectionTable.sections[i].virtualaddress != Pe2.SectionTable.sections[i].virtualaddress:
                              print("Pe1 virtualaddress : " +
                                    Pe1.SectionTable.sections[i].virtualaddress)
                              print("Pe2 virtualaddress : " +
                                    Pe2.SectionTable.sections[i].virtualaddress)
                        if Pe1.SectionTable.sections[i].sizeofrawdata != Pe2.SectionTable.sections[i].sizeofrawdata:
                              print("Pe1 sizeofrawdata : " +
                                    Pe1.SectionTable.sections[i].sizeofrawdata)
                              print("Pe2 sizeofrawdata : " +
                                    Pe2.SectionTable.sections[i].sizeofrawdata)
                        if Pe1.SectionTable.sections[i].pointertorawdata != Pe2.SectionTable.sections[i].pointertorawdata:
                              print("Pe1 pointertorawdata : " +
                                    Pe1.SectionTable.sections[i].pointertorawdata)
                              print("Pe2 pointertorawdata : " +
                                    Pe2.SectionTable.sections[i].pointertorawdata)
                        if Pe1.SectionTable.sections[i].pointertorelocations != Pe2.SectionTable.sections[i].pointertorelocations:
                              print("Pe1 pointertorelocations : " +
                                    Pe1.SectionTable.sections[i].pointertorelocations)
                              print("Pe2 pointertorelocations : " +
                                    Pe2.SectionTable.sections[i].pointertorelocations)
                        if Pe1.SectionTable.sections[i].pointertolinenumbers != Pe2.SectionTable.sections[i].pointertolinenumbers:
                              print("Pe1 pointertolinenumbers : " +
                                    Pe1.SectionTable.sections[i].pointertolinenumbers)
                              print("Pe2 pointertolinenumbers : " +
                                    Pe2.SectionTable.sections[i].pointertolinenumbers)
                        if Pe1.SectionTable.sections[i].numberofrelocations != Pe2.SectionTable.sections[i].numberofrelocations:
                              print("Pe1 numberofrelocations : " +
                                    Pe1.SectionTable.sections[i].numberofrelocations)
                              print("Pe2 numberofrelocations : " +
                                    Pe2.SectionTable.sections[i].numberofrelocations)
                        if Pe1.SectionTable.sections[i].numberoflinenumbers != Pe2.SectionTable.sections[i].numberoflinenumbers:
                              print("Pe1 numberoflinenumbers : " +
                                    Pe1.SectionTable.sections[i].numberoflinenumbers)
                              print("Pe2 numberoflinenumbers : " +
                                    Pe2.SectionTable.sections[i].numberoflinenumbers)
                        if Pe1.SectionTable.sections[i].characteristics != Pe2.SectionTable.sections[i].characteristics:
                              print("Pe1 characteristics : " +
                                    Pe1.SectionTable.sections[i].characteristics)
                              print("Pe2 characteristics : " +
                                    Pe2.SectionTable.sections[i].characteristics)
