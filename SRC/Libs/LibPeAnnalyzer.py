'''
Library made for analyzing EXE file.
-class MSDOSHEADER
      -string ToHex(self)
-class STUBPROGRAM
      -string ToHex(self)
-class SIGNATURE
      -string ToHex(self)
-class COFFHEADER
      -string ToHex(self)
-class DATADIRECTORY
      -string ToHex(self)
-class OPTIONALPEHEADER
      -string ToHex(self)
-class IMAGESECTIONHEADER
      -string ToHex(self)
-class SECTIONTABLE
      -string ToHex(self)
-class DUMMY
      -string ToHex(self)
-class PE
      -void PrintPE()
      -void PrintDosHeader()
      -void PrintStub()
      -void PrintSignature()
      -void PrintCoffHeader()
      -void PrintOptionalPEHeader()
      -void PrintSectionTable()
      -string ToHex()
-LibPeAnnalyzer.PE Extract(content: str)
-int ExtractDOSHeader(content: str, Pe: PE, index: int)
-int ExtractSTUBProgram(content: str, Pe: PE, index: int)
-int ExtractSignature(content: str, Pe: PE, index: int)
-int ExtractCOFFHeader(content: str, Pe: PE, index: int)
-int ExtractOptionalPEHeader(content: str, Pe: PE, index: int)
-int ExtractSectionsTable(content: str, Pe: PE, index: int)
-int ExtractDummy(content: str, Pe: PE, index: int)
'''
from SRC.Libs import LibDebug
from SRC.Libs import LibByteEditor
from datetime import datetime
BYTE = 2


class MSDOSHEADER:
      '''
      msdos header CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.signature = ""
            self.lastsize = ""
            self.nblocks = ""
            self.nreloc = ""
            self.hdrsize = ""
            self.minalloc = ""
            self.maxalloc = ""
            self.ss = ""
            self.sp = ""
            self.checksum = ""
            self.ip = ""
            self.cs = ""
            self.relocpos = ""
            self.noverlay = ""
            self.reserved1 = ""
            self.oem_id = ""
            self.oem_info = ""
            self.reserved2 = ""
            self.e_lfanew = ""
            self.sizeof_signature = 2*BYTE
            self.sizeof_lastsize = 2*BYTE
            self.sizeof_nblocks = 2*BYTE
            self.sizeof_nreloc = 2*BYTE
            self.sizeof_hdrsize = 2*BYTE
            self.sizeof_minalloc = 2*BYTE
            self.sizeof_maxalloc = 2*BYTE
            self.sizeof_ss = 6*BYTE  # Pourquoi 6 BYTEs ? en réalité c'est un WORD ou, "the amount of data that a machine can process at one time"
            self.sizeof_sp = 6*BYTE  # Pareil
            self.sizeof_checksum = 2*BYTE
            self.sizeof_ip = 6*BYTE  # Pareil
            self.sizeof_cs = 6*BYTE  # Pareil
            self.sizeof_relocpos = 2*BYTE
            self.sizeof_noverlay = 2*BYTE
            self.sizeof_reserved1 = 2*BYTE
            self.sizeof_oem_id = 2*BYTE
            self.sizeof_oem_info = 2*BYTE
            self.sizeof_reserved2 = 10*BYTE
            self.sizeof_e_lfanew = 4*BYTE
            self.sizeof_MSDOSHEADER = self.sizeof_signature + self.sizeof_lastsize + self.sizeof_nblocks + self.sizeof_nreloc + self.sizeof_hdrsize + self.sizeof_minalloc + self.sizeof_maxalloc + self.sizeof_ss + self.sizeof_sp + self.sizeof_checksum + self.sizeof_ip + self.sizeof_cs + self.sizeof_relocpos + self.sizeof_noverlay + self.sizeof_reserved1 + self.sizeof_oem_id + self.sizeof_oem_info + self.sizeof_reserved2  + self.sizeof_e_lfanew

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += self.signature  # On ne revert pas la signature MZ
            content += LibByteEditor.RevertBytes(self.lastsize)
            content += LibByteEditor.RevertBytes(self.nblocks)
            content += LibByteEditor.RevertBytes(self.nreloc)
            content += LibByteEditor.RevertBytes(self.hdrsize)
            content += LibByteEditor.RevertBytes(self.minalloc)
            content += LibByteEditor.RevertBytes(self.maxalloc)
            content += LibByteEditor.RevertBytes(self.ss)
            content += LibByteEditor.RevertBytes(self.sp)
            content += LibByteEditor.RevertBytes(self.checksum)
            content += LibByteEditor.RevertBytes(self.ip)
            content += LibByteEditor.RevertBytes(self.cs)
            content += LibByteEditor.RevertBytes(self.relocpos)
            content += LibByteEditor.RevertBytes(self.noverlay)
            content += LibByteEditor.RevertBytes(self.reserved1)
            content += LibByteEditor.RevertBytes(self.oem_id)
            content += LibByteEditor.RevertBytes(self.oem_info)
            content += LibByteEditor.RevertBytes(self.reserved2)
            content += LibByteEditor.RevertBytes(self.e_lfanew)
            return content


class STUBPROGRAM:  # Pourquoi pas l'analyser un jour pour une future édition "Cannot be run in HAX mode. Edit c'est faisable avec une option de compilation."
      '''
      STUB program CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.stub = ""
            self.sizeof_stub = 2*BYTE
            self.sizeof_STUBPROGRAM = self.sizeof_stub

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += self.stub  # On ne revert pas (encore) le STUB
            return content


# Pourquoi pas lister les machines aux signatures (Fausser la signature ? == resultats inconnus \o/)
class SIGNATURE:
      '''
      Signature CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.signature = ""
            self.sizeof_signature = 4*BYTE
            self.sizeof_SIGNATURE= self.sizeof_signature

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += self.signature  # On ne revert pas la signature PE
            return content


class COFFHEADER:
      '''
      COFF header CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.machine = ""
            self.numberofsections = ""
            self.timedatestamp = ""
            self.pointertosymboltable = ""
            self.numberofsymbols = ""
            self.sizeofoptionalheader = ""
            self.characteristics = ""
            self.sizeof_machine = 2*BYTE
            self.sizeof_numberofsections = 2*BYTE
            self.sizeof_timedatestamp = 4*BYTE
            self.sizeof_pointertosymboltable = 4*BYTE
            self.sizeof_numberofsymbols = 4*BYTE
            self.sizeof_sizeofoptionalheader = 2*BYTE
            self.sizeof_characteristics = 2*BYTE

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += LibByteEditor.RevertBytes(self.machine)
            content += LibByteEditor.RevertBytes(self.numberofsections)
            content += LibByteEditor.RevertBytes(self.timedatestamp)
            content += LibByteEditor.RevertBytes(self.pointertosymboltable)
            content += LibByteEditor.RevertBytes(self.numberofsymbols)
            content += LibByteEditor.RevertBytes(self.sizeofoptionalheader)
            content += LibByteEditor.RevertBytes(self.characteristics)
            return content

class DATADIRECTORY:
      '''
      Data directory CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.virtualaddress = ""
            self.size = ""
            self.sizeof_virtualaddress = 4*BYTE
            self.sizeof_size = 4*BYTE
            self.sizeof_DATADIRECTORY = self.sizeof_virtualaddress + self.sizeof_size

class OPTIONALPEHEADER:
      '''
      Optionnal header CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.signature = ""
            self.majorlinkerversion = ""
            self.minorlinkerversion = ""
            self.sizeofcode = ""
            self.sizeofinitializeddata = ""
            self.sizeofuninitializeddata = ""
            self.addressofentrypoint = ""
            self.baseofcode = ""
            self.baseofdata = ""
            self.imagebase = ""
            self.sectionalignment = ""
            self.filealignment = ""
            self.majorosversion = ""
            self.minorosversion = ""
            self.majorimageversion = ""
            self.minorimageversion = ""
            self.majorsubsystemversion = ""
            self.minorsubsystemversion = ""
            self.win32versionvalue = ""
            self.sizeofimage = ""
            self.sizeofheaders = ""
            self.checksum = ""
            self.subsystem = ""
            self.dllcharacteristics = ""
            self.sizeofstackreserve = ""
            self.sizeofstackcommit = ""
            self.sizeofheapreserve = ""
            self.sizeofheapcommit = ""
            self.loaderflags = ""
            self.numberofrvaandsizes = ""
            self.datadirectory = []
            self.sizeof_signature = 2*BYTE
            self.sizeof_majorlinkerversion = 1*BYTE
            self.sizeof_minorlinkerversion = 1*BYTE
            self.sizeof_sizeofcode = 4*BYTE
            self.sizeof_sizeofinitializeddata = 4*BYTE
            self.sizeof_sizeofuninitializeddata = 4*BYTE
            self.sizeof_addressofentrypoint = 4*BYTE
            self.sizeof_baseofcode = 4*BYTE
            self.x32_sizeof_baseofdata = 4*BYTE
            self.x32_sizeof_imagebase = 4*BYTE
            self.x64_sizeof_imagebase = 8*BYTE
            self.sizeof_sectionalignment = 4*BYTE
            self.sizeof_filealignment = 4*BYTE
            self.sizeof_majorosversion = 2*BYTE
            self.sizeof_minorosversion = 2*BYTE
            self.sizeof_majorimageversion = 2*BYTE
            self.sizeof_minorimageversion = 2*BYTE
            self.sizeof_majorsubsystemversion = 2*BYTE
            self.sizeof_minorsubsystemversion = 2*BYTE
            self.sizeof_win32versionvalue = 4*BYTE
            self.sizeof_sizeofimage = 4*BYTE
            self.sizeof_sizeofheaders = 4*BYTE
            self.sizeof_checksum = 4*BYTE
            self.sizeof_subsystem = 2*BYTE
            self.sizeof_dllcharacteristics = 2*BYTE
            self.x32_sizeof_sizeofstackreserve = 4*BYTE
            self.x64_sizeof_sizeofstackreserve = 8*BYTE
            self.x32_sizeof_sizeofstackcommit = 4*BYTE
            self.x64_sizeof_sizeofstackcommit = 8*BYTE
            self.x32_sizeof_sizeofheapreserve = 4*BYTE
            self.x64_sizeof_sizeofheapreserve = 8*BYTE
            self.x32_sizeof_sizeofheapcommit = 4*BYTE
            self.x64_sizeof_sizeofheapcommit = 8*BYTE
            self.sizeof_loaderflags = 4*BYTE
            self.sizeof_numberofrvaandsizes = 4*BYTE
            self.sizeof_OPTIONALPEHEADER = self.sizeof_signature +self.sizeof_majorlinkerversion +self.sizeof_minorlinkerversion +self.sizeof_sizeofcode +self.sizeof_sizeofinitializeddata +self.sizeof_sizeofuninitializeddata +self.sizeof_addressofentrypoint +self.sizeof_baseofcode +self.x32_sizeof_baseofdata +self.x32_sizeof_imagebase +self.sizeof_sectionalignment +self.sizeof_filealignment +self.sizeof_majorosversion +self.sizeof_minorosversion +self.sizeof_majorimageversion +self.sizeof_minorimageversion +self.sizeof_majorsubsystemversion +self.sizeof_minorsubsystemversion +self.sizeof_win32versionvalue +self.sizeof_sizeofimage +self.sizeof_sizeofheaders +self.sizeof_checksum +self.sizeof_subsystem +self.sizeof_dllcharacteristics +self.x32_sizeof_sizeofstackreserve +self.x32_sizeof_sizeofstackcommit +self.x32_sizeof_sizeofheapreserve +self.x32_sizeof_sizeofheapcommit +self.sizeof_loaderflags +self.sizeof_numberofrvaandsizes
            if self.numberofrvaandsizes:
                  for _ in range(int(self.numberofrvaandsizes,16)):
                        self.sizeof_OPTIONALPEHEADER += 8*BYTE

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += LibByteEditor.RevertBytes(self.signature)
            content += LibByteEditor.RevertBytes(self.majorlinkerversion)
            content += LibByteEditor.RevertBytes(self.minorlinkerversion)
            content += LibByteEditor.RevertBytes(self.sizeofcode)
            content += LibByteEditor.RevertBytes(self.sizeofinitializeddata)
            content += LibByteEditor.RevertBytes(self.sizeofuninitializeddata)
            content += LibByteEditor.RevertBytes(self.addressofentrypoint)
            content += LibByteEditor.RevertBytes(self.baseofcode)
            if self.signature == "010b":  # x32
                  content += LibByteEditor.RevertBytes(self.baseofdata)
            content += LibByteEditor.RevertBytes(self.imagebase)
            content += LibByteEditor.RevertBytes(self.sectionalignment)
            content += LibByteEditor.RevertBytes(self.filealignment)
            content += LibByteEditor.RevertBytes(self.majorosversion)
            content += LibByteEditor.RevertBytes(self.minorosversion)
            content += LibByteEditor.RevertBytes(self.majorimageversion)
            content += LibByteEditor.RevertBytes(self.minorimageversion)
            content += LibByteEditor.RevertBytes(self.majorsubsystemversion)
            content += LibByteEditor.RevertBytes(self.minorsubsystemversion)
            content += LibByteEditor.RevertBytes(self.win32versionvalue)
            content += LibByteEditor.RevertBytes(self.sizeofimage)
            content += LibByteEditor.RevertBytes(self.sizeofheaders)
            content += LibByteEditor.RevertBytes(self.checksum)
            content += LibByteEditor.RevertBytes(self.subsystem)
            content += LibByteEditor.RevertBytes(self.dllcharacteristics)
            content += LibByteEditor.RevertBytes(self.sizeofstackreserve)
            content += LibByteEditor.RevertBytes(self.sizeofstackcommit)
            content += LibByteEditor.RevertBytes(self.sizeofheapreserve)
            content += LibByteEditor.RevertBytes(self.sizeofheapcommit)
            content += LibByteEditor.RevertBytes(self.loaderflags)
            content += LibByteEditor.RevertBytes(self.numberofrvaandsizes)
            for i in range(int(self.numberofrvaandsizes,16)):
                  content += LibByteEditor.RevertBytes(self.datadirectory[i].virtualaddress)
                  content += LibByteEditor.RevertBytes(self.datadirectory[i].size)
            return content

class IMAGESECTIONHEADER:
      '''
      Image section header CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.name = ""
            self.virtualsize = ""
            self.virtualaddress = ""
            self.sizeofrawdata = ""
            self.pointertorawdata = ""
            self.pointertorelocations = ""
            self.pointertolinenumbers = ""
            self.numberofrelocations = ""
            self.numberoflinenumbers = ""
            self.characteristics = ""
            self.rawdata = "" # partie custom de la section qui contient la rawdata de cette section
            self.sizeof_name = 8*BYTE
            self.sizeof_virtualsize = 4*BYTE
            self.sizeof_virtualaddress = 4*BYTE
            self.sizeof_sizeofrawdata = 4*BYTE
            self.sizeof_pointertorawdata = 4*BYTE
            self.sizeof_pointertorelocations = 4*BYTE
            self.sizeof_pointertolinenumbers = 4*BYTE
            self.sizeof_numberofrelocations = 2*BYTE
            self.sizeof_numberoflinenumbers = 2*BYTE
            self.sizeof_characteristics = 4*BYTE

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += self.name # On ne revert pas le name qui est un string
            content += LibByteEditor.RevertBytes(self.virtualsize)
            content += LibByteEditor.RevertBytes(self.virtualaddress)
            content += LibByteEditor.RevertBytes(self.sizeofrawdata)
            content += LibByteEditor.RevertBytes(self.pointertorawdata)
            content += LibByteEditor.RevertBytes(self.pointertorelocations)
            content += LibByteEditor.RevertBytes(self.pointertolinenumbers)
            content += LibByteEditor.RevertBytes(self.numberofrelocations)
            content += LibByteEditor.RevertBytes(self.numberoflinenumbers)
            content += LibByteEditor.RevertBytes(self.characteristics)
            return content

class SECTIONTABLE:
      '''
      Section table CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.sections = []
      
      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            for i in range(0, len(self.sections)):
                  content += self.sections[i].ToHex()
            return content

class DUMMY:
      '''
      Dummy CLASS.
      -string ToHex(self)
      '''
      def __init__(self):
            self.dummyindex = 0
            self.dum01 = ""
      
      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += self.dum01
            return content


class PE:
      '''
      PE Class.
      -void PrintPE()
      -void PrintDosHeader()
      -void PrintStub()
      -void PrintSignature()
      -void PrintCoffHeader()
      -void PrintOptionalPEHeader()
      -void PrintSectionTable()
      -string ToHex()
      '''
      def __init__(self):
            self.Msdosheader = MSDOSHEADER()
            self.Stubprogram = STUBPROGRAM()
            self.Signature = SIGNATURE()
            self.Coffheader = COFFHEADER()
            self.Optionalpeheader = OPTIONALPEHEADER()
            self.SectionTable = SECTIONTABLE()
            self.Dummy = DUMMY()

      def PrintPE(self):
            '''
            Print all the PE informations.
            -return: void
            '''
            self.PrintDosHeader()
            self.PrintStub()
            self.PrintSignature()
            self.PrintCoffHeader()
            self.PrintOptionalPEHeader()
            self.PrintSectionTable()

      def PrintDosHeader(self):
            '''
            Print the DOS Header.
            -return: void
            '''
            print("\nDOSHEADER :")
            print("Magic number : " + self.Msdosheader.signature)
            print("Last page of file BYTEs : " + self.Msdosheader.lastsize)
            print("Pages in file : " + self.Msdosheader.nblocks)
            print("Relocations : " + self.Msdosheader.nreloc)
            print("Size of headers : " + self.Msdosheader.hdrsize)
            print("Minimum extra parapgraphs needed : " +
                  self.Msdosheader.minalloc)
            print("Maximum extra parapgraphs needed : " +
                  self.Msdosheader.maxalloc)
            print("Initial (relative) SS value : " + self.Msdosheader.ss)
            print("Initial SP value : " + self.Msdosheader.sp)
            print("Checksum : " + self.Msdosheader.checksum)
            print("Initial IP value : " + self.Msdosheader.ip)
            print("Initial (relative) CS value : " + self.Msdosheader.cs)
            print("File address of relocation table : " +
                  self.Msdosheader.relocpos)
            print("Overlay number : " + self.Msdosheader.noverlay)
            print("Reserved 1 : " + self.Msdosheader.reserved1)
            print("OEM identifier : " + self.Msdosheader.oem_id)
            print("OEM information : " + self.Msdosheader.oem_info)
            print("Reserved 2 : " + self.Msdosheader.reserved2)
            print("File adress of the new exe header : " +
                  self.Msdosheader.e_lfanew)

      def PrintStub(self):
            '''
            Print the STUB program.
            -return: void
            '''
            print("\nSTUB :")
            print("Stub : " + self.Stubprogram.stub)

      def PrintSignature(self):
            '''
            Print the signature.
            -return: void
            '''
            print("\nSIGNATURE :")
            print("Signature : " + self.Signature.signature)

      def PrintCoffHeader(self):
            '''
            Print the COFF Header.
            -return: void
            '''
            print("\nCOFF :")
            print("machine : " + self.Coffheader.machine)
            print("numberofsections : " + self.Coffheader.numberofsections)
            print("timedatestamp : " + self.Coffheader.timedatestamp + " // " +
                  str(datetime.fromtimestamp(int(self.Coffheader.timedatestamp, 16))))
            print("pointertosymboltable : " +
                  self.Coffheader.pointertosymboltable)
            print("numberofsymbols : " + self.Coffheader.numberofsymbols)
            print("sizeofoptionalheader : " +
                  self.Coffheader.sizeofoptionalheader)
            print("characteristics : " + self.Coffheader.characteristics)

      def PrintOptionalPEHeader(self):
            '''
            Print the optionnal PE Header.
            -return: void
            '''
            print("\nOPTIONALHEADER :")
            print("Signature : " + self.Optionalpeheader.signature)
            print("Major linker version : " +
                  self.Optionalpeheader.majorlinkerversion)
            print("Minor linker version : " +
                  self.Optionalpeheader.minorlinkerversion)
            print("Size of code : " + self.Optionalpeheader.sizeofcode)
            print("Size of initialized data : " +
                  self.Optionalpeheader.sizeofinitializeddata)
            print("Size of uninitialized data : " +
                  self.Optionalpeheader.sizeofuninitializeddata)
            print("Adress of entry point : " +
                  self.Optionalpeheader.addressofentrypoint)
            print("Base of code : " + self.Optionalpeheader.baseofcode)
            if self.Optionalpeheader.signature == "010b":  # x32
                  print("Base of data : " + self.Optionalpeheader.baseofdata)
            print("Image base : " + self.Optionalpeheader.imagebase)
            print("Section alignment : " +
                  self.Optionalpeheader.sectionalignment)
            print("File alignment : " + self.Optionalpeheader.filealignment)
            print("Major os version : " + self.Optionalpeheader.majorosversion)
            print("Minor os version : " + self.Optionalpeheader.minorosversion)
            print("Major image version : " +
                  self.Optionalpeheader.majorimageversion)
            print("Minor image version : " +
                  self.Optionalpeheader.minorimageversion)
            print("Major subsystem version : " +
                  self.Optionalpeheader.majorsubsystemversion)
            print("Minor subsystem version : " +
                  self.Optionalpeheader.minorsubsystemversion)
            print("Win32 version value : " +
                  self.Optionalpeheader.win32versionvalue)
            print("Size of image : " + self.Optionalpeheader.sizeofimage)
            print("Size of headers : " + self.Optionalpeheader.sizeofheaders)
            print("Checksum : " + self.Optionalpeheader.checksum)
            print("Subsystem : " + self.Optionalpeheader.subsystem)
            print("DLL characteristics : " +
                  self.Optionalpeheader.dllcharacteristics)
            print("Size of stack reserve : " +
                  self.Optionalpeheader.sizeofstackreserve)
            print("Size of stack commit : " +
                  self.Optionalpeheader.sizeofstackcommit)
            print("Size of heap reserve : " +
                  self.Optionalpeheader.sizeofheapreserve)
            print("Size of heap commit : " +
                  self.Optionalpeheader.sizeofheapcommit)
            print("Loader flags : " + self.Optionalpeheader.loaderflags)
            print("Number of RVA and sizes : " +
                  self.Optionalpeheader.numberofrvaandsizes)
            for i in range(int(self.Optionalpeheader.numberofrvaandsizes,16)):
                  print("VA " + str(i+1) + " : " + self.Optionalpeheader.datadirectory[i].virtualaddress)
                  print("SZ " + str(i+1) + " : " + self.Optionalpeheader.datadirectory[i].size)
      
      def PrintSectionTable(self):
            '''
            Print the Section table.
            -return: void
            '''
            print("\nSECTIONTABLE :")
            for i in range(0, int(self.Coffheader.numberofsections, 16)):
                  print("Image section " + str(i) + " :")
                  print("     name : " + self.SectionTable.sections[i].name + " // " + str(bytearray.fromhex(self.SectionTable.sections[i].name).decode()))
                  print("     virtualsize : " + self.SectionTable.sections[i].virtualsize)
                  print("     virtualaddress : " + self.SectionTable.sections[i].virtualaddress)
                  print("     sizeofrawdata : " + self.SectionTable.sections[i].sizeofrawdata)
                  print("     pointertorawdata : " + self.SectionTable.sections[i].pointertorawdata)
                  print("     pointertorelocations : " + self.SectionTable.sections[i].pointertorelocations)
                  print("     pointertolinenumbers : " + self.SectionTable.sections[i].pointertolinenumbers)
                  print("     numberofrelocations : " + self.SectionTable.sections[i].numberofrelocations)
                  print("     numberoflinenumbers : " + self.SectionTable.sections[i].numberoflinenumbers)
                  print("     characteristics : " + self.SectionTable.sections[i].characteristics)

      def ToHex(self):
            '''
            Return the Pe into a HEX string.
            -return: string
            '''
            content = ""
            content += self.Msdosheader.ToHex()
            content += self.Stubprogram.ToHex()

            while len(content) != int(2*int(self.Msdosheader.e_lfanew,16)):
                content += "0"

            content += self.Signature.ToHex()
            content += self.Coffheader.ToHex()
            content += self.Optionalpeheader.ToHex()
            content += self.SectionTable.ToHex()
            content += self.Dummy.ToHex()
            return content


def Extract(content: str):
      '''
      Extract all the PE informations into a PE class from a specified content HEX string.
      -return: LibPeAnnalyzer.PE
      '''
      if content[0:4] == "4d5a":
            Pe = PE()
            index = 0
            index = ExtractDOSHeader(content, Pe, index)
            index = ExtractSTUBProgram(content, Pe, index)
            index = int(2*int(Pe.Msdosheader.e_lfanew,16)) #On calcul la position de l'adresse contenue dans e_lfanew et on l'applique à l'index pour avoir le début de la section de signature
            index = ExtractSignature(content, Pe, index)
            index = ExtractCOFFHeader(content, Pe, index)
            index = ExtractOptionalPEHeader(content, Pe, index)
            index = ExtractSectionsTable(content, Pe, index)
            ExtractDummy(content, Pe, index)
            return Pe
      else:
            print("Your file isn't a valid PE Executable, invalid magic number " +
                  content[2:4] + content[0:2] + ".")
            exit()


def ExtractDOSHeader(content: str, Pe: PE, index: int):
      '''
      Extract the DOS header from a content and add it to a LibPeAnnalyzer.PE class.
      -return: int
      '''
      LibDebug.Log("WORK", "Extracting DOS Header.")
      Pe.Msdosheader.signature = content[index:index +
                                         Pe.Msdosheader.sizeof_signature]  # La PE signature ou magic number n'est pas lu de droite à gauche, considérée comme un string.
      index += Pe.Msdosheader.sizeof_signature
      Pe.Msdosheader.lastsize = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_lastsize])
      index += Pe.Msdosheader.sizeof_lastsize
      Pe.Msdosheader.nblocks = LibByteEditor.RevertBytes(content[index:index +
                                                                 Pe.Msdosheader.sizeof_nblocks])
      index += Pe.Msdosheader.sizeof_nblocks
      Pe.Msdosheader.nreloc = LibByteEditor.RevertBytes(content[index:index +
                                                                Pe.Msdosheader.sizeof_nreloc])
      index += Pe.Msdosheader.sizeof_nreloc
      Pe.Msdosheader.hdrsize = LibByteEditor.RevertBytes(content[index:index +
                                                                 Pe.Msdosheader.sizeof_hdrsize])
      index += Pe.Msdosheader.sizeof_hdrsize
      Pe.Msdosheader.minalloc = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_minalloc])
      index += Pe.Msdosheader.sizeof_minalloc
      Pe.Msdosheader.maxalloc = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_maxalloc])
      index += Pe.Msdosheader.sizeof_maxalloc
      Pe.Msdosheader.ss = LibByteEditor.RevertBytes(
          content[index:index+Pe.Msdosheader.sizeof_ss])
      index += Pe.Msdosheader.sizeof_ss
      Pe.Msdosheader.sp = LibByteEditor.RevertBytes(
          content[index:index+Pe.Msdosheader.sizeof_sp])
      index += Pe.Msdosheader.sizeof_sp
      Pe.Msdosheader.checksum = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_checksum])
      index += Pe.Msdosheader.sizeof_checksum
      Pe.Msdosheader.ip = LibByteEditor.RevertBytes(
          content[index:index+Pe.Msdosheader.sizeof_ip])
      index += Pe.Msdosheader.sizeof_ip
      Pe.Msdosheader.cs = LibByteEditor.RevertBytes(
          content[index:index+Pe.Msdosheader.sizeof_cs])
      index += Pe.Msdosheader.sizeof_cs
      Pe.Msdosheader.relocpos = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_relocpos])
      index += Pe.Msdosheader.sizeof_relocpos
      Pe.Msdosheader.noverlay = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_noverlay])
      index += Pe.Msdosheader.sizeof_noverlay
      Pe.Msdosheader.reserved1 = LibByteEditor.RevertBytes(content[index:index +
                                                                   Pe.Msdosheader.sizeof_reserved1])
      index += Pe.Msdosheader.sizeof_reserved1
      Pe.Msdosheader.oem_id = LibByteEditor.RevertBytes(content[index:index +
                                                                Pe.Msdosheader.sizeof_oem_id])
      index += Pe.Msdosheader.sizeof_oem_id
      Pe.Msdosheader.oem_info = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_oem_info])
      index += Pe.Msdosheader.sizeof_oem_info
      Pe.Msdosheader.reserved2 = LibByteEditor.RevertBytes(content[index:index +
                                                                   Pe.Msdosheader.sizeof_reserved2])
      index += Pe.Msdosheader.sizeof_reserved2
      Pe.Msdosheader.e_lfanew = LibByteEditor.RevertBytes(content[index:index +
                                                                  Pe.Msdosheader.sizeof_e_lfanew])
      index += Pe.Msdosheader.sizeof_e_lfanew
      LibDebug.Log("SUCCESS", "End of the DOS Header extraction.")
      return index


def ExtractSTUBProgram(content: str, Pe: PE, index: int):
      '''
      Extract the STUB program from a content and add it to a LibPeAnnalyzer.PE class.
      -return: LibPeAnnalyzer.PE
      '''
      LibDebug.Log("WORK", "Extracting STUB program.")
      # Le STUB est considéré comme un "micro-programme", pas besoin de le lire inversé (en tout cas pour me moment).
      while content[index:index+Pe.Stubprogram.sizeof_stub] != "5045":
            Pe.Stubprogram.stub += content[index:index+Pe.Stubprogram.sizeof_stub]
            index += Pe.Stubprogram.sizeof_stub
            if len(Pe.Stubprogram.stub) > 1024 or len(Pe.Stubprogram.stub) >= len(content)-Pe.Msdosheader.sizeof_MSDOSHEADER:
                  LibDebug.Log("ERROR", "STUB seems too long, cannot reach PE signature.")
                  exit()
      #Le STUB na pas de taille fixe, on calcul donc sa taille jusqua la signature PE 5045
      LibDebug.Log("SUCCESS", "End of the STUB program extraction.")
      return index
      

def ExtractSignature(content: str, Pe: PE, index: int):
      '''
      Extract the Signature from a content and add it to a LibPeAnnalyzer.PE class.
      -return: LibPeAnnalyzer.PE
      '''
      LibDebug.Log("WORK", "Extracting signature.")
      Pe.Signature.signature = content[index:index +
                                       Pe.Signature.sizeof_signature]  # La signature du PE est considéré comme string, pas de lecture inverse non plus.
      index += Pe.Signature.sizeof_signature
      LibDebug.Log("SUCCESS", "End of the signature extraction.")
      return index


def ExtractCOFFHeader(content: str, Pe: PE, index: int):
      '''
      Extract the COFF header from a content and add it to a LibPeAnnalyzer.PE class.
      -return: int
      '''
      LibDebug.Log("WORK", "Extracting COFF Header.")
      Pe.Coffheader.machine = LibByteEditor.RevertBytes(
          content[index:index+Pe.Coffheader.sizeof_machine])
      index += Pe.Coffheader.sizeof_machine
      Pe.Coffheader.numberofsections = LibByteEditor.RevertBytes(content[index:index +
                                                                         Pe.Coffheader.sizeof_numberofsections])
      index += Pe.Coffheader.sizeof_numberofsections
      Pe.Coffheader.timedatestamp = LibByteEditor.RevertBytes(content[index:index +
                                                                      Pe.Coffheader.sizeof_timedatestamp])
      index += Pe.Coffheader.sizeof_timedatestamp
      Pe.Coffheader.pointertosymboltable = LibByteEditor.RevertBytes(content[index:index +
                                                                             Pe.Coffheader.sizeof_pointertosymboltable])
      index += Pe.Coffheader.sizeof_pointertosymboltable
      Pe.Coffheader.numberofsymbols = LibByteEditor.RevertBytes(content[index:index +
                                                                        Pe.Coffheader.sizeof_numberofsymbols])
      index += Pe.Coffheader.sizeof_numberofsymbols
      Pe.Coffheader.sizeofoptionalheader = LibByteEditor.RevertBytes(content[index:index +
                                                                             Pe.Coffheader.sizeof_sizeofoptionalheader])
      index += Pe.Coffheader.sizeof_sizeofoptionalheader
      Pe.Coffheader.characteristics = LibByteEditor.RevertBytes(content[index:index +
                                                                        Pe.Coffheader.sizeof_characteristics])
      index += Pe.Coffheader.sizeof_characteristics
      LibDebug.Log("SUCCESS", "End of the COFF Header extraction.")
      return index


def ExtractOptionalPEHeader(content: str, Pe: PE, index: int):
      '''
      Extract the optional PE header from a content and add it to a LibPeAnnalyzer.PE class.
      -return: int
      '''
      LibDebug.Log("WORK", "Extracting optionnal PE Header.")
      Pe.Optionalpeheader.signature = LibByteEditor.RevertBytes(content[index:index +
                                                                        Pe.Optionalpeheader.sizeof_signature])
      index += Pe.Optionalpeheader.sizeof_signature
      # decimal number 010b for 32 bit, 020B for 64 bit, and 0107 for a ROM image.
      if Pe.Optionalpeheader.signature == "020b":
            LibDebug.Log(
                "SUCCESS", "Optional PE Header signature is x64 based.")
      elif Pe.Optionalpeheader.signature == "010b":
            LibDebug.Log(
                "SUCCESS", "Optional PE Header Signature is x32 based.")
      else:
            LibDebug.Log(
                "ERROR", "Bad signature found for the PE Optional Header.. Can be a ROM format")
            exit()
      Pe.Optionalpeheader.majorlinkerversion = LibByteEditor.RevertBytes(content[index:index +
                                                                                 Pe.Optionalpeheader.sizeof_majorlinkerversion])
      index += Pe.Optionalpeheader.sizeof_majorlinkerversion
      Pe.Optionalpeheader.minorlinkerversion = LibByteEditor.RevertBytes(content[index:index +
                                                                                 Pe.Optionalpeheader.sizeof_minorlinkerversion])
      index += Pe.Optionalpeheader.sizeof_minorlinkerversion
      Pe.Optionalpeheader.sizeofcode = LibByteEditor.RevertBytes(content[index:index +
                                                                         Pe.Optionalpeheader.sizeof_sizeofcode])
      index += Pe.Optionalpeheader.sizeof_sizeofcode
      Pe.Optionalpeheader.sizeofinitializeddata = LibByteEditor.RevertBytes(content[index:index +
                                                                                    Pe.Optionalpeheader.sizeof_sizeofinitializeddata])
      index += Pe.Optionalpeheader.sizeof_sizeofinitializeddata
      Pe.Optionalpeheader.sizeofuninitializeddata = LibByteEditor.RevertBytes(content[index:index +
                                                                                      Pe.Optionalpeheader.sizeof_sizeofuninitializeddata])
      index += Pe.Optionalpeheader.sizeof_sizeofuninitializeddata
      Pe.Optionalpeheader.addressofentrypoint = LibByteEditor.RevertBytes(content[index:index +
                                                                                  Pe.Optionalpeheader.sizeof_addressofentrypoint])
      index += Pe.Optionalpeheader.sizeof_addressofentrypoint
      Pe.Optionalpeheader.baseofcode = LibByteEditor.RevertBytes(content[index:index +
                                                                         Pe.Optionalpeheader.sizeof_baseofcode])
      index += Pe.Optionalpeheader.sizeof_baseofcode
      if Pe.Optionalpeheader.signature == "010b":  # x32
            Pe.Optionalpeheader.baseofdata = LibByteEditor.RevertBytes(content[index:index +
                                                                               Pe.Optionalpeheader.x32_sizeof_baseofdata])
            index += Pe.Optionalpeheader.x32_sizeof_baseofdata
            Pe.Optionalpeheader.imagebase = LibByteEditor.RevertBytes(content[index:index +
                                                                              Pe.Optionalpeheader.x32_sizeof_imagebase])
            index += Pe.Optionalpeheader.x32_sizeof_imagebase
      elif Pe.Optionalpeheader.signature == "020b":  # x64
            Pe.Optionalpeheader.imagebase = LibByteEditor.RevertBytes(content[index:index +
                                                                              Pe.Optionalpeheader.x64_sizeof_imagebase])
            index += Pe.Optionalpeheader.x64_sizeof_imagebase
      Pe.Optionalpeheader.sectionalignment = LibByteEditor.RevertBytes(content[index:index +
                                                                               Pe.Optionalpeheader.sizeof_sectionalignment])
      index += Pe.Optionalpeheader.sizeof_sectionalignment
      Pe.Optionalpeheader.filealignment = LibByteEditor.RevertBytes(content[index:index +
                                                                            Pe.Optionalpeheader.sizeof_filealignment])
      index += Pe.Optionalpeheader.sizeof_filealignment
      Pe.Optionalpeheader.majorosversion = LibByteEditor.RevertBytes(content[index:index +
                                                                             Pe.Optionalpeheader.sizeof_majorosversion])
      index += Pe.Optionalpeheader.sizeof_majorosversion
      Pe.Optionalpeheader.minorosversion = LibByteEditor.RevertBytes(content[index:index +
                                                                             Pe.Optionalpeheader.sizeof_minorosversion])
      index += Pe.Optionalpeheader.sizeof_minorosversion
      Pe.Optionalpeheader.majorimageversion = LibByteEditor.RevertBytes(content[index:index +
                                                                                Pe.Optionalpeheader.sizeof_majorimageversion])
      index += Pe.Optionalpeheader.sizeof_majorimageversion
      Pe.Optionalpeheader.minorimageversion = LibByteEditor.RevertBytes(content[index:index +
                                                                                Pe.Optionalpeheader.sizeof_minorimageversion])
      index += Pe.Optionalpeheader.sizeof_minorimageversion
      Pe.Optionalpeheader.majorsubsystemversion = LibByteEditor.RevertBytes(content[index:index +
                                                                                    Pe.Optionalpeheader.sizeof_majorsubsystemversion])
      index += Pe.Optionalpeheader.sizeof_majorsubsystemversion
      Pe.Optionalpeheader.minorsubsystemversion = LibByteEditor.RevertBytes(content[index:index +
                                                                                    Pe.Optionalpeheader.sizeof_minorsubsystemversion])
      index += Pe.Optionalpeheader.sizeof_minorsubsystemversion
      Pe.Optionalpeheader.win32versionvalue = LibByteEditor.RevertBytes(content[index:index +
                                                                                Pe.Optionalpeheader.sizeof_win32versionvalue])
      index += Pe.Optionalpeheader.sizeof_win32versionvalue
      Pe.Optionalpeheader.sizeofimage = LibByteEditor.RevertBytes(content[index:index +
                                                                          Pe.Optionalpeheader.sizeof_sizeofimage])
      index += Pe.Optionalpeheader.sizeof_sizeofimage
      Pe.Optionalpeheader.sizeofheaders = LibByteEditor.RevertBytes(content[index:index +
                                                                            Pe.Optionalpeheader.sizeof_sizeofheaders])
      index += Pe.Optionalpeheader.sizeof_sizeofheaders
      Pe.Optionalpeheader.checksum = LibByteEditor.RevertBytes(content[index:index +
                                                                       Pe.Optionalpeheader.sizeof_checksum])
      index += Pe.Optionalpeheader.sizeof_checksum
      Pe.Optionalpeheader.subsystem = LibByteEditor.RevertBytes(content[index:index +
                                                                        Pe.Optionalpeheader.sizeof_subsystem])
      index += Pe.Optionalpeheader.sizeof_subsystem
      Pe.Optionalpeheader.dllcharacteristics = LibByteEditor.RevertBytes(content[index:index +
                                                                                 Pe.Optionalpeheader.sizeof_dllcharacteristics])
      index += Pe.Optionalpeheader.sizeof_dllcharacteristics
      # decimal number 010b for 32 bit, 020B for 64 bit, and 0107 for a ROM image.
      if Pe.Optionalpeheader.signature == "010b":  # x32
            Pe.Optionalpeheader.sizeofstackreserve = LibByteEditor.RevertBytes(content[index:index +
                                                                                       Pe.Optionalpeheader.x32_sizeof_sizeofstackreserve])
            index += Pe.Optionalpeheader.x32_sizeof_sizeofstackreserve
            Pe.Optionalpeheader.sizeofstackcommit = LibByteEditor.RevertBytes(content[index:index +
                                                                                      Pe.Optionalpeheader.x32_sizeof_sizeofstackcommit])
            index += Pe.Optionalpeheader.x32_sizeof_sizeofstackcommit
            Pe.Optionalpeheader.sizeofheapreserve = LibByteEditor.RevertBytes(content[index:index +
                                                                                      Pe.Optionalpeheader.x32_sizeof_sizeofheapreserve])
            index += Pe.Optionalpeheader.x32_sizeof_sizeofheapreserve
            Pe.Optionalpeheader.sizeofheapcommit = LibByteEditor.RevertBytes(content[index:index +
                                                                                     Pe.Optionalpeheader.x32_sizeof_sizeofheapcommit])
            index += Pe.Optionalpeheader.x32_sizeof_sizeofheapcommit
      elif Pe.Optionalpeheader.signature == "020b":  # x64
            Pe.Optionalpeheader.sizeofstackreserve = LibByteEditor.RevertBytes(content[index:index +
                                                                                       Pe.Optionalpeheader.x64_sizeof_sizeofstackreserve])
            index += Pe.Optionalpeheader.x64_sizeof_sizeofstackreserve
            Pe.Optionalpeheader.sizeofstackcommit = LibByteEditor.RevertBytes(content[index:index +
                                                                                      Pe.Optionalpeheader.x64_sizeof_sizeofstackcommit])
            index += Pe.Optionalpeheader.x64_sizeof_sizeofstackcommit
            Pe.Optionalpeheader.sizeofheapreserve = LibByteEditor.RevertBytes(content[index:index +
                                                                                      Pe.Optionalpeheader.x64_sizeof_sizeofheapreserve])
            index += Pe.Optionalpeheader.x64_sizeof_sizeofheapreserve
            Pe.Optionalpeheader.sizeofheapcommit = LibByteEditor.RevertBytes(content[index:index +
                                                                                     Pe.Optionalpeheader.x64_sizeof_sizeofheapcommit])
            index += Pe.Optionalpeheader.x64_sizeof_sizeofheapcommit
      Pe.Optionalpeheader.loaderflags = LibByteEditor.RevertBytes(content[index:index +
                                                                          Pe.Optionalpeheader.sizeof_loaderflags])
      index += Pe.Optionalpeheader.sizeof_loaderflags
      Pe.Optionalpeheader.numberofrvaandsizes = LibByteEditor.RevertBytes(content[index:index +
                                                                                  Pe.Optionalpeheader.sizeof_numberofrvaandsizes])
      index += Pe.Optionalpeheader.sizeof_numberofrvaandsizes
      for i in range(int(Pe.Optionalpeheader.numberofrvaandsizes,16)):
            Pe.Optionalpeheader.datadirectory.append(DATADIRECTORY())
            Pe.Optionalpeheader.datadirectory[i].virtualaddress = LibByteEditor.RevertBytes(content[index:index +
                                                                                  Pe.Optionalpeheader.datadirectory[i].sizeof_virtualaddress])
            index += Pe.Optionalpeheader.datadirectory[i].sizeof_virtualaddress
            Pe.Optionalpeheader.datadirectory[i].size = LibByteEditor.RevertBytes(content[index:index +
                                                                                  Pe.Optionalpeheader.datadirectory[i].sizeof_size])
            index += Pe.Optionalpeheader.datadirectory[i].sizeof_size
      LibDebug.Log("SUCCESS", "End of the optional PE Header extraction.")
      return index


def ExtractSectionsTable(content: str, Pe: PE, index: int):
      '''
      Extract the sections table from a content and add it to a LibPeAnnalyzer.PE class.
      -return: LibPeAnnalyzer.PE
      '''
      LibDebug.Log("WORK", "Extracting Sections table.")
      for i in range(0, int(Pe.Coffheader.numberofsections, 16)):
            Pe.SectionTable.sections.append(IMAGESECTIONHEADER())
            Pe.SectionTable.sections[i].name = content[index:index + Pe.SectionTable.sections[i].sizeof_name]
            index += Pe.SectionTable.sections[i].sizeof_name
            Pe.SectionTable.sections[i].virtualsize = LibByteEditor.RevertBytes(content[index:index +
                                                                                        Pe.SectionTable.sections[i].sizeof_virtualsize])
            index += Pe.SectionTable.sections[i].sizeof_virtualsize
            Pe.SectionTable.sections[i].virtualaddress = LibByteEditor.RevertBytes(content[index:index +
                                                                                           Pe.SectionTable.sections[i].sizeof_virtualaddress])
            index += Pe.SectionTable.sections[i].sizeof_virtualaddress
            Pe.SectionTable.sections[i].sizeofrawdata = LibByteEditor.RevertBytes(content[index:index +
                                                                                          Pe.SectionTable.sections[i].sizeof_sizeofrawdata])
            index += Pe.SectionTable.sections[i].sizeof_sizeofrawdata
            Pe.SectionTable.sections[i].pointertorawdata = LibByteEditor.RevertBytes(content[index:index +
                                                                                             Pe.SectionTable.sections[i].sizeof_pointertorawdata])
            index += Pe.SectionTable.sections[i].sizeof_pointertorawdata
            Pe.SectionTable.sections[i].pointertorelocations = LibByteEditor.RevertBytes(content[index:index +
                                                                                                 Pe.SectionTable.sections[i].sizeof_pointertorelocations])
            index += Pe.SectionTable.sections[i].sizeof_pointertorelocations
            Pe.SectionTable.sections[i].pointertolinenumbers = LibByteEditor.RevertBytes(content[index:index +
                                                                                                 Pe.SectionTable.sections[i].sizeof_pointertolinenumbers])
            index += Pe.SectionTable.sections[i].sizeof_pointertolinenumbers
            Pe.SectionTable.sections[i].numberofrelocations = LibByteEditor.RevertBytes(content[index:index +
                                                                                                Pe.SectionTable.sections[i].sizeof_numberofrelocations])
            index += Pe.SectionTable.sections[i].sizeof_numberofrelocations
            Pe.SectionTable.sections[i].numberoflinenumbers = LibByteEditor.RevertBytes(content[index:index +
                                                                                                Pe.SectionTable.sections[i].sizeof_numberoflinenumbers])
            index += Pe.SectionTable.sections[i].sizeof_numberoflinenumbers
            Pe.SectionTable.sections[i].characteristics = LibByteEditor.RevertBytes(content[index:index +
                                                                                            Pe.SectionTable.sections[i].sizeof_characteristics]) 
            index += Pe.SectionTable.sections[i].sizeof_characteristics           
            indexTMP = index
            index = int(2*int(Pe.SectionTable.sections[i].pointertorawdata,16))
            Pe.SectionTable.sections[i].rawdata = content[index:index + int(int(Pe.SectionTable.sections[i].virtualsize,16))]
            index = indexTMP
      LibDebug.Log("SUCCESS", "End of the Sections table extraction.")
      return index

def ExtractDummy(content: str, Pe: PE, index: int):
      '''
      Extract the data part of a PE binnary.
      -return: LibPeAnnalyzer.PE
      '''
      Pe.Dummy.dummyindex = index
      Pe.Dummy.dum01 = content[index:len(content)]
