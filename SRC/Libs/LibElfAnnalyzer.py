'''
Library made for analyzing ELF file.
-class ELFHEADER
      -string ToHex(self)
-class PROGRAMHEADER
      -string ToHex(self)
-class PROGRAMHEADERTABLE
      -string ToHex(self)
-class SECTIONHEADER
      -string ToHex(self)
-class SECTIONHEADERTABLE
      -string ToHex(self)
-class ELF
      -void PrintELF()
      -void PrintElfHeader()
      -void PrintProgramHeaderTable()
      -void PrintSectionHeaderTable()
      -string ToHex()
-LibPeAnnalyzer.ELF Extract(content: str)
-int ExtractELFHeader(content: str, Elf: ELF, index: int)
-int ExtractProgramHeaderTable(content: str, Elf: ELF, index: int)
-int ExtractSectionHeaderTable(content: str, Elf: ELF, index: int)
'''
from SRC.Libs import LibDebug
from SRC.Libs import LibByteEditor
from datetime import datetime
BYTE = 2

class ELFHEADER:
      '''
      ELF HEADER Class.
      -string ToHex()
      '''
      def __init__(self):
            self.magic = "" #0x7f + ELF
            self.struct = "" #0,1,2 (Aucun, x64 ou x32)
            self.endianness = "" #0,1,2 (0, LSB, MSB)
            self.elfheaderversion = "" #ELFHEADER format Version
            self.osabi = "" #0,1,2,3,6,7,8,9,10,11,12,64,97,255
            self.abiversion = "" #ABI Version
            self.dummy = "" #range de 0, de 9 à 15 bytes
            self.filetype = "" #0,1,2,3,4
            self.machine = "" #0,2,3,4,7,8,19,20,40,50,62,243
            self.machineversion = "" #0,1 (Aucune, Version actuelle)
            self.entrypoint = "" #point d'entrée
            self.offset_programheader = "" #offset du programheader
            self.offset_sectionsheader = "" #offset du section header
            self.procflags = "" #flags de processeur
            self.elfheadersize = "" #taille du ELF header
            self.entrysize_programheader = "" #taille d'une entrée du program header
            self.entrynumber_programheader = "" #nombre d'entrée du program header
            self.entrysize_sectionheader = "" #taille d'une entrée de la section header
            self.entrynumber_sectionheader = "" #nombre d'entrée de la section header
            self.sectionnames_sectiontable_index = "" #index des noms de section dans la section table
            self.sizeof_magic = 4*BYTE
            self.sizeof_struct = 1*BYTE
            self.sizeof_endianness = 1*BYTE
            self.sizeof_elfheaderversion = 1*BYTE
            self.sizeof_osabi = 1*BYTE
            self.sizeof_abiversion = 1*BYTE
            self.sizeof_dummy = 7*BYTE #peut allez jusqua 15*BYTE
            self.sizeof_filetype = 2*BYTE
            self.sizeof_machine = 2*BYTE
            self.sizeof_machineversion = 4*BYTE
            self.x32_sizeof_entrypoint = 4*BYTE
            self.x64_sizeof_entrypoint = 8*BYTE
            self.x32_sizeof_offset_programheader = 4*BYTE
            self.x64_sizeof_offset_programheader = 8*BYTE
            self.x32_sizeof_offset_sectionsheader = 4*BYTE
            self.x64_sizeof_offset_sectionsheader = 8*BYTE
            self.sizeof_procflags = 4*BYTE
            self.sizeof_elfheadersize = 2*BYTE
            self.sizeof_entrysize_programheader = 2*BYTE
            self.sizeof_entrynumber_programheader = 2*BYTE
            self.sizeof_entrysize_sectionheader = 2*BYTE
            self.sizeof_entrynumber_sectionheader = 2*BYTE
            self.sizeof_sectionnames_sectiontable_index = 2*BYTE
            
      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += self.magic  # On ne revert pas la signature MZ
            content += LibByteEditor.RevertBytes(self.struct)
            content += LibByteEditor.RevertBytes(self.endianness)
            content += LibByteEditor.RevertBytes(self.elfheaderversion)
            content += LibByteEditor.RevertBytes(self.osabi)
            content += LibByteEditor.RevertBytes(self.abiversion)
            content += LibByteEditor.RevertBytes(self.dummy)
            content += LibByteEditor.RevertBytes(self.filetype)
            content += LibByteEditor.RevertBytes(self.machine)
            content += LibByteEditor.RevertBytes(self.machineversion)
            content += LibByteEditor.RevertBytes(self.entrypoint)
            content += LibByteEditor.RevertBytes(self.offset_programheader)
            content += LibByteEditor.RevertBytes(self.offset_sectionsheader)
            content += LibByteEditor.RevertBytes(self.procflags)
            content += LibByteEditor.RevertBytes(self.elfheadersize)
            content += LibByteEditor.RevertBytes(self.entrysize_programheader)
            content += LibByteEditor.RevertBytes(self.entrynumber_programheader)
            content += LibByteEditor.RevertBytes(self.entrysize_sectionheader)
            content += LibByteEditor.RevertBytes(self.entrynumber_sectionheader)
            content += LibByteEditor.RevertBytes(self.sectionnames_sectiontable_index)
            return content

class PROGRAMHEADER:
      '''
      PROGRAM HEADER Class.
      -string ToHex()
      '''
      def __init__(self):
            self.type = ""
            self.flags = ""
            self.offset = ""
            self.vaddr = ""
            self.paddr = ""
            self.filesz = ""
            self.memsz = ""
            self.align = ""
            self.sizeof_type = 4*BYTE
            self.sizeof_flags = 4*BYTE
            self.x32_sizeof_offset = 4*BYTE
            self.x64_sizeof_offset = 8*BYTE
            self.x32_sizeof_vaddr = 4*BYTE
            self.x64_sizeof_vaddr = 8*BYTE
            self.x32_sizeof_paddr = 4*BYTE
            self.x64_sizeof_paddr = 8*BYTE
            self.x32_sizeof_filesz = 4*BYTE
            self.x64_sizeof_filesz = 8*BYTE
            self.x32_sizeof_memsz = 4*BYTE
            self.x64_sizeof_memsz = 8*BYTE
            self.x32_sizeof_align = 4*BYTE
            self.x64_sizeof_align = 8*BYTE

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += LibByteEditor.RevertBytes(self.type)
            content += LibByteEditor.RevertBytes(self.flags)
            content += LibByteEditor.RevertBytes(self.offset)
            content += LibByteEditor.RevertBytes(self.vaddr)
            content += LibByteEditor.RevertBytes(self.paddr)
            content += LibByteEditor.RevertBytes(self.filesz)
            content += LibByteEditor.RevertBytes(self.memsz)
            content += LibByteEditor.RevertBytes(self.align)
            return content

class PROGRAMHEADERTABLE:
      '''
      PROGRAM HEADER TABLE Class.
      -string ToHex()
      '''
      def __init__(self):
            self.headertable = []
      
      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            for i in range(0, len(self.headertable)):
                  content += self.headertable[i].ToHex()
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

class SECTIONHEADER:
      '''
      SECTION HEADER Class.
      -string ToHex()
      '''
      def __init__(self):
            self.name = ""
            self.type = ""
            self.flags = ""
            self.addr = ""
            self.offset = ""
            self.size = ""
            self.link = ""
            self.info = ""
            self.addralign = ""
            self.entsize = ""
            self.sizeof_name = 4*BYTE
            self.sizeof_type = 4*BYTE
            self.x32_sizeof_flags = 4*BYTE
            self.x64_sizeof_flags = 8*BYTE
            self.x32_sizeof_addr = 4*BYTE
            self.x64_sizeof_addr = 8*BYTE
            self.x32_sizeof_offset = 4*BYTE
            self.x64_sizeof_offset = 8*BYTE
            self.x32_sizeof_size = 4*BYTE
            self.x64_sizeof_size = 8*BYTE
            self.sizeof_link = 4*BYTE
            self.sizeof_info = 4*BYTE
            self.x32_sizeof_addralign = 4*BYTE
            self.x64_sizeof_addralign = 8*BYTE
            self.x32_sizeof_entsize = 4*BYTE
            self.x64_sizeof_entsize = 8*BYTE

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            content += LibByteEditor.RevertBytes(self.name)
            content += LibByteEditor.RevertBytes(self.type)
            content += LibByteEditor.RevertBytes(self.flags)
            content += LibByteEditor.RevertBytes(self.addr)
            content += LibByteEditor.RevertBytes(self.offset)
            content += LibByteEditor.RevertBytes(self.size)
            content += LibByteEditor.RevertBytes(self.link)
            content += LibByteEditor.RevertBytes(self.info)
            content += LibByteEditor.RevertBytes(self.addralign)
            content += LibByteEditor.RevertBytes(self.entsize)
            return content
      
      def Print(self):
            print("name : " + self.name)
            print("type : " + "" + self.type)
            print("flag : " + self.flags)
            print("addr : " + self.addr)
            print("offset : " + self.offset)
            print("size : " + self.size)
            print("link : " + self.link)
            print("info : " + self.info)
            print("addralign : " + self.addralign)
            print("entsize : " + self.entsize)


class SECTIONHEADERTABLE:
      '''
      SECTION HEADER TABLE Class.
      -string ToHex()
      '''
      def __init__(self):
            self.sectiontable = []

      def ToHex(self):
            '''
            Return the section into a HEX string.
            -return: string
            '''
            content = ""
            for i in range(0, len(self.sectiontable)):
                  content += self.sectiontable[i].ToHex()
            return content

class ELF:
      '''
      ELF Class.
      -void PrintELF()
      -void PrintElfHeader()
      -void PrintProgramHeaderTable()
      -void PrintSectionHeaderTable()
      -string ToHex()
      '''
      def __init__(self):
            self.Elfheader = ELFHEADER()
            self.Programheadertable = PROGRAMHEADERTABLE()
            self.Sectionheadertable = SECTIONHEADERTABLE()
            self.Dummy = DUMMY()

      def PrintELF(self):
            '''
            Print all the ELF informations.
            -return: void
            '''
            self.PrintElfHeader()
            self.PrintProgramHeaderTable()
            self.PrintSectionHeaderTable()

      def PrintElfHeader(self):
            '''
            Print the ELF Header.
            -return: void
            '''
            print("\nELFHEADER :")
            print("Magic number : " + self.Elfheader.magic)
            print("Structure : " + self.Elfheader.struct)
            print("Endianness : " +self.Elfheader.endianness)
            print("ELF header version : " + self.Elfheader.elfheaderversion)
            print("OS/ABI : " + self.Elfheader.osabi)
            print("ABI Version : " +self.Elfheader.abiversion)
            print("Dummy : " + self.Elfheader.dummy)
            print("File type : " +self.Elfheader.filetype)
            print("Machine : " + self.Elfheader.machine)
            print("Machine Version : " +self.Elfheader.machineversion)
            print("Entrypoint : " + self.Elfheader.entrypoint)
            print("Program Header offset : " +self.Elfheader.offset_programheader)
            print("Section Header offset : " + self.Elfheader.offset_sectionsheader)
            print("Processor flags : " + self.Elfheader.procflags)
            print("ELF Header size : " + self.Elfheader.elfheadersize)
            print("Size of Entry in Program Header : " +self.Elfheader.entrysize_programheader)
            print("Number of entry in Program Header : " + self.Elfheader.entrynumber_programheader)
            print("Size of Entry in Section Header : " + self.Elfheader.entrysize_sectionheader)
            print("Number of entry in Section Header : " + self.Elfheader.entrynumber_sectionheader)
            print("Index of Section Names in Section Table : " +self.Elfheader.sectionnames_sectiontable_index)

      def PrintProgramHeaderTable(self):
            '''
            Print the Program Header Table.
            -return: void
            '''
            print("\nPROGRAMHEADERTABLE :")
            for i in range(0, int(self.Elfheader.entrynumber_programheader, 16)):
                  print("Program table " + str(i) + " :")
                  print("     Type : " + self.Programheadertable.headertable[i].type)
                  print("     Flags : " + self.Programheadertable.headertable[i].flags)
                  print("     Offset : " + self.Programheadertable.headertable[i].offset)
                  print("     Vaddr : " + self.Programheadertable.headertable[i].vaddr)
                  print("     Paddr : " + self.Programheadertable.headertable[i].paddr)
                  print("     Filesz : " +self.Programheadertable.headertable[i].filesz)
                  print("     Memsz : " + self.Programheadertable.headertable[i].memsz)
                  print("     Align : " + self.Programheadertable.headertable[i].align)

      def PrintSectionHeaderTable(self):
            '''
            Print the Section Header Table.
            -return: void
            '''
            print("\nSECTIONHEADERTABLE :")
            for i in range(0, int(self.Elfheader.entrynumber_sectionheader, 16)-1):
                  print("Section " + str(i) + " :")
                  print("     Name : " + self.Sectionheadertable.sectiontable[i].name)
                  print("     Type : " + self.Sectionheadertable.sectiontable[i].type)
                  print("     Flags : " + self.Sectionheadertable.sectiontable[i].flags)
                  print("     Addr : " + self.Sectionheadertable.sectiontable[i].addr)
                  print("     Offset : " + self.Sectionheadertable.sectiontable[i].offset)
                  print("     Size : " + self.Sectionheadertable.sectiontable[i].size)
                  print("     Link : " + self.Sectionheadertable.sectiontable[i].link)
                  print("     Info : " + self.Sectionheadertable.sectiontable[i].info)
                  print("     AddrAlign : " + self.Sectionheadertable.sectiontable[i].addralign)
                  print("     EntSize : " + self.Sectionheadertable.sectiontable[i].entsize)

      def ToHex(self):
            '''
            Return the ELF into a HEX string.
            -return: string
            '''
            content = ""
            content += self.Elfheader.ToHex()
            content += self.Programheadertable.ToHex()
            content += self.Dummy.ToHex() 
            content += self.Sectionheadertable.ToHex()
            return content


def Extract(content: str):
      '''
      Extract all the ELF informations into a ELF class from a specified content HEX string.
      -return: LibElfAnnalyzer.ELF
      '''
      if content[0:8] == "7f454c46":
            Elf = ELF()
            index = 0
            index = ExtractELFHeader(content, Elf, index)
            index = ExtractProgramHeaderTable(content, Elf, index)

            ExtractDummy(content, Elf, index)

            print("index avant",index)
            index = int(Elf.Elfheader.offset_sectionsheader, 16)*2
            print("index apres",index)
            
            index = ExtractSectionHeaderTable(content, Elf, index)
            return Elf
      else:
            print("Your file isn't a valid ELF Executable, invalid magic number " + content[2:4] + content[0:2] + ".")
            exit()


def ExtractELFHeader(content: str, Elf: ELF, index: int):
      '''
      Extract the ELF header from a content and add it to a LibElfAnnalyzer.ELF class.
      -return: int
      '''
      LibDebug.Log("WORK", "Extracting ELF Header.")
      Elf.Elfheader.magic = content[index:index + Elf.Elfheader.sizeof_magic]
      index += Elf.Elfheader.sizeof_magic
      Elf.Elfheader.struct = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_struct])
      index += Elf.Elfheader.sizeof_struct
      Elf.Elfheader.endianness = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_endianness])
      index += Elf.Elfheader.sizeof_endianness
      Elf.Elfheader.elfheaderversion = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_elfheaderversion])
      index += Elf.Elfheader.sizeof_elfheaderversion
      Elf.Elfheader.osabi = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_osabi])
      index += Elf.Elfheader.sizeof_osabi
      Elf.Elfheader.abiversion = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_abiversion])
      index += Elf.Elfheader.sizeof_abiversion
      Elf.Elfheader.dummy = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_dummy])
      index += Elf.Elfheader.sizeof_dummy
      Elf.Elfheader.filetype = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_filetype])
      index += Elf.Elfheader.sizeof_filetype
      Elf.Elfheader.machine = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_machine])
      index += Elf.Elfheader.sizeof_machine
      Elf.Elfheader.machineversion = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_machineversion])
      index += Elf.Elfheader.sizeof_machineversion
      if Elf.Elfheader.struct == "01":  # x32
            Elf.Elfheader.entrypoint = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.x32_sizeof_entrypoint])
            index += Elf.Elfheader.x32_sizeof_entrypoint
            Elf.Elfheader.offset_programheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.x32_sizeof_offset_programheader])
            index += Elf.Elfheader.x32_sizeof_offset_programheader
            Elf.Elfheader.offset_sectionsheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.x32_sizeof_offset_sectionsheader])
            index += Elf.Elfheader.x32_sizeof_offset_sectionsheader
      elif Elf.Elfheader.struct == "02":  # x64
            Elf.Elfheader.entrypoint = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.x64_sizeof_entrypoint])
            index += Elf.Elfheader.x64_sizeof_entrypoint
            Elf.Elfheader.offset_programheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.x64_sizeof_offset_programheader])
            index += Elf.Elfheader.x64_sizeof_offset_programheader
            Elf.Elfheader.offset_sectionsheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.x64_sizeof_offset_sectionsheader])
            index += Elf.Elfheader.x64_sizeof_offset_sectionsheader
      Elf.Elfheader.procflags = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_procflags])
      index += Elf.Elfheader.sizeof_procflags
      Elf.Elfheader.elfheadersize = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_elfheadersize])
      index += Elf.Elfheader.sizeof_elfheadersize
      Elf.Elfheader.entrysize_programheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_entrysize_programheader])
      index += Elf.Elfheader.sizeof_entrysize_programheader
      Elf.Elfheader.entrynumber_programheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_entrynumber_programheader])
      index += Elf.Elfheader.sizeof_entrynumber_programheader
      Elf.Elfheader.entrysize_sectionheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_entrysize_sectionheader])
      index += Elf.Elfheader.sizeof_entrysize_sectionheader
      Elf.Elfheader.entrynumber_sectionheader = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_entrynumber_sectionheader])
      index += Elf.Elfheader.sizeof_entrynumber_sectionheader
      Elf.Elfheader.sectionnames_sectiontable_index = LibByteEditor.RevertBytes(content[index:index + Elf.Elfheader.sizeof_sectionnames_sectiontable_index])
      index += Elf.Elfheader.sizeof_sectionnames_sectiontable_index
      LibDebug.Log("SUCCESS", "End of the ELF Header extraction.")
      return index

def ExtractProgramHeaderTable(content: str, Elf: ELF, index: int):
      '''
      Extract the PROGRAM header from a content and add it to a LibElfAnnalyzer.ELF class.
      -return: int
      '''
      LibDebug.Log("WORK", "Extracting PROGRAM Header.")
      for i in range(0, int(LibByteEditor.RevertBytes(Elf.Elfheader.entrynumber_programheader), 16)):
            Elf.Programheadertable.headertable.append(PROGRAMHEADER())
            Elf.Programheadertable.headertable[i].type = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].sizeof_type])
            index += Elf.Programheadertable.headertable[i].sizeof_type
            if Elf.Elfheader.struct == "02":  # x64
                  Elf.Programheadertable.headertable[i].flags = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].sizeof_flags])
                  index += Elf.Programheadertable.headertable[i].sizeof_flags
                  Elf.Programheadertable.headertable[i].offset = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x64_sizeof_offset])
                  index += Elf.Programheadertable.headertable[i].x64_sizeof_offset
                  Elf.Programheadertable.headertable[i].vaddr = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x64_sizeof_vaddr])
                  index += Elf.Programheadertable.headertable[i].x64_sizeof_vaddr
                  Elf.Programheadertable.headertable[i].paddr = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x64_sizeof_paddr])
                  index += Elf.Programheadertable.headertable[i].x64_sizeof_paddr
                  Elf.Programheadertable.headertable[i].filesz = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x64_sizeof_filesz])
                  index += Elf.Programheadertable.headertable[i].x64_sizeof_filesz
                  Elf.Programheadertable.headertable[i].memsz = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x64_sizeof_memsz])
                  index += Elf.Programheadertable.headertable[i].x64_sizeof_memsz
                  Elf.Programheadertable.headertable[i].align = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x64_sizeof_align])
                  index += Elf.Programheadertable.headertable[i].x64_sizeof_align
            elif Elf.Elfheader.struct == "01":  # x32
                  Elf.Programheadertable.headertable[i].offset = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x32_sizeof_offset])
                  index += Elf.Programheadertable.headertable[i].x32_sizeof_offset
                  Elf.Programheadertable.headertable[i].vaddr = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x32_sizeof_vaddr])
                  index += Elf.Programheadertable.headertable[i].x32_sizeof_vaddr
                  Elf.Programheadertable.headertable[i].paddr = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x32_sizeof_paddr])
                  index += Elf.Programheadertable.headertable[i].x32_sizeof_paddr
                  Elf.Programheadertable.headertable[i].filesz = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x32_sizeof_filesz])
                  index += Elf.Programheadertable.headertable[i].x32_sizeof_filesz
                  Elf.Programheadertable.headertable[i].memsz = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x32_sizeof_memsz])
                  index += Elf.Programheadertable.headertable[i].x32_sizeof_memsz
                  Elf.Programheadertable.headertable[i].flags = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].sizeof_flags])
                  index += Elf.Programheadertable.headertable[i].sizeof_flags
                  Elf.Programheadertable.headertable[i].align = LibByteEditor.RevertBytes(content[index:index + Elf.Programheadertable.headertable[i].x32_sizeof_align])
                  index += Elf.Programheadertable.headertable[i].x32_sizeof_align
      LibDebug.Log("SUCCESS", "End of the PROGRAM Header extraction.")
      return index

def ExtractSectionHeaderTable(content: str, Elf: ELF, index: int):
      '''
      Extract the SECTION header table from a content and add it to a LibElfAnnalyzer.ELF class.
      -return: int
      '''
      LibDebug.Log("WORK", "Extracting SECTION Header Table.")

      for i in range(0, int(Elf.Elfheader.entrynumber_sectionheader, 16)):
            Elf.Sectionheadertable.sectiontable.append(SECTIONHEADER())
            Elf.Sectionheadertable.sectiontable[i].name = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].sizeof_name])
            index += Elf.Sectionheadertable.sectiontable[i].sizeof_name
            Elf.Sectionheadertable.sectiontable[i].type = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].sizeof_type])
            index += Elf.Sectionheadertable.sectiontable[i].sizeof_type
            if Elf.Elfheader.struct == "02":  # x64
                  Elf.Sectionheadertable.sectiontable[i].flags = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x64_sizeof_flags])
                  index += Elf.Sectionheadertable.sectiontable[i].x64_sizeof_flags
                  Elf.Sectionheadertable.sectiontable[i].addr = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x64_sizeof_addr])
                  index += Elf.Sectionheadertable.sectiontable[i].x64_sizeof_addr
                  Elf.Sectionheadertable.sectiontable[i].offset = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x64_sizeof_offset])
                  index += Elf.Sectionheadertable.sectiontable[i].x64_sizeof_offset
                  Elf.Sectionheadertable.sectiontable[i].size = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x64_sizeof_size])
                  index += Elf.Sectionheadertable.sectiontable[i].x64_sizeof_size
            elif Elf.Elfheader.struct == "01":  # x32
                  Elf.Sectionheadertable.sectiontable[i].flags = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x32_sizeof_flags])
                  index += Elf.Sectionheadertable.sectiontable[i].x32_sizeof_flags
                  Elf.Sectionheadertable.sectiontable[i].addr = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x32_sizeof_addr])
                  index += Elf.Sectionheadertable.sectiontable[i].x32_sizeof_addr
                  Elf.Sectionheadertable.sectiontable[i].offset = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x32_sizeof_offset])
                  index += Elf.Sectionheadertable.sectiontable[i].x32_sizeof_offset
                  Elf.Sectionheadertable.sectiontable[i].size = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x32_sizeof_size])
                  index += Elf.Sectionheadertable.sectiontable[i].x32_sizeof_size
            
            Elf.Sectionheadertable.sectiontable[i].link = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].sizeof_link])
            index += Elf.Sectionheadertable.sectiontable[i].sizeof_link
            Elf.Sectionheadertable.sectiontable[i].info = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].sizeof_info])
            index += Elf.Sectionheadertable.sectiontable[i].sizeof_info

            if Elf.Elfheader.struct == "02":  # x64
                  Elf.Sectionheadertable.sectiontable[i].addralign = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x64_sizeof_addralign])
                  index += Elf.Sectionheadertable.sectiontable[i].x64_sizeof_addralign
                  Elf.Sectionheadertable.sectiontable[i].entsize = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x64_sizeof_entsize])
                  index += Elf.Sectionheadertable.sectiontable[i].x64_sizeof_entsize
            elif Elf.Elfheader.struct == "01":  # x32
                  Elf.Sectionheadertable.sectiontable[i].addralign = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x32_sizeof_addralign])
                  index += Elf.Sectionheadertable.sectiontable[i].x32_sizeof_addralign
                  Elf.Sectionheadertable.sectiontable[i].entsize = LibByteEditor.RevertBytes(content[index:index + Elf.Sectionheadertable.sectiontable[i].x32_sizeof_entsize])
                  index += Elf.Sectionheadertable.sectiontable[i].x32_sizeof_entsize
      LibDebug.Log("SUCCESS", "End of the PROGRAM Header extraction.")
      return index

def ExtractDummy(content: str, Elf: ELF, index: int):
      '''
      Extract the data part of a Elf binnary.
      -return: LibElfAnnalyzer.ELF
      '''
      Elf.Dummy.dummyindex = index
      Elf.Dummy.dum01 = LibByteEditor.RevertBytes(content[index:int(LibByteEditor.RevertBytes(Elf.Elfheader.offset_sectionsheader), 16)*2])
