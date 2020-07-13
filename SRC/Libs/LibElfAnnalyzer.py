'''
Library made for analyzing ELF file.
-class ELFHEADER
      -string ToHex(self)

-class ELF
      -void PrintELF()
      -void PrintElfHeader()
      -string ToHex()
-LibElfAnnalyzer.ELF Extract(content: str)
-int ExtractELFHeader(content: str, Elf: ELF, index: int)
'''
from SRC.Libs import LibDebug
from SRC.Libs import LibByteEditor
from datetime import datetime
BYTE = 2

class ELFHEADER:
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
            content += LibByteEditor.RevertBytes(self.abiversion)
            content += LibByteEditor.RevertBytes(self.dummy)
            content += LibByteEditor.RevertBytes(self.filetype)
            content += LibByteEditor.RevertBytes(self.machine)
            content += LibByteEditor.RevertBytes(self.offset_programheader)
            content += LibByteEditor.RevertBytes(self.offset_sectionsheader)
            content += LibByteEditor.RevertBytes(self.entrysize_programheader)
            content += LibByteEditor.RevertBytes(self.entrynumber_programheader)
            content += LibByteEditor.RevertBytes(self.entrysize_sectionheader)
            content += LibByteEditor.RevertBytes(self.entrynumber_sectionheader)
            content += LibByteEditor.RevertBytes(self.sectionnames_sectiontable_index)
            return content


class ELF:
      '''
      ELF Class.
      -void PrintELF()
      -void PrintElfHeader()
      -string ToHex()
      '''
      def __init__(self):
            self.Elfheader = ELFHEADER()

      def PrintELF(self):
            '''
            Print all the ELF informations.
            -return: void
            '''
            self.PrintElfHeader()

      def PrintElfHeader(self):
            '''
            Print the ELF Header.
            -return: void
            '''
            print("\nELFHEADER :")
            print("Magic number : " + self.Elfheader.magic)
            print("Structure : " + LibByteEditor.RevertBytes(self.Elfheader.struct))
            print("Endianness : " + LibByteEditor.RevertBytes(self.Elfheader.endianness))
            print("ELF header version : " + LibByteEditor.RevertBytes(self.Elfheader.elfheaderversion))
            print("OS/ABI : " + LibByteEditor.RevertBytes(self.Elfheader.osabi))
            print("ABI Version : " + LibByteEditor.RevertBytes(self.Elfheader.abiversion))
            print("Dummy : " + LibByteEditor.RevertBytes(self.Elfheader.dummy))
            print("File type : " + LibByteEditor.RevertBytes(self.Elfheader.filetype))
            print("Machine : " + LibByteEditor.RevertBytes(self.Elfheader.machine))
            print("Machine Version : " + LibByteEditor.RevertBytes(self.Elfheader.machineversion))
            print("Entrypoint : " + LibByteEditor.RevertBytes(self.Elfheader.entrypoint))
            print("Program Header offset : " + LibByteEditor.RevertBytes(self.Elfheader.offset_programheader))
            print("Section Header offset : " + LibByteEditor.RevertBytes(self.Elfheader.offset_sectionsheader))
            print("Processor flags : " + LibByteEditor.RevertBytes(self.Elfheader.procflags))
            print("ELF Header size : " + LibByteEditor.RevertBytes(self.Elfheader.elfheadersize))
            print("Size of Entry in Program Header : " + LibByteEditor.RevertBytes(self.Elfheader.entrysize_programheader))
            print("Number of entry in Program Header : " + LibByteEditor.RevertBytes(self.Elfheader.entrynumber_programheader))
            print("Size of Entry in Section Header : " + LibByteEditor.RevertBytes(self.Elfheader.entrysize_sectionheader))
            print("Number of entry in Section Header : " + LibByteEditor.RevertBytes(self.Elfheader.entrynumber_sectionheader))
            print("Index of Section Names in Section Table : " + LibByteEditor.RevertBytes(self.Elfheader.sectionnames_sectiontable_index))

      def ToHex(self):
            '''
            Return the ELF into a HEX string.
            -return: string
            '''
            content = ""
            content += self.Elfheader.ToHex()
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
      Elf.Elfheader.struct = content[index:index + Elf.Elfheader.sizeof_struct]
      index += Elf.Elfheader.sizeof_struct
      Elf.Elfheader.endianness = content[index:index + Elf.Elfheader.sizeof_endianness]
      index += Elf.Elfheader.sizeof_endianness
      Elf.Elfheader.elfheaderversion = content[index:index + Elf.Elfheader.sizeof_elfheaderversion]
      index += Elf.Elfheader.sizeof_elfheaderversion
      Elf.Elfheader.osabi = content[index:index + Elf.Elfheader.sizeof_osabi]
      index += Elf.Elfheader.sizeof_osabi
      Elf.Elfheader.abiversion = content[index:index + Elf.Elfheader.sizeof_abiversion]
      index += Elf.Elfheader.sizeof_abiversion
      Elf.Elfheader.dummy = content[index:index + Elf.Elfheader.sizeof_dummy]
      index += Elf.Elfheader.sizeof_dummy
      Elf.Elfheader.filetype = content[index:index + Elf.Elfheader.sizeof_filetype]
      index += Elf.Elfheader.sizeof_filetype
      Elf.Elfheader.machine = content[index:index + Elf.Elfheader.sizeof_machine]
      index += Elf.Elfheader.sizeof_machine
      Elf.Elfheader.machineversion = content[index:index + Elf.Elfheader.sizeof_machineversion]
      index += Elf.Elfheader.sizeof_machineversion
      if Elf.Elfheader.struct == "01":  # x32
            Elf.Elfheader.entrypoint = content[index:index + Elf.Elfheader.x32_sizeof_entrypoint]
            index += Elf.Elfheader.x32_sizeof_entrypoint
            Elf.Elfheader.offset_programheader = content[index:index + Elf.Elfheader.x32_sizeof_offset_programheader]
            index += Elf.Elfheader.x32_sizeof_offset_programheader
            Elf.Elfheader.offset_sectionsheader = content[index:index + Elf.Elfheader.x32_sizeof_offset_sectionsheader]
            index += Elf.Elfheader.x32_sizeof_offset_sectionsheader
      elif Elf.Elfheader.struct == "02":  # x64
            Elf.Elfheader.entrypoint = content[index:index + Elf.Elfheader.x64_sizeof_entrypoint]
            index += Elf.Elfheader.x64_sizeof_entrypoint
            Elf.Elfheader.offset_programheader = content[index:index + Elf.Elfheader.x64_sizeof_offset_programheader]
            index += Elf.Elfheader.x64_sizeof_offset_programheader
            Elf.Elfheader.offset_sectionsheader = content[index:index + Elf.Elfheader.x64_sizeof_offset_sectionsheader]
            index += Elf.Elfheader.x64_sizeof_offset_sectionsheader
      Elf.Elfheader.procflags = content[index:index + Elf.Elfheader.sizeof_procflags]
      index += Elf.Elfheader.sizeof_procflags
      Elf.Elfheader.elfheadersize = content[index:index + Elf.Elfheader.sizeof_elfheadersize]
      index += Elf.Elfheader.sizeof_elfheadersize
      Elf.Elfheader.entrysize_programheader = content[index:index + Elf.Elfheader.sizeof_entrysize_programheader]
      index += Elf.Elfheader.sizeof_entrysize_programheader
      Elf.Elfheader.entrynumber_programheader = content[index:index + Elf.Elfheader.sizeof_entrynumber_programheader]
      index += Elf.Elfheader.sizeof_entrynumber_programheader
      Elf.Elfheader.entrysize_sectionheader = content[index:index + Elf.Elfheader.sizeof_entrysize_sectionheader]
      index += Elf.Elfheader.sizeof_entrysize_sectionheader
      Elf.Elfheader.entrynumber_sectionheader = content[index:index + Elf.Elfheader.sizeof_entrynumber_sectionheader]
      index += Elf.Elfheader.sizeof_entrynumber_sectionheader
      Elf.Elfheader.sectionnames_sectiontable_index = content[index:index + Elf.Elfheader.sizeof_sectionnames_sectiontable_index]
      index += Elf.Elfheader.sizeof_sectionnames_sectiontable_index
      LibDebug.Log("SUCCESS", "End of the ELF Header extraction.")
      return index