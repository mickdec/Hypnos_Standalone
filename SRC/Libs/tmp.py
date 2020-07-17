
def CompareElf(Elf1: LibElfAnnalyzer.ELF, Elf2: LibElfAnnalyzer.PE):
      '''
      Compare two ELF object together and print the differences.
      -return: void
      '''
      if Elf1.Elfheader.ToHex() != Elf2.ELFHEADER.ToHex():
            if Elf2.Elfheader.magic != Elf1.Elfheader.magic:
                  print("magic Elf1 : " + Elf1.Elfheader.magic)
                  print("magic Elf2 : " + Elf2.Elfheader.magic)
            if Elf2.Elfheader.struct != Elf1.Elfheader.struct:
                  print("struct Elf1 : " + Elf1.Elfheader.struct)
                  print("struct Elf2 : " + Elf2.Elfheader.struct)
            if Elf2.Elfheader.endianness != Elf1.Elfheader.endianness:
                  print("endianness Elf1 : " + Elf1.Elfheader.endianness)
                  print("endianness Elf2 : " + Elf2.Elfheader.endianness)
            if Elf2.Elfheader.elfheaderversion != Elf1.Elfheader.elfheaderversion:
                  print("elfheaderversion Elf1 : " + Elf1.Elfheader.elfheaderversion)
                  print("elfheaderversion Elf2 : " + Elf2.Elfheader.elfheaderversion)
            if Elf2.Elfheader.osabi != Elf1.Elfheader.osabi:
                  print("osabi Elf1 : " + Elf1.Elfheader.osabi)
                  print("osabi Elf2 : " + Elf2.Elfheader.osabi)
            if Elf2.Elfheader.abiversion != Elf1.Elfheader.abiversion:
                  print("abiversion Elf1 : " + Elf1.Elfheader.abiversion)
                  print("abiversion Elf2 : " + Elf2.Elfheader.abiversion)
            if Elf2.Elfheader.dummy != Elf1.Elfheader.dummy:
                  print("dummy Elf1 : " + Elf1.Elfheader.dummy)
                  print("dummy Elf2 : " + Elf2.Elfheader.dummy)
            if Elf2.Elfheader.filetype != Elf1.Elfheader.filetype:
                  print("filetype Elf1 : " + Elf1.Elfheader.filetype)
                  print("filetype Elf2 : " + Elf2.Elfheader.filetype)
            if Elf2.Elfheader.machine != Elf1.Elfheader.machine:
                  print("machine Elf1 : " + Elf1.Elfheader.machine)
                  print("machine Elf2 : " + Elf2.Elfheader.machine)
            if Elf2.Elfheader.machineversion != Elf1.Elfheader.machineversion:
                  print("machineversion Elf1 : " + Elf1.Elfheader.machineversion)
                  print("machineversion Elf2 : " + Elf2.Elfheader.machineversion)
            if Elf2.Elfheader.entrypoint != Elf1.Elfheader.entrypoint:
                  print("entrypoint Elf1 : " + Elf1.Elfheader.entrypoint)
                  print("entrypoint Elf2 : " + Elf2.Elfheader.entrypoint)
            if Elf2.Elfheader.offset_programheader != Elf1.Elfheader.offset_programheader:
                  print("offset_programheader Elf1 : " + Elf1.Elfheader.offset_programheader)
                  print("offset_programheader Elf2 : " + Elf2.Elfheader.offset_programheader)
            if Elf2.Elfheader.offset_sectionsheader != Elf1.Elfheader.relocpos:
                  print("offset_sectionsheader Elf1 : " + Elf1.Elfheader.offset_sectionsheader)
                  print("offset_sectionsheader Elf2 : " + Elf2.Elfheader.offset_sectionsheader)
            if Elf2.Elfheader.procflags != Elf1.Elfheader.procflags:
                  print("procflags Elf1 : " + Elf1.Elfheader.procflags)
                  print("procflags Elf2 : " + Elf2.Elfheader.procflags)
            if Elf2.Elfheader.elfheadersize != Elf1.Elfheader.elfheadersize:
                  print("elfheadersize Elf1 : " + Elf1.Elfheader.elfheadersize)
                  print("elfheadersize Elf2 : " + Elf2.Elfheader.elfheadersize)
            if Elf2.Elfheader.entrysize_programheader != Elf1.Elfheader.entrysize_programheader:
                  print("entrysize_programheader Elf1 : " + Elf1.Elfheader.entrysize_programheader)
                  print("entrysize_programheader Elf2 : " + Elf2.Elfheader.entrysize_programheader)
            if Elf2.Elfheader.entrynumber_programheader != Elf1.Elfheader.entrynumber_programheader:
                  print("entrynumber_programheader Elf1 : " + Elf1.Elfheader.entrynumber_programheader)
                  print("entrynumber_programheader Elf2 : " + Elf2.Elfheader.entrynumber_programheader)
            if Elf2.Elfheader.entrysize_sectionheader != Elf1.Elfheader.entrysize_sectionheader:
                  print("entrysize_sectionheader Elf1 : " + Elf1.Elfheader.entrysize_sectionheader)
                  print("entrysize_sectionheader Elf2 : " + Elf2.Elfheader.entrysize_sectionheader)
            if Elf2.Elfheader.entrynumber_sectionheader != Elf1.Elfheader.entrynumber_sectionheader:
                  print("entrynumber_sectionheader Elf1 : " + Elf1.Elfheader.entrynumber_sectionheader)
                  print("entrynumber_sectionheader Elf2 : " + Elf2.Elfheader.entrynumber_sectionheader)
            if Elf2.Elfheader.sectionnames_sectiontable_index != Elf1.Elfheader.sectionnames_sectiontable_index:
                  print("sectionnames_sectiontable_index Elf1 : " + Elf1.Elfheader.sectionnames_sectiontable_index)
                  print("sectionnames_sectiontable_index Elf2 : " + Elf2.Elfheader.sectionnames_sectiontable_index)
    #   if Elf1.Stubprogram.ToHex() != Elf2.Stubprogram.ToHex():
    #         if Elf1.Stubprogram.stub != Elf2.Stubprogram.stub:
    #               print("stub Elf1 : " + Elf1.Stubprogram.stub)
    #               print("stub Elf2 : " + Elf2.Stubprogram.stub)
    #   if Elf1.magic.ToHex() != Elf2.magic.ToHex():
    #         if Elf1.magic.magic != Elf2.magic.magic:
    #               print("magic Elf1 : " + Elf1.magic.magic)
    #               print("magic Elf2 : " + Elf2.magic.magic)
    #   if Elf1.Coffheader.ToHex() != Elf2.Coffheader.ToHex():
    #         if Elf2.Coffheader.machine != Elf1.Coffheader.machine:
    #               print("Machine Elf1 : " + Elf1.Coffheader.machine)
    #               print("Machine Elf2 : " + Elf2.Coffheader.machine)
    #         if Elf2.Coffheader.numberofsections != Elf1.Coffheader.numberofsections:
    #               print("Numberofsections Elf1 : " +
    #                     Elf1.Coffheader.numberofsections)
    #               print("Numberofsections Elf2 : " +
    #                     Elf2.Coffheader.numberofsections)
    #         if Elf2.Coffheader.timedatestamp != Elf1.Coffheader.timedatestamp:
    #               print("Timedatestamp Elf1 : " + Elf1.Coffheader.timedatestamp)
    #               print("Timedatestamp Elf2 : " + Elf2.Coffheader.timedatestamp)
    #         if Elf2.Coffheader.pointertosymboltable != Elf1.Coffheader.pointertosymboltable:
    #               print("Pointertosymboltable Elf1 : " +
    #                     Elf1.Coffheader.pointertosymboltable)
    #               print("Pointertosymboltable Elf2 : " +
    #                     Elf2.Coffheader.pointertosymboltable)
    #         if Elf2.Coffheader.numberofsymbols != Elf1.Coffheader.numberofsymbols:
    #               print("Numberofsymbols Elf1 : " +
    #                     Elf1.Coffheader.numberofsymbols)
    #               print("Numberofsymbols Elf2 : " +
    #                     Elf2.Coffheader.numberofsymbols)
    #         if Elf2.Coffheader.sizeofoptionalheader != Elf1.Coffheader.sizeofoptionalheader:
    #               print("Sizeofoptionalheader Elf1 : " +
    #                     Elf1.Coffheader.sizeofoptionalheader)
    #               print("Sizeofoptionalheader Elf2 : " +
    #                     Elf2.Coffheader.sizeofoptionalheader)
    #         if Elf2.Coffheader.characteristics != Elf1.Coffheader.characteristics:
    #               print("Characteristics Elf1 : " +
    #                     Elf1.Coffheader.characteristics)
    #               print("Characteristics Elf2 : " +
    #                     Elf2.Coffheader.characteristics)
    #   if Elf1.Optionalpeheader.ToHex() != Elf2.Optionalpeheader.ToHex():
    #         if Elf2.Optionalpeheader.magic != Elf1.Optionalpeheader.magic:
    #               print("magic Elf1 :" + Elf1.magic)
    #               print("magic Elf2 :" + Elf2.magic)
    #         if Elf2.Optionalpeheader.majorlinkerversion != Elf1.Optionalpeheader.majorlinkerversion:
    #               print("majorlinkerversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.majorlinkerversion)
    #               print("majorlinkerversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.majorlinkerversion)
    #         if Elf2.Optionalpeheader.minorlinkerversion != Elf1.Optionalpeheader.minorlinkerversion:
    #               print("minorlinkerversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.minorlinkerversion)
    #               print("minorlinkerversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.minorlinkerversion)
    #         if Elf2.Optionalpeheader.sizeofcode != Elf1.Optionalpeheader.sizeofcode:
    #               print("sizeofcode Elf1 : " + Elf1.Optionalpeheader.sizeofcode)
    #               print("sizeofcode Elf2 : " + Elf2.Optionalpeheader.sizeofcode)
    #         if Elf2.Optionalpeheader.sizeofinitializeddata != Elf1.Optionalpeheader.sizeofinitializeddata:
    #               print("sizeofinitializeddate Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofinitializeddata)
    #               print("sizeofinitializeddate Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofinitializeddata)
    #         if Elf2.Optionalpeheader.sizeofuninitializeddata != Elf1.Optionalpeheader.sizeofuninitializeddata:
    #               print("sizeofuninitializeddate Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofuninitializeddata)
    #               print("sizeofuninitializeddate Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofuninitializeddata)
    #         if Elf2.Optionalpeheader.addressofentrypoint != Elf1.Optionalpeheader.addressofentrypoint:
    #               print("addressofEntryPoint Elf1 : " +
    #                     Elf1.Optionalpeheader.addressofentrypoint)
    #               print("addressofEntryPoint Elf2 : " +
    #                     Elf2.Optionalpeheader.addressofentrypoint)
    #         if Elf2.Optionalpeheader.baseofcode != Elf1.Optionalpeheader.baseofcode:
    #               print("baseofcode Elf1 : " + Elf1.Optionalpeheader.baseofcode)
    #               print("baseofcode Elf2 : " + Elf2.Optionalpeheader.baseofcode)
    #         if Elf2.Optionalpeheader.baseofdata != Elf1.Optionalpeheader.baseofdata:
    #               print("baseofdate Elf1 : " + Elf1.Optionalpeheader.baseofdata)
    #               print("baseofdate Elf2 : " + Elf2.Optionalpeheader.baseofdata)
    #         if Elf2.Optionalpeheader.imagebase != Elf1.Optionalpeheader.imagebase:
    #               print("imagebase Elf1 : " + Elf1.Optionalpeheader.imagebase)
    #               print("imagebase Elf2 : " + Elf2.Optionalpeheader.imagebase)
    #         if Elf2.Optionalpeheader.sectionalignment != Elf1.Optionalpeheader.sectionalignment:
    #               print("sectionalignmene Elf1 : " +
    #                     Elf1.Optionalpeheader.sectionalignment)
    #               print("sectionalignmene Elf2 : " +
    #                     Elf2.Optionalpeheader.sectionalignment)
    #         if Elf2.Optionalpeheader.filealignment != Elf1.Optionalpeheader.filealignment:
    #               print("filealignmene Elf1 : " +
    #                     Elf1.Optionalpeheader.filealignment)
    #               print("filealignmene Elf2 : " +
    #                     Elf2.Optionalpeheader.filealignment)
    #         if Elf2.Optionalpeheader.majorosversion != Elf1.Optionalpeheader.majorosversion:
    #               print("majorosversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.majorosversion)
    #               print("majorosversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.majorosversion)
    #         if Elf2.Optionalpeheader.minorosversion != Elf1.Optionalpeheader.minorosversion:
    #               print("minorosversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.minorosversion)
    #               print("minorosversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.minorosversion)
    #         if Elf2.Optionalpeheader.majorimageversion != Elf1.Optionalpeheader.majorimageversion:
    #               print("majorimageversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.majorimageversion)
    #               print("majorimageversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.majorimageversion)
    #         if Elf2.Optionalpeheader.minorimageversion != Elf1.Optionalpeheader.minorimageversion:
    #               print("minorimageversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.minorimageversion)
    #               print("minorimageversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.minorimageversion)
    #         if Elf2.Optionalpeheader.majorsubsystemversion != Elf1.Optionalpeheader.majorsubsystemversion:
    #               print("majorsubsystemversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.majorsubsystemversion)
    #               print("majorsubsystemversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.majorsubsystemversion)
    #         if Elf2.Optionalpeheader.minorsubsystemversion != Elf1.Optionalpeheader.minorsubsystemversion:
    #               print("minorsubsystemversioe Elf1 : " +
    #                     Elf1.Optionalpeheader.minorsubsystemversion)
    #               print("minorsubsystemversioe Elf2 : " +
    #                     Elf2.Optionalpeheader.minorsubsystemversion)
    #         if Elf2.Optionalpeheader.win32versionvalue != Elf1.Optionalpeheader.win32versionvalue:
    #               print("win32versionvalue Elf1 : " +
    #                     Elf1.Optionalpeheader.win32versionvalue)
    #               print("win32versionvalue Elf2 : " +
    #                     Elf2.Optionalpeheader.win32versionvalue)
    #         if Elf2.Optionalpeheader.sizeofimage != Elf1.Optionalpeheader.sizeofimage:
    #               print("sizeofimage Elf1 : " + Elf1.Optionalpeheader.sizeofimage)
    #               print("sizeofimage Elf2 : " + Elf2.Optionalpeheader.sizeofimage)
    #         if Elf2.Optionalpeheader.sizeofheaders != Elf1.Optionalpeheader.sizeofheaders:
    #               print("sizeofheadere Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofheaders)
    #               print("sizeofheadere Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofheaders)
    #         if Elf2.Optionalpeheader.checksum != Elf1.Optionalpeheader.checksum:
    #               print("checksue Elf1 : " + Elf1.Optionalpeheader.checksum)
    #               print("checksue Elf2 : " + Elf2.Optionalpeheader.checksum)
    #         if Elf2.Optionalpeheader.subsystem != Elf1.Optionalpeheader.subsystem:
    #               print("subsystee Elf1 : " + Elf1.Optionalpeheader.subsystem)
    #               print("subsystee Elf2 : " + Elf2.Optionalpeheader.subsystem)
    #         if Elf2.Optionalpeheader.dllcharacteristics != Elf1.Optionalpeheader.dllcharacteristics:
    #               print("dllcharacteristice Elf1 : " +
    #                     Elf1.Optionalpeheader.dllcharacteristics)
    #               print("dllcharacteristice Elf2 : " +
    #                     Elf2.Optionalpeheader.dllcharacteristics)
    #         if Elf2.Optionalpeheader.sizeofstackreserve != Elf1.Optionalpeheader.sizeofstackreserve:
    #               print("sizeofstackreserve Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofstackreserve)
    #               print("sizeofstackreserve Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofstackreserve)
    #         if Elf2.Optionalpeheader.sizeofstackcommit != Elf1.Optionalpeheader.sizeofstackcommit:
    #               print("sizeofstackcommie Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofstackcommit)
    #               print("sizeofstackcommie Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofstackcommit)
    #         if Elf2.Optionalpeheader.sizeofheapreserve != Elf1.Optionalpeheader.sizeofheapreserve:
    #               print("sizeofheapreserve Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofheapreserve)
    #               print("sizeofheapreserve Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofheapreserve)
    #         if Elf2.Optionalpeheader.sizeofheapcommit != Elf1.Optionalpeheader.sizeofheapcommit:
    #               print("sizeofheapcommie Elf1 : " +
    #                     Elf1.Optionalpeheader.sizeofheapcommit)
    #               print("sizeofheapcommie Elf2 : " +
    #                     Elf2.Optionalpeheader.sizeofheapcommit)
    #         if Elf2.Optionalpeheader.loaderflags != Elf1.Optionalpeheader.loaderflags:
    #               print("loaderflage Elf1 : " + Elf1.Optionalpeheader.loaderflags)
    #               print("loaderflage Elf2 : " + Elf2.Optionalpeheader.loaderflags)
    #         if Elf2.Optionalpeheader.numberofrvaandsizes != Elf1.Optionalpeheader.numberofrvaandsizes:
    #               print("numberofrvaandsizee Elf1 : " +
    #                     Elf1.Optionalpeheader.numberofrvaandsizes)
    #               print("numberofrvaandsizee Elf2 : " +
    #                     Elf2.Optionalpeheader.numberofrvaandsizes)
    #   if Elf1.SectionTable.ToHex() != Elf2.SectionTable.ToHex():
    #         if int(Elf1.Coffheader.numberofsections, 16) < int(Elf2.Coffheader.numberofsections, 16):
    #               Log("ERROR", "Elf2 have more sections.")
    #               for i in range(0, int(Elf1.Coffheader.numberofsections, 16)):
    #                     print("Section " + str(i) + " : ")
    #                     if Elf1.SectionTable.sections[i].name != Elf2.SectionTable.sections[i].name:
    #                           print("Elf1 name : " + Elf1.SectionTable.sections[i].name + " // " + str(
    #                                 bytearray.fromhex(Elf1.SectionTable.sections[i].name).decode()))
    #                           print("Elf2 name : " + Elf2.SectionTable.sections[i].name + " // " + str(
    #                                 bytearray.fromhex(Elf2.SectionTable.sections[i].name).decode()))
    #                     if Elf1.SectionTable.sections[i].virtualsize != Elf2.SectionTable.sections[i].virtualsize:
    #                           print("Elf1 virtualsize : " +
    #                                 Elf1.SectionTable.sections[i].virtualsize)
    #                           print("Elf2 virtualsize : " +
    #                                 Elf2.SectionTable.sections[i].virtualsize)
    #                     if Elf1.SectionTable.sections[i].virtualaddress != Elf2.SectionTable.sections[i].virtualaddress:
    #                           print("Elf1 virtualaddress : " +
    #                                 Elf1.SectionTable.sections[i].virtualaddress)
    #                           print("Elf2 virtualaddress : " +
    #                                 Elf2.SectionTable.sections[i].virtualaddress)
    #                     if Elf1.SectionTable.sections[i].sizeofrawdata != Elf2.SectionTable.sections[i].sizeofrawdata:
    #                           print("Elf1 sizeofrawdata : " +
    #                                 Elf1.SectionTable.sections[i].sizeofrawdata)
    #                           print("Elf2 sizeofrawdata : " +
    #                                 Elf2.SectionTable.sections[i].sizeofrawdata)
    #                     if Elf1.SectionTable.sections[i].pointertorawdata != Elf2.SectionTable.sections[i].pointertorawdata:
    #                           print("Elf1 pointertorawdata : " +
    #                                 Elf1.SectionTable.sections[i].pointertorawdata)
    #                           print("Elf2 pointertorawdata : " +
    #                                 Elf2.SectionTable.sections[i].pointertorawdata)
    #                     if Elf1.SectionTable.sections[i].pointertorelocations != Elf2.SectionTable.sections[i].pointertorelocations:
    #                           print("Elf1 pointertorelocations : " +
    #                                 Elf1.SectionTable.sections[i].pointertorelocations)
    #                           print("Elf2 pointertorelocations : " +
    #                                 Elf2.SectionTable.sections[i].pointertorelocations)
    #                     if Elf1.SectionTable.sections[i].pointertolinenumbers != Elf2.SectionTable.sections[i].pointertolinenumbers:
    #                           print("Elf1 pointertolinenumbers : " +
    #                                 Elf1.SectionTable.sections[i].pointertolinenumbers)
    #                           print("Elf2 pointertolinenumbers : " +
    #                                 Elf2.SectionTable.sections[i].pointertolinenumbers)
    #                     if Elf1.SectionTable.sections[i].numberofrelocations != Elf2.SectionTable.sections[i].numberofrelocations:
    #                           print("Elf1 numberofrelocations : " +
    #                                 Elf1.SectionTable.sections[i].numberofrelocations)
    #                           print("Elf2 numberofrelocations : " +
    #                                 Elf2.SectionTable.sections[i].numberofrelocations)
    #                     if Elf1.SectionTable.sections[i].numberoflinenumbers != Elf2.SectionTable.sections[i].numberoflinenumbers:
    #                           print("Elf1 numberoflinenumbers : " +
    #                                 Elf1.SectionTable.sections[i].numberoflinenumbers)
    #                           print("Elf2 numberoflinenumbers : " +
    #                                 Elf2.SectionTable.sections[i].numberoflinenumbers)
    #                     if Elf1.SectionTable.sections[i].characteristics != Elf2.SectionTable.sections[i].characteristics:
    #                           print("Elf1 characteristics : " +
    #                                 Elf1.SectionTable.sections[i].characteristics)
    #                           print("Elf2 characteristics : " +
    #                                 Elf2.SectionTable.sections[i].characteristics)
    #               for i in range(int(Elf1.Coffheader.numberofsections, 16), int(Elf2.Coffheader.numberofsections, 16)):
    #                     print("Pe 2 Section " + str(i) + " : ")
    #                     print("     name : " + Elf2.SectionTable.sections[i].name + " // " + str(
    #                           bytearray.fromhex(Elf2.SectionTable.sections[i].name).decode()))
    #                     print("     virtualsize : " +
    #                           Elf2.SectionTable.sections[i].virtualsize)
    #                     print("     virtualaddress : " +
    #                           Elf2.SectionTable.sections[i].virtualaddress)
    #                     print("     sizeofrawdata : " +
    #                           Elf2.SectionTable.sections[i].sizeofrawdata)
    #                     print("     pointertorawdata : " +
    #                           Elf2.SectionTable.sections[i].pointertorawdata)
    #                     print("     pointertorelocations : " +
    #                           Elf2.SectionTable.sections[i].pointertorelocations)
    #                     print("     pointertolinenumbers : " +
    #                           Elf2.SectionTable.sections[i].pointertolinenumbers)
    #                     print("     numberofrelocations : " +
    #                           Elf2.SectionTable.sections[i].numberofrelocations)
    #                     print("     numberoflinenumbers : " +
    #                           Elf2.SectionTable.sections[i].numberoflinenumbers)
    #                     print("     characteristics : " +
    #                           Elf2.SectionTable.sections[i].characteristics)
    #         elif int(Elf1.Coffheader.numberofsections, 16) > int(Elf2.Coffheader.numberofsections, 16):
    #               for i in range(0, int(Elf2.Coffheader.numberofsections, 16)):
    #                     Log("ERROR", "Elf1 have more sections.")
    #                     print("Section " + str(i) + " : ")
    #                     if Elf1.SectionTable.sections[i].name != Elf2.SectionTable.sections[i].name:
    #                           print("Elf1 name : " + Elf1.SectionTable.sections[i].name + " // " + str(
    #                                 bytearray.fromhex(Elf1.SectionTable.sections[i].name).decode()))
    #                           print("Elf2 name : " + Elf2.SectionTable.sections[i].name + " // " + str(
    #                                 bytearray.fromhex(Elf2.SectionTable.sections[i].name).decode()))
    #                     if Elf1.SectionTable.sections[i].virtualsize != Elf2.SectionTable.sections[i].virtualsize:
    #                           print("Elf1 virtualsize : " +
    #                                 Elf1.SectionTable.sections[i].virtualsize)
    #                           print("Elf2 virtualsize : " +
    #                                 Elf2.SectionTable.sections[i].virtualsize)
    #                     if Elf1.SectionTable.sections[i].virtualaddress != Elf2.SectionTable.sections[i].virtualaddress:
    #                           print("Elf1 virtualaddress : " +
    #                                 Elf1.SectionTable.sections[i].virtualaddress)
    #                           print("Elf2 virtualaddress : " +
    #                                 Elf2.SectionTable.sections[i].virtualaddress)
    #                     if Elf1.SectionTable.sections[i].sizeofrawdata != Elf2.SectionTable.sections[i].sizeofrawdata:
    #                           print("Elf1 sizeofrawdata : " +
    #                                 Elf1.SectionTable.sections[i].sizeofrawdata)
    #                           print("Elf2 sizeofrawdata : " +
    #                                 Elf2.SectionTable.sections[i].sizeofrawdata)
    #                     if Elf1.SectionTable.sections[i].pointertorawdata != Elf2.SectionTable.sections[i].pointertorawdata:
    #                           print("Elf1 pointertorawdata : " +
    #                                 Elf1.SectionTable.sections[i].pointertorawdata)
    #                           print("Elf2 pointertorawdata : " +
    #                                 Elf2.SectionTable.sections[i].pointertorawdata)
    #                     if Elf1.SectionTable.sections[i].pointertorelocations != Elf2.SectionTable.sections[i].pointertorelocations:
    #                           print("Elf1 pointertorelocations : " +
    #                                 Elf1.SectionTable.sections[i].pointertorelocations)
    #                           print("Elf2 pointertorelocations : " +
    #                                 Elf2.SectionTable.sections[i].pointertorelocations)
    #                     if Elf1.SectionTable.sections[i].pointertolinenumbers != Elf2.SectionTable.sections[i].pointertolinenumbers:
    #                           print("Elf1 pointertolinenumbers : " +
    #                                 Elf1.SectionTable.sections[i].pointertolinenumbers)
    #                           print("Elf2 pointertolinenumbers : " +
    #                                 Elf2.SectionTable.sections[i].pointertolinenumbers)
    #                     if Elf1.SectionTable.sections[i].numberofrelocations != Elf2.SectionTable.sections[i].numberofrelocations:
    #                           print("Elf1 numberofrelocations : " +
    #                                 Elf1.SectionTable.sections[i].numberofrelocations)
    #                           print("Elf2 numberofrelocations : " +
    #                                 Elf2.SectionTable.sections[i].numberofrelocations)
    #                     if Elf1.SectionTable.sections[i].numberoflinenumbers != Elf2.SectionTable.sections[i].numberoflinenumbers:
    #                           print("Elf1 numberoflinenumbers : " +
    #                                 Elf1.SectionTable.sections[i].numberoflinenumbers)
    #                           print("Elf2 numberoflinenumbers : " +
    #                                 Elf2.SectionTable.sections[i].numberoflinenumbers)
    #                     if Elf1.SectionTable.sections[i].characteristics != Elf2.SectionTable.sections[i].characteristics:
    #                           print("Elf1 characteristics : " +
    #                                 Elf1.SectionTable.sections[i].characteristics)
    #                           print("Elf2 characteristics : " +
    #                                 Elf2.SectionTable.sections[i].characteristics)
    #               for i in range(int(Elf2.Coffheader.numberofsections, 16), int(Elf1.Coffheader.numberofsections, 16)):
    #                     print("Pe 1 Section " + str(i) + " : ")
    #                     print("     name : " + Elf1.SectionTable.sections[i].name + " // " + str(
    #                           bytearray.fromhex(Elf1.SectionTable.sections[i].name).decode()))
    #                     print("     virtualsize : " +
    #                           Elf1.SectionTable.sections[i].virtualsize)
    #                     print("     virtualaddress : " +
    #                           Elf1.SectionTable.sections[i].virtualaddress)
    #                     print("     sizeofrawdata : " +
    #                           Elf1.SectionTable.sections[i].sizeofrawdata)
    #                     print("     pointertorawdata : " +
    #                           Elf1.SectionTable.sections[i].pointertorawdata)
    #                     print("     pointertorelocations : " +
    #                           Elf1.SectionTable.sections[i].pointertorelocations)
    #                     print("     pointertolinenumbers : " +
    #                           Elf1.SectionTable.sections[i].pointertolinenumbers)
    #                     print("     numberofrelocations : " +
    #                           Elf1.SectionTable.sections[i].numberofrelocations)
    #                     print("     numberoflinenumbers : " +
    #                           Elf1.SectionTable.sections[i].numberoflinenumbers)
    #                     print("     characteristics : " +
    #                           Elf1.SectionTable.sections[i].characteristics)
    #         else:
    #               Log("SUCCESS", "Same section number.")
    #               for i in range(0, int(Elf1.Coffheader.numberofsections, 16)):
    #                     print("Section " + str(i) + " : ")
    #                     if Elf1.SectionTable.sections[i].name != Elf2.SectionTable.sections[i].name:
    #                           print("Elf1 name : " + Elf1.SectionTable.sections[i].name + " // " + str(
    #                                 bytearray.fromhex(Elf1.SectionTable.sections[i].name).decode()))
    #                           print("Elf2 name : " + Elf2.SectionTable.sections[i].name + " // " + str(
    #                                 bytearray.fromhex(Elf2.SectionTable.sections[i].name).decode()))
    #                     if Elf1.SectionTable.sections[i].virtualsize != Elf2.SectionTable.sections[i].virtualsize:
    #                           print("Elf1 virtualsize : " +
    #                                 Elf1.SectionTable.sections[i].virtualsize)
    #                           print("Elf2 virtualsize : " +
    #                                 Elf2.SectionTable.sections[i].virtualsize)
    #                     if Elf1.SectionTable.sections[i].virtualaddress != Elf2.SectionTable.sections[i].virtualaddress:
    #                           print("Elf1 virtualaddress : " +
    #                                 Elf1.SectionTable.sections[i].virtualaddress)
    #                           print("Elf2 virtualaddress : " +
    #                                 Elf2.SectionTable.sections[i].virtualaddress)
    #                     if Elf1.SectionTable.sections[i].sizeofrawdata != Elf2.SectionTable.sections[i].sizeofrawdata:
    #                           print("Elf1 sizeofrawdata : " +
    #                                 Elf1.SectionTable.sections[i].sizeofrawdata)
    #                           print("Elf2 sizeofrawdata : " +
    #                                 Elf2.SectionTable.sections[i].sizeofrawdata)
    #                     if Elf1.SectionTable.sections[i].pointertorawdata != Elf2.SectionTable.sections[i].pointertorawdata:
    #                           print("Elf1 pointertorawdata : " +
    #                                 Elf1.SectionTable.sections[i].pointertorawdata)
    #                           print("Elf2 pointertorawdata : " +
    #                                 Elf2.SectionTable.sections[i].pointertorawdata)
    #                     if Elf1.SectionTable.sections[i].pointertorelocations != Elf2.SectionTable.sections[i].pointertorelocations:
    #                           print("Elf1 pointertorelocations : " +
    #                                 Elf1.SectionTable.sections[i].pointertorelocations)
    #                           print("Elf2 pointertorelocations : " +
    #                                 Elf2.SectionTable.sections[i].pointertorelocations)
    #                     if Elf1.SectionTable.sections[i].pointertolinenumbers != Elf2.SectionTable.sections[i].pointertolinenumbers:
    #                           print("Elf1 pointertolinenumbers : " +
    #                                 Elf1.SectionTable.sections[i].pointertolinenumbers)
    #                           print("Elf2 pointertolinenumbers : " +
    #                                 Elf2.SectionTable.sections[i].pointertolinenumbers)
    #                     if Elf1.SectionTable.sections[i].numberofrelocations != Elf2.SectionTable.sections[i].numberofrelocations:
    #                           print("Elf1 numberofrelocations : " +
    #                                 Elf1.SectionTable.sections[i].numberofrelocations)
    #                           print("Elf2 numberofrelocations : " +
    #                                 Elf2.SectionTable.sections[i].numberofrelocations)
    #                     if Elf1.SectionTable.sections[i].numberoflinenumbers != Elf2.SectionTable.sections[i].numberoflinenumbers:
    #                           print("Elf1 numberoflinenumbers : " +
    #                                 Elf1.SectionTable.sections[i].numberoflinenumbers)
    #                           print("Elf2 numberoflinenumbers : " +
    #                                 Elf2.SectionTable.sections[i].numberoflinenumbers)
    #                     if Elf1.SectionTable.sections[i].characteristics != Elf2.SectionTable.sections[i].characteristics:
    #                           print("Elf1 characteristics : " +
    #                                 Elf1.SectionTable.sections[i].characteristics)
    #                           print("Elf2 characteristics : " +
    #                                 Elf2.SectionTable.sections[i].characteristics)
