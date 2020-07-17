'''
Library made for editing bytes/HEX content, and creating files.
-string RevertBytes(content: str)
-string GetHexFromFile(input_file: str)
-string EditExistingContent(content: str, needle: str, replacement: str, numberoftime: int, index: int)
-string EditAllExistingContent(content: str, needle: str, replacement: str)
-string AddContent(content: str, index: int, adding: str)
-void CreateExeFromHex(output: str, content: str)
-void CreateBinFromClass(output: str, Pe: LibPeAnnalyzer.PE)
-string AlignData(size: int, alignment, address: str)
'''
from SRC.Libs import LibDebug
from SRC.Libs import LibPeAnnalyzer
from ctypes import c_int32


def RevertBytes(content: str):
    '''
    Read a specified HEX string from right to left, as a memory will.
    -return: string
    '''
    contentTMP = ""
    for _ in range(int(len(content)/2)):
        contentTMP += content[-2:]
        content = content[:-2]
    return contentTMP


def GetHexFromFile(inputfile: str):
    '''
    Return the full Hex of a file.
    -return: string
    '''
    LibDebug.CheckFile(inputfile)
    with open(inputfile, mode='rb') as f:
        return f.read().hex()


def EditExistingContent(content: str, needle: str, replacement: str, numberoftime: int, index: int):
    '''
    Edit a specified content of a string, a specified amount of time, at a specified position.
    -return: string
    '''
    if content.find(needle) == -1:
        LibDebug.Log("ERROR", "Content " + replacement +
                     " didn't found, aborting..")
        exit()
    else:
        LibDebug.Log("SUCCESS", "Content find here : " +
                     str(content.find(needle)))
        LibDebug.Log("WORK", "Editing..")
        try:
            return content.replace(needle, replacement, 1)
        except:
            LibDebug.Log("ERROR", "Error while replacing..")


def EditAllExistingContent(content: str, needle: str, replacement: str):
    '''
    Edit all the occurence of a specified needle in a string by his specified replacement.
    -return: string
    '''
    if content.find(needle) == -1:
        LibDebug.Log("ERROR", "Content " + replacement +
                     " didn't found, aborting..")
        exit()
    elif needle == replacement:
        LibDebug.Log("ERROR", "New content is the same as the replacement.")
        exit()
    else:
        while content.find(needle) != -1:
            LibDebug.Log("SUCCESS", "Content find here : " +
                         str(content.find(needle)))
            LibDebug.Log("WORK", "Editing..")
            try:
                content = content.replace(needle, replacement)
            except:
                print("Error while replacing..")
    return content


def AddContent(content: str, index: int, adding: str):
    '''
    Add specified hexstring into a specified content, at a specified position.
    -return: string
    '''
    print("Trying to add new bytes...")
    base_content = ""
    if len(adding) % 2 != 0:
        LibDebug.Log("ERROR", "New content isn't a valid HEX string.")
        exit()
    try:
        LibDebug.Log("WORK", "Before : " +
                     base_content[10:index] + " " + base_content[index:10])
        ret = base_content[:index] + adding + base_content[index:]
        LibDebug.Log("WORK", "After : " +
                     base_content[10:index] + base_content[index:10])
        LibDebug.Log("SUCCESS", "New bytes added.")
        return ret
    except:
        LibDebug.Log("ERROR", "Failed to add the new bytes..")


def CreateExeFromHex(output: str, content: str):
    '''
    Create a new EXE with the specified HEX content.
    -return: void
    '''
    try:
        if len(content) % 2 != 0:
            LibDebug.Log("ERROR", "New content isn't a valid HEX string.")
            exit()
        else:
            LibDebug.Log("WORK", "Creating " + output + "..")
            open(output, "wb").write(bytes.fromhex(content))
            LibDebug.Log("WORK", "Reading the first bytes..")
            with open(output, mode='rb') as f:
                newcontent = f.read().hex()
            LibDebug.Log("WORK", "Checking the first bytes...")
            if newcontent[0:100] != content[0:100]:
                LibDebug.Log(
                    "ERROR", "Content of the new file is not the same as the new content.")
            else:
                LibDebug.Log("SUCCESS", "Content seems correct. " +
                             output + " successfuly created.")
    except:
        LibDebug.Log("ERROR", "Failed to create the output file.")
        exit()


def CreateBinFromClass(output: str, Pe):
    '''
    Create a new EXE with the specified PE class.
    -return: void
    '''
    try:
        content = Pe.ToHex()
        if len(content) % 2 != 0:
            LibDebug.Log("ERROR", "New content isn't a valid HEX string.")
            exit()
        else:
            LibDebug.Log("WORK", "Creating " + output + "..")
            open(output, "wb").write(bytes.fromhex(content))
            LibDebug.Log("SUCCESS", "Content seems correct. " +
                         output + " successfuly created.")
    except:
        LibDebug.Log("ERROR", "Failed to create the output file.")
        exit()


def AlignData(size: int, alignment, address: str):
    '''
    Align a PE Data with sections.
    -return: string
    '''
    if size % alignment != 0:
        return str(hex(int(c_int32(address + int(size/alignment+1) * alignment).value)))[2:]
    else:
        return str(hex(int(address + size)))[2:]
