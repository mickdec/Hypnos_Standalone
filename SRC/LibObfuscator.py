'''
Library made for working one generated and obfuscated C source code.
-class FUNCTION
-class OBFUSCATED
-string RandomizedString(len: int)
-string RandomizedDictionnary(dictionnary: str)
-string GenerateC(complexity:int)
-string ObfuscateC(inputFile: str, complexity)
-string GenerateObfuscated(obfuscated: OBFUSCATED, outputfile: str)
-string Compile(source: str)
'''
from SRC import LibShellcode
import random
import re
import os


class FUNCTION:
    def __init__(self):
        self.name = ""
        self.content = ""


class OBFUSCATED:
    def __init__(self):
        self.dictionnary = ""
        self.includes = []
        self.functions = []


def RandomizedString(len: int):
    '''
    Generate a random string of size 'len'
    -return: string
    '''
    dic = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    formated = ""
    for _ in range(0, len):
        formated += dic[random.randint(0, 51)]
    return formated


def RandomizedDictionnary(dictionnary: str):
    '''
    Randomize a string 'dictionnary'
    -return: string
    '''
    used_child = ""
    for child in dictionnary:
        child_content = dictionnary[random.randint(0, len(dictionnary)-1)]
        while len(used_child) < len(dictionnary):
            if child_content in used_child:
                child_content = dictionnary[random.randint(
                    0, len(dictionnary)-1)]
            else:
                used_child += child_content
    return used_child


def GenerateC(complexity: int):
    '''
    Generate a C code source of complexity ((rand->complexity)*nb_functions)
    -return: string
    '''
    Source_code = OBFUSCATED()
    Source_code.includes.append("#include <stdio.h>")
    Source_code.includes.append("#include <unistd.h>")
    main_function = FUNCTION()
    main_function.name = "int main(){\n"
    number_of_functions = random.randint(10, complexity)
    a = 0
    namesize = 5
    nameTMP = ""
    trigg = 0
    for i in range(0, number_of_functions):
        function = FUNCTION()
        nameTMP = RandomizedString(namesize)
        if len(Source_code.functions) == 0:
            function.name = "void " + RandomizedString(namesize) + "(){\n"
        else:
            for func in Source_code.functions:
                if "void " + nameTMP + "(){\n" == func.name:
                    namesize += 1
                    trigg = 1
        if trigg:
            function.name = "void " + RandomizedString(namesize) + "(){\n"
            trigg = 0
        else:
            function.name = "void " + nameTMP + "(){\n"
        function.content = ""
        Source_code.functions.append(function)
        for i in range(0, number_of_functions):
            splited = Source_code.functions[random.randint(
                0, len(Source_code.functions)-1)].name.split(' ')[1]
            splitedBase = Source_code.functions[a].name.split(' ')[1]
            if splited[:-4] != splitedBase[:-4]:
                Source_code.functions[a].content += splited.split('(')[
                    0] + "();\n"
        a += 1
    for i in range(0, number_of_functions):
        splited = Source_code.functions[random.randint(
            1, number_of_functions-1)].name.split(' ')[1]
        main_function.content += splited.split('(')[0] + "();\n"
    main_function.content += "return 0;\n"
    Source_code.functions.append(main_function)
    return GenerateObfuscated(Source_code, "source.c")


def ObfuscateC(inputFile: str, complexity):
    '''
    Obfuscate a C code source based on complexity.
    -return: string
    '''
    Source_code_annalyzed = OBFUSCATED()
    Source_code_annalyzed.dictionnary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Source_code_annalyzed.dictionnary = RandomizedDictionnary(
        Source_code_annalyzed.dictionnary)
    with open(inputFile, mode='r') as f:
        content = f.read()
    Source_code_annalyzed.includes = re.findall(
        r'#include <[a-zA-Z0-9\.]*>', content)
    functionsName = re.findall(
        r'[a-zA-Z0-9_][a-zA-Z0-9_]* [a-zA-Z0-9_][a-zA-Z0-9_]*\(.*\){{0,1}', content)
    for i in range(0, len(functionsName)):
        if functionsName[i][-1:] != '{':
            functionsName[i] += '\n{'
    functionsContent = re.findall(r'{.*?}', content, flags=re.S)
    for i in range(0, len(functionsContent)):
        functionsContent[i] = functionsContent[i].replace('}', '')
        functionsContent[i] = functionsContent[i].replace('{', '')
    for i in range(0, len(functionsName)):
        function = FUNCTION()
        function.name = functionsName[i]
        function.content = functionsContent[i]
        Source_code_annalyzed.functions.append(function)
    for function in Source_code_annalyzed.functions:
        Obfuscated_function = FUNCTION()
        splited = ""
        splited = function.name.split(' ')
        if "main(" not in splited[1]:
            Obfuscated_name = ""
            Obfuscated_name = splited[0] + ' ' + \
                RandomizedString(random.randint(5, complexity))
            splited = function.name.split('(')
            Obfuscated_name += '(' + splited[1]
            splited = function.name.split(' ')[1]
            splited = splited.split('(')[0]
            Obfuscated_splited = Obfuscated_name.split(' ')[1]
            Obfuscated_splited = Obfuscated_splited.split('(')[0]
            for i in range(0, len(Source_code_annalyzed.functions)):
                if splited + '(' in Source_code_annalyzed.functions[i].content:
                    Source_code_annalyzed.functions[i].content = Source_code_annalyzed.functions[i].content.replace(
                        splited + '(', Obfuscated_splited + '(')
                if splited + ',' in Source_code_annalyzed.functions[i].content:
                    Source_code_annalyzed.functions[i].content = Source_code_annalyzed.functions[i].content.replace(
                        splited + ',', Obfuscated_splited + ',')
                if function.name == Source_code_annalyzed.functions[i].name:
                    Source_code_annalyzed.functions[i].name = Obfuscated_name
    return GenerateObfuscated(Source_code_annalyzed, "Obfuscated_source.c")


def GenerateObfuscated(obfuscated: OBFUSCATED, outputfile: str):
    '''
    Generate an OBFUSCATED object.
    return: string
    '''
    outputfile = "GeneratedC_" + outputfile
    f = open(outputfile, 'w+')
    for include in obfuscated.includes:
        f.write(include)
        f.write('\n')
    for function in obfuscated.functions:
        f.write(function.name)
        f.write(function.content)
        f.write('}\n')
    f.close()
    return outputfile


def Compile(source: str):
    '''
    Compile an input C source code.
    return: string
    '''
    os.system("gcc "+source+" -o Compiled_" + source[:-2] + ".exe")
    return "Compiled_" + source[:-2] + ".exe"


def ObfuscateShellcode(shellcode: LibShellcode.SHELLCODE, complexity):
    '''
    Obfuscate a LibShellcode.SHELLCODE object
    Beware : a complexity of 2 is higher than a complexity of 100.
    return: LibShellcode.SHELLCODE
    '''
    if complexity <= 1:
        complexity = 1
    ObfusacteDict = ["90", "898501FFFFFF31C0B8FFFFFFFF2D111111113DEEEEEEEE75F431C08B8501FFFFFF", "898501FFFFFF31C0B8FFFFFFFF2D111111113DDDDDDDDD75F431C08B8501FFFFFF", "898501FFFFFF31C0B8FFFFFFFF2D111111113DCCCCCCCC75F431C08B8501FFFFFF",
                     "898501FFFFFF31C0B8FFFFFFFF2D111111113DBBBBBBBB75F431C08B8501FFFFFF", "898501FFFFFF31C0B8FFFFFFFF2D111111113DAAAAAAAA75F431C08B8501FFFFFF", "898501FFFFFF31C0B8FFFFFFFF2D111111113D9999999975F431C08B8501FFFFFF"]
    ObfusacteDict = ["90"]
    Trigger = 0
    for i in range(0, len(shellcode.opcodes)-1):
        if random.randint(0, complexity) == 1 and Trigger == 0:
            shellcode.opcodes.insert(
                i, ObfusacteDict[random.randint(0, len(ObfusacteDict)-1)])
            Trigger = 2
        if Trigger > 0:
            Trigger -= 1
    return shellcode
