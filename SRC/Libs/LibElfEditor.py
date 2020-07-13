'''
Library made for editing the values of a PE class.
-LibPeAnnalyzer.PE ChangeCOFFTimestamp(Pe: LibPeAnnalyzer.PE, date: str)
-void AddSection(Pe, sectionname: str, shellcode: str)
-void ModifyEntryPoint(Pe, entrypoint:str)
'''
from SRC.Core import Globals
from SRC.Libs import LibDebug
from SRC.Libs import LibElfAnnalyzer
from SRC.Libs import LibByteEditor
import time
from datetime import datetime


def AddSection(Elf, sectionname: str, rawdata: str):
    '''
    Adding a new section to a specified ELF object.
    -return: void
    '''


def ModifyEntryPoint(Pe, entrypoint: str):
    '''
    Edit the entrypoint of a ELF
    return: void
    '''
