'''
Library made for editing the values of a ELF class.
-void AddSection(Elf, sectionname: str, rawdata: str)
-void ModifyEntryPoint(Elf, entrypoint: str)
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


def ModifyEntryPoint(Elf, entrypoint: str):
    '''
    Edit the entrypoint of a ELF
    return: void
    '''
