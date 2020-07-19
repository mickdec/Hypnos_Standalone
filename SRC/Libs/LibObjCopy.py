'''

'''

import subprocess

def test():  
    name="caca"
    fileRawData="a.scc"
    fileIn="EXECUTABLE/ELFx64_NOTEDITED_printf.out"
    fileOut="test.out"

    open(fileRawData, "wb").write(bytes.fromhex("4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05"))

    subprocess.call(["objcopy","--add-section","."+name+"="+fileRawData,"--set-section-flags","."+name+"=read,code",fileIn,fileOut])
