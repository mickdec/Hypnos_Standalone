'''

'''

import subprocess

def test():  
    name="caca"
    fileRawData="a.scc"
    fileIn="EXECUTABLE/ELFx64_NOTEDITED_printf.out"
    fileOut="test.out"

    open(fileRawData, "wb").write(bytes.fromhex("6a2958996a025f6a015e0f0597b02a48b9feffdd478048f7d951545eb2100f056a035eb021ffce0f0575f899b03b5248b92f2f62696e51545f0f05"))

    subprocess.call(["objcopy","--add-section","."+name+"="+fileRawData,"--set-section-flags","."+name+"=read,load,code",fileIn,fileOut])
