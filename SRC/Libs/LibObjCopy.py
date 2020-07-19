'''

'''

import subprocess

def test():  
    name="caca"
    fileRawData="a.scc"
    fileIn="EXECUTABLE/ELFx64_NOTEDITED_printf.out"
    fileOut="test.out"

    subprocess.call(["objcopy","--add-section","."+name+"="+fileRawData,"--set-section-flags","."+name+"=read,code",fileIn,fileOut])
