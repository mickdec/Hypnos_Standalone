'''

'''

import subprocess

def test():  
    name="caca"
    rawdata="4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05"
    fileRawData="rawdata.data"
    fileIn="EXECUTABLE/ELFx64_NOTEDITED_printf.out"
    fileOut="test.out"

    file=open(fileRawData, "w")
    file.write(rawdata)

    subprocess.call(["objcopy","--add-section","."+name+"="+fileRawData,"--set-section-flags","."+name+"=read,code",fileIn,fileOut])
    #print("objcopy --add-section ."+name+"="+fileRawData+" --set-section-flags ."+name+"=read,code "+fileIn+" "+fileOut)
    file.close()
