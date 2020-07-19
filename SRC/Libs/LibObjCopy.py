'''

'''

import subprocess

def test():  
    name="caca"
    fileRawData="a.scc"
    fileIn="EXECUTABLE/ELFx64_NOTEDITED_printf.out"
    fileOut="test.out"

    open(fileRawData, "wb").write(bytes.fromhex("4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05"))
    open(fileRawData, "wb").write(bytes.fromhex("554889E5488D3DA90E0000E8D5FFFFFFB8000000005DC3660F1F84000000000041574C8D3D6F2C000041564989D641554989F541544189FC55488D2D602C0000534C29FD4883EC08E863FEFFFF48C1FD03741B31DB0F1F004C89F24C89EE4489E741FF14DF4883C3014839DD75EA4883C4085B5D415C415D415E415FC30F1F00C30000004883EC084883C408C3"))


    subprocess.call(["objcopy","--add-section","."+name+"="+fileRawData,"--set-section-flags","."+name+"=alloc,code",fileIn,fileOut])
