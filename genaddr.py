import ctypes, struct, binascii, os, socket
def sockaddr():
    IP = "127.0.0.1"
    PORT = 8888
    family = struct.pack('H', socket.AF_INET)
    portbytes = struct.pack('H', socket.htons(PORT))
    ipbytes = socket.inet_aton(IP)
    number = struct.unpack('Q', family + portbytes + ipbytes)
    number = -number[0]        #negate
    print("0x" + binascii.hexlify(struct.pack('>q', number)).decode('utf-8'))

class SHELLCODE:
        '''
        SHELLCODE Class.
        -string GetShellcode()
        '''
        def __init__(self):
            self.opcodes = []

        def GetShellcode(self):
            '''
            return shellcode parsed string
            -return: string
            '''
            shellcode = ""
            for opcode in self.opcodes:
                shellcode += opcode
            return shellcode

def parseShellcode():
    shellcode = SHELLCODE()
    with open("shellcode.sc", 'r') as fc:
        unparsed_shellcode = fc.readlines()
    for line in unparsed_shellcode:
        line = line.split('\t')
        if len(line) == 3:
            shellcode.opcodes.append(line[1].replace(" ", ""))
    BadEnd = True
    while BadEnd:
        if shellcode.opcodes[len(shellcode.opcodes)-1] == "0000" or shellcode.opcodes[len(shellcode.opcodes)-1] == "00" or shellcode.opcodes[len(shellcode.opcodes)-1] == "ff" or shellcode.opcodes[len(shellcode.opcodes)-1] == "ff00" or shellcode.opcodes[len(shellcode.opcodes)-1] == "00ff" or shellcode.opcodes[len(shellcode.opcodes)-1] == "ffff":
            shellcode.opcodes.pop(len(shellcode.opcodes)-1)
        else:
            BadEnd = False
    print(shellcode.GetShellcode())
parseShellcode()