import ctypes, struct, binascii, os, socket
IP = "127.0.0.1"
PORT = 8888
family = struct.pack('H', socket.AF_INET)
portbytes = struct.pack('H', socket.htons(PORT))
ipbytes = socket.inet_aton(IP)
number = struct.unpack('Q', family + portbytes + ipbytes)
number = -number[0]        #negate
print("0x" + binascii.hexlify(struct.pack('>q', number)).decode('utf-8'))