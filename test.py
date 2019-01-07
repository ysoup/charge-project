import struct
import binascii
import sys
print("本机存储模式是{} Endian.\n".format(sys.byteorder.capitalize()))
import binascii
import datetime

def append_num(val):
    if (len(val) % 2) != 0:
        return "0" + val
    return val
# import socket
# import os
# server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)#声明socket类型，并且生成socket连接对象
# server.bind(('0.0.0.0', 8500))#把服务器绑定到localhost的6969端口上
# server.listen(5)#开始监听
# print("等待连接中……")
# while True:
#         conn, addr = server.accept()#接收连接
#         print("***连接成功***")
#         while True:
#                 data = conn.recv(512)#接收客户发来的数据
#
#                 print("接收到的命令为：",data)
#                 if not data:
#                         print("客户断开连接")
#                         break
#                 com = os.popen(data.decode()).read()#read()读取内存地址的内容
#                 print(data.decode())#输出结果为字符串dir
#                 print(os.popen(data.decode()))#输出结果为一个内存地址
#                 #py3 里socket发送的只有bytes,os.popen又只能接受str,所以要decode一下
#                 conn.sendall(com.encode('utf-8'))
# server.close()
# \xf8\x9a\xb6\x8e
# \x10\x00
# \x01a\x02

data = b"\xf8\x9a\xb6\x8e\x10\x00\x01a\x02\x00\x00\x00\x19'\x00\x00"
#print(s1.unpack_from(sign, 0))

# a1 = struct.unpack("4s2i2i8i", sign)
# print(a1)
# # print(bytes(sign).decode('ascii'))
#
ret = binascii.hexlify(data)
print(ret)
new_ret = str(ret, encoding="utf-8")
un_ret = binascii.unhexlify(ret)
print(un_ret)
pkglen = hex(23).replace("0x", "")
pkglen = "00" + pkglen
pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))
current_year = hex(datetime.datetime.now().year).replace("0x", "")
current_year = append_num(current_year)
current_year = "".join(list(reversed([current_year[i:i + 2] for i in range(0, len(current_year), 2)])))
current_month = hex(datetime.datetime.now().month).replace("0x", "")
current_month = append_num(current_month)
current_day = hex(datetime.datetime.now().day).replace("0x", "")
current_day = append_num(current_day)
current_hour = hex(datetime.datetime.now().hour).replace("0x", "")
current_hour = append_num(current_hour)
current_minute = hex(datetime.datetime.now().minute).replace("0x", "")
current_minute = append_num(current_minute)
current_second = hex(datetime.datetime.now().second).replace("0x", "")
current_second = append_num(current_second)
new_ret = "f89ab68e" + str(pkglen) + "0161" + "00000019270000" + current_hour + current_minute + current_second + current_month + current_day + current_year
tmp_ret = binascii.unhexlify("F89AB68E66000461010000001927000063616C636E6F5F323031383039313135373534393931303434363137000000000500000040E22D1180E34111C0045411C0012412DE0238121E044C1240055C1200001C13C0056013000000009E009E009E007C130000")
print(tmp_ret)
print(binascii.hexlify(tmp_ret))
# print(" ".join(list(new_tmp)))
# print("".join([(ret[0:8])[i:i+2] for i in range(0, len(ret[0:8]), 2)].reverse()))
# print(eval(b"0200000011270000"))
# # print('01a02'.decode('hex'))
# # f89ab68e 100 01a02 000000110000
# # struct.unpack(">2BHIHH",)
#
# print(type(struct.unpack("ii", byte)),a1,a2)
#
#
# val = 0x12345678
# pk = struct.pack('i', val)
# hex_pk = hex(ord(pk[0]))
#
# if hex_pk == '0x78':
#     print('小端')
# elif hex_pk == '0x12':
#     print('大端')






