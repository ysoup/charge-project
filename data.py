import binascii

new_ret = "f89ab68e5000036101000000112700003230313930313134313534373436323134353639333130303031313100000000990066000100f70000003100dddf00000e1f00000200000074ef0000401f0000"
order_no = new_ret[32:96]
order_no = binascii.unhexlify(order_no)
order_no = order_no[:-4].decode("utf-8")
print(order_no)


purchase = new_ret[96:100]
purchase = "".join(list(reversed([purchase[i:i + 2] for i in range(0, len(purchase), 2)])))
purchase = int(purchase, 16)
print(purchase)


power = new_ret[100:104]
power = "".join(list(reversed([power[i:i + 2] for i in range(0, len(power), 2)])))
power = int(power, 16)
print(power)

chargeTime = new_ret[104:108]
chargeTime = "".join(list(reversed([chargeTime[i:i + 2] for i in range(0, len(chargeTime), 2)])))
chargeTime = int(chargeTime, 16)
print(chargeTime)

balance = new_ret[108:116]
balance = "".join(list(reversed([balance[i:i + 2] for i in range(0, len(balance), 2)])))
balance = int(balance, 16)
print(balance)

soc = new_ret[116:120]
soc = "".join(list(reversed([soc[i:i + 2] for i in range(0, len(soc), 2)])))
soc = int(soc, 16)
print(soc)

voltage = new_ret[120:128]
voltage = "".join(list(reversed([voltage[i:i + 2] for i in range(0, len(voltage), 2)])))
#voltage = int(voltage, 16)
print(voltage)

cerrent = new_ret[128:136]
cerrent = "".join(list(reversed([cerrent[i:i + 2] for i in range(0, len(cerrent), 2)])))
#cerrent = int(cerrent, 16)
print(cerrent)

chargeState = new_ret[136:144]
chargeState = "".join(list(reversed([chargeState[i:i + 2] for i in range(0, len(chargeState), 2)])))
chargeState = int(chargeState, 16)
print(chargeState)



# print(len(tmp1))
# order = binascii.unhexlify(tmp1[32:96])
# print(order)
# print(order[:-4])
# tmp = "f89ab68e50000361020000001127000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
# print(len(tmp))
#
tmp2 = "f89ab68e480006610100000011270000323031393031313431353437343730373036303433313030303131340000000002000100323031393031313432303539313400be04000000"
print(len(tmp2))