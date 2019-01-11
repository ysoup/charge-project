import gevent
import binascii
import datetime
import json
import redis
import time
from gevent import socket, monkey
# from backend.redis_db import *

monkey.patch_all()

db_redis = redis.StrictRedis(host='39.106.154.14', port=6379, db=0)


def append_num(val):
    if (len(val) % 2) != 0:
        return "0" + val
    return val


def new_append_num(val, length):
    diff_len = length - len(str(val))
    new_val = ""
    for i in range(0, diff_len):
        new_val = new_val + "0"
    return new_val + str(val)


def server(port):
    s = socket.socket()
    s.bind(('0.0.0.0', port))
    s.listen(500)
    while True:
        cli, addr = s.accept()

        # socket会创建一个线程链接，这里会交给协程处理
        # 链接后通过gevent启动一个协程
        # 接收一个函数，与链接实例参数
        gevent.spawn(handle_request, cli)


# 所有交互都由handle处理
def handle_request(conn):
    try:
        while True:
            data = conn.recv(1024)
            print("recv:", data)
            # time.sleep(2)
            # conn.send(data)
            if not data:
                # 如果没有数据就关闭Client端
                conn.shutdown(socket.SHUT_WR)
            ret = binascii.hexlify(data)
            print("数据转码:", ret)
            new_ret = str(ret, encoding="utf-8")
            stx = "".join(list(reversed([(new_ret[0:8])[i:i + 2] for i in range(0, len(new_ret[0:8]), 2)])))
            pkglen = ret[8:12]
            print("stx:", stx)
            akg_id = "".join(list(reversed([(new_ret[12:16])[i:i + 2] for i in range(0, len(new_ret[12:16]), 2)])))
            print("akg_id", akg_id)
            uuid = new_ret[16:]
            stake_no = "".join(list(reversed([(uuid[:8])[i:i + 2] for i in range(0, len(uuid[:8]), 2)])))
            stake_no = int(stake_no, 16)
            print("枪号stake_no:", stake_no)
            spear_no = "".join(list(reversed([(uuid[8:])[i:i + 2] for i in range(0, len(uuid[8:]), 2)])))
            spear_no = int(spear_no, 16)
            print("桩号spear_no:", spear_no)
            # 登录信息
            if akg_id == "6101":
                # 发送响应报文
                pkglen = hex(23).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                current_year = hex(datetime.datetime.now().year).replace("0x", "")
                current_year = append_num(current_year)
                current_year = "".join(
                    list(reversed([current_year[i:i + 2] for i in range(0, len(current_year), 2)])))

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

                new_ret = "f89ab68e" + str(
                    pkglen) + "0161" + uuid + current_hour + current_minute + current_second + current_month + current_day + current_year
                print("6101-new_ret", new_ret)
                tmp_ret = binascii.unhexlify(new_ret)
                print("6101-发送的报文:", tmp_ret)
                conn.send(tmp_ret)
            elif akg_id == "6103":
                pkglen = hex(16).replace("0x", "")
                pkglen = pkglen.zfill(4)
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "6103"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))

                spear_no = hex(int(spear_no)).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + str(stake_no)
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no

                new_ret = "f89ab68e" + str(pkglen) + akg_id + uuid
                print("6103-new_ret", new_ret)
                tmp_ret = binascii.unhexlify(new_ret)
                print("6103-发送的报文:", tmp_ret)
                var_6103 = conn.send(tmp_ret)
                print(var_6103)
            elif akg_id == "6104":
                # 解析报文
                data_6104 =new_ret[32:]
                calcno = data_6104[:-8]
                calcno = binascii.unhexlify(calcno)
                calcno = calcno[:-1].decode("utf-8")
                gunstatus = data_6104[-8:]
                gunstatus = int(gunstatus, 16)
                db_redis.set("gun_status_%s" % calcno, gunstatus)
            elif akg_id == "6106":
                print("aaaa")
            # 发送查询报文6104
            data = db_redis.lpop("query_charge_6104")
            if data:
                data = str(data, encoding="utf-8")
                send_data = json.loads(data)
                pkglen = hex(106).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "6104"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))

                spear_no = hex(int(send_data["spear_no"])).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + send_data["stake_no"]
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no

                calcno = send_data["calcno"] + "\x00\x00\x00\x00"
                calcno = binascii.hexlify(bytes(calcno, encoding="utf-8"))
                calcno = str(calcno, encoding="utf-8")

                uid = hex(int(send_data["uid"])).replace("0x", "")
                uid = new_append_num(uid, 8)
                uid = "".join(list(reversed([uid[i:i + 2] for i in range(0, len(uid), 2)])))
                elecTime1 = "40E22D11"
                elecTime2 = "80E34111"
                elecTime3 = "C0045411"
                elecTime4 = "C0012412"
                elecTime5 = "DE023812"
                elecTime6 = "1E044C12"
                elecTime7 = "40055C12"
                elecTime8 = "00001C13"
                elecTime9 = "C0056013"
                elecTime10 = "00000000"
                elecPrice1 = hex(int(send_data["price"])).replace("0x", "")
                elecPrice1 = new_append_num(elecPrice1, 4)
                elecPrice1 = "".join(list(reversed([elecPrice1[i:i + 2] for i in range(0, len(elecPrice1), 2)])))

                elecPrice2 = hex(int(send_data["price"])).replace("0x", "")
                elecPrice2 = new_append_num(elecPrice2, 4)
                elecPrice2 = "".join(list(reversed([elecPrice2[i:i + 2] for i in range(0, len(elecPrice2), 2)])))

                elecPrice3 = hex(int(send_data["price"])).replace("0x", "")
                elecPrice3 = new_append_num(elecPrice3, 4)
                elecPrice3 = "".join(list(reversed([elecPrice3[i:i + 2] for i in range(0, len(elecPrice3), 2)])))

                amount = hex(int(send_data["amount"])).replace("0x", "")
                amount = new_append_num(amount, 8)
                amount = "".join(list(reversed([amount[i:i + 2] for i in range(0, len(amount), 2)])))
                new_ret = "f89ab68e" + pkglen + akg_id + uuid + calcno + uid + elecTime1 + elecTime2 + elecTime3 + elecTime4 + \
                          elecTime5 + elecTime6 + elecTime7 + elecTime8 + elecTime9 + elecTime10 + elecPrice1 + elecPrice2 + elecPrice3 + amount + "00000000"
                print("6104数据:", new_ret)
                tmp_ret_6104 = binascii.unhexlify(new_ret)
                val_6104 = conn.send(tmp_ret_6104)
                print("6104发送成功")
                print(val_6104)

            # 发送6105数据
            cache_data_6105 = db_redis.lpop("query_charge_6105")
            if cache_data_6105:
                data_6105 = str(cache_data_6105, encoding="utf-8")
                send_data_6105 = json.loads(data_6105)

                pkglen = hex(56).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "6105"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))

                spear_no = hex(int(send_data_6105["spear_no"])).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + send_data_6105["stake_no"]
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no

                order_no = send_data_6105["order_no"] + "\x00\x00\x00\x00"
                order_no = binascii.hexlify(bytes(order_no, encoding="utf-8"))
                order_no = str(order_no, encoding="utf-8")

                uid = hex(int(send_data_6105["uid"])).replace("0x", "")
                uid = new_append_num(uid, 8)
                uid = "".join(list(reversed([uid[i:i + 2] for i in range(0, len(uid), 2)])))

                is_can_begin = hex(int(send_data_6105["is_can_begin"])).replace("0x", "")
                is_can_begin = new_append_num(is_can_begin, 8)
                is_can_begin = "".join(list(reversed([is_can_begin[i:i + 2] for i in range(0, len(is_can_begin), 2)])))
                new_ret = "f89ab68e" + pkglen + akg_id + uuid + order_no + uid + is_can_begin

                print("6105数据:", new_ret)
                tmp_ret_6105 = binascii.unhexlify(new_ret)
                val_6105 = conn.send(tmp_ret_6105)

                print("6105发送成功")
                print(val_6105)

            cache_data_6106 = db_redis.lpop("query_charge_6106")
            if cache_data_6106:
                data_6106 = str(cache_data_6106, encoding="utf-8")
                send_data_6106 = json.loads(data_6106)

            cache_data_6107 = db_redis.lpop("query_charge_6107")
            if cache_data_6107:
                data_6107 = str(cache_data_6107, encoding="utf-8")
                send_data_6107 = json.loads(data_6107)

                pkglen = hex(56).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "6105"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))

                spear_no = hex(int(send_data_6107["spear_no"])).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + send_data_6107["stake_no"]
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no

                order_no = send_data_6107["order_no"] + "\x00\x00\x00\x00"
                order_no = binascii.hexlify(bytes(order_no, encoding="utf-8"))
                order_no = str(order_no, encoding="utf-8")

                uid = hex(int(send_data_6107["uid"])).replace("0x", "")
                uid = new_append_num(uid, 8)
                uid = "".join(list(reversed([uid[i:i + 2] for i in range(0, len(uid), 2)])))

                is_ok = hex(int(send_data_6107["is_ok"])).replace("0x", "")
                is_ok = new_append_num(is_ok, 4)
                is_ok = "".join(list(reversed([is_ok[i:i + 2] for i in range(0, len(is_ok), 2)])))
                new_ret = "f89ab68e" + pkglen + akg_id + uuid + order_no + uid + is_ok

                print("6107数据:", new_ret)
                tmp_ret_6107 = binascii.unhexlify(new_ret)
                val_6107 = conn.send(tmp_ret_6107)

                print("6107发送成功")
                print(val_6107)
    # 如果出现异常就打印异常
    except Exception as ex:
        print(str(ex))
    # 最后中断实例的conn
    finally:
        conn.close()


if __name__ == '__main__':
    server(8500)




