import gevent
import binascii
import datetime
import json
from gevent import socket,monkey
from backend.redis_db import *
monkey.patch_all()


def append_num(val):
    if (len(val) % 2) != 0:
        return "0" + val
    return val


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
            conn.send(data)
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
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))
                new_ret = "f89ab68e" + str(pkglen) + new_ret[12:16] + uuid
                print("6103-new_ret", new_ret)
                tmp_ret = binascii.unhexlify(new_ret)
                print("6103-发送的报文:", tmp_ret)
                conn.send(tmp_ret)

            # 发送查询报文6104
            data = db_redis.lpop("query_charge_6104")
            if not data:
                data = str(data, encoding="utf-8")
                send_data = json.dumps(data)
                pkglen = hex(102).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))
                query_no = "6104"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))
                spear_no = hex(data["spear_no"]).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + data["stake_no"]
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no
                uuid = binascii.unhexlify(uuid)


    # 如果出现异常就打印异常
    except Exception as ex:
        print(ex)
    # 最后中断实例的conn
    finally:
        conn.close()


if __name__ == '__main__':
    data = db_redis.lpop("query_charge_6104")
    if data:
        data = str(data, encoding="utf-8")
        send_data = json.loads(data)
        pkglen = hex(102).replace("0x", "")
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
        uid = hex(int(send_data["uid"])).replace("0x", "")
        uid = "0000000" + uid
        uid = "".join(list(reversed([uid[i:i + 2] for i in range(0, len(uid), 2)])))



    server(8500)

