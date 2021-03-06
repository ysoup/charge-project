import gevent
import binascii
import datetime
import json
import redis
import time
import logging
import traceback
from gevent import socket, monkey

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='charge_socket.log', level=logging.DEBUG, format=LOG_FORMAT)
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
            logging.info("数据转码:" + str(ret, encoding="utf-8"))
            new_ret = str(ret, encoding="utf-8")
            stx = "".join(list(reversed([(new_ret[0:8])[i:i + 2] for i in range(0, len(new_ret[0:8]), 2)])))
            pkglen = ret[8:12]
            logging.info("stx:" + stx)
            akg_id = "".join(list(reversed([(new_ret[12:16])[i:i + 2] for i in range(0, len(new_ret[12:16]), 2)])))
            logging.info("akg_id:" + akg_id)
            uuid = new_ret[16:]
            stake_no = "".join(list(reversed([(uuid[:8])[i:i + 2] for i in range(0, len(uuid[:8]), 2)])))
            stake_no = int(stake_no, 16)
            logging.info("枪号stake_no:" + str(stake_no))
            spear_no = "".join(list(reversed([(uuid[8:])[i:i + 2] for i in range(0, len(uuid[8:]), 2)])))
            spear_no = int(spear_no, 16)
            logging.info("桩号spear_no:" + str(spear_no))
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
                logging.info("6101-new_ret发送的报文:" + new_ret)
                tmp_ret = binascii.unhexlify(new_ret)
                # logging.info("6101-发送的报文:" + str(tmp_ret, encoding="utf-8"))
                conn.send(tmp_ret)
            elif akg_id == "6103":
                logging.info("6103-解析报文:" + new_ret)
                if new_ret[32:] == "0".zfill(128):
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
                    logging.info("6103-new_ret发送的报文:" + new_ret)
                    tmp_ret = binascii.unhexlify(new_ret)
                    # logging.info("6103-发送的报文:" + tmp_ret)
                    var_6103 = conn.send(tmp_ret)
                    # print(var_6103)
                else:
                    # 充电详情
                    dic = {}
                    order_no = new_ret[32:96]
                    order_no = binascii.unhexlify(order_no)
                    order_no = order_no[:-4].decode("utf-8")
                    dic["order_no"] = order_no

                    purchase = new_ret[96:100]
                    purchase = "".join(list(reversed([purchase[i:i + 2] for i in range(0, len(purchase), 2)])))
                    purchase = int(purchase, 16)
                    dic["purchase"] = purchase

                    power = new_ret[100:104]
                    power = "".join(list(reversed([power[i:i + 2] for i in range(0, len(power), 2)])))
                    power = int(power, 16)
                    dic["power"] = power

                    chargeTime = new_ret[104:108]
                    chargeTime = "".join(list(reversed([chargeTime[i:i + 2] for i in range(0, len(chargeTime), 2)])))
                    chargeTime = int(chargeTime, 16)
                    dic["chargeTime"] = chargeTime

                    balance = new_ret[108:116]
                    balance = "".join(list(reversed([balance[i:i + 2] for i in range(0, len(balance), 2)])))
                    balance = int(balance, 16)
                    dic["balance"] = balance

                    soc = new_ret[116:120]
                    soc = "".join(list(reversed([soc[i:i + 2] for i in range(0, len(soc), 2)])))
                    soc = int(soc, 16)
                    dic["soc"] = soc

                    voltage = new_ret[120:128]
                    voltage = "".join(list(reversed([voltage[i:i + 2] for i in range(0, len(voltage), 2)])))
                    voltage = int(voltage, 16)
                    dic["voltage"] = voltage

                    cerrent = new_ret[128:136]
                    cerrent = "".join(list(reversed([cerrent[i:i + 2] for i in range(0, len(cerrent), 2)])))
                    cerrent = int(cerrent, 16)
                    dic["cerrent"] = cerrent

                    chargeState = new_ret[136:144]
                    chargeState = "".join(list(reversed([chargeState[i:i + 2] for i in range(0, len(chargeState), 2)])))
                    chargeState = int(chargeState, 16)
                    dic["chargeState"] = chargeState
                    logging.info("6103充电详情:" + json.dumps(dic))
                    db_redis.lpush("6103_charge_details_%s" % dic["order_no"], json.dumps(dic))

            elif akg_id == "6104":
                # 解析报文
                logging.info("6104-解析报文:" + new_ret)
                data_6104 =new_ret[32:]
                calcno = data_6104[:-8]
                calcno = binascii.unhexlify(calcno)
                calcno = calcno[:-1].decode("utf-8")
                gunstatus = data_6104[-8:]
                gunstatus = int(gunstatus, 16)
                db_redis.set("gun_status_%s" % calcno, gunstatus)
            elif akg_id == "6106":
                # 解析报文
                dic = {}
                logging.info("6106-解析报文:" + new_ret)
                order_no = new_ret[32:96]
                order_no = binascii.unhexlify(order_no)
                order_no = order_no[:-4].decode("utf-8")
                dic["order_no"] = order_no

                purchase = new_ret[96:100]
                purchase = "".join(list(reversed([purchase[i:i + 2] for i in range(0, len(purchase), 2)])))
                purchase = int(purchase, 16)
                dic["purchase"] = purchase

                power = new_ret[100:104]
                power = "".join(list(reversed([power[i:i + 2] for i in range(0, len(power), 2)])))
                power = int(power, 16)
                dic["power"] = power

                endTime = new_ret[104:136]
                endTime = binascii.unhexlify(endTime)
                endTime = endTime[:-2].decode("utf-8")
                dic["endTime"] = endTime

                stopreason = new_ret[136:144]
                logging.info("6106充电结算:%s" % json.dumps(dic))
                db_redis.lpush("6106_charge_balance_%s" % dic["order_no"], json.dumps(dic))

            # 发送查询报文6104
            data = db_redis.lpop("query_charge_6104_" + str(spear_no))
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
                logging.info("6104发送的报文:" + new_ret)
                tmp_ret_6104 = binascii.unhexlify(new_ret)
                val_6104 = conn.send(tmp_ret_6104)
                logging.info("6104发送成功")
                print(val_6104)

            # 发送6105数据
            cache_data_6105 = db_redis.lpop("query_charge_6105_" + str(spear_no))
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

                logging.info("6105发送的报文::" + new_ret)
                tmp_ret_6105 = binascii.unhexlify(new_ret)
                for i in range(0, 8):
                    val_6105 = conn.send(tmp_ret_6105)
                logging.info("6105发送成功")

            cache_data_6106 = db_redis.lpop("query_charge_6106_" + str(spear_no))
            if cache_data_6106:
                data_6106 = str(cache_data_6106, encoding="utf-8")
                send_data_6106 = json.loads(data_6106)

                pkglen = hex(48).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "6106"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))

                spear_no = hex(int(send_data_6106["spear_no"])).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + send_data_6106["stake_no"]
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no

                order_no = send_data_6106["order_no"] + "\x00\x00\x00\x00"
                order_no = binascii.hexlify(bytes(order_no, encoding="utf-8"))
                order_no = str(order_no, encoding="utf-8")

                new_ret = "f89ab68e" + pkglen + akg_id + uuid + order_no
                logging.info("6106发送的报文::" + new_ret)

                tmp_ret_6106 = binascii.unhexlify(new_ret)
                val_6106 = conn.send(tmp_ret_6106)
                logging.info("6106发送成功")

            cache_data_6107 = db_redis.lpop("query_charge_6107_" + str(spear_no))
            if cache_data_6107:
                data_6107 = str(cache_data_6107, encoding="utf-8")
                send_data_6107 = json.loads(data_6107)

                pkglen = hex(50).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "6107"
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

                is_ok = hex(int(send_data_6107["is_ok"])).replace("0x", "")
                is_ok = new_append_num(is_ok, 4)
                is_ok = "".join(list(reversed([is_ok[i:i + 2] for i in range(0, len(is_ok), 2)])))
                new_ret = "f89ab68e" + pkglen + akg_id + uuid + order_no + is_ok

                logging.info("6107发送的报文:" + new_ret)
                tmp_ret_6107 = binascii.unhexlify(new_ret)
                val_6107 = conn.send(tmp_ret_6107)
                logging.info("6107发送成功")
            cache_data_610a = db_redis.lpop("query_charge_610a")
            if cache_data_610a:
                data_610a = str(cache_data_610a, encoding="utf-8")
                send_data_610a = json.loads(data_610a)

                pkglen = hex(50).replace("0x", "")
                pkglen = "00" + pkglen
                pkglen = "".join(list(reversed([pkglen[i:i + 2] for i in range(0, len(pkglen), 2)])))

                query_no = "610a"
                akg_id = "".join(list(reversed([query_no[i:i + 2] for i in range(0, len(query_no), 2)])))

                spear_no = hex(int(send_data_610a["spear_no"])).replace("0x", "")
                spear_no = "0000" + spear_no
                spear_no = "".join(list(reversed([spear_no[i:i + 2] for i in range(0, len(spear_no), 2)])))
                stake_no = "0000000" + send_data_610a["stake_no"]
                stake_no = "".join(list(reversed([stake_no[i:i + 2] for i in range(0, len(stake_no), 2)])))
                uuid = stake_no + spear_no

                is_ok = hex(int(send_data_610a["is_ok"])).replace("0x", "")
                is_ok = new_append_num(is_ok, 8)
                is_ok = "".join(list(reversed([is_ok[i:i + 2] for i in range(0, len(is_ok), 2)])))
                new_ret = "f89ab68e" + pkglen + akg_id + uuid + is_ok

                logging.info("610a发送的报文:" + new_ret)
                tmp_ret_6107 = binascii.unhexlify(new_ret)
                val_6107 = conn.send(tmp_ret_6107)
                logging.info("610a发送成功")
    # 如果出现异常就打印异常
    except Exception as ex:
        logging.error(traceback.format_exc())
    # 最后中断实例的conn
    finally:
        conn.close()


if __name__ == '__main__':
    server(7500)