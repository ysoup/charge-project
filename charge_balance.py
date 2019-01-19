# coding:utf-8

import json
import decimal
import logging
import traceback
from backend.mysql_model.charge import *
from backend.redis_db import *
from backend.mysql_model import db_mysql

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(filename='charge_balance.log', level=logging.DEBUG, format=LOG_FORMAT)


def charge_order_balance():
    # 查询未结算的订单
    while True:
        try:
            order_info = ChargeOrderInfo.select().where(ChargeOrderInfo.pay_status == 0)
            if order_info:
                for x in order_info:
                    order_no = x.order_no
                    user_no = x.user_no
                    logging.info("当前结帐用户:%s;订单号:%s" % (user_no, order_no))
                    cache_data = db_redis.lpop("6106_charge_balance_%s" % order_no)
                    if cache_data:
                        blance_data = str(cache_data, encoding="utf-8")
                        blance_data = json.loads(blance_data)
                        logging.info("当前结帐用户:%s;订单号:%s;消费详情:%s" % (user_no, order_no, json.dumps(blance_data)))
                        account_info = AccountInfo.select().where(AccountInfo.user_no == user_no).first()
                        if account_info:
                            # 计算金额
                            amount = account_info.total_amount - decimal.Decimal(blance_data["purchase"])
                            logging.info("当前结帐用户:%s;订单号:%s;当请用户余额:%s" % (user_no, order_no, amount))
                            # 更新账户金额
                            AccountInfo.update(total_amount=amount).where(AccountInfo.user_no == user_no).execute()
                            # 更新订单状态
                            ChargeOrderInfo.update(pay_status=1, amount=blance_data["purchase"],
                                                   power=blance_data["power"]).where(
                                ChargeOrderInfo.order_no == order_no).execute()

                            # 发送服务端结算信息
                            balance_info = {"amount": blance_data["purchase"], "power": blance_data["power"],
                                            "status": 1}
                            db_redis.set("charge_balance_%s" % order_no, json.dumps(balance_info))

                            # 发送结帐信息
                            charge_data = {
                                "order_no": order_no,
                                "spear_no": x.spear_no,
                                "stake_no": x.stake_no,
                                "is_ok": 1
                            }
                            db_redis.lpush("query_charge_6107", json.dumps(charge_data))
                            logging.info("当前结帐用户:%s;订单号:%s;结帐成功" % (user_no, order_no))
        except Exception as e:
            logging.error(traceback.format_exc())


if __name__ == '__main__':
    logging.info("订单服务开启.....")
    charge_order_balance()