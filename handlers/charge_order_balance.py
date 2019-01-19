# coding:utf-8

import json
import decimal
from backend.mysql_model.charge import *
from backend.redis_db import *
from backend.mysql_model import db_mysql


def charge_order_balance():
    # 查询未结算的订单
    order_info = ChargeOrderInfo.select().where(ChargeOrderInfo.pay_status == 0)
    if order_info:
        for x in order_info:
            order_no = x.order_no
            user_no = x.user_no
            cache_data = db_redis.lpop("6106_charge_balance_%s" % order_no)
            if cache_data:
                blance_data = str(cache_data, encoding="utf-8")
                blance_data = json.loads(blance_data)

                account_info = AccountInfo.select().where(AccountInfo.user_no == user_no).first()
                if account_info:
                    # 计算金额
                    amount = account_info.total_amount - decimal.Decimal(blance_data["purchase"])
                    # 更新账户金额
                    AccountInfo.update(total_amount=amount).where(AccountInfo.user_no == user_no).execute()
                    # 更新订单状态
                    ChargeOrderInfo.update(pay_status=1, amount=blance_data["purchase"],
                                           power=blance_data["power"]).where(
                        ChargeOrderInfo.order_no == order_no).execute()

                    # 发送服务端结算信息
                    balance_info = {"amount": blance_data["purchase"], "power": blance_data["power"], "status": 1}
                    db_redis.set("charge_balance_%s" % order_no, json.dumps(balance_info))

                    # 发送结帐信息
                    charge_data = {
                        "order_no": order_no,
                        "spear_no": x.spear_no,
                        "stake_no": x.stake_no,
                        "is_ok": 1
                    }
                    db_redis.lpush("query_charge_6107", json.dumps(charge_data))


if __name__ == '__main__':
    charge_order_balance()