# coding:utf-8
import sys
import time, datetime
from hashlib import md5
from backend.mysql_model import BaseModel
from peewee import *
from utils.util import random_str


class AccountInfo(BaseModel):
    create_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    total_amount = DecimalField(constraints=[SQL("DEFAULT 0.0000")])
    update_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    user_no = CharField(constraints=[SQL("DEFAULT ''")])

    class Meta:
        table_name = 'account_info'


class ChargeStation(BaseModel):
    auxiliary_source = IntegerField(null=True)
    business_hours = IntegerField(null=True)
    charge_api = IntegerField(null=True)
    charge_method = IntegerField(null=True)
    charge_name = CharField(null=True)
    charge_station_status = IntegerField(null=True)
    charge_type = IntegerField(null=True)
    create_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    depot = IntegerField(null=True)
    ground_lock = IntegerField(null=True)
    operation_type = IntegerField(null=True)
    parking_fee = IntegerField(null=True)
    update_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    voltage = IntegerField(null=True)

    class Meta:
        table_name = 'charge_station'


class MobileCheckCode(BaseModel):
    code = CharField(constraints=[SQL("DEFAULT ''")], null=True)
    create_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    mobile_no = CharField(constraints=[SQL("DEFAULT ''")], null=True, unique=True)
    update_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)

    class Meta:
        table_name = 'mobile_check_code'


class PayOrderDetails(BaseModel):
    create_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    order_no = CharField(constraints=[SQL("DEFAULT ''")])
    pay_fee = CharField(constraints=[SQL("DEFAULT ''")], null=True)
    pay_status = CharField(constraints=[SQL("DEFAULT '0'")], null=True)
    pay_type = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    update_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    user_no = CharField(constraints=[SQL("DEFAULT ''")])

    class Meta:
        table_name = 'pay_order_details'


class UseInfo(BaseModel):
    birth_day = CharField(constraints=[SQL("DEFAULT ''")], null=True)
    create_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    mobile_no = CharField(constraints=[SQL("DEFAULT ''")])
    nick_name = CharField(constraints=[SQL("DEFAULT ''")], null=True)
    update_time = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")], null=True)
    use_img = CharField(constraints=[SQL("DEFAULT ''")], null=True)
    use_name = CharField(constraints=[SQL("DEFAULT ''")])
    use_sex = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    use_type = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    user_no = CharField(primary_key=True)

    class Meta:
        table_name = 'use_info'

