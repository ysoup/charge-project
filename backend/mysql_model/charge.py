# coding:utf-8
import sys
import time, datetime
from hashlib import md5
from backend.mysql_model import BaseModel
from peewee import *
#from utils.util import random_st


class AccountInfo(BaseModel):
    create_time = DateTimeField(null=True)
    total_amount = DecimalField()
    update_time = DateTimeField(null=True)
    user_no = CharField()

    class Meta:
        table_name = 'account_info'


class ChargeInfoDetails(BaseModel):
    balance = CharField(null=True)
    cerrent = CharField(null=True)
    chargestate = CharField(column_name='chargeState', null=True)
    chargetime = CharField(column_name='chargeTime', null=True)
    charge_address = CharField(null=True)
    charge_no = CharField(null=True)
    create_time = DateTimeField(null=True)
    order_no = CharField(null=True)
    power = CharField(null=True)
    purchase = CharField(null=True)
    soc = CharField(null=True)
    update_time = DateTimeField(null=True)
    voltage = CharField(null=True)

    class Meta:
        table_name = 'charge_details'


class ChargeOrderInfo(BaseModel):
    amount = CharField(null=True)
    create_time = DateTimeField(null=True)
    order_no = CharField()
    pay_status = IntegerField(null=True)
    power = CharField(null=True)
    spear_no = CharField(null=True)
    stake_no = CharField(null=True)
    update_time = DateTimeField(null=True)
    user_no = CharField()

    class Meta:
        table_name = 'charge_order_info'


class ChargeStation(BaseModel):
    auxiliary_source = IntegerField(null=True)
    business_hours = IntegerField(null=True)
    charge_address = CharField(null=True)
    charge_api = IntegerField(null=True)
    charge_method = IntegerField(null=True)
    charge_name = CharField(null=True)
    charge_station_status = IntegerField(null=True)
    charge_type = IntegerField(null=True)
    create_time = DateTimeField(null=True)
    depot = IntegerField(null=True)
    ground_lock = IntegerField(null=True)
    latitude = CharField(null=True)
    longitude = CharField(null=True)
    operation_type = IntegerField(null=True)
    parking_fee = IntegerField(null=True)
    qr_code = CharField(null=True)
    spear_no = CharField(null=True)
    stake_1 = IntegerField(null=True)
    stake_1_status = IntegerField(null=True)
    stake_2 = IntegerField(null=True)
    stake_2_status = IntegerField(null=True)
    station_img = CharField(null=True)
    update_time = DateTimeField(null=True)
    voltage = IntegerField(null=True)
    charge_fee = CharField(null=True)

    class Meta:
        table_name = 'charge_station'


class MobileCheckCode(BaseModel):
    code = CharField(null=True)
    create_time = DateTimeField(null=True)
    mobile_no = CharField(null=True, unique=True)
    update_time = DateTimeField(null=True)

    class Meta:
        table_name = 'mobile_check_code'


class PayOrderDetails(BaseModel):
    create_time = DateTimeField(null=True)
    order_no = CharField()
    pay_fee = CharField(null=True)
    pay_status = CharField(null=True)
    pay_type = IntegerField(null=True)
    update_time = DateTimeField(null=True)
    user_no = CharField()

    class Meta:
        table_name = 'pay_order_details'


class UseInfo(BaseModel):
    birth_day = CharField(null=True)
    create_time = DateTimeField(null=True)
    mobile_no = CharField()
    nick_name = CharField(null=True)
    update_time = DateTimeField(null=True)
    use_img = CharField(null=True)
    use_name = CharField()
    use_sex = IntegerField(null=True)
    use_type = IntegerField(null=True)
    user_no = CharField(unique=True)

    class Meta:
        table_name = 'use_info'


class User(BaseModel):
    email = CharField(null=True, unique=True)
    last_seen = DateTimeField(null=True)
    password = CharField(null=True)
    phone_no = IntegerField(null=True, unique=True)

    class Meta:
        table_name = 'user'


class UserCalcnoInfo(BaseModel):
    calc_no = CharField(null=True)
    create_time = DateTimeField(null=True)
    spear_no = CharField(null=True)
    stake_no = CharField(null=True)
    update_time = DateTimeField(null=True)
    user_no = CharField(null=True)

    class Meta:
        table_name = 'user_calcno_info'


