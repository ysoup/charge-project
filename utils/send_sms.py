# -*- coding: utf-8 -*-

from sdk.ailiyun.aliyunsdkdysmsapi.request.v20170525 import SendSmsRequest, QuerySendDetailsRequest
from sdk.ailiyun.aliyunsdkcore.client import AcsClient
from sdk.ailiyun.aliyunsdkcore.profile import region_provider
import uuid



"""
短信业务调用接口示例，版本号：v20170525

Created on 2017-06-12

"""

# 注意：不要更改
REGION = "cn-hangzhou"
PRODUCT_NAME = "Dysmsapi"
DOMAIN = "dysmsapi.aliyuncs.com"

# ACCESS_KEY_ID/ACCESS_KEY_SECRET 根据实际申请的账号信息进行替换
ACCESS_KEY_ID = "LTAIn1qaaa9jFY5H"
ACCESS_KEY_SECRET = "1iKJsKjaUhxWrCdXERfiTa0UJFOldI"
CHARGE_SIGN_NAME = u"鼎天新能源"

acs_client = AcsClient(ACCESS_KEY_ID, ACCESS_KEY_SECRET, REGION)
region_provider.add_endpoint(PRODUCT_NAME, REGION, DOMAIN)


def send_sms_code(business_id, phone_numbers, template_code, template_param=None, sign_name=CHARGE_SIGN_NAME):
    smsRequest = SendSmsRequest.SendSmsRequest()
    # 申请的短信模板编码,必填
    smsRequest.set_TemplateCode(template_code)

    # 短信模板变量参数
    if template_param is not None:
        smsRequest.set_TemplateParam(template_param)

    # 设置业务请求流水号，必填。
    smsRequest.set_OutId(business_id)

    # 短信签名
    smsRequest.set_SignName(sign_name)

    # 短信发送的号码列表，必填。
    smsRequest.set_PhoneNumbers(phone_numbers)

    # 调用短信发送接口，返回json
    smsResponse = acs_client.do_action_with_exception(smsRequest)

    # TODO 业务处理

    return smsResponse.decode("utf-8")


def query_send_detail(biz_id, phone_number, page_size, current_page, send_date):
    queryRequest = QuerySendDetailsRequest.QuerySendDetailsRequest()
    # 查询的手机号码
    queryRequest.set_PhoneNumber(phone_number)
    # 可选 - 流水号
    queryRequest.set_BizId(biz_id)
    # 必填 - 发送日期 支持30天内记录查询，格式yyyyMMdd
    queryRequest.set_SendDate(send_date)
    # 必填-当前页码从1开始计数
    queryRequest.set_CurrentPage(current_page)
    # 必填-页大小
    queryRequest.set_PageSize(page_size)

    # 调用短信记录查询接口，返回json
    queryResponse = acs_client.do_action_with_exception(queryRequest)

    # TODO 业务处理

    return queryResponse


if __name__ == '__main__':
    __business_id = uuid.uuid1()
    print(__business_id)
    params = "{\"code\":\"57890\",}"
    print(send_sms_code(__business_id, "18310029092", "SMS_153725691", params, sign_name="鼎天新能源"))
