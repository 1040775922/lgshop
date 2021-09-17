# @ Time    : 2021/1/29 20:39
# @ Author  : JuRan

# 定义任务：发送短信
from celery_tasks.sms.ronglianyun.ccp_sms import CCP
from . import constants
from celery_tasks.main import celery_app


@celery_app.task(name="send_sms_code")
def send_sms_code(mobile, sms_code):
    """
    发送短信验证码的异步任务
    :param mobile: 手机号
    :param sms_code: 短信验证码
    :return: 成功 0 失败 -1
    """
    send_ret = CCP().send_message(mobile, (sms_code, constants.SMS_CODE_REDIS_EXPIRES // 60), constants.SEND_SMS_TEMPLATE_ID)
    return send_ret