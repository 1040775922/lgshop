# @ Time    : 2021/1/29 20:34
# @ Author  : JuRan

# celery入口文件
from celery import Celery

import os
if not os.getenv('DJANGO_SETTINGS_MODULE'):
    os.environ['DJANGO_SETTINGS_MODULE'] = 'lgshop.dev'

# 创建celery实例
celery_app = Celery('lg')

# 加载配置文件
celery_app.config_from_object('celery_tasks.config')

# 注册任务
celery_app.autodiscover_tasks(['celery_tasks.sms', 'celery_tasks.email'])

# 启动celery
# celery -A celery_tasks.main worker -l info
# Windows启动celery
# celery -A celery_tasks.main worker -l info --pool=solo
# celery -A celery_tasks.main worker -l info -P eventlet



