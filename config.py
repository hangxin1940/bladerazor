import sys

from loguru import logger

stdout_fmt = '<cyan>{time:HH:mm:ss,SSS}</cyan> ' \
             '[<level>{level: <5}</level>] ' \
             '<blue>{module}</blue>:<cyan>{line}</cyan> - ' \
             '<level>{message}</level>'

logger.remove()
logger.level(name='TRACE', color='<cyan><bold>')
logger.level(name='DEBUG', color='<blue><bold>')
logger.level(name='INFOR', no=20, color='<green><bold>')
logger.level(name='QUITE', no=25, color='<green><bold>')
logger.level(name='ALERT', no=30, color='<yellow><bold>')
logger.level(name='ERROR', color='<red><bold>')
logger.level(name='FATAL', no=50, color='<RED><bold>')

logger.add(sys.stderr, level='DEBUG', format=stdout_fmt, enqueue=True)
