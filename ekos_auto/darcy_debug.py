import os,sys,time,json
sys.path.insert(0, '/root/ekos_auto')
from log import *
import ekosUtils
my_utils = ekosUtils.Utils()
ip = sys.argv[1]


rtn = my_utils.get_app_replica(ip,"hello-test")
print rtn

rtn = my_utils.change_app_replica(ip,"hello-test",3)
print rtn

time.sleep(5)

rtn = my_utils.get_app_replica(ip,"hello-test")
print rtn