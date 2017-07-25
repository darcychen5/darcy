import os,sys,time
sys.path.insert(0, '/root/ekos_auto')
from log import *
import ekosUtils
my_utils = ekosUtils.Utils()
#rtn = my_utils.clean_app("192.168.20.81")
rtn = my_utils.remove_all_nfs_volume("192.168.20.81","darcy-nfs")
print rtn