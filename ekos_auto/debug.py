import os,sys,time
sys.path.insert(0, '/root/ekos_auto')
from log import *
import ekosUtils
my_utils = ekosUtils.Utils()
my_utils.active_plugin("192.168.13.37")