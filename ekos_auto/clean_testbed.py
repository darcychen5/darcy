import ekosUtils,json,time,sys,yaml
from log import *
my_utils = ekosUtils.Utils()
ip = sys.argv[1]

'''
rtn = my_utils.get_all_app(ip)
print rtn
'''
rtn = my_utils.clean_app(ip)