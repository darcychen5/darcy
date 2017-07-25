import sys,json,time,random
sys.path.insert(0, '/root/ekos_auto/')
import ekosUtils
from log import *

ip = sys.argv[1]
appname_tmp = "hello-powercycle-"
app_num = 10
node_list = ["EKOS-offline-darcy-62","EKOS-offline-darcy-63","EKOS-offline-darcy-64"]


my_utils = ekosUtils.Utils()
#create 10 app
ip = sys.argv[1]
cookies = my_utils._get_cookie(ip)
url = "http://" + ip + ":30000/service/stack/api/app"
obj_json = {"name":"hello-test2","namespace":"default","stateful":"none","replicas":1,"cpu":500,"memory":256,"diskSize":20000,"containers":[{"name":"hello-test","image":"registry.ekos.local/library/hello:latest","command":"sh","envs":[],"logDir":"","healthCheck":None,"cpuPercent":100,"memPercent":100}],"service":{"ports":[{"protocol":"TCP","containerPort":666,"servicePort":666}]},"volumes":[],"desc":"111"}
for i in range(app_num):
	obj_json['name'] = appname_tmp + str(i)
	app_rtn = my_utils.call_rest_api(url,"POST",cookies=cookies,json=json.dumps(obj_json))
	if "success" in json.loads(app_rtn)['status']:
		info('create application: %s successfully' % obj_json['name'])
	else:
		sys.exit()

info('sleep 60 seconds')
my_utils.bar_sleep(60)

#get app name
app_list = []
for i in range(app_num):
	appname = appname_tmp + str(i)
	app_list.append(appname)
#check app running
rtn = my_utils.check_app_status(ip,app_list)
if rtn != True:
	sys.exit()

#power off nodes sequentially
for node in node_list:
	rtn = my_utils.poweroff_vm(node)
	if rtn != True:
		error("power off node failed!")
		sys.exit()
	my_utils.bar_sleep(10)

info('power off node done,sleep 60 seconds')
my_utils.bar_sleep(60)

	#power on all nodes

for node in node_list:
	rtn = my_utils.poweron_vm(node)
	if rtn != True:
		error('power on node failed')
		sys.exit()

info('Power on node done,sleep 6 minutes')
my_utils.bar_sleep(360)

#check node ready
rtn = my_utils.check_node_ready(ip,"root","password")
if rtn != True:
	sys.exit()
#check app status
rtn = my_utils.check_app_status(ip,app_list)
if rtn != True:
	sys.exit()	

#clean testbed
my_utils.clean_app(ip)

info('ok')
