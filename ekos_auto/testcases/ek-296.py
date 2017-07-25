import sys,json,time,random
sys.path.insert(0, '/root/ekos_auto/')
import ekosUtils
from log import *
my_utils = ekosUtils.Utils()


ip = sys.argv[1]
appname_tmp = "hello-ha-"
app_num = 10
node_list = ["EKOS-offline-darcy-62","EKOS-offline-darcy-63","EKOS-offline-darcy-64"]

#create 10 app
cookies = my_utils._get_cookie(ip)
url = "http://" + ip + ":30000/service/stack/api/app"
obj_json = {"name":"hello-test2","namespace":"default","stateful":"none","replicas":1,"cpu":500,"memory":256,"diskSize":20000,"containers":[{"name":"hello-test","image":"registry.ekos.local/library/hello:latest","command":"sh","envs":[],"logDir":"","healthCheck":None,"cpuPercent":100,"memPercent":100}],"service":{"ports":[{"protocol":"TCP","containerPort":666,"servicePort":666}]},"volumes":[],"desc":"111"}
for i in range(app_num):
	obj_json['name'] = appname_tmp + str(i)
	app_rtn = my_utils.call_rest_api(url,"POST",cookies=cookies,json=json.dumps(obj_json))
	if "success" in json.loads(app_rtn)['status']:
		info('create application: %s successfully' %obj_json['name'])
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


#check node ready
rtn = my_utils.check_node_ready(ip,"root","password")
if rtn != True:
	sys.exit()

# power off random node

poweroff_nodes = random.sample(node_list,1)
for poweroff_node in poweroff_nodes:
	my_utils.poweroff_vm(poweroff_node)
info("sleep 420 seconds")
my_utils.bar_sleep(420)

#check pods status
rtn = my_utils.check_app_status(ip,app_list)
if rtn != True:
	sys.exit()
	
#power on the node
for poweroff_node in poweroff_nodes:
	my_utils.poweron_vm(poweroff_node)

#clean testbed
my_utils.clean_app(ip)

info('ok')






