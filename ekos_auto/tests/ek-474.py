import sys,json,time,random
sys.path.insert(0, '/root/ekos_auto/')
import ekosUtils
from log import *

ip = sys.argv[1]
my_utils = ekosUtils.Utils()
volume_prefix = "volume-"
app_prefix = "hello-nfs-"
volume_number = 10
app_num = 10
nfs_name = "darcy-nfs"


#add nfs 
nfs_server = "192.168.20.255"
nfs_dir = "/mnt/nfs-share"
rtn = my_utils.create_nfs_storage(ip,nfs_name,nfs_server,nfs_dir)
if rtn == False:
	error('create nfs storage failed!')
	sys.exit()
info('create nfs volume done')
my_utils.bar_sleep(10)

#check nfs
rtn = my_utils.get_nfs_status(ip,nfs_name)
info("nfs is in %s state" % rtn)
if rtn != "ok":
	sys.exit()

#create volumes
for i in range(volume_number):
	full_volume_name = volume_prefix + str(i)
	rtn = my_utils.create_nfs_volume(ip,nfs_name,full_volume_name)
	if rtn == False:
		sys.exit()
my_utils.bar_sleep(10)

#create app

url = "http://" + ip + ":30000/service/stack/api/app" 
obj_json = {"name":"hello-test","namespace":"default","stateful":"share","replicas":1,"cpu":125,"memory":128,"diskSize":20000,"containers":[{"name":"hello-test","image":"registry.ekos.local/library/hello:latest","command":"","envs":[],"logDir":"","healthCheck":None,"cpuPercent":100,"memPercent":100}],"service":{"ports":[{"protocol":"TCP","containerPort":80,"servicePort":999}]},"volumes":[{"persistentVolumeClaim":{"claimName":"volume-1","mountPath":"/mnt/volume/","readOnly":False}}],"desc":""}

volume_list = my_utils.get_nfs_volume_name(ip,nfs_name)
app_list = []

for volume in volume_list:
	obj_json['name'] = app_prefix + volume
	app_list.append(obj_json['name'])
	obj_json['volumes'][0]['persistentVolumeClaim']['claimName'] = volume
	rtn = my_utils.call_rest_api(url,"POST",json=json.dumps(obj_json))
	if "success" in json.loads(rtn)['status']:
		info('create application: %s successfully' % obj_json['name'])
	else:
		sys.exit()

my_utils.bar_sleep(60)

#check app status
rtn = my_utils.check_app_status(ip,app_list)
if rtn != True:
	sys.exit()

#let runnning 30 min
my_utils.bar_sleep(60)
#check 
rtn = my_utils.check_app_status(ip,app_list)
if rtn != True:
	sys.exit()
nfs_list = my_utils.get_nfs_list(ip)
rtn = my_utils.check_nfs_status(ip,nfs_list)
if rtn != True:
	sys.exit()

#clean testbed
rtn = my_utils.clean_app(ip)
if rtn != True:
	sys.exit()

my_utils.bar_sleep(30)

rtn = my_utils.remove_all_nfs_volume(ip,nfs_name)
if rtn != True:
	sys.exit()
my_utils.bar_sleep(30)	
rtn = my_utils.remove_nfs(ip,nfs_name)
if rtn != True:
	sys.exit()

info('ok')