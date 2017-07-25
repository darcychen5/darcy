import json,time,sys,ConfigParser,os,threading
sys.path.insert(0, '/root/ekos_auto')
from log import *
import ekosUtils
flag = sys.argv[1]
configfile = 'config.ini'
member_list = ["darcy","fengqianjun","helimeng","lichengsong","wangmeng","xiebin","darcy1","jiangjun","FC","demo"]

my_utils = ekosUtils.Utils()
package = my_utils.get_latest_build()
os.chdir("/root/ekos_auto/install")

class Multi_deploy_ekos(threading.Thread):
	def __init__(self,member,package,inventory_list,node_name_list,vip,username,password):
		threading.Thread.__init__(self)
		self.package = package
		self.inventory_list = inventory_list
		self.node_name_list = node_name_list
		self.vip = vip
		self.username = username
		self.password = password
		self.member = member
	def run(self):
		self.rtn = my_utils.deploy_ekos(self.package,self.inventory_list,self.node_name_list,vip=self.vip,username=self.username,password=self.password)
	def get_return(self):
		return self.rtn
	def get_member(self):
		return self.member

def _get_config(section, key, configfile):
	config = ConfigParser.ConfigParser()
	path = (os.path.realpath(configfile))
	config.read(path)
	rtn = config.get(section, key)
	return rtn


info('flag: %s' %flag)
if flag == "all":
	all_result = {}
	thread_list = []
	for member in member_list:
		info('Deploy testbed for %s' % member)
		inventory_list = eval(_get_config(member,"inventory_list",configfile))
		node_name_list = eval(_get_config(member,"node_name_list",configfile))
		username = _get_config(member,"username",configfile)
		password = _get_config(member,"password",configfile)
		vip = _get_config(member,"vip",configfile)
		refresh = _get_config(member,"refresh",configfile)
		if refresh == "true":
			t = Multi_deploy_ekos(member,package,inventory_list,node_name_list,vip,username,password)
			thread_list.append(t)
		else:
			info('%s do not want to refresh testbed!' % member)
	for thread in thread_list:
		thread.start()
	for thread in thread_list:
		thread.join()
	for thread in thread_list:
		rtn = thread.get_return()
		member = thread.get_member()
		if rtn == True:
			info('Deploy testbed for %s successfully!' % member)
			all_result[member] = "success"
		else:
			error('Deploy testbed for %s failed!' % member)
			all_result[member] = "failed"
	print all_result
	#send mail
	all_content = "<h3>build: %s</h3>\n" % package
	for name,result in all_result.iteritems():
		content = "<tr><td>%s</td><td>%s</td></tr>\n" % (name,result)
		all_content = all_content + '\n' + content
	html_content = "<table border=\"1\" cellpadding=\"10\" width=\"400\">" + all_content + "</table>"
	cmd = "echo \"" + html_content + "\"" "| mail -s \"$(echo -e \"Build Refresh result\\nContent-Type: text/html;charset=gb2312\")\" chenlong@ghostcloud.cn fengqianjun@ghostcloud.cn helimeng@ghostcloud.cn lichengsong@ghostcloud.cn xiebin@ghostcloud.cn, zhufuchun@ghostcloud.cn wangmeng@ghostcloud.cn weijunxu@ghostcloud.cn lixu@ghostcloud.cn"
	my_utils.runcmd(cmd)


elif flag in member_list:
	info('Deploy testbed for %s' % flag)
	inventory_list = eval(_get_config(flag,"inventory_list",configfile))
	node_name_list = eval(_get_config(flag,"node_name_list",configfile))
	username = _get_config(flag,"username",configfile)
	password = _get_config(flag,"password",configfile)
	vip = _get_config(flag,"vip",configfile)
	rtn = my_utils.deploy_ekos(package,inventory_list,node_name_list,vip=vip,username=username,password=password)
	if rtn == True:
		info('Deploy testbed for %s successfully!' % flag)
	else:
		error('Deploy testbed for %s failed!' % flag)
else:
	error('wrong flag!')
	sys.exit()
