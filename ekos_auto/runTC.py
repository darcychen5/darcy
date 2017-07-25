import os,sys,time,ekosUtils,re
from log import *


master_ip = "192.168.20.61"
my_utils = ekosUtils.Utils()
refresh_testbed = False
if len(sys.argv) == 3:
	workdir = sys.argv[1]
	cycle_number = int(sys.argv[2])
elif len(sys.argv) == 4:
	workdir = sys.argv[1]
	cycle_number = int(sys.argv[2])
	refresh_testbed = sys.argv[3]
else:
	error('wrong args')
	sys.exit()

#refresh testbed
test_build = my_utils.get_latest_build()
if refresh_testbed:
	info('refresh testbed!')
	cmd = "python /root/ekos_auto/install/install_ekos.py darcy1"
	rtn = my_utils.runcmd(cmd)
	info(rtn)
	#active plugin
	rtn = my_utils.active_plugin(master_ip)
	if rtn != True:
		error('active plugin failed')
		sys.exit()

log_dir = "/var/log/"

test_result = {}

for tc in os.listdir(workdir):

	flag = 0
	path = os.path.join(workdir, tc)
	tc_name = tc.split('.')[-2]
	test_result[tc_name] = {}
	logname = log_dir + tc_name + ".log"
	cmd = "python " + path + " " + master_ip + " >" + logname
	start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
	for i in range(1, cycle_number + 1):
		my_utils.runcmd(cmd)
		f = open(logname,'r')
		try:
			f.seek(-3,2)
			line = f.readline()
		except:
			error('file %s is empty' % logname)
			sys.exit()
		info(line)
		if re.search('ok',line):
			info('testcase: %s execute %d successfully' % (tc_name,i))
		else:
			info('testcase %s execute %d failed!' % (tc_name,i))
			flag = 1
			break

	end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
	test_result[tc_name]['tc_id'] = tc_name
	test_result[tc_name]['start_time'] = start_time
	test_result[tc_name]['end_time'] = end_time
	if flag == 0:
		test_result[tc_name]['result'] = "success"
	else:
		test_result[tc_name]['result'] = "failed"


info(test_result)
all_content = "<h3>build: %s</h3>\n<tr><td>TC ID</td><td>Start Time</td><td>End Time</td><td>Result</td></tr>" % test_build
for result in test_result.keys():
	content = "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" % (test_result[result]['tc_id'],test_result[result]['start_time'],test_result[result]['end_time'],test_result[result]['result'])
	all_content = all_content + '\n' + content
html_content = "<table border=\"1\" cellpadding=\"2\" width=\"800\">" + all_content + "</table>"
cmd = "echo \"" + html_content + "\"" "| mail -s \"$(echo -e \"stress result\\nContent-Type: text/html;charset=gb2312\")\" chenlong@ghostcloud.cn"
my_utils.runcmd(cmd)

