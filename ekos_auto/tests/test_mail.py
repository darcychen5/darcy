import ekosUtils,json,time,sys,yaml
from log import *
my_utils = ekosUtils.Utils()
all_result = {'darcy':'success','darcy1':'failed'}
all_content = ""
for name,result in all_result.iteritems():
	content = "<tr><td>%s</td><td>%s</td></tr>\n" % (name,result)
	all_content = all_content + '\n' + content
html_content = "<table border=\"1\" cellpadding=\"10\" width=\"400\" >" + all_content + "</table>"
cmd = "echo \"" + html_content + "\"" "| mail -s \"$(echo -e \"Build Refresh result\\nContent-Type: text/html;charset=gb2312\")\" chenlong@ghostcloud.cn"
my_utils.runcmd(cmd)