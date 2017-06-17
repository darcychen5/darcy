# -------------------------------------------------------------------------
# Name:        runTC.py
# Purpose:     Run HA testcases in a folder
#
# Author:      Raidy
#
# Created:     15/09/2015
# Copyright:   (c) Administrator 2015
# Licence:     <your licence>
# -------------------------------------------------------------------------

import os
import re
import argparse
import sys
import time
import commands
import subprocess
from report import Template, JIRA


obj_JIRA = JIRA()

parser = argparse.ArgumentParser(description='Run Testcases Tools')
parser.add_argument('-d', '--directory', action='store',
                    dest='dir', help='directory of testcases', required=True)
parser.add_argument('-i', '--number', action='store',
                    dest='num', help='number of testcases')
parser.add_argument('-s', '--static', action='store_true',
                    dest='staticbuild', default=False,
                    help='Using static build please add -s')
args = parser.parse_args()

rootDir = args.dir

if args.staticbuild is False:
############################## USE LATEST BUILD ###############################
# define ovf path
    # BUILDPATH = '/mnt/build/FLEXCLOUD/3.5.0/USX/'
    BUILDPATH = '/mnt/build/FLEXCLOUD/3.5.1/USX/'
    # find the latest build ovf
    cmd = 'find %s -name "*.ovf" | xargs ls -t | head -1' % BUILDPATH
    rtn = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    OVFPATH = rtn.stdout.read().strip()
    print OVFPATH
    cmd = 'sed -i ' + "'s:^usx_build_path.*:usx_build_path = %s:'" % OVFPATH + ' ' + args.dir + '/*.ini'
    # print cmd
    os.system(cmd)
    version = OVFPATH.split('/')[-2].replace('-Full', '')
else:
############################# USE GIVED BUILD #################################
# change the ovf version
# cmd = 'sed -i ' + "'/^usx_build_path*/s/.*/usx_build_path = \/mnt\/build\/FLEXCLOUD\/3.2.0\/USX\/USX-3.2.0.438-Full\/USX-3.2.0.438-Full.ovf/' " + args.dir + '\/*.ini'
    cmd = 'sed -i ' + "'/^usx_build_path*/s/.*/usx_build_path = \/mnt\/build\/FLEXCLOUD\/3.5.1\/USX\/USX-3.5.1.2240-Full\/USX-3.5.1.2240-Full.ovf/' " + args.dir + '\/*.ini'
# cmd = 'sed -i ' + "'/^usx_build_path*/s/.*/usx_build_path = \/mnt\/build\/FLEXCLOUD\/3.5.0\/USX\/USX-3.5.0.818-Full\/USX-3.5.0.818-Full.ovf/' " + args.dir + '\/*.ini'
# cmd = 'sed -i ' + "'/^usx_build_path*/s/.*/usx_build_path = \/mnt\/build\/FLEXCLOUD\/3.1.2\/USX\/USX-3.1.2.5001-Full\/USX-3.1.2.5001-Full.ovf/' " + args.dir + '\/*.ini'
# cmd = 'sed -i ' + "'/^usx_build_path*/s/.*/usx_build_path = \/mnt\/build\/FLEXCLOUD\/3.1.2_UBS\/USX\/USX-3.1.2.5018-Full\/USX-3.1.2.5018-Full.ovf/' " + args.dir + '\/*.ini'
    os.system(cmd)
    version = cmd.split()[-2].split('/')[-2].replace('-Full', '')
###############################################################################

testcases_list = []
testcases_config_list = []
testcases_log_list = []
pass_case_list = '\n'
fail_case_list = '\n'
passed_num = 0
failed_num = 0
detail_info = '\n'
detail_table = ""
basedir = rootDir.replace("/", "").upper()
comment = {'body': "Passed in build %s on Esxi" % version.replace('USX-', '')}
jql_temp = {'jql': "'TC Template' ~ USX-%s AND parent in (USX-60949, USX-61001, USX-60878, USX-60937, USX-71279)"}

for lists in os.listdir(rootDir):
    path = os.path.join(rootDir, lists)
    if not os.path.isdir(path):
        p = re.search("test_(.*)\.py", path)
        if p != None:
            testcases_list.append(path)
        q = re.search("usx-(.*)\.ini", path)
        if q != None:
            testcases_config_list.append(path.split("/")[-1])


print testcases_list
testcases_list.sort()
testcases_config_list.sort()
# get test start time
start_test_time = time.time()
start_readable_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

# get the date e.g.(20151013)
obj_time = time.localtime()
# date = str(obj_time.tm_year) + str(obj_time.tm_mon) + str(obj_time.tm_mday)
date = time.strftime('%Y%m%d', obj_time)
print date
# create log path
log_path = "/root/log/" + str(date) + "/"
if not os.path.isdir(log_path):
    os.mkdir(log_path)


for tc in testcases_list:
    for testcases_config in testcases_config_list:
        start_time = time.time()
        if '_' in testcases_config.split("/")[-1]:
            p = re.search("usx-(.*?)_(.*)\.ini", testcases_config)
            if p.group(1).isdigit():
                p = re.search("usx-(.*)\.ini", testcases_config)
        else:
            p = re.search("usx-(.*)\.ini", testcases_config)
        if p.group(1) in tc.split("/")[-1]:
            if len(p.groups()) > 1:
                caseID = p.group(2)
                logname = log_path + caseID + ".log"
                print("Run test case: %s start ..." % caseID)
                rtn = os.system("unbuffer python " + tc + " " + testcases_config +
                                " > " + logname)
                print("Run test case: %s done." % caseID)
            else:
                caseID = p.group(1)
                logname = log_path + caseID + ".log"
                print("Run test case: %s start ..." % caseID)
                rtn = os.system("unbuffer python " + tc + " " + testcases_config +
                                " > " + logname)
                print("Run test case: %s done." % caseID)
            end_time = time.time()
            take_time = time.strftime(
                '%H:%M:%S', time.gmtime(int(end_time - start_time)))
        #   check log
            print logname
            testcases_log_list.append(logname)
            cmd = 'tail -1 ' + logname
            tmp = commands.getoutput(cmd)
            temp_string = caseID + "(take time: %s)" % take_time + "\n"
            caseID_list = caseID.split("_")

            if tmp == 'OK':
                print("Passed:" + temp_string)
                passed_num += len(caseID_list)
                pass_case_list = pass_case_list + temp_string
                detail_info = detail_info + "Passed: " + temp_string

                Summary = ""
                if len(caseID_list) > 1:    # get the multi test cases summary
                    for case in caseID_list:
                        Summary = Summary + case + '--' + obj_JIRA.getsummary(case) + "<br/>"
                        jql = {}            # get JIRA ID and add comment
                        jql['jql'] = jql_temp['jql'] % case
                        testcase_jiraID = obj_JIRA.getjiraIDbyjql(jql)
                        if testcase_jiraID:
                            obj_JIRA.addcomment(testcase_jiraID, comment)
                else:
                    Summary = caseID + '--' + obj_JIRA.getsummary(caseID)
                    jql = {}
                    jql['jql'] = jql_temp['jql'] % caseID
                    testcase_jiraID = obj_JIRA.getjiraIDbyjql(jql)
                    if testcase_jiraID:
                        obj_JIRA.addcomment(testcase_jiraID, comment)
                print('======', Summary)
                detail_table = detail_table + Template.add_table(caseID, take_time, Summary=Summary, Pass=len(caseID_list))
            else:
                print("Faild:" + temp_string)
                failed_num += 1
                fail_case_list = fail_case_list + temp_string
                detail_info = detail_info + "Faild: " + temp_string

                Summary = ""
                if len(caseID_list) > 1:
                    for case in caseID_list:
                        Summary = Summary + case + '--' + obj_JIRA.getsummary(case) + "<br/>"
                else:
                    Summary = caseID + '--' + obj_JIRA.getsummary(caseID)

                print('======', Summary)
                detail_table = detail_table + Template.add_table(caseID, take_time, Summary=Summary, Fail=1)
#    os.system("cli vc12011 del tis33D")
#    time.sleep(300)
print("Passed:", passed_num)
print("Passed testcase list:", pass_case_list)
print("Failed:", failed_num)
print("Faild testcase list:", fail_case_list)
info = """
USX version#: %s
Passed#: %s
Faild#:  %s
Passed testcase list#: %s
Faild testcase list#: %s
*************************************************************************
""" % (version, passed_num, failed_num, pass_case_list, fail_case_list)

# end test time
end_test_time = time.time()
take_test_time = time.strftime(
    '%H:%M:%S', time.gmtime(int(end_test_time - start_test_time)))

detail_table = detail_table + Template.add_table('Total', take_test_time, Pass=passed_num, Fail=failed_num)
HEAD_TMPL = Template.HEAD_TMPL % dict(
                                    feature=basedir,
                                    starttime=start_readable_time,
                                    duration=take_test_time,
                                    build=version,
                                    total=passed_num + failed_num,
                                    passed=passed_num,
                                    failed=failed_num,
                                    table=detail_table)
detail_info = Template.REPORT_TMPL + HEAD_TMPL

# os.system("echo HA AUTO TEST" + " > " +log_path + ".log")
log_file = log_path + "result.html"
with open(log_file, 'w') as log:
    log.write(detail_info)
    log.flush()
    log.close()

attatch_file = ' '.join(testcases_log_list)

subject = '\"HA Automation -- %s results on build %s\"' % (basedir, version)
address = 'shlei@sigma-rt.com, cluo@sigma-rt.com, ' + \
        'zheyu@sigma-rt.com, bxie@sigma-rt.com, fzhu@sigma-rt.com, ' + \
        'qying@sigma-rt.com, darcy.chen@atlantiscomputing.com, ' + \
        'yuwu@sigma-rt.com, kyao@sigma-rt.com'
address_bak = 'shlei@sigma-rt.com'

if passed_num > failed_num:
    send_mail_cmd = 'mutt -e "set content_type=text/html" -s %s %s -a %s < %s' % (subject, address, attatch_file, log_file)
else:
    send_mail_cmd = 'mutt -e "set content_type=text/html" -s %s %s -a %s < %s' % (subject, address_bak, attatch_file, log_file)
time.sleep(30)
os.system(send_mail_cmd)
time.sleep(5)
print "send mail to %s done." % address
