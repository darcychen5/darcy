#-------------------------------------------------------------------------------
# Name:        Mail
# Purpose:     This modul will send mail to anyone
#
# Author:      k
#
# Created:     24/04/2015
# Copyright:   (c) sigma 2015
# Licence:     1.1
#-------------------------------------------------------------------------------
#-*- coding:utf-8 -*-
import subprocess
import argparse
import re
import os
import datetime
import sys
import time
import json
from log import *
from xml.etree import ElementTree
reload(sys)
sys.setdefaultencoding("utf-8")
self_path = os.path.split(os.path.realpath(__file__))[0]
LOG_FILE = '%s/mail_run.log' % (self_path)


def main(args):
    mailTo = 'shlei@sigma-rt.com cluo@sigma-rt.com zheyu@sigma-rt.com bxie@sigma-rt.com fzhu@sigma-rt.com qying@sigma-rt.com darcy.chen@atlantiscomputing.com yuwu@sigma-rt.com kyao@sigma-rt.com hgan@sigma-rt.com'
    issendmail = True
    #get job description
    jobXmlFile = "/root/tis33/job.xml"
    jobId = None
    desArray = []
    cmd = "rd-jobs -n "+args.jobName+" --file "+jobXmlFile+" -p "+args.projectName
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    time.sleep(3)
    root = ElementTree.parse(jobXmlFile)
    for cmd in root.getiterator("command"):
        #desArray.append(cmd.getchildren()[0].text)
        desArray.append(cmd.find("description").text)
    #jobId = root.getiterator("id")[0].text

    #set environment filei
    
    with open('/root/tis33/config.json') as json_file:
        data = json.loads(json_file.read())
        build = data[args.jobName]
        print build

    #defined variable
    cmd = "ifconfig eth0 | grep 'inet\ addr' | sed 's/:/ /g' | awk '{print $3}'"
    rtn = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    rundeck_serverip = rtn.stdout.read().strip()
    logHref = "http://"+rundeck_serverip+":4440/project/"+args.projectName+"/execution/show/" + args.executionId
    totalNum = 0
    passNum = 0
    not_run = 0

    #get job execute result
    stepArray = []
    timeArray = [] #time array
    with open(args.jsonlog) as json_file:
        logJson = json.loads(json_file.read())

    print logJson
    for s in logJson["steps"]:
        totalNum = totalNum + 1
        stepArray.append(s["executionState"])
        if s["executionState"] == "NOT_STARTED":
            timeArray.append('None')
        else:
            timeArray.append(str(datetime.datetime.strptime(s["endTime"],'%Y-%m-%dT%H:%M:%SZ')-datetime.datetime.strptime(s["startTime"],'%Y-%m-%dT%H:%M:%SZ')))
        if s["executionState"] == "SUCCEEDED":
            passNum = passNum + 1
        if s["executionState"] == "NOT_STARTED":
            not_run = not_run + 1
            issendmail = False

    executionState = logJson["executionState"]
    startTime = logJson["startTime"]
    endTime = logJson["endTime"]
    print totalNum
    print passNum
    failedNum = totalNum - passNum - not_run
    print "failedNum2 %d"%(int(failedNum))
    if passNum <= failedNum:
        issendmail = False

    #create html mail body
    mailBody = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/><style>.title{font-size:18px;font-weight:800;margin-left:-40px;margin-top:10px;}</style></head><body style="font-family:Calibri;padding-left:60px;font-size:12px;">'
    #job information
    
    mailBody = mailBody + '<div class="title">Job Information:</div>'
    mailBody = mailBody+'<table style= "width:100%;font-family:Calibri"> <tr><td style="width:150px;">User:</td><td>guest</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Password:</td><td>1234</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Rundeck log link:</td><td>'+ logHref+'</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Jira ID:</td><td>AUT-52</td></tr></table>'
    
    #test bed
    mailBody = mailBody+ '<div class="title">Testbed Information</div> '
    mailBody = mailBody+ '<table style= "width:100%;font-family:Calibri">'
    mailBody = mailBody+ '<tr><td style="width:100px;">Build:</td><td>' + build + '</td></tr></table>'
    #execution

    mailBody = mailBody+ '<div class="title">Execution:</div> '
    mailBody = mailBody+'<table style= "width:100%;font-family:Calibri">'
    mailBody = mailBody+ '<tr><td style="width:100px;">During:</td><td>'+str(datetime.datetime.strptime(endTime,'%Y-%m-%dT%H:%M:%SZ')-datetime.datetime.strptime(startTime,'%Y-%m-%dT%H:%M:%SZ')) +'</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Start time:</td><td>'+startTime +'</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">End time:</td><td>'+ endTime+'</td></tr></table>'
    #summary
    mailBody = mailBody+ '<div class="title">Summary:</div>'
    mailBody = mailBody+'<table style= "width:100%;font-family:Calibri">'
    mailBody = mailBody+ '<tr><td style="width:100px;">Total:</td><td>'+ str(totalNum-1) +'</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Passed:</td><td>'+ str(passNum-1)+'</td></tr>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Failed:</td><td>'+ str(failedNum)+'</td></tr>'
    #mailBody = mailBody+ '<tr><td style="width:100px;">Failed:</td><td>'+ str(failNum.replace('\n',""))+'</td></tr>'
    #mailBody = mailBody+ '<tr><td style="width:100px;">Not run:</td><td>'+ str(totalNum - passNum - int(failNum.replace('\n',"")))+'</td></tr></table>'
    mailBody = mailBody+ '<tr><td style="width:100px;">Not run:</td><td>'+ str(totalNum - passNum - int(failedNum))+'</td></tr></table>'
    #details
    mailBody = mailBody+ '<div class="title">Details:</div>'
    mailBody = mailBody+'<table style= "width:100%;font-family:Calibri"> <tr><td style="width:100px;">Result </td><td style="width:60px;">Step#</td><td style="width:70px;">Duration</td><td>Steps</td></tr>'
    print(len(stepArray))
    print(len(timeArray))
    print(len(desArray))
   
    i = 0
    for t in stepArray:
        if i == 0:
            i = i + 1
            continue

        if stepArray[i] == "NOT_STARTED":
            stepArray[i] = '<font style="color:blue;">NA</font>'

        if stepArray[i] == "FAILED":
            stepArray[i] = '<font style="color:red;">' + stepArray[i] + '</font>'
        mailBody = mailBody+"<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (stepArray[i],i,timeArray[i],desArray[i])
        i=i+1
    mailBody = mailBody+'</table>'
    mailBody = mailBody+"</div></body></html>"

    # write mail to file
    bodyFilePath = "/root/tis33/bodyFile.txt"
    bodyFile = open(bodyFilePath, 'w')
    bodyFile.write(mailBody)
    bodyFile.close()

    subject = args.projectName + " - " + args.jobName + " on " + build
    cmd = "python /rd/sendmail.py \'%s\' \'%s\' \'%s\' " % (mailTo, subject, bodyFilePath)
    if issendmail:
        rtn = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        print rtn.stdout.read()


if __name__ == '__main__':
    # do our args
    parser = argparse.ArgumentParser(prog='Mail.py', usage='%(prog)s [-c][-j] [-e]')
    parser.add_argument("-p", "--projectName", default=None, help="the project name", type=str)
    parser.add_argument("-l", "--jsonlog", default=None, help="the fullpath of the job state", type=str)
    parser.add_argument("-j", "--jobName", default=None, help="the job name", type=str)
    parser.add_argument("-e", "--executionId", default=None, help="the execution ID", type=str)
    args = parser.parse_args()

    main(args)
