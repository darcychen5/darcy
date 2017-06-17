# -------------------------------------------------------------------------
# Name:        modify_version.py
# Purpose:     Modify the build version for test case config file
#
# Author:      Raidy
#
# Created:     01/11/2016
# Copyright:   (c) Administrator 2016
# Licence:     <your licence>
# -------------------------------------------------------------------------

import os
import re
import json
import time
import argparse
import subprocess
from xml.etree import ElementTree
from report import JIRA
obj_JIRA = JIRA()


JOB_OVF_PATH = '/root/tis33/config.json'
BUILDPATH = '/mnt/build/FLEXCLOUD/'
jql_temp = {'jql': "'TC Template' ~ USX-%s AND parent in (USX-60949, USX-61001, USX-60878, USX-60937, USX-71279, USX-60876, USX-60875, USX-80461, \
            USX-80255, USX-80346, USX-80382, USX-80409, USX-80422, USX-80368, USX-80317)"}


def store(data):
    with open(JOB_OVF_PATH, 'w') as json_file:
        json.dump(data, json_file, indent=4)


def load():
    with open(JOB_OVF_PATH) as json_file:
        data = json.load(json_file)
        return data


def changeStatusToProgress(jiraID, version):
    jql = {}
    jql['jql'] = jql_temp['jql'] % jiraID
    testcase_jiraID_list = obj_JIRA.getjiraIDbyjql(jql)
    if testcase_jiraID_list:
        for testcase_jiraID in testcase_jiraID_list:
            print(jiraID + "==>" +testcase_jiraID)
            # Reset Status anyway for test if it's not Open
            if obj_JIRA.setstatus(testcase_jiraID, "Reset Status"):
                print("Reset status done")
            # set inprogress when it's open
            else:
                obj_JIRA.setstatus(testcase_jiraID, "Start Test")

            # add build verison to summary
            addBuildToSummary(testcase_jiraID, version)


def addBuildToSummary(jiraID, version):
    summary = obj_JIRA.getsummary(jiraID)
    pattern = '\d+\.\d+\.\d+\.\d+'
    if not summary:
        print('Can not get summary !')
        return False

    resarch_result = re.search(pattern, summary)
    # If there is no verison in summary just add the version to it
    # or replace the old verison to the newest version
    # change version USX-3.6.0.1234 to Build-3.6.0.1234
    version = version.replace('USX-', 'Build-')

    if not resarch_result:
        summary = summary + ' - ' + version
    else:
        summary = summary.replace('-USX-', ' - USX-')
        summary = summary.replace('-Build-', ' - Build-')
        summary = summary.replace('USX-', '')
        summary = summary.replace('Build-', '')
        summary = re.sub(pattern, version, summary)
    obj_JIRA.setsummary(jiraID, summary)


def getIdFromJobName(args, version):
    p = re.findall('USX-(\d+)-', args.jobname)
    if p:
        for jiraID in p:
            changeStatusToProgress(jiraID, version)
        return True
    return False


def getIdFromStepsDescription(args, version):
    jobXmlFile = "/tmp/{0}.xml".format(args.jobname)
    jobId = None
    desArray = []
    cmd = "rd-jobs -n "+args.jobname+" --file "+jobXmlFile+" -p "+args.jobproject
    rtn_tmp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    rtn_tmp.wait()
    root = ElementTree.parse(jobXmlFile)
    for cmd in root.getiterator("command"):
        description = cmd.find("description").text
        p = re.findall('USX-(\d+)', description)
        if p:
            for jiraID in p:
                changeStatusToProgress(jiraID, version)


def main(args):
    rootDir = args.dir
    print rootDir
    print(args.version)

    if len(args.version.split('.')) < 4:
        # ############################# USE LATEST BUILD #######################
        # define ovf path
        # BUILDPATH = '/mnt/build/FLEXCLOUD/3.5.0/USX/'
        # BUILDPATH = '/mnt/build/FLEXCLOUD/3.5.1/USX/'
        # find the latest build ovf
        cmd = 'find %s -name "*Full.ovf" | xargs ls -t | head -1' % (BUILDPATH + args.version)
        rtn = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True)
        OVFPATH = rtn.stdout.read().strip()
        print OVFPATH
        if args.upgrade:
            cmd = 'sed -i ' + "'s:^migration_usx_build_path.*:migration_usx_build_path = %s:'" % OVFPATH + \
                ' ' + args.dir + '/*.ini'
        else:
            cmd = 'sed -i ' + "'s:^usx_build_path.*:usx_build_path = %s:'" % OVFPATH + \
                ' ' + args.dir + '/*.ini'
    else:
        # ############################ USE GIVED BUILD #########################
        # find the build version given
        # cmd = 'find %s -name "USX-%s-Full.ovf"' % (BUILDPATH, args.version)
        cmd = 'find %s -name "*%s*.ovf" ! -name "*.hs.ovf"' % (BUILDPATH, args.version)
        rtn = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True)
        OVFPATH = rtn.stdout.read().strip()
        if OVFPATH:
            print OVFPATH
            if args.upgrade:
                cmd = 'sed -i ' + "'s:^migration_usx_build_path.*:migration_usx_build_path = %s:'" % OVFPATH + \
                    ' ' + args.dir + '/*.ini'
            else:
                cmd = 'sed -i ' + "'s:^usx_build_path.*:usx_build_path = %s:'" % OVFPATH + \
                    ' ' + args.dir + '/*.ini'
        else:
            raise ValueError('The build is not exist in build server!')

        # cmd = 'sed -i ' + "'/^usx_build_path*/s/.*/usx_build_path = \/mnt\/build\/FLEXCLOUD\/3.5.1\/USX\/USX-3.5.1.2240-Full\/USX-3.5.1.2240-Full.ovf/' " + args.dir + '\/*.ini'
    ##########################################################################

    os.system(cmd)
    version = OVFPATH.split('/')[-2].replace('-Full', '')
    # update the ovf version in json file
    rtn_dict = load()
    rtn_dict[args.jobname] = version
    store(rtn_dict)
    # Get the jiraID from jobname first, if it's none
    # the get from the descrition
    try:
        if not getIdFromJobName(args, version):
            getIdFromStepsDescription(args, version)
    except Exception as e:
        print(str(e))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run Testcases Tools')

    parser.add_argument('-d', '--directory', action='store',
                        dest='dir', help='directory of testcases', required=True)

    parser.add_argument('-u', '--jobuuid', action='store',
                        dest='jobuuid', help='The uuid of the job')

    parser.add_argument('-j', '--jobname', action='store',
                        dest='jobname', help='The name of the job', required=True)

    parser.add_argument('-p', '--jobproject', action='store',
                        dest='jobproject', help='The project name of the job')

    parser.add_argument('-v', '--version', action='store',
                        dest='version', default=False, help='The version of the job')

    parser.add_argument('-U', '--upgrade', action='store_true',
                        dest='upgrade', default=False, help='Modify the upgrade version')

    args = parser.parse_args()
    main(args)
