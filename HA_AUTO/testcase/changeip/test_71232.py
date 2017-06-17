# coding=utf-8
import unittest
import sys
import ConfigParser
import os
import re
import time
import pysphere
from utils import Utils, Tools, Multi
from ha import Ha

class Changeip(unittest.TestCase):
    def setUp(self):
        self.configfile = sys.argv[1]
        self.utils = Utils()
        self.all_config = self.utils.init_allconfig(self.configfile)
        self.utils.deploy_usx(self.all_config)
        self.amc_ip = self.all_config['amc_ip']
        self.tests = Ha(self.configfile)
        # self.tools = Tools(self.amc_ip)
        #==================================
        # self.tools.set_snapshot('false')
        #==================================
        # login the slave amc
        # amc_member_ip_list = self.tests.tools.get_amc_member_ip_list()
        # self.tests.tools = Tools(amc_member_ip_list[0])




    def tearDown(self):
        clean_testbed_op = ["clean_testbed:"]
        self.tests._exec(clean_testbed_op)
        print("done!!!!!!!!!!!!")

    def changeip(self):
        self.assertEqual(self.test_changeip(), True)

    def test_changeip(self):
        # change master amc ip
        new_master_ip = '10.16.163.250'
        rtn = self.tests.tools.change_usx_ip(new_ip=new_master_ip, netmask='255.255.0.0', gateway='10.16.0.1')
        if self.utils.is_poweron(new_master_ip):
            self.tests.tools = Tools(new_master_ip)
            tms = 20
            while tms:
                jobid = self.tests.tools.get_jobid_by_string("Successfully changed IP address.")
                if jobid:
                    print("get jobid ===> %s" % jobid)
                    break
                else:
                    tms -= 1
                    self.utils.progressbar_k(10)
                    if tms == 0:
                        print("Change ip time out")
                        return False
            self.tests.amc_ip = new_master_ip

            # login slave amc to check /opt/amc/server/config/master.json
            amc_member_ip_list = self.tests.tools.get_amc_member_ip_list()
            cmd2 = "cat /opt/amc/server/config/master.json"
            result2 = self.utils.ssh_cmd(amc_member_ip_list[0], 'admin', 'poweruser', cmd2)['stdout'].strip()
            if new_master_ip not in result2:
                print('master ip not in slave master.json')
                return False
            self.utils.progressbar_k(60)
            # check interfaces after reset amc
            if self.tests._reset_master_amc():
                cmd1 = "cat /etc/network/interfaces | awk '/address/{print $2}'"
                result1 = self.utils.ssh_cmd(new_master_ip, 'admin', 'poweruser', cmd1)['stdout'].strip()
                print('get message from interfaces is %s' % result1)
                if new_master_ip != result1:
                    return False
# ======================================================================================================================
        # login the slave amc
        self.tests.tools = Tools(amc_member_ip_list[0])
        # Clear all the tasks message&change slave amc ip
        self.tests.tools.delete_all_jobstatus()
        # define new usx ip
        new_ip = '10.16.163.251'
        rtn = self.tests.tools.change_usx_ip(new_ip=new_ip, netmask='255.255.0.0', gateway='10.16.0.1')
        if self.utils.is_poweron(new_ip):
            self.tests.tools = Tools(new_ip)
            tms = 20
            while tms:
                jobid = self.tests.tools.get_jobid_by_string("Successfully changed IP address.")
                if jobid:
                    print("get jobid ===> %s" % jobid)
                    break
                else:
                    tms -= 1
                    self.utils.progressbar_k(10)
                    if tms == 0:
                        print("Change ip time out")
                        return False
            self.utils.progressbar_k(60)
            self.tests.amc_ip = new_ip

            # check interfaces and master.json after reset slave amc
            if self.tests._reset_slave_amc():
                cmd1 = "cat /etc/network/interfaces | awk '/address/{print $2}'"
                cmd2 = "cat /opt/amc/server/config/master.json"
                result1 = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd1)['stdout'].strip()
                result2 = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd2)['stdout'].strip()

                print('get message from interfaces is %s' % result1)
                print('get message from master.json is %s' % result2)

                if new_ip == result1 and new_master_ip in result2:
                    return True

        return False




    

def suite():
    suite = unittest.TestSuite()
    suite.addTest(Changeip("changeip"))

    return suite

if __name__ =='__main__':
    unitrunner = unittest.TextTestRunner()
    test_suite = suite()
    rtn = unitrunner.run(test_suite)
    if len(rtn.errors) != 0 or len(rtn.failures) != 0:
        sys.exit(1)

