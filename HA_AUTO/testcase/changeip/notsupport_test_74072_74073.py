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
        #login the member amc
        # amc_member_ip_list = self.tools.get_amc_member_ip_list()
        # self.tests.tools = Tools(amc_member_ip_list[0])


    def tearDown(self):
        clean_testbed_op = ["clean_testbed:"]
        self.tests._exec(clean_testbed_op)
        print("done!!!!!!!!!!!!")

    def changeip(self):
        self.assertEqual(self.test_changeip(), True)

    def change_ip_to_dhcp(self):
        # Clear all the tasks message
        self.tests.tools.delete_all_jobstatus()
        amc_name = self.tests._get_amc_name()
        # define new usx ip
        rtn = self.tests.tools.change_usx_ip(dhcp=True)
        self.utils.progressbar_k(60)
        server = self.tests._conn_vcenter(self.tests.vc, self.tests.vc_username, self.tests.vc_password)
        tms = 10
        while tms:
            new_ip = self.utils.get_ip_by_vmname(server, amc_name)
            print('get dchp ip ======> %s' % new_ip)
            if new_ip != self.amc_ip:
                break
            else:
                print('the amc ip has not changed')
                tms = tms - 1
                self.utils.progressbar_k(10)
        self.tests._disconnect(server)
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
            # check interfaces after reset amc
            if self.tests._reset_amc(new_ip):
                cmd = "cat /etc/network/interfaces | awk '/^iface/{print $4}' | tail -1"
                result = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd)['stdout'].strip()
                print('get message from interfaces is %s' % result)
                if 'dhcp' in result:
                    return True

    def change_ip_to_static(self, new_ip):
        # Clear all the tasks message
        self.tests.tools.delete_all_jobstatus()
        # define new usx ip
        new_ip = new_ip
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
            # check interfaces after reset amc
            if self.tests._reset_amc(new_ip):
                cmd = "cat /etc/network/interfaces | awk '/address/{print $2}'"
                result = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd)['stdout'].strip()
                print('get message from interfaces is %s' % result)
                if new_ip == result:
                    return True

    def test_changeip(self):
        rtn1 = self.change_ip_to_dhcp()
        if rtn1 is not True:
            print('change amc ip to dhcp failed')
            return False
        rtn2 = self.change_ip_to_static(self.all_config['amc_ip'])
        if rtn2 is not True:
            print('Change AMC IP to static failed')
            return False

        return True




    

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

