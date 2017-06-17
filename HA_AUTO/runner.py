import utils,pysphere,sys,time,random,threading,paramiko
from pysphere import VIServer
import re, os, sys, time, threading
from utils import Multi,Utils,Tools
from operator import itemgetter
import log

obj_utils = Utils()
obj_log = log.get_logger()

class Runner:
    def __init__(self):
        pass

    def _del_(self):
        return 0;

    def _check_ssh(self, ssh,ip,username,passwd):
        if ssh.get_transport().is_active() == True:
            return ssh
        try:
            ssh.connect(ip,22,username,passwd,timeout=5)  
            return ssh
        except:
            return False

    def _ssh(self, node, command, expect=''):

        op = ''
        if node['ssh'] is False:
            fail()
        stdin, stdout, stderr = node['ssh'].exec_command(command)
        op = stdout.read() + stderr.read()

        if expect != '':
            searchResult = re.search(expect, op)
            if not searchResult:
                return searchResult
            else:
                return searchResult.group()
        return op

    def _exec(self, lines):
        op = ''
        for line in lines:
            command = line.split(':')
            obj_log.debug('All parameters %s' % command)
            if command[0] == '' or command[0] == 'cli':
                nodes = self._node_operate(command[1:])
                for node in nodes:
                    op = self._ssh(node, command[2], command[3])
                    if not op:
                        return False
                if command[-1] != '' and len(command) >= 4:
                    if not re.match(command[-1], op):
                        return False
                    else:
                        return True
                continue
            obj_log.debug('Function %s' % command[0])
            obj_log.debug('Pamameters %s' % command[1:])
            exec 'op = self.'+'_'+command[0]+'(command[1:])'
            # if command[-1] != '' and len(command) >= 4:
            #     if not re.match(command[-1], op):
            #         return False
            #     else:
            #         return True

        return op

    def _get_ssh(self, host):
        try:
            host['ssh'] = paramiko.SSHClient()
            host['ssh'].load_system_host_keys()
            host['ssh'].set_missing_host_key_policy(paramiko.AutoAddPolicy())
            host['ssh'].connect(host['eth0'], 22, 'poweruser', 'poweruser', timeout=5)
        except:
            obj_log.debug("cant connect " + host['containername'] + ': ' + host['eth0'])
            return 0
        return host['ssh']


    def _reconstructure_usx(self):
        usx_cluster = self.tools.get_all_node_info()
        
        service_vm_info = usx_cluster['service_vm_info']
        volume_info = usx_cluster['volume_info']
        ha_info = usx_cluster['ha_info']
        vc_info = usx_cluster['vc_info']

#         self.amc = amc
        self.cluster = {'svs':[], 'vols':{}, 'ha':[], 'vc':[]}

        if usx_cluster['service_vm_info']:
            for key in usx_cluster['service_vm_info']:
                self.cluster['svs'].append(usx_cluster["service_vm_info"][key])
                self.cluster['svs'][-1]['ssh'] = self._get_ssh(self.cluster['svs'][-1])

        for key in usx_cluster['volume_info']:
            node_type = usx_cluster['volume_info'][key]['type']
            if not self.cluster['vols'].has_key(node_type):
                self.cluster['vols'][node_type] = []

            self.cluster['vols'][node_type].append(usx_cluster["volume_info"][key])
            # self.cluster['vols'][node_type][-1]['ssh'] = self._get_ssh(self.cluster['vols'][node_type][-1])
            # sort volume by resource name
            self.cluster['vols'][node_type] = sorted(self.cluster['vols'][node_type], key=itemgetter('name'))


        if usx_cluster["ha_info"]:
            for key in usx_cluster['ha_info']:
                self.cluster['ha'].append(usx_cluster['ha_info'][key])
                # self.cluster['ha'][-1]['ssh'] = self._get_ssh(self.cluster['ha'][-1])
                # sort ha by container name
                self.cluster['ha'] = sorted(self.cluster['ha'], key=itemgetter('containername'))

        for key in usx_cluster['vc_info']:
            self.cluster['vc'].append(usx_cluster['vc_info'][key])

        # self.cluster['vc'][-1]['cli'] = pysphere.VIServer()
        # self.cluster['vc'][-1]['cli'].connect(self.cluster['vc'][-1]['ip'], 'root', 'vmware')
        
        i = 0
        server_vc_dict = {}
        for key in usx_cluster['vc_info']:
            self.cluster['vc'].append(usx_cluster['vc_info'][key])
            server_tmp = pysphere.VIServer()
            server_tmp.connect(usx_cluster['vc_info'][key]['ip'], self.vc_username, self.vc_password)
            server_vc_dict[usx_cluster['vc_info'][key]['ip']] = server_tmp

        self.all_server_dict = {}
        for vc_tmp,server_tmp in server_vc_dict.items():
            self.all_server_dict[server_tmp] = []
            if service_vm_info:
                for sv in service_vm_info.keys():
                    if vc_tmp == service_vm_info[sv]['vcip']:
                        self.all_server_dict[server_tmp].append(service_vm_info[sv]['containername'])

            for vol in volume_info.keys():
                if vc_tmp == volume_info[vol]['vcip']:
                    self.all_server_dict[server_tmp].append(volume_info[vol]['containername'])

            if ha_info != None:
                for ha in ha_info:
                    if vc_tmp == ha_info[ha]['vcip']:
                        self.all_server_dict[server_tmp].append(ha_info[ha]['containername'])


                        

    def _cmds_structure(self, cmds):
        cmd_array = []
        for line in cmds:
            cmd_array.append(re.split(':', line))
        return cmd_array

    def _node_operate(self, obj):
        obj_log.debug(obj[0])
        self._reconstructure_usx()
        
        volume = 'vols'
        hybrid = 'HYBRID'
        memory = 'MEMORY'
        flash = 'ALL_FLASH'
        infra = 'INFRA'
        hyperconverge = 'HYPERCONVERGE'
        simplehybrid = 'SIMPLE_HYBRID'
        simplememory = 'SIMPLE_MEMORY'
        simpleflash = 'SIMPLE_FLASH'
        if obj[0] == "'svs'" or obj[0] == "'ha'" or obj[0] == "'vols'":
            node_array = obj[0] + ']'
        elif obj[0] == "'all'":
            return usx_cluster
        else:
            node_array = re.sub('\[', '][', obj[0], 1)
            
        obj_log.debug('===== %s' % node_array)
        nodes = ''
        # use ',' to split the list
        node_array = node_array.replace(',', ':') if ',' in node_array else node_array
        if node_array:
            node_array = 'self.cluster[' + node_array
            try:
                nodes = eval(node_array)
            except Exception as e:
                return None
        if nodes != None and isinstance(nodes, list):
            return nodes
        elif nodes != None and not isinstance(nodes, list):
            nodesList = [nodes]
            return nodesList
        return None


