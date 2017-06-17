import utils,pysphere,sys,time,random,threading,json,datetime
from pysphere import VIServer
import re, os, sys, time, threading, glob
from utils import Multi,Utils,Tools
from operator import itemgetter
from runner import Runner
import log

obj_utils = Utils()
obj_log = log.get_logger()

ATLAS_JSON = '/etc/ilio/atlas.json'
RAID1_ENABLED = 'raid1enabled'

VOLUME_TYPE_DICT = {'HYBRID': 'hybrid',
                    'ALL_FLASH': 'flash',
                    'MEMORY': 'memory',
                    'SIMPLE_HYBRID': 'simplehybrid',
                    'SIMPLE_FLASH': 'simpleflash',
                    'SIMPLE_MEMORY': 'simplememory',
                    'INFRA': 'infra',
                    'HYPERCONVERGE': 'hyperconverge'
                    }

class Ha(Runner):
    def __init__(self, configfile):
        Runner.__init__(self)
        self.configfile = configfile
        self.utils = utils.Utils()
        self.multi = utils.Multi()
        self.all_config = self.utils.init_allconfig(configfile)
        self.amc_ip = self.all_config['amc_ip']
        self.tools = utils.Tools(self.amc_ip)
        # self.vcs = eval(self.utils.get_config('main', 'vcs', configfile))
        self.vcs = self.all_config['vcs']
        self.vc = self.vcs.keys()[0]
        self.vc_username = self.vcs[self.vc]['username']
        self.vc_password = self.vcs[self.vc]['password']
        self.amc_username = self.all_config['login_config']['username']
        self.amc_password = self.all_config['login_config']['password']
        self.all_node_info = self.tools.get_all_node_info()
        self.volume_info = self.all_node_info['volume_info']
        # self.cookies = self.tools.login_amc()
        self.usx = self._reconstructure_usx()
        # get version from USX 2017-4-18 14:57:53
        usx_version = self.utils.get_usx_version(self.all_config['amc_ip'])
        self.all_config['usx_version'] = usx_version
    # @staticmethod
    def _exec2(self, line):
        op = ''
        command = line.split(':')
        obj_log.debug('------- %s' % command)
        obj_log.debug('Function %s' % command[0])
        obj_log.debug('Parameters %s' % command[1:])
        exec 'op = self.'+'_'+command[0]+'(command[1:])'
        return op

    def _multi_exec(self, lines, return_dict=None, worker=None):
        op = ''
        thread_list = []
        rtn_dict = {}
        for line in lines:
            t = self.Multi_exec(line, self.configfile)
            thread_list.append(t)

        if worker == None:
            for thread in thread_list:
                thread.start()

            for thread in thread_list:
                thread.join()
        else:
            k = 0
            thread_count = len(thread_list)
            m = thread_count/worker
            n = thread_count%worker
            count = 0
            for flag in range(m):
                count = k + worker
                for i in range(k , count):
                    thread_list[i].start()
                thread_list[i].join()
                k = count
                if flag < (m-1) :
                    count = count + worker

            for p in range(count, count + n):
                thread_list[p].start()

            for p in range(count, count + n):
                thread_list[p].join()

        for thread in thread_list:
            rtn = thread.get_return()
            if rtn != True:
                return_dict["return_value"].append(rtn)
                return False

        return True


    def _reboot(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    rtn = self.utils.reboot_vm(k, node['containername'])
        obj_utils.progressbar_k(200)
        return rtn

    def _poweron(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug(node['containername'] + 'begin poweron\n')
                op = self.utils.poweron_vm(k, node['containername'])
                obj_utils.progressbar_k(200)
                rtn = self._check_vm_health(k, node['containername'])
        return rtn

    def _multi_poweron(self, obj):
        nodes = self._node_operate(obj)

        thread_list = []
        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug("poweron %s!\n" % (node['containername']))
                thread_list.append(node['containername'])
            rtn = self.multi.poweron_vm(k, thread_list)
        return rtn

    def _poweroff(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                rtn = self.utils.poweroff_vm(k, node['containername'])
        obj_utils.progressbar_k(180)
        return rtn

    def _multi_poweroff(self, obj):
        nodes = self._node_operate(obj)

        thread_list = []
        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug("poweron %s!\n" % (node['containername']))
                thread_list.append(node['containername'])
            rtn = self.multi.poweroff_vm(k, thread_list)
            obj_utils.progressbar_k(180)

        return rtn

    def _shutdown(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug('begin shutdown ' + node['containername'])
                    rtn = self.utils.shutdown_vm(k, node['containername'])
        obj_utils.progressbar_k(60)
        return rtn

    def _createdata(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug("create file on " + node['name'])
                node_ip = node['eth0']
                cmd = 'dd if=/dev/urandom of=' + node['mountpoint'] + '/bigFile bs=1M count=100 oflag=dsync'
                rtn = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)['stdout']

        return rtn


    def _createdata_free(self, obj):

        nodes = self._node_operate(obj)
        obj_log.debug("create file on " + nodes[0]['name'])
        node_ip = nodes[0]['eth0']
        cmd = 'dd if=/dev/urandom of=' + nodes[0]['mountpoint'] + '/bigFile bs=1M count=' + obj[1]
        rtn = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)['stdout']
        return rtn

    def _deletedata(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug("delete file on " + node['name'])
                node_ip = node['eth0']
                cmd = 'rm -rf ' + node['mountpoint'] + '/bigFile'
                rtn = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)['stdout']

        return rtn

    def _get_data_size(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug("delete file on " + node['name'])
                node_ip = node['eth0']
                cmd = 'du -sh ' + node['mountpoint'] + '/bigFile'
                rtn = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)['stdout']
                rtn_size = rtn.split()[0]
                obj_log.debug(rtn_size)

        return rtn_size

    def _check_md5(self, obj):
        nodes = self._node_operate(obj)
        tms = 50
        for _ in range(tms):
            node = nodes[0]
            obj_log.debug("check md5 on %s\n"%(node['name']))
            node_ip = node['eth0']
            cmd = 'md5sum ' + node['mountpoint'] + '/bigFile'
            rtn_temp = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)
            if 'stdout' in rtn_temp:
                rtn = rtn_temp['stdout']
                obj_log.warning(rtn)
                if len(rtn.split()) > 1:
                    rtn_md5 = rtn.split()[0]
                    obj_log.debug(rtn_md5)
                    return rtn_md5
                else:
                    obj_log.error(rtn)
                    obj_utils.progressbar_k(20)
            else:
                obj_log.error(rtn_temp)
                obj_utils.progressbar_k(20)
        return 0

    def _check_snapshot_md5(self, obj):
        obj_log.debug(obj[1])
        nodes = self._node_operate(obj)

        for node in nodes:
            snapshot_list = self._get_volume_snapshot_list(node['name'])
            obj_log.debug("check md5 on %s\n"%(snapshot_list[int(obj[1])]['mountedpoint']))
            node_ip = node['eth0']
            snapshot_mounted_point = snapshot_list[int(obj[1])]['mountedpoint']
            cmd = 'md5sum ' + snapshot_mounted_point + '/bigFile'
            rtn = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)['stdout']
            rtn_md5 = rtn.split()[0]
            obj_log.debug(rtn_md5)

        return rtn_md5


    def _replace_sv(self, obj):
        nodes = self._node_operate(obj)
        hyper = self.utils.get_all_hypervisors_uuid(self.amc_ip)


        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    self.utils.poweroff_vm(k, node['containername'])
                    self.utils.delete_vm(k, node['containername'])

                    rtn = self.tools.replace_sv(hyper[node['host']])


        return rtn

    def _extend(self, obj):
        obj_log.debug('=====-======= ' + obj)
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:

                    rtn = self.tools.extend_volume(node['containername'], obj[-1])


        return rtn

    def _mount_vol(self, obj):
        nodes = self._node_operate(obj)
        op = ''
        rtn = {}

        for k in self.all_server_dict.keys():
            for node in nodes:
                node_type = node['type']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(node['mountpoint'])
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("mount<" + node_type + "> start.")
                    mount_rtn = self.tools.mount_volume(volume_resource_name)
                    if mount_rtn == True:
                        obj_log.info(volume_resource_name + ' mount successfully.')
                    else:
                        obj_log.debug(mount_rtn)
                        raise self.customError("mount failed !")
                        return False

        return True

    def _umount_vol(self, obj):
        nodes = self._node_operate(obj)
        op = ''
        rtn = {}

        for k in self.all_server_dict.keys():
            for node in nodes:
                node_type = node['type']
                mounthost = node['mounthost']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(node['mountpoint'])
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("umount<" + node_type + "> start.")
                    umount_rtn = self.tools.umount_volume(volume_resource_name, mounthost)
                    if umount_rtn == True:
                        obj_log.info(volume_resource_name + ' umount successfully.')

                    else:
                        obj_log.debug(umount_rtn)
                        raise self.customError("umount failed !")
                        return False
        return True


    def _clone_vm(self, obj):
        nodes = self._node_operate(obj)
        containername = None
        if len(obj[0].split("]")) == 3:
            containername = nodes[0]["containername"]

        for k in self.all_server_dict.keys():
            for node in nodes:
                obj_log.debug(node)
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug("clone WIN7-dd start !!! containerName:%s" % containername)
                    if obj[1] != 'poweroff':
                        clone_rtn = self.multi.clone_vm(self.amc_ip, self.vcs, clone_num=1, poweron=True, containername=containername)
                    else:
                        clone_rtn = self.multi.clone_vm(self.amc_ip, self.vcs, clone_num=1, poweron=False, containername=containername)
                    obj_log.debug('clone_rtn %s' % clone_rtn)
                    if not clone_rtn:
                        raise self.customError("Clone Failed")
                        return False
        return True


    def _delete_win7(self, obj):
        rtn_dict = self.tools.get_volume_vm()
        obj_log.debug('=========== %s' % rtn_dict)
        for volume_name in rtn_dict:
            if rtn_dict[volume_name] is not None:
                obj_log.debug(rtn_dict[volume_name][0]['vmname'])
                obj_log.debug(rtn_dict[volume_name][0]['vmmanagername'])
                obj_log.debug(rtn_dict[volume_name][0]['hypervisorname'])
                try:
                    rtn = self.tools.delete_volume_vm(rtn_dict[volume_name][0]['vmname'],
                                                        rtn_dict[volume_name][0]['vmmanagername'],
                                                        rtn_dict[volume_name][0]['hypervisorname'])
                except Exception as e:
                    obj_log.error(e)

    def _multi_shutdown_vm(self, obj):
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        nodes = self._node_operate(obj)
        op = ''
        rtn = {}
        node_list = []
        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug('begin shutdown ' + node['containername'])
                    node_list.append(node['containername'])
        rtn = self.multi.multi_shutdown_vm(server, node_list)
        obj_utils.progressbar_k(120)
        self._disconnect(server)
        return rtn

    def _reset(self, obj):
        obj_log.debug("method:  reset")
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    rtn = self.utils.reset_vm(k, node['containername'])
        obj_utils.progressbar_k(200)
        return rtn

    def _poweroff_vm_by_wildcard(self, obj):
        obj_log.debug("method: poweroff_by_wild_card")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        obj_log.debug(obj[1])
        vms_string = obj[1] + self.all_config['testbed_name']
        obj_log.debug(vms_string)
        vms_list = self.utils.get_vm_list_by_wildcard(self.vcs, vms_string)
        obj_log.debug(vms_list)
        new_vm_list = []
        for vm in vms_list:
            if self.all_config['user'] in vm:
                new_vm_list.append(vm)
        obj_log.debug(new_vm_list)
        rtn = self.multi.poweroff_vm(server, new_vm_list)
        obj_log.debug(rtn)
        obj_utils.progressbar_k(120)
        self._disconnect(server)
        return rtn

    def _poweron_vm_by_wildcard(self, obj):
        obj_log.debug("method: poweron_by_wild_card")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        obj_log.debug(obj[1])
        vms_string = obj[1] + self.all_config['testbed_name']
        vms_list = self.utils.get_vm_list_by_wildcard(self.vcs, vms_string)
        new_vm_list = []
        for vm in vms_list:
            if self.all_config['user'] in vm:
                new_vm_list.append(vm)
        obj_log.debug(new_vm_list)
        rtn = self.multi.poweron_vm(server, new_vm_list)
        obj_log.debug(rtn)
        obj_utils.progressbar_k(300)
        for vm in new_vm_list:
            self._check_vm_health(server, vm)
        #  login amc
        self.tools = utils.Tools(self.amc_ip)
        self._disconnect(server)
        return rtn

    def _multi_poweroff_all_volume(self, obj):
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        vol_list = self._get_all_need_info()
        obj_log.debug(vol_list)
        volume_list = vol_list["volume_list"]
        rtn = self.multi.poweroff_vm(server, volume_list)
        obj_utils.progressbar_k(120)
        self._disconnect(server)
        return rtn


    def _get_vms_on_volume(self, obj):
        nodes = self._node_operate(obj)
        uuid = nodes[0]["uuid"]

        return self.tools.get_vms_by_volume_uuid(uuid)


    def _check_windows(self, obj):
        return 0


    def _conn_vcenter(self, vc, username, password):
        server = pysphere.VIServer()
        server.connect(vc, username, password)
        return server

    def _disconnect(self,server):
        try:
            server.disconnect()
        except Exception as e:
            pass

    def _get_network_device_from_conf(self, host):
        temp_dict={}
        for vc_ip in self.vcs.keys():
            for datacenter, item_list in self.vcs[vc_ip]['dcs'].items():
                for items in item_list:
                    for host_ip, host_info in items['hosts'].items():
                        if host_ip == host:
                            temp_dict['managenetwork'] = host_info['network']['1g']
                            temp_dict['storagenetwork'] = host_info['network']['10g']

        return temp_dict

    def _connect_storage_network(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug('begin connect storage network ' + node['containername'])
                    host = node['host']
                    device_name = self._get_network_device_from_conf(host)['storagenetwork']
                    rtn = self.utils.change_network_device_connect_status(k, node['containername'], device_name, status=True)
                    if rtn is False:
                        raise self.customError("connect storage network failed")
        return True

    def _disconnect_storage_network(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug('begin disconnect storage network ' + node['containername'])
                    host = node['host']
                    device_name = self._get_network_device_from_conf(host)['storagenetwork']
                    rtn = self.utils.change_network_device_connect_status(k, node['containername'], device_name, status=False)
                    if rtn is False:
                        raise self.customError("disconnect storage network failed")
        return True

    def _connect_manage_network(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug('begin connect manager network ' + node['containername'])
                    host = node['host']
                    device_name = self._get_network_device_from_conf(host)['managenetwork']
                    rtn = self.utils.change_network_device_connect_status(k, node['containername'], device_name, status=True)
                    if rtn is False:
                        raise self.customError("connect managenetwork network failed")
        return True

    def _disconnect_manage_network(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    obj_log.debug('begin disconnect manager network ' + node['containername'])
                    host = node['host']
                    device_name = self._get_network_device_from_conf(host)['managenetwork']
                    rtn = self.utils.change_network_device_connect_status(k, node['containername'], device_name, status=False)
                    if rtn is False:
                        raise self.customError("disconnect managenetwork network failed")
        return True

    def disconnect_manage_network(self, server, volume_node):
        if isinstance(volume_node, list):
            # add device_name in each volume_node, network device name may be different in each host
            for node in volume_node:
                obj_log.info('Start to disconnect manage network %s' % node['containername'])
                node['device_name'] = self._get_network_device_from_conf(node['host'])['managenetwork']

            rtn = self.multi.multi_change_network_status(server, volume_node, status=False)
        else:
            obj_log.info('Start to disconnect manage network %s' % volume_node['containername'])
            device_name = self._get_network_device_from_conf(volume_node['host'])['managenetwork']
            rtn = self.utils.change_network_device_connect_status(server, volume_node['containername'], device_name,
                                                                  status=False)
        if rtn is False:
            raise self.customError("disconnect manage network failed")

    def connect_manage_network(self, server, volume_node):
        if isinstance(volume_node, list):
            for node in volume_node:
                obj_log.info('Start to connect manage network %s' % node['containername'])
                node['device_name'] = self._get_network_device_from_conf(node['host'])['managenetwork']
            rtn = self.multi.multi_change_network_status(server, volume_node, status=True)
        else:
            obj_log.info('Start to connect manage network %s' % volume_node['containername'])
            device_name = self._get_network_device_from_conf(volume_node['host'])['managenetwork']
            rtn = self.utils.change_network_device_connect_status(server, volume_node['containername'], device_name,
                                                                  status=True)
        if rtn is False:
            raise self.customError("connect manage network failed")

    def disconnect_storage_network(self, server, volume_node):
        if isinstance(volume_node, list):
            for node in volume_node:
                obj_log.info('Start to disconnect storage network %s' % node['containername'])
                node['device_name'] = self._get_network_device_from_conf(node['host'])['storagenetwork']
            rtn = self.multi.multi_change_network_status(server, volume_node, status=False)
        else:
            obj_log.info('Start to disconnect storage network %s' % volume_node['containername'])
            device_name = self._get_network_device_from_conf(volume_node['host'])['storagenetwork']
            rtn = self.utils.change_network_device_connect_status(server, volume_node['containername'], device_name,
                                                                  status=False)
        if rtn is False:
            raise self.customError("disconnect storage network failed")

    def connect_storage_network(self, server, volume_node):
        if isinstance(volume_node, list):
            for node in volume_node:
                obj_log.info('Start to connect storage network %s' % node['containername'])
                node['device_name'] = self._get_network_device_from_conf(node['host'])['storagenetwork']
            rtn = self.multi.multi_change_network_status(server, volume_node, status=True)
        else:
            obj_log.info('Start to connect storage network %s' % volume_node['containername'])
            device_name = self._get_network_device_from_conf(volume_node['host'])['storagenetwork']
            rtn = self.utils.change_network_device_connect_status(server, volume_node['containername'], device_name,
                                                                  status=True)
        if rtn is False:
            raise self.customError("connect storage network failed")

    def _enable_ha(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                node_type = node['type']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(node['mountpoint'])
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("enable<" + node_type + "> ha start.")
                    enable_ha_rtn = self.tools.enable_ha(volume_resource_name)
                    self.utils.progressbar_k(60)
                    if enable_ha_rtn == True:
                        obj_log.info(volume_resource_name + ' enable ha successfully.')
                    else:
                        obj_log.debug(enable_ha_rtn)
                        raise self.customError("enable ha failed, please check !")
        return True

    def _enable_ha_negetive(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                node_type = node['type']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = node['name']
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("enable<" + node_type + "> ha start.")
                    enable_ha_rtn = self.tools.enable_ha(volume_resource_name, get_err_msg=True)
                    obj_log.debug(enable_ha_rtn)
                    return enable_ha_rtn


    def _disable_ha(self, obj):
        nodes = self._node_operate(obj)

        for k in self.all_server_dict.keys():
            for node in nodes:
                node_type = node['type']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(node['mountpoint'])
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("disable<" + node_type + "> ha start.")
                    disable_ha_rtn = self.tools.disable_ha(volume_resource_name)
                    self.utils.progressbar_k(60)
                    if disable_ha_rtn == True:
                        obj_log.info(volume_resource_name + ' disable ha successfully.')
                    else:
                        obj_log.debug(disable_ha_rtn)
                        raise self.customError("disable ha failed, please check !")
        return True

    def _sync_vm(self, obj):
        obj_log.debug("run commands 'sync' on each volume nodes start...")
        vol_list = self._get_volume_list(self.all_node_info)
        for vol_ip in vol_list[1]:
            rtn = obj_utils.ssh_cmd(vol_ip,"poweruser","poweruser","sync")
            obj_log.debug(rtn)
        obj_log.debug("run commands 'sync' on each volume nodes done.")

    def _get_volume_type_list_from_config(self):
        volume_type_list = []
        volume_type_dict = {
            'HYBRID': 'hybrid',
            'MEMORY': 'memory',
            'ALL_FLASH': 'flash',
            'SIMPLE_HYBRID': 'simplehybrid',
            'SIMPLE_MEMORY': 'simplememory',
            'SIMPLE_FLASH': 'simpleflash'
        }
        for volume_temp in self.all_config['volume_config']:
            if self.all_config['only_infrastructure'] == 'true':
                volume_type_list.append('infra')
                break
            if self.all_config['volume_config'][volume_temp].has_key('hyperconvergedvolume'):
                volume_type_list.append('hyperconverge')
                break
            volumetype = self.all_config['volume_config'][volume_temp]['volumetype']
            volume_type = volume_type_dict[volumetype]
            volume_type_list.append(volume_type)
        volume_type_list = list(set(volume_type_list))
        obj_log.info(volume_type_list)
        return volume_type_list

    def _get_volume_list(self,all_node_info):
        volume_list = []
        volume_ip_list = []
        volume_info = all_node_info['volume_info']
        for volume in volume_info.keys():
            volume_name = volume_info[volume]['containername']
            volume_ip = volume_info[volume]['eth0']
            volume_list.append(volume_name)
            volume_ip_list.append(volume_ip)

        return (volume_list,volume_ip_list)

    def _get_obj_volume_list(self, obj):
        nodes = self._node_operate(obj)
        node_list = []
        node_ip_list = []
        obj_log.debug(self.all_server_dict)
        obj_log.debug(nodes)
        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['containername'] in self.all_server_dict[k]:
                    node_name = node['containername']
                    node_ip = node['eth0']
                    node_list.append(node_name)
                    node_ip_list.append(node_ip)
        obj_log.debug(node_list)
        obj_log.debug(node_ip_list)
        return (node_list, node_ip_list)

    def _get_obj_volume_resource_list(self, obj):
        nodes = self._node_operate(obj)
        resource_name_list = []
        obj_log.debug(nodes)
        for node in nodes:
            resource_name_list.append(node['name'])
        obj_log.debug(resource_name_list)
        return resource_name_list

    def _get_obj_volume_info_for_replication(self, obj):
        nodes = self._node_operate(obj)
        obj_log.info("nodes:%s, obj:%s" % (nodes, obj))
        info_for_replication_dict = {}
        for node in nodes:
            info_for_replication_dict['name'] = node['name']
            info_for_replication_dict['containername'] = node['containername']
            info_for_replication_dict['serviceip'] = node.get('serviceip', node['eth1'])
            info_for_replication_dict['eth1'] = node['eth1']
            info_for_replication_dict["volumeresourceuuids"] = node["uuid"]
        obj_log.debug(info_for_replication_dict)
        return info_for_replication_dict

    def _get_ha_list(self,all_node_info):
        ha_list = []
        ha_ip_list = []
        ha_info = all_node_info['ha_info']
        for ha in ha_info.keys():
            ha_name = ha_info[ha]['containername']
            ha_ip = ha_info[ha]['eth0']
            ha_list.append(ha_name)
            ha_ip_list.append(ha_ip)

        return (ha_list,ha_ip_list)

    def _get_svm_list(self,all_node_info):
        svm_list = []
        svm_ip_list = []
        svm_info = all_node_info['service_vm_info']
        if svm_info:  # all_flash sharestorage has no svm
            for svm in svm_info.keys():
                svm_name = svm_info[svm]['containername']
                svm_ip = svm_info[svm]['eth0']
                svm_list.append(svm_name)
                svm_ip_list.append(svm_ip)

        return (svm_list,svm_ip_list)

    def _get_svm_host_ip_list(self, all_node_info):
        host_ip_list = []
        svm_info = all_node_info['service_vm_info']
        if svm_info: # all_flash sharestorage has no svm
            for svm in svm_info.keys():
                host_ip = svm_info[svm]['host']
                host_ip_list.append(host_ip)

        return host_ip_list

    def _get_host_vm_dict(self):
        host_vm_dict = {}
        all_node_info = self.tools.get_all_node_info()
        svm_info = all_node_info['service_vm_info']
        ha_info = all_node_info['ha_info']
        volume_info = all_node_info['volume_info']
        host_svm_ip_list = self._get_svm_host_ip_list(all_node_info)

        if host_svm_ip_list:
            for host_ip in host_svm_ip_list:
                host_vm_dict[host_ip] = []
                for svm in svm_info.keys():
                    if svm_info[svm]['host'] == host_ip:
                        host_vm_dict[host_ip].append(svm_info[svm]['containername'])

                for ha in ha_info.keys():
                    if ha_info[ha]['host'] == host_ip:
                        host_vm_dict[host_ip].append(ha_info[ha]['containername'])

                for volume in volume_info.keys():
                    if volume_info[volume]['host'] == host_ip:
                        host_vm_dict[host_ip].append(volume_info[volume]['containername'])

            obj_log.debug(host_vm_dict)
            return host_vm_dict

    # just for noly 1 amc
    def _get_amc_name(self):
        vms_list = self.utils.get_vm_list_by_wildcard(self.vcs, self.all_config['testbed_name'])
        for vm in vms_list:
            if "AMC" in vm and self.all_config['user'] in vm:
                amc_name = vm
                obj_log.debug(amc_name)
        return amc_name

    def _get_amc_name_list(self):
        vms_list = self.utils.get_vm_list_by_wildcard(self.vcs, self.all_config['testbed_name'])
        amc_list = []
        for vm in vms_list:
            if "AMC" in vm and self.all_config['user'] in vm:
                amc_list.append(vm)
                obj_log.debug(amc_list)
        return amc_list

    def _get_vm_list_by_wildcard(self, obj):
        obj_log.debug(obj[1])
        vms_string = obj[1] + self.all_config['testbed_name']
        vms_list = self.utils.get_vm_list_by_wildcard(self.vcs, vms_string)
        return vms_list

    def _get_online_node_number(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            node_ip = node['eth0']
            online_node = self.utils.getHAOnlineNodes(node_ip)
            online_node_number = len(online_node)
        return online_node_number

    def _get_offline_node_number(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            node_ip = node['eth0']
            offline_node = self.utils.getHAOfflineNodes(node_ip)
            offline_node_number = len(offline_node)
        return offline_node_number


    def _get_all_need_info(self):
        temp = {}
        tms = 30
        while tms:
            try:
                all_node_info = self.tools.get_all_node_info()
                obj_log.debug("all_node_info: %s" % all_node_info)
                break
            except Exception as e:
                obj_log.debug(str(e))
                time.sleep(60)
                tms -= 1
        vol_tuple = self._get_volume_list(all_node_info)
        ha_tuple = self._get_ha_list(all_node_info)
        svm_tuple = self._get_svm_list(all_node_info)
        node_list = vol_tuple[0] + ha_tuple[0]
        node_ip_list = vol_tuple[1] + ha_tuple[1]

        temp["node_list"] = node_list
        temp["node_ip_list"] = node_ip_list
        temp["volume_list"] = vol_tuple[0]
        temp["volume_ip_list"] = vol_tuple[1]
        temp["svm_list"] = svm_tuple[0]
        temp["svm_ip_list"] = svm_tuple[1]
        temp["volume_info"] = all_node_info['volume_info']

        return temp

    def _get_volume_health_status(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            node_uuid = node['uuid']
            stauts_dict = self.tools.get_usx_status(node_uuid)
            obj_log.info(stauts_dict)
            return stauts_dict['VOLUME_SERVICE_STATUS']

    def _clean_testbed(self, obj):
        obj_log.info("clean up testbed start..")
        testbed_name = self.all_config['testbed_name']
        user = self.all_config['user']
        obj_log.debug(testbed_name)
        rtn = self.utils.clean_testbed(self.vcs, testbed_name, user)
        return rtn

    def _clean_testbed_except_amc(self, obj):
        obj_log.info("clean up testbed except AMC start..")
        testbed_name = self.all_config['testbed_name']
        user = self.all_config['user']
        obj_log.debug(testbed_name)
        rtn = self.utils.clean_testbed(self.vcs, testbed_name, user, False)
        return rtn

    def _check_nfs_crm(self,resource):

        pattern_ds = r'ds.*?Started\s(?P<vol>\w+.*\d)'
        pattern_dedup = r'dedup.*?Started\s(?P<vol>\w+.*\d)'
        pattern_ip = r'ip.*?Started\s(?P<vol>\w+.*\d)'
        pattern_nfs = r'nfs.*?Started\s(?P<vol>\w+.*\d)'

        ds = re.search(pattern_ds, resource).group('vol')
        dedup = re.search(pattern_dedup, resource).group('vol')
        ip = re.search(pattern_ip, resource).group('vol')
        nfs = re.search(pattern_nfs, resource).group('vol')
        res = re.search(r'_(?P<res>.*?)_ds', resource).group('res')
        if ds == dedup == ip == nfs != None:
            obj_log.info("Volume " + res + "'s resources on " + ds + " and they are health")
            return True
        else:
            return False

    def _check_iscsi_crm(self,resource):

        pattern_ds = r'ds.*?Started\s(?P<vol>\w+.*\d)'
        pattern_dedup = r'dedup.*?Started\s(?P<vol>\w+.*\d)'
        pattern_ip = r'ip.*?Started\s(?P<vol>\w+.*\d)'
        pattern_target = r'target.*?Started\s(?P<vol>\w+.*\d)'
        pattern_lun = r'lun.*?Started\s(?P<vol>\w+.*\d)'

        ds = re.search(pattern_ds, resource).group('vol')
        dedup = re.search(pattern_dedup, resource).group('vol')
        ip = re.search(pattern_ip, resource).group('vol')
        target = re.search(pattern_target, resource).group('vol')
        lun = re.search(pattern_lun, resource).group('vol')
        res = re.search(r'_(?P<res>.*?)_ds', resource).group('res')
        if ds == dedup == ip == target == lun != None:
            obj_log.info("Volume " + res + "'s resources on " + ds + " and they are health")
            return True
        else:
            return False

    def _verifyCrm(self, obj):
        if isinstance(obj, list):    # obj is a list or not ?
            nodes = self._node_operate(obj)

            for node in nodes:
                obj_log.debug(node['eth0'])
                node_ip = node['eth0']
        else:
            node_ip = obj
        cmd = 'crm_mon -1r'
        cmd1 = 'ibdmanager -r a -s get | grep level'
        cmd_check_reset = 'find /var/log/ -iname *reset*'
        tms = 10
        while tms:
            try:
                crm_mon = self.utils.ssh_cmd(node_ip, 'poweruser','poweruser', cmd)['stdout']

                crm_mon1 = self.utils.ssh_cmd(node_ip, 'poweruser','poweruser', cmd1)['stdout']

                crm_mon_reset = self.utils.ssh_cmd(node_ip, 'poweruser','poweruser', cmd_check_reset)['stdout']

                obj_log.info(crm_mon)
                obj_log.warning(crm_mon1)
                obj_log.warning(crm_mon_reset)
                if "readonly" in crm_mon1:
                    obj_log.error("ibd read only, please check!")

                # check reset log in /var/log/
                if crm_mon_reset:
                    obj_log.error("reset log found in /var/log/")
                break
            except Exception as e:
                obj_log.error(str(e))
                self.utils.progressbar_k(30)
                tms -= 1
                if tms == 0:
                    raise self.customError("can not verify crm_mon, please check!")



        vol_list = re.findall(r'Resource Group: (?P<res>\w+.*?)_group', crm_mon)
        lines = []
        res_group = []
        for line in crm_mon.split('\n'):
            if "ocf" in line:
                lines.append(line)
        for vol in vol_list:
            res_list = []
            for line in lines:
                if vol in line:
                    res_list.append(line)
            res_group.append('\n'.join(res_list))

        for resource in res_group:
            if "iscsi" not in resource: # nfs
                rtn = self._check_nfs_crm(resource)
                if rtn == False:
                    break
            else: #iscsi
                rtn = self._check_iscsi_crm(resource)
                if rtn == False:
                    break
        return rtn


    def _method_reset(self, obj, i, node_list, node_ip_list, num=1):
        obj_log.info("method:  reset")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)

        # get group1 info for ha resourse map check
        # self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip_list[i])
        group1 = self.utils.getHAResourceMap(node_ip_list[i])
        obj_log.debug("group1 %s" % group1)

        # do failover method
        if obj[0] != '':
            node_list = random.sample(node_list, num)
            rtn = self.multi.reset_vm(server, node_list)
            obj_log.debug(rtn)
        else:
            for j in range(num):
                if i > len(node_list)-1:
                    i = 0
                rtn = self.multi.reset_vm(server, [node_list[i]])
                obj_log.debug(rtn)
                i += 1

        self.utils.progressbar_k(90)

        if obj[0] != '':
            nodes = self._node_operate(obj)
            # wait until there is not offline volume
            for node in nodes:
                obj_log.debug(node['eth0'])
                node_ip = node['eth0']
            self._check_ha_resource_map(node['eth0'], group1)
            self._check_node(node_ip)
            ver_rtn = self._verifyCrm(node_ip)
        else:
            if i > len(node_list)-1:
                i = 0
            vol_list = self._get_all_need_info()
            obj_log.debug(vol_list)
            node_list = vol_list["volume_list"]
            node_ip_list = vol_list["volume_ip_list"]
            self._check_ha_resource_map(node_ip_list[i], group1)
            self._check_node(node_ip_list[i])
            ver_rtn = self._verifyCrm(node_ip_list[i])

        if not ver_rtn:
            raise self.customError("failover failed, some resources crashed")
        obj_log.info("failover sucessful.")
        self._disconnect(server)
        return i

    def _method_reboot(self, obj, i, node_list, node_ip_list, num=1):
        obj_log.info("method:  reboot")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        crm_mon = 'crm_mon -1r'

        # get group1 info for ha resourse map check
        # self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip_list[i])
        group1 = self.utils.getHAResourceMap(node_ip_list[i])
        obj_log.debug("group1 %s" % group1)

        # do failover method
        if obj[0] != '':
            node_list = random.sample(node_list, num)
            rtn = self.multi.reboot_vm(server, node_list)
            obj_log.debug(rtn)
        else:
            for j in range(num):
                if i > len(node_list)-1:
                    i = 0
                rtn = self.multi.reboot_vm(server, [node_list[i]])
                obj_log.debug(rtn)
                i += 1

        obj_utils.progressbar_k(200)

        if obj[0] != '':
            nodes = self._node_operate(obj)
            # wait until there is not offline volume
            for node in nodes:
                obj_log.debug(node['eth0'])
                node_ip = node['eth0']
            self._check_ha_resource_map(node['eth0'], group1)
            self._check_node(node_ip)
            ver_rtn = self._verifyCrm(node_ip)
        else:
            if i > len(node_list)-1:
                i = 0
            vol_list = self._get_all_need_info()
            obj_log.debug(vol_list)
            node_list = vol_list["volume_list"]
            node_ip_list = vol_list["volume_ip_list"]
            self._check_ha_resource_map(node_ip_list[i], group1)
            self._check_node(node_ip_list[i])
            ver_rtn = self._verifyCrm(node_ip_list[i])

        if not ver_rtn:
            raise self.customError("failover failed, some resources crashed")
        obj_log.info("failover sucessful.")
        self._disconnect(server)
        return i

    def _method_poweroff_on(self, obj, i, node_list, node_ip_list, num=1):
        obj_log.info("method:  poweroff")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        crm_mon = 'crm_mon -1r'
        powoffed = []

        # get group1 info for ha resourse map check
        # self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip_list[i])
        group1 = self.utils.getHAResourceMap(node_ip_list[i])
        obj_log.debug("group1 %s" % group1)

        # do failover method
        if obj[0] != '':
            node_list = random.sample(node_list, num)
            rtn = self.multi.poweroff_vm(server, node_list)
            obj_log.debug(rtn)
            powoffed.extend(node_list)
        else:
            for j in range(num):
                if i > len(node_list)-1:
                    i = 0
                rtn = self.multi.poweroff_vm(server, [node_list[i]])
                obj_log.debug(rtn)
                powoffed.append(node_list[i])
                i += 1

        obj_utils.progressbar_k(100)

        # before power on volume check the resource map
        if obj[0] != '':
            nodes = self._node_operate(obj)
            for node in nodes:
                obj_log.debug(node['eth0'])
            self._check_ha_resource_map(node['eth0'], group1)
        else:
            if i > len(node_list)-1:
                i = 0
            self._check_ha_resource_map(node_ip_list[i], group1)


        # power on volume
        rtn = self.multi.poweron_vm(server, powoffed)
        obj_log.debug(rtn)
        obj_utils.progressbar_k(100)

        if obj[0] != '':
            nodes = self._node_operate(obj)
            # wait until there is not offline volume
            for node in nodes:
                obj_log.debug(node['eth0'])
                node_ip = node['eth0']
            self._check_node(node_ip)
            ver_rtn = self._verifyCrm(node_ip)
        else:
            if i > len(node_list)-1:
                i = 0
            vol_list = self._get_all_need_info()
            obj_log.debug(vol_list)
            node_list = vol_list["volume_list"]
            node_ip_list = vol_list["volume_ip_list"]
            self._check_node(node_ip_list[i])
            ver_rtn = self._verifyCrm(node_ip_list[i])

        if not ver_rtn:
            raise self.customError("failover failed, some resources crashed")
        obj_log.info("failover sucessful.")
        self._disconnect(server)
        return i

    def _method_shutdown(self, obj, i, node_list, node_ip_list, num=1):
        obj_log.info("method:  shutdown")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        crm_mon = 'crm_mon -1r'
        shutdowned = []

        # get group1 info for ha resourse map check
        # self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip_list[i])
        group1 = self.utils.getHAResourceMap(node_ip_list[i])
        obj_log.debug("group1 %s" % group1)

        # do failover method
        if obj[0] != '':
            node_list = random.sample(node_list, num)
            rtn = self.multi.multi_shutdown_vm(server, node_list)
            obj_log.debug(rtn)
            shutdowned.extend(node_list)
        else:
            for j in range(num):
                if i > len(node_list)-1:
                    i = 0
                rtn = self.multi.multi_shutdown_vm(server, [node_list[i]])
                obj_log.debug(rtn)
                shutdowned.append(node_list[i])
                i += 1

        obj_utils.progressbar_k(100)

        # before power on check the resource map
        if obj[0] != '':
            nodes = self._node_operate(obj)
            for node in nodes:
                obj_log.debug(node['eth0'])
            self._check_ha_resource_map(node['eth0'], group1)
        else:
            if i > len(node_list)-1:
                i = 0
            self._check_ha_resource_map(node_ip_list[i], group1)


        # Power on volume
        self.multi.poweron_vm(server, shutdowned)
        obj_utils.progressbar_k(100)

        if obj[0] != '':
            nodes = self._node_operate(obj)
            # wait until there is not offline volume
            for node in nodes:
                obj_log.debug(node['eth0'])
                node_ip = node['eth0']
            self._check_node(node_ip)
            ver_rtn = self._verifyCrm(node_ip)
        else:
            if i > len(node_list)-1:
                i = 0
            vol_list = self._get_all_need_info()
            obj_log.debug(vol_list)
            node_list = vol_list["volume_list"]
            node_ip_list = vol_list["volume_ip_list"]
            self._check_node(node_ip_list[i])
            ver_rtn = self._verifyCrm(node_ip_list[i])

        if not ver_rtn:
            raise self.customError("failover failed, some resources crashed")
        obj_log.info("failover sucessful.")
        self._disconnect(server)
        return i

    def _failover_case(self, obj):
        obj_log.info("start failover test")
        num = int(self.utils.get_config("testcase","failover_num", self.configfile))
        poweroff_amc = self.utils.get_config("testcase","poweroff_amc", self.configfile)
        if poweroff_amc == 'false':
            if obj[0] != '':
                nodes = self._node_operate(obj)
                # first empty the dict, then put the node ip list to ha_nodes_dict

                self.utils.ha_nodes_dict = {}
                self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(nodes[0]['eth0'])


            failover_method = ["reset","reboot","poweroff","shutdown"]
            rand_methods_list = random.sample(failover_method,3)
            obj_log.debug(rand_methods_list)

            i = 0
            for j in rand_methods_list:
                if obj[0] != '':
                    vol_list = self._get_obj_volume_list(obj)
                    node_list = vol_list[0]
                    node_ip_list = vol_list[1]
                else:
                    vol_list = self._get_all_need_info()
                    obj_log.debug(vol_list)
                    node_list = vol_list["volume_list"]
                    node_ip_list = vol_list["volume_ip_list"]
                    # first empty the dict, then put the node ip list to ha_nodes_dict

                    self.utils.ha_nodes_dict = {}
                    self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip_list[0])

                if j == "reset":
                    i = self._method_reset(obj, i, node_list, node_ip_list, num)
                elif j == "reboot":
                    i = self._method_reboot(obj, i, node_list, node_ip_list, num)
                elif j == "poweroff":
                    i = self._method_poweroff_on(obj, i, node_list, node_ip_list, num)
                else:
                    i = self._method_shutdown(obj, i, node_list, node_ip_list, num)
            obj_log.debug("failover test done")
            return True
        else:
            return self._non_amc_failover(obj)

    def _non_amc_failover(self, obj):
        obj_log.info("None AMC failover start")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        num = int(self.utils.get_config("testcase", "failover_num", self.configfile))
        nodes = self._node_operate(obj)
        node_ip = nodes[0]['eth0']
        self.utils.ha_nodes_dict = {}
        self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip)

        # get resource group list
        group = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group %s" % group)
        resource_group_list = group.keys()

        # power off AMC
        amc_name_list = self._get_amc_name_list()
        self.multi.poweroff_vm(server, amc_name_list)
        self.utils.progressbar_k(60)

        # random choice failover method
        failover_method = ["reset", "reboot", "poweroff", "shutdown"]
        rand_methods_list = random.sample(failover_method, 3)
        obj_log.debug(rand_methods_list)

        for method in rand_methods_list:
            random_resource_group_list = random.sample(resource_group_list, num)
            if method == "reset":
                self._non_amc_method_reset(server, node_ip, random_resource_group_list)
            elif method == "reboot":
                self._non_amc_method_reboot(server, node_ip, random_resource_group_list)
            elif method == "poweroff":
                self._non_amc_method_poweroff_on(server, node_ip, random_resource_group_list)
            else:
                self._non_amc_method_shutdown(server, node_ip, random_resource_group_list)
        self._poweron_all_amc(obj)
        self.utils.progressbar_k(100)
        return True

    def _non_amc_method_reset(self, server, node_ip, random_resource_group_list):
        obj_log.info("method:  none amc reset")
        group1 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group1 %s" % group1)
        node_list = []
        for resource in random_resource_group_list:
            node_list.append(group1[resource])
        # do failover method
        rtn = self.multi.reset_vm(server, node_list)
        obj_log.debug(rtn)
        self.utils.progressbar_k(90)

        self._check_ha_resource_map(node_ip, group1)
        self._check_node(node_ip)
        ver_rtn = self._verifyCrm(node_ip)

        if not ver_rtn:
            raise self.customError("reset failover failed, some resources crashed")
        obj_log.info("failover sucessful.")

    def _non_amc_method_reboot(self, server, node_ip, random_resource_group_list):
        obj_log.info("method:  none amc reboot")
        group1 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group1 %s" % group1)
        node_list = []
        for resource in random_resource_group_list:
            node_list.append(group1[resource])
        # do failover method
        rtn = self.multi.reboot_vm(server, node_list)
        obj_log.debug(rtn)
        self.utils.progressbar_k(200)

        self._check_ha_resource_map(node_ip, group1)
        self._check_node(node_ip)
        ver_rtn = self._verifyCrm(node_ip)

        if not ver_rtn:
            raise self.customError("reboot failover failed, some resources crashed")
        obj_log.info("failover sucessful.")

    def _non_amc_method_poweroff_on(self, server, node_ip, random_resource_group_list):
        obj_log.info("method:  none amc poweroff")
        group1 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group1 %s" % group1)
        node_list = []
        for resource in random_resource_group_list:
            node_list.append(group1[resource])
        # do failover method
        rtn = self.multi.poweroff_vm(server, node_list)
        obj_log.debug(rtn)
        self.utils.progressbar_k(100)

        self._check_ha_resource_map(node_ip, group1)
        # power on volume
        rtn = self.multi.poweron_vm(server, node_list)
        obj_log.debug(rtn)
        obj_utils.progressbar_k(100)

        self._check_node(node_ip)
        ver_rtn = self._verifyCrm(node_ip)

        if not ver_rtn:
            raise self.customError("power off failover failed, some resources crashed")
        obj_log.info("failover sucessful.")

    def _non_amc_method_shutdown(self, server, node_ip, random_resource_group_list):
        obj_log.info("method:  none amc shutdown")
        group1 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group1 %s" % group1)
        node_list = []
        for resource in random_resource_group_list:
            node_list.append(group1[resource])
        # do failover method
        rtn = self.multi.multi_shutdown_vm(server, node_list)
        obj_log.debug(rtn)
        self.utils.progressbar_k(100)

        self._check_ha_resource_map(node_ip, group1)
        # power on volume
        rtn = self.multi.poweron_vm(server, node_list)
        obj_log.debug(rtn)
        obj_utils.progressbar_k(100)

        self._check_node(node_ip)
        ver_rtn = self._verifyCrm(node_ip)

        if not ver_rtn:
            raise self.customError("shutdown failover failed, some resources crashed")
        obj_log.info("failover sucessful.")

    def _down_storage_network_failover(self, server, node_ip, random_resource_group_list):
        obj_log.info("method: disconnect storage network failover")
        group1 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group1 %s" % group1)
        node_list = []
        for resource in random_resource_group_list:
            node_list.append(group1[resource])
        # disconnect
        rtn = self._disconnect_storage_network(node_list)
        obj_log.debug(rtn)
        self.utils.progressbar_k(100)

        self._check_ha_resource_map(node_ip, group1)
        # connect
        rtn = self._connect_storage_network(node_list)
        obj_log.debug(rtn)
        obj_utils.progressbar_k(100)

        self._check_node(node_ip)
        ver_rtn = self._verifyCrm(node_ip)

    def _failover_button(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            volume_resource_uuid = node["uuid"]
            volume_container_uuid = node["containeruuid"]
            rtn = self.tools.failover_volume(volume_resource_uuid, volume_container_uuid)
            if not rtn:
                raise self.customError("Failover by failover button Failed")
            obj_utils.progressbar_k(20)
        return True

    def _reset_vc(self, obj):
        obj_log.debug("reset " + obj[0] + " start")
        self.vcs2 = eval(self.utils.get_config('testcase', 'vcs2', self.configfile))
        self.host_ip_name_dict = eval(self.utils.get_config('testcase', 'host_ip_name_dict', self.configfile))
        vc = self.vcs2.keys()[0]
        vc_username = self.vcs2[vc]['username']
        vc_password = self.vcs2[vc]['password']
        server = self._conn_vcenter(vc, vc_username, vc_password)
        self.utils.reset_vm(server, obj[0])
        obj_log.debug("reset done, wait for boot up")
        self._disconnect(server)
        self.utils.progressbar_k(300)
        #---------------------------
        # try to connect vCenter
        #---------------------------
        self._check_vc(self.vc, self.vc_username, self.vc_password)

    def _poweroff_vc(self, obj):
        obj_log.debug("reset " + obj[0] + " start")
        self.vcs2 = eval(self.utils.get_config('testcase', 'vcs2', self.configfile))
        self.host_ip_name_dict = eval(self.utils.get_config('testcase', 'host_ip_name_dict', self.configfile))
        vc = self.vcs2.keys()[0]
        vc_username = self.vcs2[vc]['username']
        vc_password = self.vcs2[vc]['password']
        server = self._conn_vcenter(vc, vc_username, vc_password)
        self.utils.poweroff_vm(server, obj[0])
        obj_log.debug("power off done!")
        self.utils.progressbar_k(300)
        self.utils.poweron_vm(server, obj[0])
        self.utils.progressbar_k(300)
        self._disconnect(server)
        #---------------------------
        # try to connect vCenter
        #---------------------------
        self._check_vc(self.vc, self.vc_username, self.vc_password)

    def _reset_host(self, obj):
        obj_log.debug("start reset host test")
        self.vcs2 = eval(self.utils.get_config('testcase', 'vcs2', self.configfile))
        self.host_ip_name_dict = eval(self.utils.get_config('testcase', 'host_ip_name_dict', self.configfile))
        all_node_info = self.tools.get_all_node_info()
        svm_host_ip_list = self._get_svm_host_ip_list(all_node_info)
        if svm_host_ip_list:
            for host_ip in svm_host_ip_list:
                # get ha group resource map before action
                nodes = self._node_operate(obj)
                for node in nodes:
                    obj_log.debug(node['eth0'])
                    node_ip = node['eth0']
                self.utils.ha_nodes_dict = {}
                self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip)


                group1 = self.utils.getHAResourceMap(node_ip)
                obj_log.debug("group1 %s" % group1)

                host_name = self.host_ip_name_dict[host_ip]
                vc = self.vcs2.keys()[0]
                vc_username = self.vcs2[vc]['username']
                vc_password = self.vcs2[vc]['password']
                server = self._conn_vcenter(vc, vc_username, vc_password)
                self.utils.reset_vm(server, host_name)
                obj_log.info("reset " + host_name + " done, wait for host boot up")
                self.utils.progressbar_k(120)
                #---------------------------
                # try to connect host
                #---------------------------
                self._check_vm_health(server, host_name)
                # check_vm_health is just check power status and ping the host ip
                # For virtual host it may not connect the vCenter so add deplay
                self.utils.progressbar_k(300)
                self._disconnect(server)

                #--------------------------------------------------------------------------------
                # if amc not in poweroff host get ha group before poweron volume
                #--------------------------------------------------------------------------------
                ret1 = self.utils.is_reachable(self.amc_ip.encode('utf8'))
                ret2 = self.utils.is_reachable(node_ip.encode('utf8'))
                amc_num = int(self.utils.get_config('main', 'amc_num', self.configfile))
                if ret1 or amc_num != 1:
                # if (ret1 and (not ret2)) or (amc_num != 1 and (not ret2)):          # amc isn't offline and volume is offline
                    # nodes = self._node_operate(obj)
                    # for node in nodes:
                    #     obj_log.debug(node['eth0'])
                    #     node_ip = node['eth0']
                    # if amc_num > 1:
                    #     self.login_alive_amc()
                    obj_log.debug(self.utils.checkHAStatus(node_ip))
                    self._check_ha_status(node_ip)
                    tms = 5
                    while tms:
                        group2 = self.utils.getHAResourceMap(node_ip)
                        obj_log.debug("group2 %s" % group2)
                        if group2.values() != ['']:
                            rtn = self.utils.compareResourceMap(group1, group2)
                            obj_log.debug(rtn)
                            break
                        self.utils.progressbar_k(60)
                        tms -= 1
                        if tms == 0:
                            raise self.customError("failover failed, ha does not get the resourses")

                #---------------------------------
                # power on volume in reset host
                #---------------------------------
                obj_log.debug("Power on the volume in reset host")
                server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
                rtn = self.utils.poweron_all_vm_by_wildcard(self.vcs, self.all_config['testbed_name'])
                obj_log.debug(rtn)
                obj_utils.progressbar_k(300)

                #------------------------------------------------------
                # sharestorage poweron fail need to remove second disk
                #------------------------------------------------------
                vms = self.utils.get_vm_list_by_wildcard(self.vcs, self.all_config['testbed_name'])
                for vmname in vms :
                    vm = server.get_vm_by_name(vmname)
                    if not vm.is_powered_on():
                        self.utils.removeSecondDisk(server, vmname)
                        obj_utils.progressbar_k(20)
                        self.utils.poweron_vm(server, vmname)
                        obj_utils.progressbar_k(200)



                #------------------------------------
                # If amc in the reset host Login amc
                #------------------------------------
                self.tools = utils.Tools(self.amc_ip)

                #------------------------------------
                # check ibd get back
                # for multi-type volume, need to check all
                # the volumes' ibd status
                #------------------------------------
                self._check_all_volume_mdstat()

                # get ha group after failover
                obj_log.info("===============check ha status============")
                self._check_ha_status(node_ip)
                group2 = self.utils.getHAResourceMap(node_ip)
                obj_log.debug("group2 %s" % group2)
                rtn = self.utils.compareResourceMap(group1, group2)
                obj_log.debug(rtn)

                self._disconnect(server)

    def _poweroff_host(self, obj):
        obj_log.debug("start poweroff host test")
        self.vcs2 = eval(self.utils.get_config('testcase', 'vcs2', self.configfile))
        self.host_ip_name_dict = eval(self.utils.get_config('testcase', 'host_ip_name_dict', self.configfile))
        all_node_info = self.tools.get_all_node_info()
        svm_host_ip_list = self._get_svm_host_ip_list(all_node_info)
        if svm_host_ip_list:
            for host_ip in svm_host_ip_list:
                # get ha group resource map before action
                nodes = self._node_operate(obj)
                for node in nodes:
                    obj_log.debug(node['eth0'])
                    node_ip = node['eth0']
                self.utils.ha_nodes_dict = {}
                self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip)

                group1 = self.utils.getHAResourceMap(node_ip)
                obj_log.debug("group1 %s" % group1)

                host_name = self.host_ip_name_dict[host_ip]
                vc = self.vcs2.keys()[0]
                vc_username = self.vcs2[vc]['username']
                vc_password = self.vcs2[vc]['password']
                server = self._conn_vcenter(vc, vc_username, vc_password)
                self.utils.poweroff_vm(server, host_name)
                obj_log.debug("power off done")
                self.utils.progressbar_k(200)
                #--------------------------------------------------------------------------------
                # if amc not in poweroff host get ha group before poweron volume
                #--------------------------------------------------------------------------------
                ret1 = self.utils.is_reachable(self.amc_ip.encode('utf8'))
                ret2 = self.utils.is_reachable(node_ip.encode('utf8'))
                amc_num = int(self.utils.get_config('main', 'amc_num', self.configfile))
                if ret1 or amc_num != 1:          # amc isn't offline and volume is offline
                    # if amc_num > 1:
                    #     self.login_alive_amc()
                    # nodes = self._node_operate(obj)
                    # for node in nodes:
                    #     obj_log.debug(node['eth0'])
                    #     node_ip = node['eth0']
                    obj_log.debug(self.utils.checkHAStatus(node_ip))
                    self._check_ha_status(node_ip)
                    tms = 5
                    while tms:
                        group2 = self.utils.getHAResourceMap(node_ip)
                        obj_log.debug("group2 %s" % group2)
                        if group2.values() != ['']:
                            rtn = self.utils.compareResourceMap(group1, group2)
                            obj_log.debug(rtn)
                            break
                        self.utils.progressbar_k(60)
                        tms -= 1
                        if tms == 0:
                            raise self.customError("failover failed, ha does not get the resourses")



                self.utils.poweron_vm(server, host_name)
                obj_log.debug("power on done, wait for host boot up")
                self.utils.progressbar_k(200)
                #---------------------------
                # try to connect host
                #---------------------------
                self._check_vm_health(server, host_name)
                # check_vm_health is just check power status and ping the host ip
                # For virtual host it may not connect the vCenter so add deplay
                self.utils.progressbar_k(300)
                self._disconnect(server)

                #---------------------------------
                # power on volume in reset host
                #---------------------------------
                obj_log.debug("Power on the volume in powered off host")
                server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
                rtn = self.utils.poweron_all_vm_by_wildcard(self.vcs, self.all_config['testbed_name'])
                obj_log.debug(rtn)
                obj_utils.progressbar_k(300)

                #------------------------------------------------------
                # sharestorage poweron fail need to remove second disk
                #------------------------------------------------------
                vms = self.utils.get_vm_list_by_wildcard(self.vcs, self.all_config['testbed_name'])
                for vmname in vms :
                    vm = server.get_vm_by_name(vmname)
                    if not vm.is_powered_on():
                        self.utils.removeSecondDisk(server, vmname)
                        obj_utils.progressbar_k(20)
                        self.utils.poweron_vm(server, vmname)
                        obj_utils.progressbar_k(200)


                #------------------------------------
                # If amc in the reset host Login amc
                #------------------------------------
                self.tools = utils.Tools(self.amc_ip)

                #------------------------------------
                # check ibd get back
                # for multi-type volume, need to check all
                # the volumes' ibd status
                #------------------------------------
                #------------------------------------
                self._check_all_volume_mdstat()
                #------------------------------------
                # get ha group after failover
                #------------------------------------
                obj_log.info("===============check ha status============")
                self._check_ha_status(node_ip)
                group2 = self.utils.getHAResourceMap(node_ip)
                obj_log.debug("group2 %s" % group2)
                rtn = self.utils.compareResourceMap(group1, group2)
                obj_log.debug(rtn)

                self._disconnect(server)

    def _poweroff_one_site_host(self, obj):
        obj_log.debug("start poweroff one site host test")
        self.vcs2 = eval(self.utils.get_config('testcase', 'vcs2', self.configfile))
        self.host_ip_name_dict = eval(self.utils.get_config('testcase', 'host_ip_name_dict', self.configfile))
        site_host_dict = self.tools.get_site_host_dict()
        site_tag = random.choice(site_host_dict.keys())
        # get ha group resource map before action
        nodes = self._node_operate(obj)
        for node in nodes:
            obj_log.debug(node['eth0'])
            node_ip = node['eth0']
            node_host = node['host']
        self.utils.ha_nodes_dict = {}
        self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(node_ip)

        for site_tag in site_host_dict:
            if node_host in site_host_dict[site_tag]:
                break

        group1 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group1 %s" % group1)

        poweroff_host_name_list = []
        for host_ip in site_host_dict[site_tag]:
            poweroff_host_name_list.append(self.host_ip_name_dict[host_ip])
        vc = self.vcs2.keys()[0]
        vc_username = self.vcs2[vc]['username']
        vc_password = self.vcs2[vc]['password']
        server = self._conn_vcenter(vc, vc_username, vc_password)
        self.multi.poweroff_vm(server, poweroff_host_name_list)
        obj_log.debug("power off done")
        self.utils.progressbar_k(200)
        #--------------------------------------------------------------------------------
        # if amc not in poweroff host get ha group before poweron volume
        #--------------------------------------------------------------------------------
        ret1 = self.utils.is_reachable(self.amc_ip.encode('utf8'))
        ret2 = self.utils.is_reachable(node_ip.encode('utf8'))
        amc_num = int(self.utils.get_config('main', 'amc_num', self.configfile))
        if ret1 or amc_num != 1:
            self._check_ha_status(node_ip)
            obj_log.debug(self.utils.checkHAStatus(node_ip))
            tms = 5
            while tms:
                group2 = self.utils.getHAResourceMap(node_ip)
                obj_log.debug("group2 %s" % group2)
                if group2.values() != ['']:
                    rtn = self.utils.compareResourceMap(group1, group2)
                    obj_log.debug(rtn)
                    break
                self.utils.progressbar_k(60)
                tms -= 1
                if tms == 0:
                    raise self.customError("failover failed, ha does not get the resourses")

        self.multi.poweron_vm(server, poweroff_host_name_list)
        obj_log.debug("power on done, wait for host boot up")
        self.utils.progressbar_k(200)
        #---------------------------
        # try to connect host
        #---------------------------
        for host_name in poweroff_host_name_list:
            self._check_vm_health(server, host_name)
        # check_vm_health is just check power status and ping the host ip
        # For virtual host it may not connect the vCenter so add delay
        self.utils.progressbar_k(300)
        self._disconnect(server)

        #---------------------------------
        # power on volume in reset host
        #---------------------------------
        obj_log.debug("Power on the volume in powered off host")
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        rtn = self.utils.poweron_all_vm_by_wildcard(self.vcs, self.all_config['testbed_name'])
        obj_log.debug(rtn)
        obj_utils.progressbar_k(300)

        #------------------------------------------------------
        # sharestorage poweron fail need to remove second disk
        #------------------------------------------------------
        vms = self.utils.get_vm_list_by_wildcard(self.vcs, self.all_config['testbed_name'])
        for vmname in vms :
            vm = server.get_vm_by_name(vmname)
            if not vm.is_powered_on():
                self.utils.removeSecondDisk(server, vmname)
                obj_utils.progressbar_k(20)
                self.utils.poweron_vm(server, vmname)
                obj_utils.progressbar_k(200)


        #------------------------------------
        # If amc in the reset host Login amc
        #------------------------------------
        self.tools = utils.Tools(self.amc_ip)

        #------------------------------------
        # check ibd get back
        # for multi-type volume, need to check all
        # the volumes' ibd status
        #------------------------------------
        #------------------------------------
        self._check_all_volume_mdstat()
        #------------------------------------
        # get ha group after failover
        #------------------------------------
        obj_log.info("===============check ha status============")
        self._check_ha_status(node_ip)
        group2 = self.utils.getHAResourceMap(node_ip)
        obj_log.debug("group2 %s" % group2)
        rtn = self.utils.compareResourceMap(group1, group2)
        obj_log.debug(rtn)

        self._disconnect(server)

    def _reset_amc(self, obj):
        amc_name = self._get_amc_name()
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        self.utils.reboot_vm(server, amc_name)
        obj_log.debug("reboot " + amc_name + " done, wait for AMC boot up")
        self.utils.progressbar_k(60)
        #---------------------------
        # try to connect amc
        #---------------------------
        self._check_vm_health(server, amc_name)
        self.tools = utils.Tools(self.amc_ip)
        self._disconnect(server)
        return True

    def _reset_master_amc(self):
        amc_name_list = self._get_amc_name_list()
        amc_name_list.sort()
        obj_log.debug(amc_name_list)

        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        self.utils.reset_vm(server, amc_name_list[0])
        obj_log.debug("reset " + amc_name_list[0] + " done, wait for AMC boot up")
        self.utils.progressbar_k(60)
        #---------------------------
        # try to connect amc
        #---------------------------
        self._check_vm_health(server, amc_name_list[0])
        master_amc_ip = self.utils.get_ip_by_vmname(server, amc_name_list[0])
        self.tools = utils.Tools(master_amc_ip)
        self._disconnect(server)
        return True

    def _reset_slave_amc(self):
        amc_name_list = self._get_amc_name_list()
        amc_name_list.sort()
        obj_log.debug(amc_name_list)

        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        self.utils.reset_vm(server, amc_name_list[1])
        obj_log.debug("reset " + amc_name_list[1] + " done, wait for AMC boot up")
        self.utils.progressbar_k(60)
        #---------------------------
        # try to connect amc
        #---------------------------
        self._check_vm_health(server, amc_name_list[1])
        slave_amc_ip = self.utils.get_ip_by_vmname(server, amc_name_list[1])
        self.tools = utils.Tools(slave_amc_ip)
        self._disconnect(server)
        return True

    def _poweroff_master_amc(self, obj):
        amc_name_list = self._get_amc_name_list()
        amc_name_list.sort()
        obj_log.debug(amc_name_list)

        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        self.utils.poweroff_vm(server, amc_name_list[0])
        self.utils.progressbar_k(60)
        self._disconnect(server)

    def _poweroff_slave_amc(self, obj):
        amc_name_list = self._get_amc_name_list()
        amc_name_list.sort()
        obj_log.debug(amc_name_list)

        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        self.utils.poweroff_vm(server, amc_name_list[1])
        self.utils.progressbar_k(60)
        self._disconnect(server)

    def _poweron_all_amc(self, obj):
        amc_name_list = self._get_amc_name_list()
        amc_name_list.sort()
        obj_log.debug(amc_name_list)
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        self.multi.poweron_vm(server, amc_name_list)
        self.utils.progressbar_k(60)
        #---------------------------
        # try to connect amc
        #---------------------------
        self._check_vm_health(server, amc_name_list[0])
        self.tools = utils.Tools(self.amc_ip)
        self._disconnect(server)

    def login_alive_amc(self):
        amc_name_list = self._get_amc_name_list()
        # login the amc which is power on
        for amc in amc_name_list:
            vm_obj = server.get_vm_by_name(amc)
            if vm_obj.is_powered_on():
                ip = vm_obj.get_property('ip_address', from_cache=False)
                self.tools = utils.Tools(ip)

    def get_slave_amc_ip(self):
        amc_name_list = self._get_amc_name_list()
        for amc in amc_name_list:
            server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
            vm = server.get_vm_by_name(amc)
            ip = vm.get_property('ip_address', from_cache=False)
            if self.amc_ip not in ip:
                return ip

    def _shutdown_4svm(self, obj):
        # nodes = self._node_operate(obj)
        # obj_log.debug(nodes)
        # tms = 4
        # for k in self.all_server_dict.keys():
        #     for node in nodes:
        #         if node['containername'] in self.all_server_dict[k]:
        #             rtn = self.utils.shutdown_vm(k, node['containername'])
        #             tms -= 1
        #             if tms == 0:
        #                 break
        # self.utils.progressbar_k(60)
        # return rtn
        nodes = self._node_operate(obj)
        all_raid1_info = self.utils.get_raid1_info(self.amc_ip)
        obj_log.debug("==================================")
        obj_log.debug(all_raid1_info)
        # poweroff_svm_dict = {}
        # for node in nodes:
        #     for k in self.all_server_dict.keys():
        #         poweroff_svm_dict[k] = []
        #         for raid1_info in all_raid1_info[node['name']].values():
        #             for sv in raid1_info:
        #                 if sv in self.all_server_dict[k]:
        #                     poweroff_svm_dict[k].append(sv)
        #                     break
        for node in nodes:
            for server in self.all_server_dict.keys():
                poweroff_svm_list = []
                md_flag = 0
                k = 0
                # get the two svm which used to make raid1 for read cache and write cache
                md_list = all_raid1_info[node['name']].keys()
                md_list.sort()
                if len(md_list) < 4:    # compatible there is read cache or not
                    for md in md_list:
                        if k == 0:
                            poweroff_svm_list.extend(all_raid1_info[node['name']][md])
                            k = k + 1
                        else:
                            poweroff_svm_list.append(all_raid1_info[node['name']][md][0])

                else:
                    cache_raid1_list = all_raid1_info[node['name']][md_list[-1]]
                    for md in md_list[:-1]:
                        if not list(set(cache_raid1_list).difference(set(all_raid1_info[node['name']][md]))):
                            md_flag = 1

                    if md_flag:
                        for md in md_list[:-1]:
                            if not list(set(cache_raid1_list).difference(set(all_raid1_info[node['name']][md]))):
                                poweroff_svm_list.append(cache_raid1_list[0])
                            else:
                                if k == 0:
                                    poweroff_svm_list.extend(all_raid1_info[node['name']][md])
                                    k = k + 1
                                else:
                                    poweroff_svm_list.append(all_raid1_info[node['name']][md][0])
                    else:
                        for md in md_list[:-1]:
                            if all_raid1_info[node['name']][md][0] not in cache_raid1_list and all_raid1_info[node['name']][md][1] not in cache_raid1_list:
                                poweroff_svm_list.extend(all_raid1_info[node['name']][md])
                            else:
                                for sv in all_raid1_info[node['name']][md]:
                                    if sv in cache_raid1_list and k == 0:
                                        poweroff_svm_list.append(sv)
                                        k = k + 1
                                        break
                                    elif sv not in cache_raid1_list and k != 0:
                                        poweroff_svm_list.append(sv)


                poweroff_rtn = self.multi.poweroff_vm(server, poweroff_svm_list)
                if poweroff_rtn == False:
                    return False
        return True

    def _poweroff_one_site_svm(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)

        site_host_dict = self.tools.get_site_host_dict()
        site_tag = random.choice(site_host_dict.keys())
        obj_log.debug(site_tag)
        for k in self.all_server_dict.keys():
            for node in nodes:
                if node['host'] in site_host_dict[site_tag]:
                    rtn = self.utils.poweroff_vm(k, node['containername'])
        self.utils.progressbar_k(60)
        return rtn

    # poweroff one site vm include volume ha service vm usx
    def _poweroff_one_site_vm(self, obj):
        poweroff_list = []
        amc_num = int(self.utils.get_config('main', 'amc_num', self.configfile))
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)

        site_host_dict = self.tools.get_site_host_dict()
        # site_tag = random.choice(site_host_dict.keys())
        # obj_log.debug(site_tag)

        all_node_info = self.tools.get_all_node_info()
        svm_info = all_node_info['service_vm_info']
        ha_info = all_node_info['ha_info']
        volume_info = all_node_info['volume_info']

        for site in site_host_dict:
            for volume in volume_info.keys():
                if volume_info[volume]['host'] in site_host_dict[site]:
                    site_tag = site
                    poweroff_list.append(volume_info[volume]['containername'])

        for svm in svm_info.keys():
            if svm_info[svm]['host'] in site_host_dict[site_tag]:
                poweroff_list.append(svm_info[svm]['containername'])

        # for ha in ha_info.keys():
        #     if ha_info[ha]['host'] in site_host_dict[site_tag]:
        #         poweroff_list.append(ha_info[ha]['containername'])

        amc_name_list = self._get_amc_name_list()
        if amc_num > 1:
            for amc in amc_name_list:
                amc_host_ip = self.utils.get_vm_host_ip(server, amc)
                if amc_host_ip in site_host_dict[site_tag]:
                    poweroff_list.append(amc)


        rtn = self.multi.poweroff_vm(server, poweroff_list)
        self.utils.progressbar_k(120)
        # login the amc which is power on
        for amc in amc_name_list:
            vm_obj = server.get_vm_by_name(amc)
            if vm_obj.is_powered_on():
                ip = vm_obj.get_property('ip_address', from_cache=False)
                self.tools = utils.Tools(ip)
        return rtn


    def _check_ibd(self, ip, num):
        for k in range(5):
            try:
                mdstat = self.utils.ssh_cmd(ip, 'poweruser', 'poweruser', "cat /proc/mdstat")['stdout']
                break
            except Exception as e:
                obj_log.debug(str(e))
                self.utils.progressbar_k(10)
        find_rtn = re.findall(r'(?P<recovery>\[=*>*\.*\]).*?recovery = \s*\d+\.\d+%', mdstat)
        if not find_rtn:
            obj_log.debug('Check IBD info: \n' + mdstat + '\n' + '*'*100 + '\n')
            rtn_list = re.findall(r'algorithm.*?\[(?P<ibd>_*U*_*U*_*)\]', mdstat)
            rtn_list_count = []
            for rtn in rtn_list:   # raidy++ change the method of check ibd
                rtn_list_count.append(rtn.count("U"))
            obj_log.debug(rtn_list_count)
            return (num in rtn_list_count)
        else:
            self.utils.progressbar_k(30)
            return self._check_ibd(ip, num)

    def get_ibd_name(self, ip, username="poweruser", password="poweruser"):
        cmd = '/usr/local/bin/ibdmanager -r a -s get | grep devname'
        retval =[]

        ret = obj_utils.ssh_cmd(ip, username, password, cmd)
        if ret['error'] != None:
            obj_log.debug(ret['error'])
            return False
        else:
            p = 'devname:.*/(.*)'
            retval=re.findall(p,ret['stdout'])

            return retval

    def get_ibd_count(self, ip, username="poweruser", password="poweruser"):
        cmd = '/usr/local/bin/ibdmanager -r a -s get | grep devname | wc -l'

        ret = obj_utils.ssh_cmd(ip, username, password, cmd)
        if ret['error'] != None:
            obj_log.debug(ret['error'])
            return False
        else:
            return int(ret['stdout'])

    def check_raid_sync_progress(self, ibd_name, raid_info):
        obj_log.debug("check_raid_sync_progress start ***")

        for name in ibd_name:
            if name+'p' not in raid_info:
                return False

        if ' active raid5' not in raid_info:
            return False
        if '(F)' in raid_info:
            return False
        if 'speed' not in raid_info:
            return False
        if 'speed=0K/sec' in raid_info:
            return False

        obj_log.debug("check_raid_sync_progress end ***")
        return True

    def check_raid(self, out, raid='raid5'):
        if raid == 'raid5' or raid == 'raid1':
            tmp = 'active ' + raid

            if tmp not in out:
                return False

            for item in out.split(':'):
                if tmp in item:
                    p = "\[(\d*)/(\d*)\]"
                    m = re.search(p, item)
                    if m != None:
                        if int(m.group(2)) != int(m.group(1)):
                            obj_log.error("Result of verifying %s is: %s" % (raid, False))
                            return False

        elif raid == 'raid15':
            tmp_list = ['active raid1', 'active raid5']

            for tmp in tmp_list:
                for item in out.split(':'):
                    if tmp in item:
                        p = "\[(\d*)/(\d*)\]"
                        m = re.search(p, item)
                        if m != None:
                            if int(m.group(2)) != int(m.group(1)):
                                obj_log.error("Result of verifying %s is: %s" % (raid, False))
                                return False

        return True

    def _check_raid_lose(self, obj, username='poweruser', password='poweruser'):
        nodes = self._node_operate(obj)
        cmd = 'ibdmanager -r a -s get |grep "state"| grep -v "state:working" | wc -l'

        volume_ip_list = []
        for node in nodes:
            obj_log.info('Check ' + node['name'] + ' raid lose start...')
            time_flag = 0
            while True:
                if time_flag > 600:
                    obj_log.error('check raid lose timeout.')
                    return False
                count = obj_utils.ssh_cmd(node['eth0'], username, password, cmd)
                if count['error'] != None:
                    return False
                if int(count['stdout']) > 0:
                    volume_ip_list.append(node['eth0'])
                    break
                else:
                    time_flag = time_flag + 1
                    time.sleep(1)

        rtn = self.multi_verify_raid(volume_ip_list,True)
        if rtn == False:
            obj_log.info('Check raid lose done.')
            return True
        else:
            return False

    def verify_raid(self, ip, flag=False, username="poweruser", password="poweruser"):
        obj_log.info('=====verify_raid: %s start =====' % ip)
        ibd_count = self.get_ibd_count(ip)
        ibd_name = self.get_ibd_name(ip)

        pattern = '/exports/\w+.+ type dedup'
        pattern1 = '/\w+.+ type dedup'
        cmd = 'mount'
        ret = obj_utils.ssh_cmd(ip, username, password, cmd)
        if ret['error'] != None:
            obj_log.error(ret['error'])
            return False

        mount_info = ret['stdout']

        m = re.search(pattern, mount_info)
        m1 = re.search(pattern1, mount_info)
        if m == None or m1 == None:
            obj_log.error('m=%s m1=%s can not find type dedup in mount point') % (m, m1)
            return False

        mountpoint = m.group()[:-11]
        mountpoint_count = len(mountpoint)
        section = mountpoint_count + 11 + 4
        mount_src = m1.group()[:-section]

        check_mdstat_cmd = 'cat /proc/mdstat'
        rtn = obj_utils.ssh_cmd(ip, username, password, check_mdstat_cmd)

        md_stat = rtn['stdout']

        cmd = ('cat %s | python -m json.tool | grep -i "%s"' % (ATLAS_JSON, RAID1_ENABLED))
        ret = obj_utils.ssh_cmd(ip, username, password, cmd)
        cmd1 = 'python -m json.tool %s | grep -i %s' % (ATLAS_JSON, 'stretchcluster')
        ret1 = obj_utils.ssh_cmd(ip, username, password, cmd1)
        if 'true' in ret['stdout'].lower():
            raid_type = 'raid1'
        elif 'true' in ret1['stdout'].lower():
            raid_type = 'raid15'
        else:
            raid_type = 'raid5'

        j = 1
        g = 1
        synctimes = 300
        while True:
            #ioping disk
            ioping_cmd = '/usr/local/bin/ioping -A -D -c 3 -s 512 ' + mount_src
            obj_log.info('%s:%s' % (ip,ioping_cmd))
            ret1 = obj_utils.ssh_cmd(ip, username, password, ioping_cmd)
            time.sleep(10)

            ret1 = obj_utils.ssh_cmd(ip, username, password, check_mdstat_cmd)
            obj_log.info(ret1['stdout'])

            verify_ret = self.check_raid(ret1['stdout'], raid_type)

            if verify_ret == True:
                g = g + 1
                if g > 3:
                    obj_log.info('=====Verify_raid: %s end =====' % ip)
                    return True
            else:
                g = 1
                #check raid wether sync or not
                ret = self.check_raid_sync_progress(ibd_name, ret1['stdout'])

                if not ret:
                    j = j + 1
                else:
                    j = 1

                if flag == False:
                    obj_log.info('Retry %s times to check raid sync state -> %s time(s) the result are %s' % (synctimes, j-1, ret))
                    if j > synctimes:
                        return False
                else:
                    obj_log.info('Retry 3 times to check raid state -> %s time(s) the result are %s' % (j-1, ret))
                    if j > 3:
                        return False


    def multi_verify_raid(self, ip_list, flag=False):
        thread_list = []
        obj_log.debug('ip_list %s' % ip_list)
        for ip in ip_list:
            t = self.Multi_verify_raid(ip, self.configfile, flag)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            ret = thread.get_return()
            if ret == False:
                return False
            else:
                continue

        return True

    def _check_mdstat(self, obj, username='poweruser', password='poweruser'):
        obj_log.info('check_mdstat ' + obj[0] + ' start ***')
        nodes = self._node_operate(obj)
        if nodes == None:
            return False

        volume_ip_list = []
        ATLAS_JSON = '/etc/ilio/atlas.json'
        retVal = False

        for node in nodes:
            obj_log.info('Check ' + node['name'] + ' raid status start...')
            if 'SIMPLE' in node['type']:
                continue
            elif not obj_utils.is_reachable(node['eth0']):
                continue
            elif node['type'] == 'ALL_FLASH': # skip check for all flash with pure shared storage
                cmd = ('cat %s | python -m json.tool | grep -i "plandetail"' % ATLAS_JSON)
                ret = obj_utils.ssh_cmd(node['eth0'], username, password, cmd)
                result = ret['stdout']
                if result:
                    result = result.strip() # remove spaces of cmd returned result
                    result = '{' + result.rstrip(',') + '}' # construct json string; removing the trailing comma
                    plandetail = json.loads(result)
                    detail_dict = json.loads(plandetail['plandetail'])
                    if detail_dict.has_key('subplans'):
                        if detail_dict['subplans']:
                            if detail_dict['subplans'][0].has_key('raidbricks'):
                                if not detail_dict['subplans'][0]['raidbricks']:
                                    continue
                                else:
                                    volume_ip_list.append(node['eth0'])

            else:
                volume_ip_list.append(node['eth0'])

        for volumeIP in volume_ip_list:
            obj_log.info('Check volume %s ibd connected status start...' % volumeIP)
            for i in range(180):
                cmd = 'ibdmanager -r a -s get |grep "state"| grep -v "state:working" | wc -l'
                count = obj_utils.ssh_cmd(volumeIP, username, password, cmd)
                if count['error'] != None:
                    retVal = False
                    break
                obj_log.error('Count of disconnected ibd server: %s' % count['stdout'])
                if int(count['stdout']) > 1:
                    retVal = True
                    key = ''
                    cmd = 'ibdmanager -r a -s get'
                    retval = obj_utils.ssh_cmd(volumeIP, username, password, cmd)
                    for item in retval['stdout'].split('Service'):
                        if 'state:working' not in item:
                            p = "ip:([\d|\.]*)"
                            m = re.search(p, item)
                            if m != None:
                                if key == '':
                                    key = m.group(1)
                                    continue
                                else:
                                    if key != m.group(1):
                                        retVal = False
                                        time.sleep(20)
                                        break
                else:
                    retVal = True
                    break
            else:
                retVal = False

            if retVal == True:
                obj_log.info('Check volume %s ibd connected status is %s' % (volumeIP, retVal))
            elif retVal == False:
                obj_log.error('Check volume %s ibd connected status is %s' % (volumeIP, retVal))
                break

        if retVal == True:
            retVal = self.multi_verify_raid(volume_ip_list)
        if not volume_ip_list:
            retVal = True

        obj_log.info('check_mdstat end ***')
        if retVal == True:
            obj_log.info('Check ' + node['name'] + ' raid status done.')
        else:
            raise self.customError('Check ' + node['name'] + ' raid status failed.')
            return retVal

    def _check_all_volume_mdstat(self):
        volume_info = self.tools.get_all_node_info()['volume_info']
        for volume in volume_info.keys():
            volume_type = volume_info[volume]['type']
            volume_type_temp = VOLUME_TYPE_DICT[volume_type]
            obj_list = ["'vols'[" + volume_type_temp + "]"]
            self._check_mdstat(obj_list)
    
    def _get_ha_num(self):
        all_node_info = self.tools.get_all_node_info()
        ha_list = self._get_ha_list(all_node_info)[0]
        ha_numbers = len(ha_list)
        return ha_numbers

    def _check_ha_num(self, obj):
        ha_numbers = self._get_ha_num()
        if ha_numbers == int(obj[1]):
            obj_log.debug("ha numbers are correct")
            return True
        else:
            raise self.customError("ha numbers are in correct")
            return False

    def _check_online_node_number(self, obj):
        obj_log.debug("The expected nodes number are %s" % obj[1])
        tms = 10
        while tms:
            online_node_number = self._get_online_node_number(obj)
            if int(obj[1]) == online_node_number:
                obj_log.debug("The online node number is match")
                break

            self.utils.progressbar_k(30)
            tms -= 1
            if tms == 0:
                raise self.customError("The online node number is not match, Please check!")
        return True

    def _check_offline_node_number(self, obj):
        obj_log.debug("The expected nodes number are %s" % obj[1])
        tms = 10
        while tms:
            offline_node_number = self._get_offline_node_number(obj)
            if int(obj[1]) == offline_node_number:
                obj_log.debug("The offline node number is match")
                break

            self.utils.progressbar_k(30)
            tms -= 1
            if tms == 0:
                raise self.customError("The offline node number is not match, Please check!")
        return True

    def _get_ha_group_info(self, ip):
        self.utils.ha_nodes_dict = self.utils.getHAGroupInfo(ip)
        obj_log.debug(self.utils.ha_nodes_dict)
        group1 = self.utils.getHAResourceMap(ip)
        return group1


    def _compare_resource_map(self, group1, group2):
        if group1 and group2:
            rtn = self.utils.compareResourceMap(group1, group2)
            obj_log.debug(rtn)
            if rtn == {}:
                obj_log.warning("group1 {} and group2 {} are the same".format(group1, group2))
                return False
            else:
                obj_log.info("resource has change between group1 and group2")
                return True
        raise self.customError("group1 or group2 is empty please check!")

     #kezhang
     #get enable volume ha number
    def _check_ha_Group_num(self,obj):

        nodes = self._node_operate(obj)
        obj_log.debug("nodes %s" % nodes)

        for k in self.all_server_dict.keys():
            for node in nodes:
                node_eth0 = node['eth0']
                if node_eth0 != '':
                     ha_number=self.utils.getHAOnlineNodes(node_eth0)
                     obj_log.debug(ha_number)
                     if len(ha_number)-1 == int(obj[1]):
                        obj_log.debug("ha numbers are correct")
                        return True
                     else:
                        raise self.customError("HA number is not correct")
                        return False
                else:
                    raise self.customError("eth0 is null")
                    return False

    def conf_hypervisors(self):
        all_config = self.all_config
        obj_log.debug('Configurator hypervisors start...')
        # configurator hypervisors
        conf_hypervisors_rtn = self.tools.conf_hypervisors(all_config['vcs'], all_config['platform'])
        if conf_hypervisors_rtn == True:
            obj_log.debug('Configurator hypervisors done.\n')
        else:
            obj_log.debug('conf_hypervisors_rtn', conf_hypervisors_rtn)
            return False

        if all_config['stretch_cluster'] == 'true':
            obj_log.debug('Config stretch cluster start...')
            rtn = self.tools.set_stretch_cluster('true')
            rtn = self.tools.set_raid_plan('true')
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False

            rtn = self.tools.create_site_tag()
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False

            rtn = self.tools.set_tiebreakerip(all_config['tiebreaker_ip'])
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False

            rtn = self.tools.set_sharedstorageforvmdisk('false')
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False

            rtn = self.tools.conf_site_group(all_config['vcs'])
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False

            obj_log.debug('Config stretch cluster done.')

        obj_log.debug('Configurator datastore start...')
        conf_storage_rtn = self.tools.conf_storage(all_config['vcs'], all_config['disk_allocation'],
                                                  all_config['flash_allocation'], all_config['platform'])

        if conf_storage_rtn == True:
            obj_log.debug('Configurator datastore done.\n')
        else:
            obj_log.debug('conf_storage_rtn', conf_storage_rtn)
            return False

    def delete_hypervisors_config(self):
        return self.tools.delete_storage_profiles() and self.tools.delete_hypervisors_profiles()


    def conf_network(self):
        all_config = self.all_config
        obj_log.debug('Configurator network start...')
        # configurator network profiles
        conf_network_rtn = self.tools.conf_network(all_config['vcs'], all_config['ip_range'])
        if conf_network_rtn == False:
            return False
        obj_log.debug('Configurator network done.\n')

        obj_log.debug('Configurator network mapping start...')
        # configurator network profiles mapping
        conf_network_mapping_rtn = self.tools.conf_network_mapping(all_config['vcs'], all_config['platform'],
                                                                  conf_network_rtn)
        if conf_network_mapping_rtn == True:
            obj_log.debug('Configurator network mapping done.\n')
        else:
            obj_log.debug('Configurator network mapping fail.')
            return False

    def delete_networkprofile(self):
        networkprofile_uuid_dict = self.tools.get_networkprofile_uuid()
        for network_dict in networkprofile_uuid_dict.values():
            for network_uuid in network_dict.values():
                ret = self.tools.delete_network_profile(network_uuid)
                if ret == True:
                    obj_log.info('Delete network {0} profile successfully.'.format(network_uuid))
                else:
                    obj_log.debug(enable_ha_rtn)
                    raise self.customError("delete network {0} profile {1} failed, please check!".format(network_uuid))

    def _re_deploy_volume(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        elif obj[0] == "'vols'[infra]":
            volumetype = 'INFRA'
        for volume_temp in self.all_config['volume_config']:
            volumesize = self.all_config['volume_config'][volume_temp]['volumesize']
            sharestorageforvmdisk = self.all_config['volume_config'][volume_temp]['prefersharedstorageforvmdisk']
            exportfstype = self.all_config['volume_config'][volume_temp]['exportfstype']
            fs_sync = self.all_config['volume_config'][volume_temp]['fs_sync']
            raidtype = self.all_config['volume_config'][volume_temp]['raidtype']
            if volumetype == 'HYBRID' == self.all_config['volume_config'][volume_temp]['volumetype']:
                preferflashformemory = self.all_config['volume_config'][volume_temp]['preferflashformemory']
                prefersharedstorageforexports = self.all_config['volume_config'][volume_temp]['prefersharedstorageforexports']
                deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, prefersharedstorageforexports=prefersharedstorageforexports, \
                    preferflashformemory=preferflashformemory, sharestorageforvmdisk=sharestorageforvmdisk, usx_version=self.all_config['usx_version'], robo=self.all_config['robo'],\
                    exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
            elif volumetype == 'ALL_FLASH' == self.all_config['volume_config'][volume_temp]['volumetype']:
                prefersharedstorageforexports = self.all_config['volume_config'][volume_temp]['prefersharedstorageforexports']
                deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, prefersharedstorageforexports=prefersharedstorageforexports,\
                    sharestorageforvmdisk=sharestorageforvmdisk, usx_version=self.all_config['usx_version'], robo=self.all_config['robo'],\
                    exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
            elif volumetype == 'MEMORY' == self.all_config['volume_config'][volume_temp]['volumetype']:
                deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, sharestorageforvmdisk=sharestorageforvmdisk, \
                    usx_version=self.all_config['usx_version'], robo=self.all_config['robo'], exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
            elif volumetype == 'INFRA' == self.all_config['volume_config'][volume_temp]['volumetype']:
                deploy_rtn = self.tools.deploy_infrastructure(self.all_config['user'], self.all_config['testbed_name'], self.all_config['hyperconverge_cluster'], sharestorageforvmdisk=sharestorageforvmdisk, \
                    usx_version=self.all_config['usx_version'],stretch_cluster='false',robo=self.all_config['robo'],exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)


        if deploy_rtn == True:
            obj_log.debug('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_volume_simple(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        elif obj[0] == "'vols'[simplehybrid]":
            volumetype = 'SIMPLE_HYBRID'
        elif obj[0] == "'vols'[simpleflash]":
            volumetype = 'SIMPLE_FLASH'
        elif obj[0] == "'vols'[simplememory]":
            volumetype = 'SIMPLE_MEMORY'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize)

        if deploy_rtn == True:
            obj_log.debug('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")


    def _re_deploy_simple_memory_enable_snapclone(self, obj):
        volumesize = obj[1]
        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], "SIMPLE_MEMORY", volumesize, enable_snapclone="true")

        if deploy_rtn == True:
            obj_log.debug('Deploy simple memory with snapclone enabled successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_simple_memory_disable_snapclone(self, obj):
        volumesize = obj[1]
        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], "SIMPLE_MEMORY", volumesize, enable_snapclone="false")

        if deploy_rtn == True:
            obj_log.debug('Deploy simple memory with snapclone disabled successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")


    def _re_deploy_volume_share(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, prefersharedstorageforexports='true', \
            usx_version=self.all_config['usx_version'], robo=self.all_config['robo'])


        if deploy_rtn == True:
            obj_log.info('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_volume_share_only(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, prefersharedstorageforexports='true', \
            sharestorageforvmdisk='false', usx_version=self.all_config['usx_version'], robo=self.all_config['robo'])

        if deploy_rtn == True:
            obj_log.info('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")      

    def _re_deploy_stretch_cluster_volume(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, stretch_cluster='true', usx_version=self.all_config['usx_version'], \
            robo=self.all_config['robo'])

        if deploy_rtn == True:
            obj_log.info('Deploy stretch_cluster ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_robo_stretch_cluster_volume(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, stretch_cluster='true', usx_version=self.all_config['usx_version'], \
            robo='true')

        if deploy_rtn == True:
            obj_log.info('Deploy stretch_cluster ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_robo_volume(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, stretch_cluster='false', usx_version=self.all_config['usx_version'], \
            robo='true')

        if deploy_rtn == True:
            obj_log.info('Deploy stretch_cluster ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_hyperconverge(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        vc_ip = self.vcs.keys()[0]
        datacenter = self.vcs[vc_ip]['dcs'].keys()[0]
        hyperconverge_cluster = self.vcs[vc_ip]['dcs'][datacenter][0]['clustername']
        hyperconvergedvolume = 'true'

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, hyperconverge_cluster, hyperconvergedvolume, \
            only_infrastructure='false', stretch_cluster='false', usx_version=self.all_config['usx_version'], robo=self.all_config['robo'])
        if deploy_rtn == True:
            obj_log.info('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_hyperconverge_share(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        vc_ip = self.vcs.keys()[0]
        datacenter = self.vcs[vc_ip]['dcs'].keys()[0]
        hyperconverge_cluster = self.vcs[vc_ip]['dcs'][datacenter][0]['clustername']
        hyperconvergedvolume = 'true'

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, hyperconverge_cluster, hyperconvergedvolume, \
            only_infrastructure='false', stretch_cluster='false',prefersharedstorageforexports='true', usx_version=self.all_config['usx_version'], robo=self.all_config['robo'])
        if deploy_rtn == True:
            obj_log.info('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_stretch_cluster_hyperconverge(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        vc_ip = self.vcs.keys()[0]
        datacenter = self.vcs[vc_ip]['dcs'].keys()[0]
        hyperconverge_cluster = self.vcs[vc_ip]['dcs'][datacenter][0]['clustername']
        hyperconvergedvolume = 'true'

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, hyperconverge_cluster, hyperconvergedvolume, \
            only_infrastructure='false', stretch_cluster='true', usx_version=self.all_config['usx_version'], robo=self.all_config['robo'])
        if deploy_rtn == True:
            obj_log.info('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_volume_disable_snapshot(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, snapshot='false', usx_version=self.all_config['usx_version'], \
            robo=self.all_config['robo'])


        if deploy_rtn == True:
            obj_log.info('Deploy ' + volumetype + ' successfully.')
            return True
        else:
            obj_log.debug("Deployed failed")
            return False
            raise self.customError("Deployed failed")

    def _re_deploy_raid6_volume(self, obj):
        obj_log.debug(obj[0])
        if obj[0] == "'vols'[hybrid]":
            volumetype = 'HYBRID'
        elif obj[0] == "'vols'[memory]":
            volumetype = 'MEMORY'
        elif obj[0] == "'vols'[flash]":
            volumetype = 'ALL_FLASH'
        volumesize = int(obj[1])

        deploy_rtn = self.tools.deploy_volume(self.all_config['user'], self.all_config['testbed_name'], volumetype, volumesize, usx_version=self.all_config['usx_version'], \
            raidtype='RAID_6')

    def _delete_volume(self, obj):
        nodes = self._node_operate(obj)
        for k in self.all_server_dict.keys():
            for node in nodes:
                node_name = node['containername']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("delete<" + node_name + "> start.")
                    delete_rtn = self.tools.delete_volume_by_api(volume_resource_name, 'true')
                    if delete_rtn == True:
                        obj_utils.progressbar_k(10)
                        obj_log.info(volume_resource_name + ' delete successfully.')
                    else:
                        obj_log.debug(delete_rtn)
                        return False
        return True

    # usx-53277, usx-53278, delete infra which has hyperconverge
    def _delete_volume_negetive(self, obj):
        nodes = self._node_operate(obj)
        for k in self.all_server_dict.keys():
            for node in nodes:
                node_name = node['containername']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(volume_resource_name)

                    obj_log.debug("delete<" + node_name + "> start.")
                    delete_rtn = self.tools.delete_volume_by_api(
                        volume_resource_name, 'true',
                        force_delete='false',
                        get_err_msg=True)
                    obj_log.debug(delete_rtn)
                    return delete_rtn

    def _delete_volume_has_snapshot_with_disable_forcedelete(self, obj):

        nodes = self._node_operate(obj)
        for k in self.all_server_dict.keys():
            for node in nodes:
                node_name = node['containername']
                if node['containername'] in self.all_server_dict[k]:
                    volume_resource_name = re.sub("/exports/", "", node['mountpoint'])
                    obj_log.debug(volume_resource_name)

        obj_log.debug("delete<" + node_name + "> start.")
        delete_rtn = self.tools.delete_volume_by_api(volume_resource_name, 'true', force_delete='false', get_err_msg=True)
        obj_log.debug(delete_rtn)
        if "There is snapshot under volume resource" in delete_rtn:
            obj_log.info(node_name +
                ' There is snapshot under volume resource')
            return True
        else:
            obj_log.debug(delete_rtn)
            return False


    def _delete_ha(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            ha_container_name = node['containername']
            obj_log.debug(ha_container_name)

            obj_log.debug("delete<" + ha_container_name + "> start.")
            delete_rtn = self.tools.delete_volume_by_api(ha_container_name, 'false')
            if delete_rtn == True:
                obj_utils.progressbar_k(5)
                obj_log.info(ha_container_name + ' delete successfully.')
            else:
                obj_log.debug(delete_rtn)
                return False
        return True

    # this faction is test the only online ha node can not be delete
    def _delete_only_ha(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            ha_container_name = node['containername']
            obj_log.debug(ha_container_name)

        obj_log.debug("delete<" + ha_container_name + "> start.")
        delete_rtn = self.tools.delete_volume_by_api(ha_container_name, 'false', force_delete='true', get_err_msg=True)
        if "only one powered on standby HA node in the cluster, can not delete" in delete_rtn:
            obj_log.info(ha_container_name +
                ' There is only one powered on standby HA node in the cluster, can not delete.')
            return True
        else:
            obj_log.debug(delete_rtn)
            return False

    def _get_volume_snapshot_list(self, volume_resource_name):
        all_snapshot_info = self.tools.get_all_snapshot_info()
        volume_snapshot_list = []
        for snapshot in all_snapshot_info[volume_resource_name]:
            volume_snapshot_list.append(all_snapshot_info[volume_resource_name][snapshot])
            # sorted by ctime(snapshot created time)
            volume_snapshot_list = sorted(volume_snapshot_list, key=itemgetter('ctime'))
        obj_log.debug(volume_snapshot_list)
        return volume_snapshot_list

    def _create_snapshot(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        snapshot_name = obj[1]
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
        obj_log.debug("create <" + volume_resource_name + " ===> " + snapshot_name + "> start.")
        rtn = self.tools.create_snapshot(snapshot_name, volume_resource_name)
        self.utils.progressbar_k(3)
        obj_log.debug(rtn)
        if rtn == True:
            return True
        else:
            raise self.customError("Create snapshot failed")
            return False

    def _multi_create_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            volres_uuid = node["uuid"]
            obj_log.debug(volume_resource_name)
        obj_log.debug("multi create snapclone ===> " + volume_resource_name + "> start.")
        rtn = self.tools.create_snapclone(volres_uuid, True)
        obj_log.debug(rtn)
        return rtn

    def _add_second_disk(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        disk_size = 50 if not obj[1] else int(obj[1])
        server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
        for node in nodes:
            container_name = node['containername']
            obj_log.debug(container_name)
        rtn = self.utils.add_second_disk(server, container_name, disk_size_in_GB=disk_size)
        obj_log.debug(rtn)
        if rtn == True:
            return True
        else:
            return False

    def _create_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            volres_uuid = node["uuid"]
            obj_log.debug(volume_resource_name)
        obj_log.debug("create snapclone ===> " + volume_resource_name + "> start.")
        rtn = self.tools.create_snapclone(volres_uuid)
        self.utils.progressbar_k(3)
        obj_log.debug(rtn)
        if rtn == True:
            return True
        else:
            time.sleep(60)
            obj_log.debug("create second snapclone ===> " + volume_resource_name + "> start.")
            rtn = self.tools.create_snapclone(volres_uuid)
            self.utils.progressbar_k(3)
            obj_log.debug(rtn)
            if rtn:
                return True
            return False


    def _replication_now(self, obj):
        resource = ["'vols'[" + obj[0] + "]"]
        target = ["'vols'[" + obj[1] + "]"]
        schedule = "0 0 0 1/1 * ? *"

        resource_volume_info = self._get_obj_volume_info_for_replication(resource)
        resource_volume_name = resource_volume_info['name']
        resource_volume_uuid = resource_volume_info["volumeresourceuuids"]

        target_volume_info = self._get_obj_volume_info_for_replication(target)
        target_volume_name = target_volume_info['name']
        target_volume_ip = target_volume_info['serviceip']

        try:
            if not self.tools.have_replication_policy(resource_volume_uuid):
                obj_log.debug("setup replication schedule <" + resource_volume_uuid + " ===> " + "> start.")
                rtn = self.tools.schedule_replication(schedule, resource_volume_name, target_volume_ip, target_volume_name)
                obj_log.debug(rtn)
                if rtn == False:
                    return False
            obj_log.debug("replicate <" + resource_volume_uuid + " ===> " + "now" + "> start.")
            rtn = self.tools.replication_now(resource_volume_uuid, target_volume_name, target_volume_ip)
            obj_log.debug(rtn)
            if rtn == True:
                return True
            else:
                raise self.customError("Replication now failed")
                return False
        except Exception:
            obj_log.error(Exception)

    def _fastclone(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            volume_name = node['name']
            name_tem_uuid = self.tools.get_all_name_temp()['fastclone']
            if not name_tem_uuid:
                obj_log.warning("\nNot have fastclone name templete will add a new\n")
                name_tem_uuid = self.tools.add_fastclone_template(self.all_config)

            num = int(obj[1])
            src_vm_name = self.tools.get_vms_by_volume_uuid(node["uuid"])

        return self.tools.fastclone(volume_name, src_vm_name, num, name_tem_uuid)

    def _start_vms_in_volume(self, obj):
        nodes = self._node_operate(obj)
        server = pysphere.VIServer()
        for vc_ip in self.vcs.keys():
            vc_user = self.vcs[vc_ip]['username']
            vc_pwd = self.vcs[vc_ip]['password']
            server.connect(vc_ip, vc_user, vc_pwd)

        for node in nodes:
            vms_list = self.tools.get_vms_by_volume_uuid(node['uuid'])
            rnt = self.multi.poweron_vm(server, vms_list)
            if not rnt:
                obj_log.warning("power on user vms failed!")
        server.disconnect()

    def _teleport_vm(self, obj):
        volume_resource_uuid = obj[0]
        target_volume_uuid = obj[1]

        obj_log.debug("teleport <" + volume_resource_uuid + " ===> " + "now" + "> start.")
        return self.tools.teleport_vm(volume_resource_uuid, target_volume_uuid)

    def _backup_vm(self, obj):
        volume_resource_uuid = obj[0]
        target_volume_uuid = obj[1]

        obj_log.debug("backup <" + volume_resource_uuid + " ===> " + "> start.")
        return self.tools.backup_vm(volume_resource_uuid, target_volume_uuid)

    def _get_node_ip(self, obj):
        nodes = self._node_operate(obj)
        manage_ip = nodes[0]["eth0"]
        storage_ip = nodes[0]["eth1"]
        return (manage_ip, storage_ip)

    def _change_usx_ip(self, obj):
        new_ip = obj[0]
        admin = "admin"
        password = "poweruser"
        dns = None
        if len(obj) > 1:
            dns = obj[1]

        rtn = self.tools.change_usx_ip(new_ip=new_ip, netmask='255.255.0.0', gateway='10.16.0.1', dns=dns)
        usx_version = self.utils.get_usx_version(self.amc_ip)
        if usx_version in ['3.6.0']:
            admin = 'usxadmin'
        self.tools = Tools(new_ip)
        if self.utils.is_poweron(new_ip):
            if not self.tools.retry_to_check_jobstatus_msg("Successfully changed IP address.") and not self.utils.check_amc_status(new_ip):
                return False
            self.utils.progressbar_k(10)
            cmd = "cat /etc/network/interfaces | awk '/address/{print $2}'"
            result = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd)['stdout'].strip()
            print('get message from interfaces is %s' % result)
            if new_ip == result:
                self.amc_ip = new_ip
                return True

    def _change_slave_usx_ip(self, obj):
        amc_slave = self.get_slave_amc_ip()
        self.amc_slave = Tools(amc_slave)
        new_ip = obj[0]
        admin = "admin"
        password = "poweruser"
        dns = None

        if len(obj) > 1:
            dns = obj[1]
        rtn = self.amc_slave.change_usx_ip(new_ip=new_ip, netmask='255.255.0.0', gateway='10.16.0.1', dns=dns)
        usx_version = self.utils.get_usx_version(amc_slave)
        if usx_version in ['3.6.0']:
            admin = 'usxadmin'
        self.amc_slave = Tools(new_ip)
        if self.utils.is_poweron(new_ip):
            if not self.amc_slave.retry_to_check_jobstatus_msg("Successfully changed IP address.") and not self.utils.check_amc_status(new_ip):
                return False
            self.utils.progressbar_k(10)
            cmd = "cat /etc/network/interfaces | awk '/address/{print $2}'"
            result = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd)['stdout'].strip()
            print('get message from interfaces is %s' % result)
            if new_ip == result:
                del self.amc_slave
                return True
            return False

    def _change_volume_manage_ip(self, obj):
        # new_config = {"storagenetwork":{"network_ip":"", "gateway":"", "netmask":""}, "managenetwork":{"network_ip":"", "gateway":"", "netmask":""}, "power_cycle":False};
        old_manage_ip = ""
        old_storage_ip = ""
        netmask = ""
        gateway = ""
        power_cycle = False
        ip = obj[1]
        if len(obj) > 2:
            netmask = obj[2]
            gateway = obj[3]
            power_cycle = obj[4]


        nodes = self._node_operate(obj)
        obj_log.debug(obj[1])
        for node in nodes:
            containeruuid = node["containeruuid"]
            if len(node["eth0"].split(".")[1]) == 2:
                old_manage_ip = node["eth0"]
            if len(node["eth1"].split(".")[1]) == 3:
                old_storage_ip = node["eth1"]

        obj_log.debug("change <" + old_manage_ip + " ===> " + ip + "> start.")
        rtn = self.tools.change_volume_manage_ip(containeruuid, ip, netmask, gateway, old_manage_ip, old_storage_ip, power_cycle)
        self.utils.progressbar_k(3)
        obj_log.debug(rtn)
        if rtn == True:
            return True
        else:
            raise self.customError("Change volume IP failed")
            return False


    def _change_volume_storage_ip(self, obj):
        # new_config = {"storagenetwork":{"network_ip":"", "gateway":"", "netmask":""}, "managenetwork":{"network_ip":"", "gateway":"", "netmask":""}, "power_cycle":False};
        old_manage_ip = ""
        old_storage_ip = ""
        netmask = ""
        gateway = ""
        power_cycle = False
        ip = obj[1]
        if len(obj) > 2:
            netmask = obj[2]
            gateway = obj[3]
            power_cycle = obj[4]


        nodes = self._node_operate(obj)
        obj_log.debug(obj[1])
        for node in nodes:
            containeruuid = node["containeruuid"]
            if len(node["eth0"].split(".")[1]) == 2:
                old_manage_ip = node["eth0"]
            if len(node["eth1"].split(".")[1]) == 3:
                old_storage_ip = node["eth1"]

        obj_log.debug("change <" + old_storage_ip + " ===> " + ip + "> start.")
        rtn = self.tools.change_volume_storage_ip(containeruuid, ip, netmask, gateway, old_manage_ip, old_storage_ip, power_cycle)
        self.utils.progressbar_k(3)
        obj_log.debug(rtn)
        if rtn == True:
            return True
        else:
            raise self.customError("Change volume IP failed")
            return False

    def _change_volume_ip(self, obj):
        obj_manage = [obj[0], obj[1]]
        obj_storage = [obj[0], obj[-1]]

        nodes = self._node_operate(obj)
        for i in range(2):
            rtn = self._change_volume_manage_ip(obj_manage)
            if rtn:
                self.utils.progressbar_k(60)
                rtn = self._change_volume_storage_ip(obj_storage)
                if rtn:
                    rtn = self.utils.reboot_vm(self.all_server_dict.keys()[0], nodes[0]['containername'])
                    if not self.tools.retry_to_check_jobstatus_msg("Successfully started bootstrap for USX node with role VOLUME"):
                        return False
                    return True
            else:
                return False

    def _export_snapshot(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
        if obj[1] != '':
            snapshot_uuid = snapshot_list[int(obj[1])]['uuid']
            rtn = self.tools.export_snapshot(snapshot_uuid)
            if not rtn:
                raise self.customError("export snapshot failed")
                return False
        else:
            for snapshot in snapshot_list:
                snapshot_uuid = snapshot['uuid']
                rtn = self.tools.export_snapshot(snapshot_uuid)
                if not rtn:
                    raise self.customError("export snapshot failed")
                    return False
        return True


    def _unexport_snapshot(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
        if obj[1] != '':
            snapshot_uuid = snapshot_list[int(obj[1])]['uuid']
            rtn = self.tools.unexport_snapshot(snapshot_uuid)
            if not rtn:
                raise self.customError("unexport snapshot failed")
                return False
        else:
            for snapshot in snapshot_list:
                snapshot_uuid = snapshot['uuid']
                rtn = self.tools.unexport_snapshot(snapshot_uuid)
                if not rtn:
                    raise self.customError("unexport snapshot failed")
                    return False
        return True

    def _delete_snapshot(self, obj):
        obj_log.debug(obj[1])  # obj[1] point the sequence number in the snapshot list
        snapshot_uuid_list = []
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
            snapshot_uuid = snapshot_list[int(obj[1])]['uuid']
            # unexport snapshot before delete
            if snapshot_list[int(obj[1])]['mountedpoint'] != None:
                rtn1 = self.tools.unexport_snapshot(snapshot_uuid)
            snapshot_uuid_list.append(snapshot_uuid)
            rtn2 = self.tools.delete_snapshot(volume_resource_name, snapshot_uuid_list)
            if not rtn2:
                raise self.customError("delete snapshot failed")
                return False
        return True

    def _delete_all_snapshot(self, obj):
        snapshot_uuid_list = []
        nodes = self._node_operate(obj)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
            for snapshot in snapshot_list:
                if snapshot['mountedpoint'] != None:
                    rtn1 = self.tools.unexport_snapshot(snapshot['uuid'])
                snapshot_uuid_list.append(snapshot['uuid'])

            rtn2 = self.tools.delete_snapshot(volume_resource_name, snapshot_uuid_list)
            if not rtn2:
                raise self.customError("delete all snapshot by resource name failed")
                return False
        return True

    def _rollback_snapshot(self, obj):
        obj_log.debug(obj[1]) #obj[1] point the sequence number in the snapshot list
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
            snapshot_uuid = snapshot_list[int(obj[1])]['uuid']
            rtn = self.tools.rollback_snapshot(snapshot_uuid)
            if not rtn:
                raise self.customError("rollback %s =====> %s snapshot failed" % \
                    (volume_resource_name, snapshot_uuid))
                return False
        return True

    def _check_snapshot_rollback_backup(self, obj):
        lvs_cmd= 'lvs'

        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']

            volume_resource_name = node['name']
            j = 0
            rtn_rollback = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', lvs_cmd)['stdout']
            obj_log.debug(rtn_rollback + '\n++++++++++++++')
            rollback_backup_list = re.findall(r'(?P<size>\S*)\s*dedupvg\s+', rtn_rollback)
            if not rollback_backup_list:
                rollback_backup_list = re.findall(r'(?P<size>\S*)\s*ibd-target-vg\s+', rtn_rollback)
            obj_log.debug(rollback_backup_list)
            for i in rollback_backup_list:
                s = i.find('rollback_backup')
                if s != -1 :
                    j = j+1

            obj_log.debug(j)
            if j != 0:
                obj_log.info("The rollback_backup is created")
                # return True
            else :
                raise self.customError('There is no rollback_backup')
                return False

        return True

    def _get_amc_date_now(self,obj):
        date_on_amc = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password,'date')['stdout']
        obj_log.debug('Time now===>>>>> ' + date_on_amc)
        time_list = date_on_amc.split()
        # obj_log.debug(time_list)
        return time_list

    def _create_weekly_schedule_snapshot(self, obj):

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        if obj[1] != '':
            maxsnapshot = int(obj[1])
        else:
            maxsnapshot = 3

        cmd_date = 'date +%H:%M:%a --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        schedule = '0 %s %s ? * %s *' %(d[1],d[0],d[2])

        rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=maxsnapshot)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True

    def _create_daily_schedule_snapshot(self,obj):

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule_minute = d[1]
        schedule_hours = d[0]
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])
        obj_log.debug(schedule)

        if obj[1] != '':
            maxsnapshot = int(obj[1])
        else:
            maxsnapshot = 3

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name + '\n++++++++++++++++++++\n')
            rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=maxsnapshot)

            if not rtn:
                raise self.customError("create snapshot schedule failed")
                return False

            self.utils.progressbar_k(200)
        return True


    def _get_cron_time(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        volres_uuid = nodes[0]['uuid']
        vol_ip = nodes[0]['eth0']
        cmd = "cat /etc/crontab| grep usx_simplememory_sync| awk '{print $2}'"
        rtn = self.utils.ssh_cmd(vol_ip, "poweruser", "poweruser", cmd)['stdout']
        if not rtn:
            raise self.customError("create snapshot schedule failed")
            return False
        else:
            return rtn 


    def _enable_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        volres_uuid = nodes[0]['uuid']
        rtn = self.tools.enable_snapclone(volres_uuid)
        if not rtn:
            raise self.customError("enable snapclone failed")
            return False
        else:
            return True


    def _disable_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        volres_uuid = nodes[0]['uuid']
        rtn = self.tools.disable_snapclone(volres_uuid)
        if not rtn:
            raise self.customError("disable snapclone schedule failed")
            return False
        else:
            return True


    def _modify_hourly_schedule_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        volres_uuid = nodes[0]['uuid']
        vol_ip = nodes[0]['eth0']

        schedule = '0 0 0/1 1/1 * ? *'
        obj_log.debug(schedule)

        rtn = self.tools.modify_schedule_snapclone(volres_uuid, schedule)
        if not rtn:
            raise self.customError("create snapclone schedule failed")
            return False

        cmd_date = "date |awk '{print $4}'"
        rtn_time = self.utils.ssh_cmd(vol_ip, 'poweruser', 'poweruser', cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        cmd_dates = 'date -s "%s:59:00"' % d[0]
        self.utils.ssh_cmd(vol_ip, 'poweruser', 'poweruser', cmd_dates)
        return True


    def _modify_daily_schedule_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        volres_uuid = nodes[0]['uuid']
        vol_ip = nodes[0]['eth0']

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(vol_ip, 'poweruser', 'poweruser', cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule_minute = d[1]
        schedule_hours = d[0]
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])
        obj_log.debug(schedule)

        rtn = self.tools.modify_schedule_snapclone(volres_uuid, schedule)
        if not rtn:
            raise self.customError("create snapclone schedule failed")
            return False

        return True


    def _modify_daily_schedule_snapshot(self,obj):

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule_minute = d[1]
        schedule_hours = d[0]
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])
        obj_log.debug(schedule)

        if obj[1] != '':
            maxsnapshot = int(obj[1])
        else:
            maxsnapshot = 3

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name + '\n++++++++++++++++++++\n')
            rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=maxsnapshot, req_type = 'PUT')

            if not rtn:
                raise self.customError("create snapshot schedule failed")
                return False

            self.utils.progressbar_k(200)
        return True


    def _create_schedule_snapshot(self, obj):
        """
        snapshot schedule:
        1 hour snapshot
        schedule: "0 0 0/1 1/1 * ? *"

        6 hour snapshot
        schedule: "0 0 0/6 1/1 * ? *"

        daily 3.00AM
        schedule: "0 0 3 1/1 * ? *"

        daily 2.00PM
        schedule: "0 0 14 1/1 * ? *"

        weekly 5:00PM SUN, MON
        schedule: "0 0 17 ? * SUN,MON *"

        monthly 5:00PM MON the second week
        schedule: "0 0 17 ? 1/1 MON#2 *"

        monthly 5:00PM WEN the last week
        schedule: "0 0 17 ? 1/1 WEDL *"

        """
        obj_log.debug(obj[1])
        schedule = obj[1]
        if obj[2] != '':
            maxsnapshot = int(obj[2])
        else:
            maxsnapshot = 3

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=maxsnapshot)
            if not rtn:
                raise self.customError("create snapshot schedule failed")
                return False
        return True

    def _modify_schedule_snapshot(self, obj):
        obj_log.debug(obj[1])
        schedule = obj[1]
        if obj[2] != '':
            maxsnapshot = int(obj[2])
        else:
            maxsnapshot = 3

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            rtn = self.tools.modify_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=maxsnapshot)
            if not rtn:
                raise self.customError("modify snapshot schedule failed")
                return False
        return True

    def _hour_schedule_snapshout(self,obj):

        modify_time_list = self._hour_modification_time(obj)
        date_after_add1 = modify_time_list[0]
        schedule = modify_time_list[1]
        obj_log.debug("\n______________will change time to ______________\n"+date_after_add1+"\n_______________________________")
        date_cmd = 'date -s ' + date_after_add1

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=3)
            if not rtn:
                raise self.customError("create snapshot schedule failed")
                return False

            self.utils.ssh_cmd(self.amc_ip,self.amc_username, self.amc_password,date_cmd)['stdout']
            self._get_amc_date_now(obj)
        self.utils.progressbar_k(200)

        return True

    def _modify_hour_schedule_snapshout(self,obj):

        modify_time_list = self._hour_modification_time(obj)
        date_after_add1 = modify_time_list[0]
        schedule = modify_time_list[1]
        obj_log.debug("\n______________will change time to ______________\n"+date_after_add1+"\n_______________________________")
        date_cmd = 'date -s ' + date_after_add1

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        for node in nodes:
            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=3, req_type='PUT')
            if not rtn:
                raise self.customError("create snapshot schedule failed")
                return False

            self.utils.ssh_cmd(self.amc_ip,self.amc_username, self.amc_password, date_cmd)['stdout']
            self._get_amc_date_now(obj)
        self.utils.progressbar_k(200)

        return True

    def _modify_testbed(self, cur_path):
        testbed_count = int(self.all_config["testbed_count"]) + 1
        cmd = "sed -i 's:^testbed_count.*:testbed_count = %s:' %s/*.ini" % (testbed_count, cur_path)
        os.system(cmd)


    def _hour_modification_time(self,obj):
        time_now_list = self._get_amc_date_now(obj)
        # obj_log.debug(time_now_list)
        daily_time = time_now_list[3]
        obj_log.debug(daily_time)
        daily_time_list = daily_time.split(':')
        if obj[1] == "1":
            schedule = '0 0 0/1 1/1 * ? *'
            obj_log.debug(obj[1])
        elif obj[1] == "2":
            schedule = '0 0 0/2 1/1 * ? *'
            if int(daily_time_list[0])%2==0:
                daily_time_list[0] = str(int(daily_time_list[0])+1)
            else: daily_time_list[0] = str(int(daily_time_list[0]))
        elif obj[1] == "4":
            schedule = '0 0 0/4 1/1 * ? *'
            if int(daily_time_list[0])%4==0:
                daily_time_list[0] = str(int(daily_time_list[0])+3)
            elif int(daily_time_list[0])%4==1:
                daily_time_list[0] = str(int(daily_time_list[0])+2)
            elif int(daily_time_list[0])%4==2:
                daily_time_list[0] = str(int(daily_time_list[0])+1)
            elif int(daily_time_list[0])%4==3:
                daily_time_list[0] = str(int(daily_time_list[0]))
        elif obj[1] == "6":
            schedule = '0 0 0/6 1/1 * ? *'
            if int(daily_time_list[0])<6:
                daily_time_list[0] = '5'
            elif 6<=int(daily_time_list[0])<12:
                daily_time_list[0] = '11'
            elif 12<=int(daily_time_list[0])<18:
                daily_time_list[0] = '17'
            elif 18<=int(daily_time_list[0])<24:
                daily_time_list[0] = '23'

        elif obj[1] == '8':
            schedule = '0 0 0/8 1/1 * ? *'
            if int(daily_time_list[0])<8:
                daily_time_list[0] = '7'
            elif 8<=int(daily_time_list[0])<16:
                daily_time_list[0] = '15'
            elif 16<=int(daily_time_list[0])<24:
                daily_time_list[0] = '23'

        elif obj[1] == '12':
            schedule = '0 0 0/12 1/1 * ? *'
            if int(daily_time_list[0])<12:
                daily_time_list[0] = '11'
            elif 12<=int(daily_time_list[0])<24:
                daily_time_list[0] = '23'
        daily_time_list[1] = '59' #minute
        daily_time_list[2] = '00'

        date_after_add = ':'.join(daily_time_list)
        self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, 'date -s ' + date_after_add)['stdout']
        return [date_after_add, schedule]

    def _hour_schedule_replication_Setup(self,obj):
        obj_log.debug(obj[1])
        schedule = obj[1]

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        if 'SIMPLE' in nodes[1]['type']:
            target_volume_ip = nodes[1]['eth1']
        else:
            target_volume_ip = nodes[1]['serviceip']
        target_volume_name = nodes[1]['name']


        modify_time_list = self._hour_modification_time(obj)
        date_after_add1 = modify_time_list[0]
        schedule = modify_time_list[1]
        obj_log.debug("\n______________will change time to ______________\n"+date_after_add1+"\n_______________________________")
        #date_cmd = 'date -s ' + date_after_add1

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        else:
            return True


    def _hour_schedule_replication(self,obj):

        """
        snapshot schedule:
        1 hour snapshot
        schedule: "0 0 0/1 1/1 * ? *"

        6 hour snapshot
        schedule: "0 0 0/6 1/1 * ? *"
        """

        obj_log.debug(obj[1])
        schedule = obj[1]

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        volume_resource_name = nodes[0]['name']

        if 'SIMPLE' in nodes[1]['type']:
            target_volume_ip = nodes[1]['eth1']
        else:
            target_volume_ip = nodes[1]['serviceip']
        target_volume_name = nodes[1]['name']


        modify_time_list = self._hour_modification_time(obj)
        date_after_add1 = modify_time_list[0]
        schedule = modify_time_list[1]
        obj_log.debug("\n______________will change time to ______________\n"+date_after_add1+"\n_______________________________")
        date_cmd = 'date -s ' + date_after_add1

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False

        self.utils.ssh_cmd(self.amc_ip,self.amc_username, self.amc_password, date_cmd)['stdout']
        self._get_amc_date_now(obj)            # obj_log.debug(daily_time_list,'\n**********')
        self.utils.progressbar_k(200)
        return True


    def _modify_hour_schedule_replication(self,obj):

        """
        snapshot schedule:
        1 hour snapshot
        schedule: "0 0 0/1 1/1 * ? *"

        6 hour snapshot
        schedule: "0 0 0/6 1/1 * ? *"
        """

        obj_log.debug(obj[1])
        schedule = obj[1]

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        if 'SIMPLE' in nodes[1]['type']:
            target_volume_ip = nodes[1]['eth1']
        else:
            target_volume_ip = nodes[1]['serviceip']
        target_volume_name = nodes[1]['name']


        modify_time_list = self._hour_modification_time(obj)
        date_after_add1 = modify_time_list[0]
        schedule = modify_time_list[1]
        obj_log.debug("\n______________will change time to ______________\n"+date_after_add1+"\n_______________________________")
        date_cmd = 'date -s ' + date_after_add1

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name,req_type ="PUT")
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.ssh_cmd(self.amc_ip,self.amc_username, self.amc_password, date_cmd)['stdout']
        self._get_amc_date_now(obj)            # obj_log.debug(daily_time_list,'\n**********')
        self.utils.progressbar_k(200)
        return True

    '''
        daily 3.00AM
        schedule: "0 0 3 1/1 * ? *"

        daily 2.00PM
        schedule: "0 0 14 1/1 * ? *"
    '''
    def _daily_schedule_replication(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']
        if 'SIMPLE' in nodes[1]['type']:
            target_volume_ip = nodes[1]['eth1']
        else:
            target_volume_ip = nodes[1]['serviceip']
        target_volume_name = nodes[1]['name']

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True

    def _modify_daily_schedule_replication(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']
        if 'SIMPLE' in nodes[1]['type']:
            target_volume_ip = nodes[1]['eth1']
        else:
            target_volume_ip = nodes[1]['serviceip']
        target_volume_name = nodes[1]['name']

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name, req_type='PUT')
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True


    def _daily_schedule_replication_negetive(self, obj):
        volume_resource_name = obj[0]
        target_volume_ip = obj[1]
        target_volume_name = obj[2]

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name, get_err_msg=True)

        self.utils.progressbar_k(200)
        return rtn

    def _modify_daily_schedule_replication_negetive(self, obj):
        volume_resource_name = obj[0]
        target_volume_ip = obj[1]
        target_volume_name = obj[2]

        cmd_date = 'date +%H:%M --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        schedule = '0 %s %s 1/1 * ? *' %(d[1],d[0])

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name, req_type='PUT', get_err_msg=True)

        self.utils.progressbar_k(200)
        return rtn

    '''
        Do not modify the AMC time,week
    '''

    def _week_schedule_replication(self, obj):

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        target_volume_ip = nodes[1]['eth1']
        target_volume_name = nodes[1]['name']

        cmd_date = 'date +%H:%M:%a --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        schedule = '0 %s %s ? * %s *' %(d[1],d[0],d[2])

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True

    def _modify_week_schedule_replication(self, obj):

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        target_volume_ip = nodes[1]['eth1']
        target_volume_name = nodes[1]['name']

        cmd_date = 'date +%H:%M:%a --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        schedule = '0 %s %s ? * %s *' %(d[1],d[0],d[2])

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name,req_type ="PUT")
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True


    def _modify_weekly_schedule_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)

        volres_uuid = nodes[0]['uuid']
        vol_ip = nodes[0]['eth0']
        cmd_date = 'date +%H:%M:%a --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(vol_ip, 'poweruser', 'poweruser', cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        schedule = '0 %s %s ? * %s *' %(d[1],d[0],d[2])
        rtn = self.tools.modify_schedule_snapclone(volres_uuid, schedule)
        if not rtn:
            raise self.customError('modify weekly schedule_snapclone failed')
            return False

        return True


    def _modify_monthly_schedule_snapclone(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volres_uuid = nodes[0]['uuid']
        vol_ip = nodes[0]['eth0']

        cmd_date = 'date +%Y:%m:%d:%a'
        rtn_time = self.utils.ssh_cmd(vol_ip, 'poweruser', 'poweruser', cmd_date)
        t = rtn_time['stdout'].replace("\n","").split(':')
        #obj_time = time.localtime()
        #obj_log.debug(obj_time.tm_mday)
        if int(t[2]) % 7:
            weeks = (int(t[2])/7)+1
        else:
            weeks = int(t[2])/7
        obj_log.debug("weeks"+str(weeks))

        cmd_date = 'date +%H:%M:%a: --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(vol_ip, 'poweruser', 'poweruser', cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        if weeks == 5:
            schedule = '0 %s %s ? 1/1  %s *' % (d[1], d[0], d[2]+"L")
        else:
            schedule = '0 %s %s ? 1/1  %s#%s *' % (d[1], d[0], d[2], str(weeks))

        rtn = self.tools.modify_schedule_snapclone(volres_uuid, schedule)
        if not rtn:
            raise self.customError('schedule monthly snapclone failed')
            return False
        return True


    def _create_monthly_schedule_snapshot(self, obj):
        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        if obj[1] != '':
            maxsnapshot = int(obj[1])
        else:
            maxsnapshot = 3


        cmd_date = 'date +%Y:%m:%d:%a'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        t = rtn_time['stdout'].replace("\n","").split(':')
        #obj_time = time.localtime()
        #obj_log.debug(obj_time.tm_mday)
        if int(t[2]) % 7:
            weeks = (int(t[2])/7)+1
        else:
            weeks = int(t[2])/7
        obj_log.debug("weeks"+str(weeks))
        '''
        #end = int(datetime.datetime(int(t[0]), int(t[1]), int(t[2])).strftime("%W"))
        #begin = int(datetime.datetime(int(t[0]), int(t[1]), 1).strftime("%W"))
        #weeks = str(end - begin + 1)
        obj_log.debug(weeks)
        if weeks == 1:
            week = '1'
        elif weeks == '2':
            week = '2'
        elif weeks == '3':
            week = '3'
        elif weeks == '4':
            week = '4'
        elif weeks == '5':
            week = "WENL"  <==== "WEN" + "L"
        '''
        cmd_date = 'date +%H:%M:%a: --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        if weeks == 5:
            schedule = '0 %s %s ? 1/1  %s *' % (d[1], d[0], d[2]+"L")
        else:
            schedule = '0 %s %s ? 1/1  %s#%s *' % (d[1], d[0], d[2], str(weeks))

        rtn = self.tools.create_schedule_snapshot(volume_resource_name, schedule, maxsnapshot=maxsnapshot)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True


    '''
        Do not modify the AMC time,monthly
        monthly 5:00PM MON the second week
        schedule: "0 0 17 ? 1/1 MON#2 *"
        "0 0 0 ? 1/1 MONL *"
    '''

    def _monthly_schedule_replication(self, obj):

        nodes = self._node_operate(obj)
        obj_log.debug(nodes)
        # for node in nodes:
        volume_resource_name = nodes[0]['name']

        target_volume_ip = nodes[1]['eth1']
        target_volume_name = nodes[1]['name']


        cmd_date = 'date +%Y:%m:%d:%a'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        t = rtn_time['stdout'].replace("\n","").split(':')
        #obj_time = time.localtime()
        #obj_log.debug(obj_time.tm_mday)
        if int(t[2]) % 7:
            weeks = (int(t[2])/7)+1
        else:
            weeks = int(t[2])/7
        obj_log.debug("weeks"+str(weeks))
        '''
        #end = int(datetime.datetime(int(t[0]), int(t[1]), int(t[2])).strftime("%W"))
        #begin = int(datetime.datetime(int(t[0]), int(t[1]), 1).strftime("%W"))
        #weeks = str(end - begin + 1)
        obj_log.debug(weeks)
        if weeks == 1:
            week = '1'
        elif weeks == '2':
            week = '2'
        elif weeks == '3':
            week = '3'
        elif weeks == '4':
            week = '4'
        elif weeks == '5':
            week = "WENL"  <==== "WEN" + "L"
        '''
        cmd_date = 'date +%H:%M:%a: --date="+1 minute"'
        rtn_time = self.utils.ssh_cmd(self.amc_ip, self.amc_username, self.amc_password, cmd_date)
        d = rtn_time['stdout'].replace("\n","").split(':')
        obj_log.debug(d)
        if weeks == 5:
            schedule = '0 %s %s ? 1/1  %s *' % (d[1], d[0], d[2]+"L")
        else:
            schedule = '0 %s %s ? 1/1  %s#%s *' % (d[1], d[0], d[2], str(weeks))

        rtn = self.tools.schedule_replication(schedule, volume_resource_name, target_volume_ip, target_volume_name)
        if not rtn:
            raise self.customError('schedule replication failed')
            return False
        self.utils.progressbar_k(200)
        return True

    def _upgrade(self, version=None):
        # if version is not None, will use the specify version 
        if version:
            ovf_path = "/mnt/build/FLEXCLOUD/%s/USX/USX-%s-Full/USX-%s-Full.ovf" % (version[:5],version,version)
        else:
            ovf_path = self.all_config['migration_usx_build_path']
        # make upgrade zip file path from ovf path
        upgrade_zip_path = re.sub('USX-', 'upgrade_', ovf_path)
        upgrade_zip_path = re.sub('USX', 'PATCH', upgrade_zip_path)
        upgrade_zip_path = re.sub('-Full', '', upgrade_zip_path)
        upgrade_zip_path = re.sub('ovf', 'zip', upgrade_zip_path)
        obj_log.info(upgrade_zip_path)
        rtn = self.tools.upgrade(upgrade_zip_path)
        if rtn:
            return True
        raise self.customError('Start upgrade failed ...')

    def _check_upgrade(self):
        pass

    # def _check_res(self, svm_ip_list, primary_disk_num, primary_flash_num):
    def _check_res(self, obj):
        cmd = "lvs"
        primary_disk_num = int(self.utils.get_config("testcase","primary_disk_num", self.configfile))
        primary_flash_num = int(self.utils.get_config("testcase","primary_flash_num", self.configfile))
        primary_memory_num = int(self.utils.get_config("testcase","primary_memory_num", self.configfile))
        svm_tuple = self._get_svm_list(self.all_node_info)
        svm_ip_list = svm_tuple[1]
        for svm_ip in svm_ip_list:
            rtn = self.utils.ssh_cmd(svm_ip,"poweruser","poweruser",cmd)['stdout']
            obj_log.debug(rtn)
            primary_disk_list = re.findall(r'PRIMARY_DISK_.*?-wi-ao.*?\s*(?P<res>\d+)', rtn)
            primary_flash_list = re.findall(r'PRIMARY_FLASH_.*?-wi-ao.*?\s*(?P<res>\d+)', rtn)
            obj_log.info(primary_disk_list)
            obj_log.info(primary_flash_list)
            # check primary disk resourse
            if primary_disk_num != 0:  # the volume use disk resourse
                if str(primary_disk_num) in primary_disk_list:
                    obj_log.debug("primary disk resourse is OK")
                else:
                    obj_log.debug("primary disk resourse is not OK, please check!!!")
                    return False
            else:                           # the volume don't use disk resourse
                if not primary_disk_list:
                    obj_log.debug("no disk resourse has been used, It's OK")
                else: return False

            # check primary flash resourse
            if primary_flash_num != 0:  # the volume use flash resourse
                if str(primary_flash_num) in primary_flash_list:
                    obj_log.debug("primary flash resourse is OK")
                else:
                    obj_log.debug("primary flash resourse is not OK, please check!!!")
                    return False
            else:                           # the volume don't use flash resourse
                if not primary_flash_list:
                    obj_log.debug("no flash resourse has been used, It's OK")
                else: return False

        obj_log.info("volume's resources of SVM is OK")

        return True

    def _check_res_back(self, obj):
        cmd = "lvs"
        svm_tuple = self._get_svm_list(self.all_node_info)
        svm_ip_list = svm_tuple[1]
        self.utils.progressbar_k(60)

        for svm_ip in svm_ip_list:
            rtn = self.utils.ssh_cmd(svm_ip,"poweruser","poweruser",cmd)['stdout']
            obj_log.debug(rtn)
            primary_disk_list = re.findall(r'PRIMARY_DISK_.*?-wi-ao.*?\s*(?P<res>\d+)', rtn)
            primary_flash_list = re.findall(r'PRIMARY_FLASH_.*?-wi-ao.*?\s*(?P<res>\d+)', rtn)
            obj_log.info(primary_disk_list)
            obj_log.info(primary_flash_list)
            if not primary_disk_list:
                obj_log.debug("primary disk resourse got back")
            else:
                obj_log.debug("primary disk resourse didn't get back, please check!!!")
                return False
            if not primary_flash_list:
                obj_log.debug("primary flash resourse got back")
            else:
                obj_log.debug("primary flash resourse didn't get back, please check!!!")
                return False
        obj_log.info("volume's resources get back to SVM successuflly")

        return True

    def _check_memory_res(self, obj):
        cmd = "free -m"
        svm_tuple = self._get_svm_list(self.all_node_info)
        svm_ip_list = svm_tuple[1]
        total_memory_list = []
        for svm_ip in svm_ip_list:
            rtn = self.utils.ssh_cmd(svm_ip,"poweruser","poweruser",cmd)['stdout']
            obj_log.debug(rtn)
            find_rtn = re.findall(r'Mem:\s*(?P<recovery>\d+)\s*\d+', rtn)
            obj_log.debug(find_rtn)
            total_memory_list.extend(find_rtn)
        obj_log.info(total_memory_list)
        total_memory_list.sort()
        return total_memory_list

    def _check_lsscsi(self, obj):
        cmd = "lsscsi | wc -l"
        obj_log.debug(obj[1])
        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']
            rtn = self.utils.ssh_cmd(node_ip, "poweruser", "poweruser", cmd)['stdout']
            obj_log.debug(rtn)
            if int(rtn) == int(obj[1]):
                obj_log.info("lsscsi check ok")
                return True
            else:
                raise self.customError("lsscsi is not correct")
                return False

    def _check_mount_host_num(self, obj):
        obj_log.debug(obj[1])
        nodes = self._node_operate(obj)

        for node in nodes:
            mount_host_list = node['mounthost']
            if len(mount_host_list) == int(obj[1]):
                obj_log.info("mount host number is correct!")
                return True
            else:
                raise self.customError("mount host number is not correct")
                return False

    def _check_vc(self, vc, username, password):
        tms = 10
        while tms:
            try:
                server = self._conn_vcenter(self.vc, self.vc_username, self.vc_password)
                break
            except Exception as e:
                obj_log.debug(str(e))
                self.utils.progressbar_k(120)
                tms -= 1
                if tms == 0:
                    raise self.customError("can not connect vCenter, please check the issue")
        return True

    def _check_vm_health(self, server, vmname):
        tms = 25
        while tms:
            powered_on = self.utils.get_vm_health(server, vmname)
            if powered_on:
                break
            self.utils.progressbar_k(120)
            tms -= 1
            if tms == 0:
                raise self.customError("volume can not boot up, please check the issue")
        return True

    def _check_node(self, node_ip):
        crm_mon = 'crm_mon -1r'
        for tms in range(10):
            try:
                rtn_content = self.utils.ssh_cmd(node_ip, 'poweruser', 'poweruser', crm_mon)['stdout']
                if 'OFFLINE' not in rtn_content and 'offline' not in rtn_content \
                    and 'Stopped' not in rtn_content and 'FAILED' not in rtn_content \
                    and 'fail' not in rtn_content:

                    break
            except Exception as e:
                obj_log.error(str(e))

            self.utils.progressbar_k(60)
            if tms == 9:
                raise self.customError("some nodes almost offline, it's a issue")
        return True

    def _check_ha_status(self, ip):
        tms = 10
        while tms:
            result = self.utils.checkHAStatus(ip)
            if result['error'] == "":
                break
            self.utils.progressbar_k(60)
            tms -= 1
            if tms == 0:
                raise self.customError("some resources is not normal, please check the issue")
        return True

    def _check_obj_ha_status(self, obj):

        tms = 10
        while tms:
            nodes = self._node_operate(obj)

            for node in nodes:
                ip = node['eth0']

                result = self.utils.checkHAStatus(ip)
                if result['error'] == "":
                    return True
                self.utils.progressbar_k(60)
                tms -= 1
                if tms == 0:
                    raise self.customError("some resources is not normal, please check the issue")

    # check the volume status after disable
    def _check_disabled_volume_status(self, obj):
        crm_mon = 'crm_mon -1r'
        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']
            vmname = node['containername']

        key_string = "Node %s: maintenance" % vmname
        obj_log.debug(key_string)

        tms = 5
        while tms:
            rtn_content = self.utils.ssh_cmd(node_ip, 'poweruser', 'poweruser', crm_mon)['stdout']
            if key_string in rtn_content:
                break
            obj_log.info(rtn_content)
            self.utils.progressbar_k(60)
            tms -= 1
            if tms == 0:
                obj_log.info(rtn_content)
                raise self.customError("There is no disabled volume, please check!")
        return True

    def _check_ha_resource_map(self, ip, group1):
        obj_log.debug(self.utils.checkHAStatus(ip))
        tms = 100
        while tms:
            group2 = self.utils.getHAResourceMap(ip)
            obj_log.debug("group2 %s" % group2)
            if group2 != {} and '' not in group2.values():
                rtn = self.utils.compareResourceMap(group1, group2)
                obj_log.debug(rtn)
                break
            obj_log.info("wait for resource back remaining time %s min" % tms)
            self.utils.progressbar_k(5)
            tms -= 1
            if tms == 0:
                raise self.customError("failover failed, please check the resource")

    def _check_stretch_cluster_vm_site(self, obj):
        site_host_dict = self.tools.get_site_host_dict()

        all_node_info = self.tools.get_all_node_info()
        svm_info = all_node_info['service_vm_info']
        ha_info = all_node_info['ha_info']
        volume_info = all_node_info['volume_info']

        site_vm_count_dict = {}

        for site_tag in site_host_dict.keys():
            site_vm_count_dict[site_tag] = 0
            for svm in svm_info.keys():
                if svm_info[svm]['host'] in site_host_dict[site_tag]:
                    site_vm_count_dict[site_tag] += 1

            for ha in ha_info.keys():
                if ha_info[ha]['host'] in site_host_dict[site_tag]:
                    site_vm_count_dict[site_tag] += 1

            for volume in volume_info.keys():
                if volume_info[volume]['host'] in site_host_dict[site_tag]:
                    site_vm_count_dict[site_tag] += 1

        obj_log.info(site_vm_count_dict)
        if site_vm_count_dict.values()[0] == site_vm_count_dict.values()[1]:
            return True
        else:
            raise self.customError("stretch cluster site vm numbers not correct")
            return False

    def _check_snapshot_by_lvs(self, obj):
        crm_mon= 'lvs'
        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']

            volume_resource_name = node['name']
            obj_log.debug(volume_resource_name)
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)

            rtn_content = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', crm_mon)['stdout']
            for snapshot in snapshot_list:
                if snapshot['uuid'] not in rtn_content:
                    obj_log.error("% s not in %s lvs info" % (snapshot['uuid'], volume_resource_name))
                    raise self.customError("snapshot uuid not in volume's lvs info, please check!")
                    return False
            obj_log.info("% s is in %s lvs info" % (snapshot['uuid'], volume_resource_name))
        return True

    def _check_space_by_df(self, obj):
        df_h= 'df -h'
        # grep_dev = 'df -h | grep /dev/mapper'


        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']

            volume_resource_name = node['name']
            # obj_log.debug('>>>>>>>>>>>>',volume_resource_name)
            rtn_space = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', df_h)['stdout']
            # dev_dedupvg = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', grep_dev)['stdout']
            space_flash_list = re.findall(r'/dev/mapper/dedupvg-deduplv\s*(?P<size>\w+)\s*(?P<used>\S*)\s*', rtn_space)
            if not space_flash_list:
                space_flash_list = re.findall(r'/dev/ibd6\s*(?P<size>\w+)\s*(?P<used>\S*)\s*', rtn_space)
            # obj_log.debug(dev_dedupvg,"\n++++++++++++++++++++")
            obj_log.debug(rtn_space + '\n********************')
            # obj_log.debug(space_flash_list[0][1])
        return space_flash_list[0][1]

    def _check_snapshot_number(self, obj):
        obj_log.debug(obj[1])
        nodes = self._node_operate(obj)
        tms = 100
        for node in nodes:
            volume_resource_name = node['name']
            while True:
                snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
                if len(snapshot_list) == int(obj[1]):
                    break
                tms -= 1
                self.utils.progressbar_k(5)
                obj_log.warning("snapshot number is %s, expected number is %s" % (len(snapshot_list), obj[1]))
                if tms == 0:
                    raise self.customError("snapshot number is not correct, please check!")
                    return False
        obj_log.info("snapshot number is correct")
        return True

    def _check_export_snapshot(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            volume_resource_name = node['name']
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)
        # check given export snapshot
        if obj[1] !='':
            snapshot_mount_point = snapshot_list[int(obj[1])]['mountedpoint']
            if snapshot_mount_point == None:
                raise self.customError("the snapshot has not mountedpoint")
                return False
        # check all export snapshot
        else:
            for snapshot in snapshot_list:
                snapshot_mount_point = snapshot['mountedpoint']
                if snapshot_mount_point == None:
                    raise self.customError("the snapshot has not mountedpoint")
                    return False
        obj_log.info("export snapshot mount point is OK")
        return True

    def _check_unexport_snapshot(self, obj):
        nodes = self._node_operate(obj)
        for node in nodes:
            volume_resource_name = node['name']
            snapshot_list = self._get_volume_snapshot_list(volume_resource_name)

        if obj[1] !='':
            snapshot_mount_point = snapshot_list[int(obj[1])]['mountedpoint']
            if snapshot_mount_point != None:
                raise self.customError("the snapshot mountedpoint is exist")
                return False
        else:
            for snapshot in snapshot_list:
                snapshot_mount_point = snapshot['mountedpoint']
                if snapshot_mount_point != None:
                    raise self.customError("the snapshot mountedpoint is exist")
                    return False
        obj_log.info("unexport snapshot is None. It's OK")
        return True

    def _check_snapshot_by_dmsetup_table(self, obj):
        crm_mon= 'dmsetup table'
        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']

            rtn_content = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', crm_mon)['stdout']
            obj_log.info(rtn_content)
            result1 = re.findall(r'dedupvg-deduplv:\s*\S*\s*\S*\s*([a-z]+)\s*', rtn_content)
            result2 = re.findall(r'dedupvg-dedupvgpool:\s*\S*\s*\S*\s*([a-z]+)\s*', rtn_content)
            obj_log.debug('dedupvg-deduplv:', result1, ' dedupvg-dedupvgpool:', result2)
            if 'thin' not in result1:
                obj_log.error("dmsetup table dedupvg-deduplv is not thin")
                raise self.customError("dmsetup table dedupvg-deduplv is not thin, please check!")
                return False
            elif 'linear' not in result2:
                obj_log.error("dmsetup table dedupvg-dedupvgpool is not linear")
                raise self.customError("dmsetup table dedupvg-dedupvgpool is not linear, please check!")

            obj_log.info("dmsetup table is OK!")
        return True

    def _check_unsnapshot_by_dmsetup_table(self, obj):
        crm_mon= 'dmsetup table'
        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']

            rtn_content = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', crm_mon)['stdout']
            obj_log.info(rtn_content)
            result = re.findall(r'dedupvg-deduplv:\s*\S*\s*\S*\s*([a-z]+)\s*', rtn_content)
            obj_log.debug(result)
            if 'linear' not in result:
                obj_log.error("dmsetup table dedupvg-deduplv is not linear")
                raise self.customError("dmsetup table dedupvg-deduplv is not linear, please check!")
                return False
            elif 'dedupvg-dedupvgpool' in rtn_content:
                obj_log.error("dmsetup table should not has dedupvg-dedupvgpool")
                raise self.customError("dmsetup table should not has dedupvg-dedupvgpool, please check!")

            obj_log.info("dmsetup table is OK!")
        return True

    def _check_is_ext4(self, obj):
        cmd = "mount"
        nodes = self._node_operate(obj)

        for node in nodes:
            node_ip = node['eth0']
            rtn_content = self.utils.ssh_cmd(node_ip , 'poweruser','poweruser', cmd)['stdout']
            obj_log.info(rtn_content)

            export_fs_type= re.findall(r'\/dev/mapper\/dedupvg-deduplv.*', rtn_content)
            obj_log.info("The export fs type is" + export_fs_type[0].split()[4])
            if export_fs_type[0].split()[4] == 'ext4':
                return True
            else:
                return False

    def _check_snapclone_restored(self, obj):
        nodes = self._node_operate(obj)
        cmd ="ls -l %s| awk '{print $5}'" %  (nodes[0]['mountpoint'] + '/bigFile')
        node_ip = nodes[0]['eth0']
        retry_count = 100
        while(retry_count > 0):
            rtn1 = self.utils.ssh_cmd(node_ip, 'poweruser', 'poweruser', cmd)['stdout']
            print "waiting to check data,cmd={1} rtn1={0}".format(rtn1, cmd)
            time.sleep(60)
            rtn2 = self.utils.ssh_cmd(node_ip, 'poweruser', 'poweruser', cmd)['stdout']
            if int(rtn2) == int(rtn1):
                print "snapclone has been restored"
                return True
            else:
                print "waiting for data restored"
                time.sleep(10)
                retry_count -= 1
        else:
            print "timeout"
            return False

    def _create_vmgroup(self, obj):
        nodes = self._node_operate(obj)

        volume_list = []
        group_name = obj[1]
        for node in nodes:
            volume_list.append(node['name'])

        num = int(obj[2]) if len(obj)==3 else 0          
        rtn = self.tools.create_vm_group(volume_list, group_name, num)
        if rtn is False:
            raise self.customError("Create VM Group Failed")
        return rtn

    def _check_jobstatus_msg(self, obj):
        nodes = self._node_operate(obj)
        msg = obj[1]
        containeruuid = nodes[0]['containeruuid']
        if self.tools.retry_to_check_jobstatus_msg(msg, uuid=containeruuid, retry_num=200):
            return True
        else:
            raise self.customError("Can not get expected message !")

    def _get_snapclone_enable_status(self, obj):
        nodes = self._node_operate(obj)
        vol_res_uuid = nodes[0]['uuid']
        rtn = self.tools.get_snapclone_enable_status(vol_res_uuid)
        if rtn is None:
            obj_log.error(rtn)
            raise self.customError("get_snapclone_enable_status")
        return rtn

    def _get_snapclone_activate_status(self, obj):
        nodes = self._node_operate(obj)
        vol_res_uuid = nodes[0]['uuid']
        rtn = self.tools.get_snapclone_activate_status(vol_res_uuid)
        if rtn is None:
            obj_log.error(rtn)
            raise self.customError("get_snapclone_activate_status")
        return rtn


    def _snapclone_ratio_size(self, obj):
        rtn = self.tools.snapclone_ratio_size()
        if rtn is False:
            raise self.customError("Create VM Group Failed")
        return rtn


    def _setup_vmschedul(self, obj):
        vmgroup_uuid = obj[1]
        nodes = self._node_operate(obj)
        target_ip = nodes[0]['eth1']
        targetvolume = nodes[0]['name']

        schedule = {}
        schedule['cron'] = self._gen_schedul('daily', False) 
        schedule["scheduleformat"] = "CRON"
        rtn = self.tools.setup_vmschedul(vmgroup_uuid, schedule, targetvolume, target_ip)
        obj_log.debug(rtn)

    def _modify_vmschedul(self, obj):
        # ["modify_vmschedul:'vols'[" + volume + "][0]:`vmgroup_uuid`:`schedlue`"]
        vmgroup_uuid = obj[1]
        nodes = self._node_operate(obj)
        target_ip = nodes[0]['eth1']
        targetvolume = nodes[0]['name']

        schedule = {}
        schedule['cron'] = self._gen_schedul('daily', True, 1) if not obj[2] else obj[2]
        schedule["scheduleformat"] = "CRON"
        rtn = self.tools.setup_vmschedul(vmgroup_uuid, schedule, targetvolume, target_ip, req_type='PUT')
        obj_log.debug(rtn)

    def _gen_schedul(self, schedule_type, trigger, waittime=1):
        flg = '+' if trigger else '-'
        if schedule_type=='daily':
            cmd_date = 'date +%H:%M --date="' + flg + str(waittime) +' minute "'

            rtn_time = self.utils.ssh_cmd(
                self.amc_ip,self.amc_username,self.amc_password, cmd_date)
            d = rtn_time['stdout'].replace('\n','').split(':')
            schedule = "0 %s %s 1/1 * ? *" %(d[1],d[0])
        elif schedule_type=='hours':
            pass #TODO
        elif schedule_type=='week':
            cmd_date = 'date + %H:%M:%a --date="' + flg + '2 minute "'
            rtn_time = self.utils.ssh_cmd(
                self.amc_ip,self.amc_username, self.amc_password, cmd_date)
            d = rtn_time['stdout'].replace('\n','').split(':')
            schedule = "0 %s %s ? * %s *" %(d[1],d[0],d[2])
        elif schedule_type=='mounth':
            pass #TODO
        else:
            raise "schedule_type should in 'daily,week...'"

        return schedule

    def _vm_replication_now(self, obj):
        vmgroup_uuid = obj[1]
        rnt = self.tools.vmreplication_now(vmgroup_uuid)
        return rnt

    def _snapshot_ratio_lv(self, obj):
        cmd = "lvs"
        nodes = self._node_operate(obj)
        except_ratio = obj[1]

        for node in nodes:
            node_ip = node['eth0']
            all_info = self.utils.ssh_cmd(node_ip,'poweruser','poweruser',cmd)["stdout"]
            deduplv = re.search(r'deduplv\s*\S*\s*\S*\s*(?P<deduplv>\d+\.\d+|\d+)',all_info)
            dedupvgpool = re.search(r'dedupvgpool\s*dedupvg*\s*\S*\s*(?P<dedupvgpool>\d+\.\d+|\d+)',all_info)

            try:
                real_ratio = float(dedupvgpool.group('dedupvgpool'))/float(deduplv.group("deduplv")) - 1
                obj_log.info("real ratio is %s" % real_ratio)
                if int(obj[1])-2 < real_ratio * 100 < int(obj[1]) + 2:
                    return True
                else:
                    return False
            except Exception as e:
                obj_log.warning("May be snapshot not enable!")
                obj_log.warning(e)
                # if return 2 snapshot is disabled 
                return 2


    class customError(Exception):
        def __init__(self, error):
            self.error = error

        def __str__(self):
            return self.error
    #=================================================

    class Multi_exec(threading.Thread):
        def __init__(self, line, configfile):
            threading.Thread.__init__(self)
            self.line = line
            self.configfile = configfile
        def run(self):
            ha = Ha(self.configfile)
            self.rtn = ha._exec2(self.line)
        def get_return(self):
            return self.rtn

    class Multi_verify_raid(threading.Thread):
        def __init__(self, ip, configfile, flag):
            threading.Thread.__init__(self)
            self.ip = ip
            self.flag = flag
            self.ret = ''
            self.configfile = configfile
        def run(self):
            ha = Ha(self.configfile)
            self.ret = ha.verify_raid(self.ip, self.flag)
        def get_return(self):
            return self.ret



