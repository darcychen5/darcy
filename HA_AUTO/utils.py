# coding: utf-8
try:
    import XenAPI
except Exception:
    pass
import pysphere,re,subprocess,random,time,paramiko,threading,json,configparser,logging,copy,sys,os,shlex
from progressbar import *
from pysphere import *
from pysphere.resources import VimService_services as VI
from logging.handlers import RotatingFileHandler
import urllib2,log, urllib
import functools
# import requests
# requests.packages.urllib3.disable_warnings()

obj_log = log.get_logger()

global false, true, null
false = ''
true = ''
null = ''

server = pysphere.VIServer()

# Color escape string
COLOR_RED='\033[1;31m'
COLOR_GREEN='\033[1;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[1;34m'
COLOR_PURPLE='\033[1;35m'
COLOR_CYAN='\033[1;36m'
COLOR_GRAY='\033[1;37m'
COLOR_WHITE='\033[1;38m'
COLOR_RESET='\033[1;0m'
 
# Define log color
LOG_COLORS = {
    'DEBUG': '%s',
    'INFO': COLOR_GREEN + '%s' + COLOR_RESET,
    'WARNING': COLOR_YELLOW + '%s' + COLOR_RESET,
    'ERROR': COLOR_RED + '%s' + COLOR_RESET,
    'CRITICAL': COLOR_RED + '%s' + COLOR_RESET,
    'EXCEPTION': COLOR_RED + '%s' + COLOR_RESET,
}


vc_vm_template_dict = {'10.10.120.11': 'win7-dd-71', '10.16.134.19': 'win7-jin-10g', '10.16.134.2': 'win7-jin-10g','10.16.0.35': 'win7-dd-35', '10.16.0.57':'win7-dd-57', '10.16.0.71':'win7-dd-71', '10.16.2.55':'win7-dd-55', '10.16.0.83': 'WIN7-dd-Template-1M-Neil-83', '10.16.0.62': 'WIN7-dd-Template-1M-Neil-62', '10.16.0.21': 'WIN7-dd-Template-1M-Neil-21', '10.21.120.11': 'WIN7-dd-Template-Neil-11', '10.21.120.12': 'WIN7-dd-Template-Neil-12', '10.21.120.13': 'WIN7-dd-Template-Neil-13','10.21.120.14': 'WIN7-dd-Template-1M-Neil-14', '10.21.120.15': 'WIN7-dd-Template-1M-Neil-15', '10.21.120.16': 'WIN7-dd-Template-Neil-16', '10.21.2.46': 'WIN7-dd-Template-Neil-46', '10.21.2.47': 'WIN7-dd-Template-Neil-47', '10.21.2.48': 'WIN7-dd-Template-Neil-48', '10.21.2.49': 'WIN7-dd-Template-Neil-49', '10.21.2.50': 'WIN7-dd-Template-Neil-50', '10.21.2.52': 'WIN7-dd-Template-Neil-52'}


# real singleton
class Singleton(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(cls)
        return cls._instance


def memoize(fn):
    known = dict()

    @functools.wraps(fn)
    def memoizer(*args):
        if args not in known:
            known[args] = fn(*args)
        return known[args]

    return memoizer


class log_colour(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None):
        logging.Formatter.__init__(self, fmt, datefmt)
        
    def format(self, record):
        level_name = record.levelname
        msg = logging.Formatter.format(self, record)
        return LOG_COLORS.get(level_name, '%s') % msg


class log_print:
    def __init__(self, log_path_dir, logfile_name):
        self.log_ger = logging.Logger('utils')
        self.log_ger.setLevel(0)
        terminal = logging.StreamHandler()
        terminal.setLevel(logging.INFO)
        
        log_path = log_path_dir + logfile_name
        log_file = RotatingFileHandler(log_path, maxBytes=2*20*1024, backupCount=3)
        log_file.setLevel(logging.INFO)
        
        formatter_ter = log_colour('%(asctime)s %(levelname)s %(message)s')
        formatter_log = logging.Formatter('%(asctime)s: %(message)s')
        
        terminal.setFormatter(formatter_ter)
        log_file.setFormatter(formatter_log)
        
        self.log_ger.addHandler(terminal)
        self.log_ger.addHandler(log_file)
        
    def getlog(self):
        return self.log_ger


class Resources(object):
    def __init__(self):
        self.share_level = "normal" #'low', 'high', 'custom'
        self.share_value = 4000 # ignored unless share_level is 'custom'
        self.reservation = 0
        self.expandabla_reservation = True
        self.limit = -1 #unlimited


class Utils(Singleton):
    #init resource value
    cpu_resources = Resources()
    memory_resources = Resources()
    ha_nodes_dict = {} #For failover script

    def _ssh(self,ip,cmd,username="poweruser",password="poweruser"):
        result = {}
        result['error'] = []
        result['stdout'] = []
        ssh_flag = 0

        if self.ha_nodes_dict != {}:
            obj_log.debug("ha nodes dict: %s" % self.ha_nodes_dict)
            for node in self.ha_nodes_dict:
                if not ssh_flag:
                    temp_result = self.ssh_cmd(self.ha_nodes_dict[node],username,password,cmd)
                    if temp_result['error'] == None:
                        if (temp_result['stderr'] != '' and not(re.search("Warning: Permanently added", temp_result['stderr']))):
                                obj_log.debug("Execute 'cmd' on " + self.ha_nodes_dict[node] +" failed")
                        else:
                            ssh_flag = 1

            if not ssh_flag:
                result['error'] = temp_result['error']
                obj_log.debug(result['error'])
                return result
        else:
            temp_result = self.ssh_cmd(ip,username,password,cmd)
            if temp_result['error'] == None:
                if (temp_result['stderr'] != '' and not (re.search("Warning: Permanently added", temp_result['stderr']))):
                    result['stderr'] = temp_result['stderr']
            else:
                result['error'] = temp_result['error']
                return result

        result['stdout'] = temp_result['stdout']
        return result
    
    def getHACrmInfo(self,ip):
        result = {}

        #Get Online Nodes list
        crm = self._ssh(ip,"crm_mon -r1")
        result = str(crm['stdout'])
        return result
    
    def getHAGroupInfo(self,ip):
            online_nodes = {}

            #Get IP list
            corosync = self._ssh(ip,"corosync-quorumtool -li")
            corosync_result = str(corosync['stdout']).split("\n")
            cmd = "hostname ; ifconfig eth0 | awk '/inet addr:/' | sed -r 's/.*addr:(\S+).*/\\1/'"
            for i in range(0,len(corosync_result)):
                p = re.search('(\d+\.\d+\.\d+\.\d+)', corosync_result[i])
                if p != None:
                    ip = str(p.group(1))
                    temp = self._ssh(ip, cmd)
                    hostname_and_ip = str(temp['stdout']).split("\n")
                    online_nodes[hostname_and_ip[0]] = hostname_and_ip[1]
                    
            return online_nodes


    def getHAResourceMap(self,ip):
        result = {}

        #Get Online Nodes list
        crm = self._ssh(ip,"crm_mon -r1")
        crm_result = str(crm['stdout']).split("\n")
        flag = 0
        current_resource = ""
        current_container = ""
        for line in crm_result:
            p = re.search("Resource Group:\s(\S*)", line)
            if p != None:
                current_resource = p.group(1)
                current_container = ""
                flag = 1
            else:
                if flag:
                    q = re.match("\s*(\S*_\S*).*?(St.*)", line)
                    if q != None:
                        r = re.match("Started\s(\S*)", q.group(2))
                        if r != None:
                            if current_container == "":
                                current_container = r.group(1)
                                result[current_resource] = current_container
                            if current_container != r.group(1):
                                result[current_resource] = ""
                        else:
                            result[current_resource] = ""
        return result

    def compareResourceMap(self,previous_resource_map,resource_map):
        result = {}

        for resource in previous_resource_map:
            if resource_map[resource] == '':
                result[resource] = {}
                result[resource]['previous'] = previous_resource_map[resource]
                result[resource]['current'] = ''
                result[resource]['error'] = 1
            if previous_resource_map[resource] != resource_map[resource]:
                result[resource] = {}
                result[resource]['previous'] = previous_resource_map[resource]
                result[resource]['current'] = resource_map[resource]
        return result

    def checkHAStatus(self, ip, type_flag='resource'):
        result = {}
        result['error'] = ""
        
        #Check if there are offline nodes
        if type_flag != "resource":
            offlineNodes = self.getHAOfflineNodes(ip)
            if offlineNodes:
                obj_log.error("There are offline nodes " + str(offlineNodes) + " , HA status is incorrect")
                obj_log.error(self.getHACrmInfo(ip))
                result['error'] = "Offline nodes exist"
                return result

        #Check if there are stopped resource
        ha_resourcemap = self.getHAResourceMap(ip)
        obj_log.info(ha_resourcemap)
        if ha_resourcemap != {}:
            for key in ha_resourcemap:
                if ha_resourcemap[key] is "":
                    obj_log.error("There are stopped resources " + key + " , HA status is incorrect")
                    obj_log.error(self.getHACrmInfo(ip))
                    result['error'] = "Stopped resources exist"
                    return result
        
            obj_log.info(self.getHACrmInfo(ip))
            obj_log.info("HA status is correct")
            return result
        else:
            obj_log.error("ha resource map is empty")
            result['error'] = "resource map is empty"
            return result

    def check_ha_status(self, ip):
        for i in range(3600):
            check_rtn = self.checkHAStatus(ip)
            if check_rtn['error'] == '':
                obj_log.info('Check ha status successful.')
                return True
            else:
                time.sleep(1)
        else:
            return False

    def getHAOnlineNodes(self, ip):

        #Get Online Nodes list
        online_nodes = []
        crm = self._ssh(ip, "crm_mon -r1")
        crm_result = str(crm['stdout']).split("\n")
        for i in range(0,len(crm_result)):
            p = re.match('Online:.*?\[\s*(.*?)\s*]', crm_result[i])
            if p != None:
                obj_log.debug(p.group(1))
                online_nodes = str(p.group(1)).split()
                obj_log.debug(online_nodes)
        return online_nodes

    def getHAOfflineNodes(self, ip):

        #Get Offline Nodes list
        offline_nodes = []
        crm = self._ssh(ip, "crm_mon -r1")
        crm_result = str(crm['stdout']).split("\n")
        for i in range(0,len(crm_result)):
            p = re.match('OFFLINE:.*?\[\s*(.*?)\s*]', crm_result[i])
            if p != None:
                obj_log.debug(p.group(1))
                offline_nodes = str(p.group(1)).split()
                obj_log.debug(offline_nodes)
        return offline_nodes

    def removeSecondDisk(self, vc, name):
        result = {}
        result['error'] = ""

        vm = vc.get_vm_by_name(name)
        disk_list = []
        for dev in vm.properties.config.hardware.device:
            if dev._type == "VirtualDisk":
                disk_list.append(dev._obj)

        if len(disk_list) > 1:
            for i in range(1,len(disk_list)):
                request = VI.ReconfigVM_TaskRequestMsg()
                _this = request.new__this(vm._mor)
                _this.set_attribute_type(vm._mor.get_attribute_type())
                request.set_element__this(_this)
                spec = request.new_spec()
                dev_change = spec.new_deviceChange()
                dev_change.set_element_device(disk_list[i])
                dev_change.set_element_operation("remove")
                spec.set_element_deviceChange([dev_change])
                request.set_element_spec(spec)
                ret = vc._proxy.ReconfigVM_Task(request)._returnval

        return result

    def add_second_disk(self, server, name, disk_size_in_GB):
        s = server
        VM_NAME = name

        vm = s.get_vm_by_name(VM_NAME)
        info = vm._properties
        VM_PATH = info["path"]

        DATASTORE_NAME = VM_PATH.split()[0] #WHERE THE DISK WILL BE CREATED AT
        DISK_SIZE_IN_MB = disk_size_in_GB*1024
        UNIT_NUMBER = 1

        obj_log.debug("DATASTORE_NAME=%s"%DATASTORE_NAME)

        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(vm._mor)
        _this.set_attribute_type(vm._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()
        dc = spec.new_deviceChange()
        dc.Operation = "add"
        dc.FileOperation = "create"

        hd = VI.ns0.VirtualDisk_Def("hd").pyclass()
        hd.Key = -100
        hd.UnitNumber = UNIT_NUMBER
        hd.CapacityInKB = DISK_SIZE_IN_MB * 1024
        hd.ControllerKey = 1000

        backing = VI.ns0.VirtualDiskFlatVer2BackingInfo_Def("backing").pyclass()
        backing.FileName = DATASTORE_NAME
        backing.DiskMode = "persistent"
        backing.Split = False
        backing.WriteThrough = False
        backing.ThinProvisioned = False
        backing.EagerlyScrub = False
        hd.Backing = backing

        dc.Device = hd

        spec.DeviceChange = [dc]
        request.Spec = spec

        task = s._proxy.ReconfigVM_Task(request)._returnval
        vi_task = VITask(task, s)

        #Wait for task to finis
        status = vi_task.wait_for_state([vi_task.STATE_SUCCESS,
                                         vi_task.STATE_ERROR])
        if status == vi_task.STATE_ERROR:
            obj_log.error("ERROR CONFIGURING VM:%s" % vi_task.get_error_message())
            s.disconnect()
            return False
        else:
            obj_log.info("VM CONFIGURED SUCCESSFULLY")
            s.disconnect()
            return True

    # status=True means connect, status=False means disconnect
    # device_name ex. "VM Network 10g", "VM Network"
    def change_network_device_connect_status(self, server, name, device_name, status=False):
        vm = server.get_vm_by_name(name)

        # Find Virtual Nic device
        net_device = None
        for dev in vm.properties.config.hardware.device:
            if dev.deviceInfo.summary == device_name:
                net_device = dev._obj
                break

        if not net_device:
            server.disconnect()
            raise Exception("The vm seems to lack a Virtual Nic")

        # Disconnect the device
        net_device.Connectable.Connected = status
             
        # Invoke ReconfigVM_Task
        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(vm._mor)
        _this.set_attribute_type(vm._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()
        dev_change = spec.new_deviceChange()
        dev_change.set_element_device(net_device)
        dev_change.set_element_operation("edit")
        spec.set_element_deviceChange([dev_change])
        request.set_element_spec(spec)
        ret = server._proxy.ReconfigVM_Task(request)._returnval
        
        # Wait for the task to finish
        task = VITask(ret, server)
        
        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            obj_log.info("VM successfully reconfigured")
            return True
        elif status == task.STATE_ERROR:
            obj_log.error("Error reconfiguring vm: %s" % task.get_error_message())
            return False

    def __create_sub_rp(self,server, parent_rp, name):
        req = VI.CreateResourcePoolRequestMsg()
        _this = req.new__this(parent_rp)
        _this.set_attribute_type(parent_rp.get_attribute_type())
        req.set_element__this(_this)
    
        req.Name = name
        spec = req.new_spec()
        cpu_allocation = spec.new_cpuAllocation()
        memory_allocation = spec.new_memoryAllocation()
    
        #cpu allocation settings
        cpu_allocation.ExpandableReservation = self.cpu_resources.expandabla_reservation
        cpu_allocation.Limit = self.cpu_resources.limit
        cpu_allocation.Reservation = self.cpu_resources.reservation
        shares = cpu_allocation.new_shares()
        shares.Level = self.cpu_resources.share_level
        shares.Shares = self.cpu_resources.share_value
        cpu_allocation.Shares = shares
        spec.CpuAllocation = cpu_allocation
    
        #memory allocation settings
        memory_allocation.ExpandableReservation = self.memory_resources.expandabla_reservation
        memory_allocation.Limit = self.memory_resources.limit
        memory_allocation.Reservation = self.memory_resources.reservation
        shares = memory_allocation.new_shares()
        shares.Level = self.memory_resources.share_level
        shares.Shares = self.memory_resources.share_value
        memory_allocation.Shares = shares
        spec.MemoryAllocation = memory_allocation
    
        req.Spec = spec
    
        return server._proxy.CreateResourcePool(req)._returnval
    
    def __get_parent_rp(self, server, parent):
        if parent == "root" :
            parent = ""
        else :
            parent = "/"+parent
    
        parent_mor_list = []
        for k,v in server.get_resource_pools().items():
            if v == '/Resources'+parent:
                parent_mor_list.append(k)
    
        return parent_mor_list
    
    def create_resource_pool(self, server, res_pool_name, parent='root'):
        parent_mor_list = self.__get_parent_rp(server,parent)
        
        for item in parent_mor_list :
            try:
                self.__create_sub_rp(server, item, res_pool_name)
            except Exception as e:
                obj_log.debug('Create resource pool ' + res_pool_name + str(e))
                return False
            else:
                obj_log.debug('Create resource pool <' + res_pool_name + '> successfully.')
                return True
    
    def __delete_res_pool(self,server, mor):
        req = VI.Destroy_TaskRequestMsg()
        _this = req.new__this(mor)
        _this.set_attribute_type(mor.get_attribute_type())
        req.set_element__this(_this)
    
        task_mor = server._proxy.Destroy_Task(req)._returnval
        return VITask(task_mor, server)
    
    def delete_resource_pool(self,server, res_pool_name, parent='root'):
        if parent == "root" :
            parent = ""
        else :
            parent = parent+"/"

        resources = server.get_resource_pools()
        res_mor_list = []
        for k,v in resources.items():
            if v == '/Resources/' + parent + res_pool_name:
                res_mor_list.append(k)

        for item in res_mor_list:
            try:
                self.__delete_res_pool(server, item)
            except Exception as e:
                obj_log.debug('Delete resource pool ' + res_pool_name + str(e))
                return False
            else:
                obj_log.debug('Delete resource pool <' + res_pool_name + '> successfully.')
                return True
    ########################################################################################
    def __get_host_mor(self,server, host):
        mor = None
        for host_mor, host_name in server.get_hosts().items():
            if host_name == host:
                mor = host_mor
                break
        return mor

    def __get_res_pool_mor(self,server, resource_pool):
        mor = None
        res_pool_temp = '/Resources/' + resource_pool
        for rp_mor, rp_path in server.get_resource_pools().items():
            if res_pool_temp == rp_path:
                mor = rp_mor
                break
        return mor

    def __get_datastore_mor(self,server, datastore):
        mor = None
        for ds_mor, ds_path in server.get_datastores().items():
            if ds_path == datastore:
                mor = ds_mor
                break
        return mor

    def get_datastore_info(self, server, host, datastore_name):
        rtn_dict = {}
        host_mor = self.__get_host_mor(server, host)
        props = pysphere.VIProperty(server, host_mor)

        for item in props.datastore:
            if datastore_name == item.summary.name:
                rtn_dict['accessible'] = item.summary.accessible
                rtn_dict['free_space'] = item.summary.freeSpace
                rtn_dict['type'] = item.summary.type
                rtn_dict['capacity'] = item.summary.capacity
                rtn_dict['name'] = item.summary.name
                rtn_dict['multiple_host_access'] = item.summary.multipleHostAccess
                return rtn_dict
    # ========================================================================================
    # ==========================upload&download from datastorage==============================
    # ========================================================================================

    def _do_request(self, server, url, data=None):
        opener = urllib2.build_opener(self._build_auth_handler(server))
        request = urllib2.Request(url, data=data)
        if data:
            request.get_method = lambda: 'PUT'
        return opener.open(request)

    def _get_url(self, server, resource, datastore_name, dc_name):
        if not resource.startswith("/"):
            resource = "/" + resource

        params = {"dsName": datastore_name}
        if dc_name:
            params["dcPath": dc_name]
        params = urllib.urlencode(params)

        return "%s%s?%s" % (self._get_service_url(server), resource, params)

    def _get_service_url(self, server):
        service_url = server._proxy.binding.url
        return service_url[:service_url.rindex("/sdk")]

    def _build_auth_handler(self, server):
        service_url = self._get_service_url(server)
        user = server._VIServer__user
        password = server._VIServer__password
        auth_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
        auth_manager.add_password(None, service_url, user, password)
        return urllib2.HTTPBasicAuthHandler(auth_manager)

    def upload(self, server, local_file_path, remote_file_path, datastore_name, dc_name=None):
        fd = open(local_file_path, "r")
        data = fd.read()
        fd.close()
        resource = "/folder/%s" % remote_file_path.lstrip("/")
        url = self._get_url(server, resource, datastore_name, dc_name)
        resp = self._do_request(server, url, data)
        return resp.code == 200

    def download(self, server, remote_file_path, local_file_path, datastore_name, dc_name=None):
        resource = "/folder/%s" % remote_file_path.lstrip("/")
        url = self._get_url(server, resource, datastore_name, dc_name)
        if sys.version_info >= (2, 6):
            resp = self._do_request(server, url)
            CHUNK = 16 * 1024
            fd = open(local_file_path, "wb")
            while True:
                chunk = resp.read(CHUNK)
                if not chunk: break
                fd.write(chunk)
            fd.close()
        else:
            urllib.urlretrieve(url, local_file_path)


    def run_cmd(self, cmd, timeout=600):
        rtn_dict = {}
        obj_rtn = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        start_time = time.time()
        while True:
            if obj_rtn.poll() != None:
                break
             
            end_time = time.time()
             
            run_time = end_time - start_time
             
            if run_time > timeout:
                obj_rtn.terminate()
                raise Exception('Run command timeout: %s' % cmd)
             
            time.sleep(0.1)
        
        out = obj_rtn.stdout.read()
        err = obj_rtn.stderr.read()
        
        rtn_dict['stdout'] = out
        rtn_dict['stderr'] = err
        rtn_dict['returncode'] = obj_rtn.returncode
        
        return rtn_dict
    
    def clone_vm(self, server, name, vm_template, host, datastore, poweron=True, sync=True, resourcepool=None):

        obj_log.debug('server', server.get_hosts())

        #name: name of cloned VM;
        #vm_template: name of source template;
        #labName: VM''s belong to a training lab;
        #host: to deploy the VM on;
        #labgroup: sequence number of lab system to use;
        #sync: synchronous mode or not
        try:
            vm = server.get_vm_by_name(name=vm_template)
        except Exception as e:
            obj_log.debug(e)
            return False

        host_mor = self.__get_host_mor(server, host)   #locate destination host MOR

        if resourcepool != None:
            rp_mor = self.__get_res_pool_mor(server,resourcepool)   # locate default resource pool of destination host (the resource pool which parent folder is equal to the parent folder of the host)
        else:
            rp_mor = None

        ds_mor = self.__get_datastore_mor(server, datastore)   # destination data store
        try:
            vm.clone(name=name, sync_run=sync, resourcepool=rp_mor, datastore=ds_mor, host=host_mor, power_on=poweron)  # returns a VITask object
        except Exception as e:
            obj_log.debug('Clone <' + name + '> to ' + host + ' failure.')
            obj_log.debug('Clone ' + name + str(e))
            return False
        else:
            obj_log.debug('Clone <' + name + '> to ' + host +' successfully.')
            return True
    ########################################################################################

    def delete_vm(self, server, vm_name) :
        try:
            vm = server.get_vm_by_name(name=vm_name)
        except Exception as e:
            obj_log.error(e)
            return False

        request = VI.Destroy_TaskRequestMsg()
        _this = request.new__this(vm._mor)
        _this.set_attribute_type(vm._mor.get_attribute_type())
        request.set_element__this(_this)
        ret = server._proxy.Destroy_Task(request)._returnval

        #Wait for the task to finish
        task = VITask(ret, server)

        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            obj_log.info('Delete <' + vm_name + '> successfully')
            return True
        elif status == task.STATE_ERROR:
            obj_log.error("Delete " + vm_name + " error message : " + task.get_error_message())
            return False

    def get_vm_status(self, server, vm_name):
        try:
            vm = server.get_vm_by_name(name=vm_name)
        except Exception as e:
            obj_log.debug(e)
            return False
        
        rtn = vm.get_status()

        return rtn

    def create_snapshot(self, server, vm_name, snapshot_name, sync_run=True, description=None,memory=True, quiesce=True):
        try:
            vm = server.get_vm_by_name(name=vm_name)
        except Exception as e:
            obj_log.debug(e)
            return False

        try:
            vm.create_snapshot(snapshot_name, sync_run, description, memory, quiesce)
        except Exception as e:
            obj_log.debug('Create snapshot <' + snapshot_name + '> for ' + vm_name + ' failure.')
            obj_log.debug('Create snapshot ' + snapshot_name + ' '+ str(e))
            return False
        else:
            obj_log.debug('Create snapshot <' + snapshot_name + '> for ' + vm_name + ' successfully.')
            return True

    def delete_snapshot(self, server, vm_name, snapshot_name, sync_run=True, remove_children=False):
        try:
            vm = server.get_vm_by_name(name=vm_name)
        except Exception as e:
            obj_log.debug(e)
            return False

        try:
            vm.delete_named_snapshot(snapshot_name, remove_children, sync_run)
        except Exception as e:
            obj_log.debug('Delete snapshot <' + snapshot_name + '> for ' + vm_name + ' failure.')
            obj_log.debug('Delete snapshot ' + snapshot_name + ' '+ str(e))
            return False
        else:
            obj_log.debug('Delete snapshot <' + snapshot_name + '> for ' + vm_name + ' successfully.')
            return True

    def __create_nas_store(self, server, host, ds_name, remote_host, remote_path, username=None, password=None, volume_type=None, access_mode = 'readWrite'):

        #access_mode: 'readOnly' or 'readWrite' (if not set defaults to readWrite)
        #volume_type: 'CIFS' or 'NFS' (if not set defaults to NFS)
        host_properties = VIProperty(server, host)

        hds = host_properties.configManager.datastoreSystem._obj

        request = VI.CreateNasDatastoreRequestMsg()
        _this = request.new__this(hds)
        _this.set_attribute_type(hds.get_attribute_type())
        request.set_element__this(_this)

        spec = request.new_spec()
        spec.set_element_accessMode(access_mode)
        spec.set_element_localPath(ds_name)
        spec.set_element_remoteHost(remote_host)
        spec.set_element_remotePath(remote_path)
        if username:
            spec.set_element_userName(username)
        if password:
            spec.set_element_password(password)
        if volume_type:
            spec.set_element_type(volume_type)

        request.set_element_spec(spec)

        return server._proxy.CreateNasDatastore(request)._returnval

    def mount_nfs(self, server, host, ds_name, ads_eth1, path, username=None, password=None, volume_type=None, access_mode = 'readWrite'):
        host_mor = self.__get_host_mor(server, host)
        try:
            self.__create_nas_store(server, host_mor, ds_name, ads_eth1, path, username, password, volume_type, access_mode)
        except Exception as e:
            obj_log.debug('Mount <' + ds_name + '> nfs share to <' + host + '> failure, ' + str(e))
            return False
        else:
            obj_log.debug('Mount <' + ds_name + '> nfs share to <' + host + '> successfully.')
            return True

    def __delete_nas_store(self, server, host_mor, ds_mor):

        host = VIProperty(server, host_mor)

        ds_system = host.configManager.datastoreSystem._obj

        request = VI.RemoveDatastoreRequestMsg()
        _this = request.new__this(ds_system)
        _this.set_attribute_type(ds_system.get_attribute_type())
        request.set_element__this(_this)
        request.Datastore = ds_mor

        return server._proxy.RemoveDatastore(request)

    def umount_nfs(self, server, host, ds_name):
        hosts = server.get_hosts()
        datastores = server.get_datastores()

        for k,v in hosts.items():
            if v == host:
                host_mor = k

        for k,v in datastores.items():
            if v == ds_name:
                ds_mor = k
        try:
            self.__delete_nas_store(server, host_mor, ds_mor)
        except Exception as e:
            obj_log.debug('Umount ' + ds_name + str(e))
            return False
        else:
            obj_log.debug('Umount <' + ds_name + '> nfs share successfully.')
            return True

    def poweron_vm(self, server, vm_name, datacenter=None, sync_run=True, host=None, errorMsgFlag=False):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.error(e)
            if not errorMsgFlag:
                return str(e)
            else:
                return False
        
        if vm.get_status() == 'POWERED ON':
            return True
        
        try:
            vm.power_on(sync_run, host)
        except Exception as e:
            obj_log.error('Power on ' + vm_name + str(e))
            if not errorMsgFlag:
                return False
            else:
                return ('Power on ' + vm_name + str(e))
        else:
            obj_log.info('Power on <' + vm_name + '> successfully')
            if not errorMsgFlag:
                return True
            else:
                return ('Power on <' + vm_name + '> successfully')

    def poweroff_vm(self, server, vm_name, datacenter=None, sync_run=True):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.error(e)
            return False
        
        if vm.get_status() == 'POWERED OFF':
            obj_log.info(vm_name + " has been poweroff.\n")
            return True
        
        try:
            vm.power_off(sync_run)
        except Exception as e:
            obj_log.error('Power off ' + vm_name + str(e))
            return False
        else:
            time_flag = 0
            while True:
                if time_flag > 300:
                    obj_log.error('Poweroff ' + vm_name + ' timeout.')
                    return False
                
                rtn = self.get_vm_status(server, vm_name)
                if rtn == 'POWERED OFF':
                    obj_log.info(vm_name + " has been poweroff.\n")
                    break
                else:
                    time.sleep(1)
                    time_flag = time_flag + 1
                    
            return True

    def reset_vm(self, server, vm_name, sync_run=True, datacenter=None):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.error(e)
            return False

        try:
            vm.reset(sync_run)
        except Exception as e:
            obj_log.error('Reset ' + vm_name + str(e))
            return False

        else:
            obj_log.info('Reset <' + vm_name + '> successfully')
            return True

    def reboot_vm(self, server, vm_name, datacenter=None):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.error(e)
            return False

        try:
            vm.reboot_guest()
        except Exception as e:
            obj_log.error('Reboot ' + vm_name + str(e))
            return False

        else:
            obj_log.info('Reboot <' + vm_name + '> successfully')
            return True

    def shutdown_vm(self, server, vm_name, timeout=1800, datacenter=None):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.error(e)
            return False

        try:
            vm.shutdown_guest()
        except Exception as e:
            obj_log.error('Shutdown ' + vm_name + str(e))
            return False
        else:
            time_flag = 0
            while True:
                if time_flag > timeout:
                    obj_log.error('Shutdown ' + vm_name + ' timeout.')
                    return False
                
                rtn = self.get_vm_status(server, vm_name)
                if rtn == 'POWERED OFF':
                    obj_log.info(vm_name + " has been shutdown.\n")
                    break
                else:
                    time.sleep(1)
                    time_flag = time_flag + 1
                    
            return True

    def migrate_vm(self, server, vm_name, datacenter=None, sync_run=True, priority='default', resource_pool=None, host=None, state=None):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.debug(e)
            return False

        if resource_pool != None:
            rp_mor = self.__get_res_pool_mor(server,resource_pool)
        else:
            rp_mor = None

        if host != None:
            host_mor = self.__get_host_mor(server, host)
        else:
            host_mor = None

        try:
            vm.migrate(sync_run, priority, rp_mor, host_mor, state)
        except Exception as e:
            obj_log.debug(vm_name + ': ' + str(e))
            return False
        else:
            obj_log.debug('Migrate <' + vm_name + '> successfully')
            return True

    def relocate_vm(self, server, vm_name, datacenter=None, sync_run=True, priority='default', datastore=None, resource_pool=None, host=None, transform=None):
        try:
            vm = server.get_vm_by_name(vm_name, datacenter)
        except Exception as e:
            obj_log.debug(e)
            return False

        if datastore != None:
            ds_mor = self.__get_datastore_mor(server, datastore)
        else:
            ds_mor = None

        if resource_pool != None:
            rp_mor = self.__get_res_pool_mor(server,resource_pool)
        else:
            rp_mor = None

        if host != None:
            host_mor = self.__get_host_mor(server, host)
        else:
            host_mor = None

        try:
            vm.relocate(sync_run, priority, ds_mor, rp_mor, host_mor, transform)
        except Exception as e:
            obj_log.debug(vm_name + str(e))
            return False
        else:
            obj_log.debug('Relocate <' + vm_name + '> successfully')
            return True

    def get_ssd_datastore(self, ip, username, password):
        obj_log.debug('ip', ip)

        deviceCmd = 'esxcli storage core device list'
        vmfsCmd = 'esxcli storage vmfs extent list'

        result1 = self.ssh_cmd(ip, username, password, deviceCmd)
        result2 = self.ssh_cmd(ip, username, password, vmfsCmd)

        deviceList = result1['stdout'].split("\n\n")

        deviceRes = []
        pattern1 = 'Display Name:.*\((.*)\)'
        pattern2 = 'Is SSD: (.*)\n'
        for device in deviceList :
            m = re.search(pattern1,device)
            n = re.search(pattern2,device)
            if n.group(1) == "true" :
                deviceRes.append(m.group(1))

        vmfsRes = []
        temp = result2['stdout'].split("\n")
        for i in range(2,len(temp)-1):
            vmfsTemp = temp[i].split()
            vmfsDict = {}
            vmfsDict['VName'] = vmfsTemp[0]
            vmfsDict['DisplayName'] = vmfsTemp[3]
            vmfsRes.append(vmfsDict)

        ssdStorage = []
        for datastore in vmfsRes :
            if datastore['DisplayName'] in deviceRes :
                ssdStorage.append(datastore['VName'])

        return ssdStorage

    def get_local_datastore(self, ip, username, password):
        deviceCmd = 'esxcli storage core device list'
        vmfsCmd = 'esxcli storage vmfs extent list'

        result1 = self.ssh_cmd(ip, username, password, deviceCmd)
        result2 = self.ssh_cmd(ip, username, password, vmfsCmd)

        deviceList = result1['stdout'].split("\n\n")

        deviceRes = []
        pattern1 = 'Display Name:.*\((.*)\)'
        pattern2 = 'Is Local: (.*)\n'
        for device in deviceList :
            m = re.search(pattern1,device)
            n = re.search(pattern2,device)
            if n.group(1) == "true" :
                deviceRes.append(m.group(1))

        vmfsRes = []
        temp = result2['stdout'].split("\n")
        for i in range(2,len(temp)-1):
            vmfsTemp = temp[i].split()
            vmfsDict = {}
            vmfsDict['VName'] = vmfsTemp[0]
            vmfsDict['DisplayName'] = vmfsTemp[3]
            vmfsRes.append(vmfsDict)

        localStorage = []
        for datastore in vmfsRes :
            if datastore['DisplayName'] in deviceRes :
                localStorage.append(datastore['VName'])

        return localStorage

#     def get_vcenter_ssd(self, vcs) :
#         result = []
#         for vc in vcs.keys():
#             obj_log.debug('--------', vc)
#             server = VIServer()
#             server.connect(vc, "root", "vmware")
#             info = []
#             ssdDict = {}
#             for host_ip in server.get_hosts().values() :
#                 if host_ip == '10.21.2.60':
#                     continue
#                 ssdDict['host'] = host_ip
#                 ssdDict['ds'] = self.get_ssd_datastore(host_ip,'root','password')
#                 info.appent(ssdDict)
#             result[vc].appent(info)
#         return result
#
#     def get_vc_info(self, vcs):
#         obj_log.debug("Please wait for get vCenter info...")
#         VCInfo = {}
#         server = VIServer()
#
#         m = 1
#
#         for vc_ip in vcs.keys():
#             VCInfo['VC'+str(m)] = {}
#             vc_username = vcs[vc_ip]['username']
#             vc_password = vcs[vc_ip]['password']
#             server.connect(vc_ip, vc_username, vc_password)
#
#             cluster_info = server.get_clusters()
#             obj_log.debug('------', cluster_info)
#
#
#             temp = vc_ip.split(".")
#             VCInfo['VC'+str(m)]['VCName'] = "VC" + temp[2] + temp[3]
#             VCInfo['VC'+str(m)]['VCIP'] = vc_ip
#             VCInfo['VC'+str(m)]['username'] = vc_username
#             VCInfo['VC'+str(m)]['password'] = vc_password
#             VCInfo['VC'+str(m)]['esxHost'] = {}
#             VCInfo['VC'+str(m)]['cluster_num'] = 0
#
#             if cluster_info == {}:
#
#                 i = 1
#
#                 for (host_mor, host_ip) in server.get_hosts().items():
#                     if host_ip == '10.16.3.41' or host_ip == '10.16.3.43' or host_ip == '10.16.3.44' or host_ip == '10.16.190.12' or host_ip == '10.16.3.96'  or host_ip == '10.16.3.97' or host_ip == '10.16.3.98':
#                         continue
#                     props = VIProperty(server,host_mor)
#
#                     obj_log.debug('---', props)
#
#                     VCInfo['VC'+str(m)]['esxHost']['host'+str(i)] = {}
#                     VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostIP'] = host_ip
#                     j = 1
#                     VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS'] = {}
#                     VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS']['nonssd'] = {}
#                     VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS']['nfs'] = {}
#                     for item in props.datastore:
#                         if item.summary.type == "VMFS" and int(item.summary.freeSpace)/1024/1024/1024 > 50 and item.summary.accessible == True:
#                             VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS']['nonssd']['DS'+str(j)] = item.summary.name
#                             j += 1
#                         elif item.summary.type == 'NFS':
#                             VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS']['nfs']['DS'+str(j)] = item.summary.name
#                             j += 1
#                     i += 1
#
#                 for host in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     if VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'] == {}:
#                         del VCInfo['VC'+str(m)]['esxHost'][host]
#
#                 if VCInfo['VC'+str(m)]['esxHost'] == {}:
#                     del VCInfo['VC'+str(m)]['esxHost']
#
#                 all_ssd_list = []
#
#                 for host in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     host_ip = VCInfo['VC'+str(m)]['esxHost'][host]['hostIP']
#                     if host_ip == '10.21.2.60' or host_ip == '10.16.3.41' or host_ip == '10.16.3.43' or host_ip == '10.16.3.44' or host_ip == '10.16.190.12' or host_ip == '10.16.3.96' or host_ip == '10.16.3.97' or host_ip == '10.16.3.98':
#                         continue
#                     ssd_list = self.get_ssd_datastore(host_ip, 'root', 'password')
#                     all_ssd_list.extend(ssd_list)
#
#                     local_list = self.get_local_datastore(host_ip, 'root', 'password')
#
#                     for ds in VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'].keys():
#                         if VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'][ds] not in local_list:
#                             del VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'][ds]
#
#                 for host in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['ssd'] = {}
#                     for ds in VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'].keys():
#                         if VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'][ds] in all_ssd_list:
#                             VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['ssd'][ds] = VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'][ds]
#                             del VCInfo['VC'+str(m)]['esxHost'][host]['hostDS']['nonssd'][ds]
#
#
#             else:
#                 for cluster_mor, cluster_name in cluster_info.items():
#                     VCInfo['VC'+str(m)]['cluster_num'] = VCInfo['VC'+str(m)]['cluster_num'] + 1
#
#
#                     host_info = server.get_hosts(from_mor=cluster_mor)
#                     i = 1
#
#                     VCInfo['VC'+str(m)]['esxHost'][cluster_name] = {}
#
#                     for (host_mor, host_ip) in host_info.items():
#                         props = VIProperty(server,host_mor)
#                         VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)] = {}
#                         VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)]['hostIP'] = host_ip
#                         j = 1
#                         VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)]['hostDS'] = {}
#                         VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)]['hostDS']['nonssd'] = {}
#                         VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)]['hostDS']['nfs'] = {}
#                         for item in props.datastore:
#                             if item.summary.type == "VMFS" and int(item.summary.freeSpace)/1024/1024/1024 > 50 and item.summary.accessible == True:
#                                 VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)]['hostDS']['nonssd']['DS'+str(j)] = item.summary.name
#                                 j += 1
#                             elif item.summary.type == 'NFS':
#                                 VCInfo['VC'+str(m)]['esxHost'][cluster_name]['host'+str(i)]['hostDS']['nfs']['DS'+str(j)] = item.summary.name
#                                 j += 1
#
#                         i += 1
#
#                 for cluster in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     for host in VCInfo['VC'+str(m)]['esxHost'][cluster].keys():
#                         if VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'] == {}:
#                             del VCInfo['VC'+str(m)]['esxHost'][cluster][host]
#
#                 for cluster in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     if VCInfo['VC'+str(m)]['esxHost'][cluster] == {}:
#                         del VCInfo['VC'+str(m)]['esxHost'][cluster]
#
#                 all_ssd_list = []
#
#                 for cluster in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     for host in VCInfo['VC'+str(m)]['esxHost'][cluster].keys():
#                         host_ip = VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostIP']
#                         if host_ip == '10.21.2.60':
#                             continue
#                         ssd_list = self.get_ssd_datastore(host_ip, 'root', 'password')
#                         all_ssd_list.extend(ssd_list)
#
#                         local_list = self.get_local_datastore(host_ip, 'root', 'password')
#
#                         for ds in VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'].keys():
#                             if VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'][ds] not in local_list:
#                                 del VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'][ds]
#
#                 for cluster in VCInfo['VC'+str(m)]['esxHost'].keys():
#                     for host in VCInfo['VC'+str(m)]['esxHost'][cluster].keys():
#                         VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['ssd'] = {}
#                         for ds in VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'].keys():
#                             if VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'][ds] in all_ssd_list:
#                                 VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['ssd'][ds] = VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'][ds]
#                                 del VCInfo['VC'+str(m)]['esxHost'][cluster][host]['hostDS']['nonssd'][ds]
#
#             m = m + 1
#
#
#         server.disconnect()
#         obj_log.debug("Get vCenter info done.\n")
#         return VCInfo

    def get_host_network_info(self, server):

        host_network_dict = {}

        host_info = server.get_hosts()

        for host_mor, host_ip in host_info.items():

            props = VIProperty(server,host_mor)

            vswitch_active_nic = {}

            for item in props.configManager.networkSystem.networkInfo.vswitch:
                try:
                    vswitch_active_nic[item.name] = item.spec.policy.nicTeaming.nicOrder.activeNic
                except Exception:
                    pass

            active_nic = {}
            active_nic['1g'] = []
            active_nic['10g'] = []
            for item in props.configManager.networkSystem.networkInfo.pnic:
                try:
                    if item.linkSpeed.speedMb == 1000:
                        active_nic['1g'].append(item.device)
                    elif item.linkSpeed.speedMb == 10000:
                        active_nic['10g'].append(item.device)
                except Exception:
                    pass

            rtn_dict = {}

            for tmp in active_nic.keys():
                rtn_dict[tmp] = {}
                for tmp1 in vswitch_active_nic.keys():
                    for tmp2 in vswitch_active_nic[tmp1]:
                        for tmp3 in active_nic[tmp]:
                            if tmp2 == tmp3:
                                rtn_dict[tmp][tmp1] = tmp2
                                break

            rtn_dict_1 = {}

            for rtn in rtn_dict.keys():
                rtn_dict_1[rtn] = []

                for item in props.configManager.networkSystem.networkInfo.portgroup:

                    for rtn_tmp in rtn_dict[rtn].keys():

                        if rtn_tmp == item.spec.vswitchName:
                            rtn_dict_1[rtn].append(item.spec.name)

            tmp_list = []

            for item in props.network:

                if item.summary.accessible == True:
                    tmp_list.append(item.summary.name)

            for rtn_1 in rtn_dict_1.keys():
                tmp_list_1 = copy.deepcopy(rtn_dict_1[rtn_1])
                for tmp in tmp_list_1:
                    if tmp_list.count(tmp) == 0:
                        rtn_dict_1[rtn_1].remove(tmp)

            host_network_dict[host_ip] = rtn_dict_1

        return host_network_dict

#     def get_usx_ip(self, ip_template, testbed_name):
#         pattern = '\d+$'
#         rtn_tmp = re.search(pattern, testbed_name)
#         ip_segment = rtn_tmp.group()
#
#         ip_list = []
#
#         for m in range(29):
#             j = (m+1)/10
#             k = (m+1)%10
#             ip = ip_template + str(int(ip_segment)+j) + str(k)
#             ip_list.append(ip)
#
#         return ip_list
#
#     def get_vg_size(self, all_config):
#         agg_num = all_config['agg_config']['agg_num']
#         agg_collect_disk = all_config['agg_config']['export']['disk']
#         agg_collect_mem = all_config['agg_config']['export']['memory']
#         if ( agg_num >= 6) :
#             if all_config['pool_config']["pool1"]["raid_type"] == "raid_0" :
#                 vgDiskSize = (agg_num*agg_collect_disk)/2
#             else :
#                 vgDiskSize = (agg_num*agg_collect_disk)/2 - agg_collect_disk
#
#             if all_config['pool_config']["pool2"]["raid_type"] == "raid_0" :
#                 vgMemSize = (agg_num*agg_collect_mem)/2
#             else :
#                 vgMemSize = (agg_num*agg_collect_mem)/2 - agg_collect_mem
#         else :
#             if all_config['pool_config']["pool1"]["raid_type"] == "raid_0" :
#                 vgDiskSize = (agg_num*agg_collect_disk)
#             else :
#                 vgDiskSize = (agg_num*agg_collect_disk) - agg_collect_disk
#
#             if all_config['pool_config']["pool2"]["raid_type"] == "raid_0" :
#                 vgMemSize = (agg_num*agg_collect_mem)
#             else :
#                 vgMemSize = (agg_num*agg_collect_mem) - agg_collect_mem
#
#         allADSDisk = 0
#         allADSMem = 0
#         for exports in all_config['ads_config'].values() :
#             allADSDisk += exports["export"]["disk"]
#             allADSMem += exports["export"]["memory"]
#
#         allADSDisk = allADSDisk + 3
#         allADSMem = allADSMem + 3
#
#         if (allADSDisk > vgDiskSize) or (allADSMem > vgMemSize):
#             print ("Capacity pool volume group size: " + str(vgDiskSize))
#             print ("Memory pool volume group size: " + str(vgMemSize))
#             rtn = "Get vg size fail, the ADS export disk or memory is greater than pool volume group size, please check it"
#             return rtn
#         else:
#             vg = {
#                   'vg_disk': vgDiskSize,
#                   'vg_mem': vgMemSize
#                   }
#             return vg
#
#     def mk_json_path(self, testbed_name):
#         jsonFilePath = "./Json"
#         if not os.path.isdir(jsonFilePath):
#             os.mkdir(jsonFilePath)
#         tempFilePath = jsonFilePath+"/"+testbed_name
#         if os.path.isdir(tempFilePath):
#             cmd = "rm -rf " + tempFilePath
#             os.system(cmd)
#         os.mkdir(tempFilePath)
#         json_path = tempFilePath
#
#         return json_path

    def check_migration_status(self, amc_ip, username='admin', password='poweruser'):
        cmd = "cat /var/log/usxm-migration.log"
        obj_log.debug("Start check migration log")
        for __ in range(100):
            rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd)
            if rtn_dict['error'] != None:
                obj_utils.progressbar_k(5)
                continue
            if "Successfully migrated USX manager server" in rtn_dict['stdout']:
                obj_log.info('Check AMC migration successfully')
                return True
            else:
                obj_log.info('Waiting migration ...')
                obj_utils.progressbar_k(5)
        obj_log.error('Check AMC migration time out...')
        return False

    def check_amc_status(self, amc_ip, username='admin', password='poweruser', usx_version='3.2.0'):
        cmd1 = "ps -ef|grep amc"
        timeout= 0
        while True:
            if timeout == 60:
                obj_log.debug('Check amc status timeout.')
                return False
            # add timeout for avoid it was stuck with some bug
            try:
                rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd1, timeout=300)
            except Exception as e:
                obj_log.error(e)
                obj_log.error("Timeout to run ssh_cmd on AMC")
                return False

            if rtn_dict['error'] != None:
                obj_log.error(rtn_dict['error'])
                obj_utils.progressbar_k(10)
                timeout = timeout + 1
                continue

            if usx_version not in ['3.0.1', '3.1.0', '3.1.1', '3.1.2', '3.2.0']:
                if 'amc-config.yml' in rtn_dict['stdout']:
                    return True
                else:
                    obj_utils.progressbar_k(5)
                    timeout = timeout + 1
                    continue
            else:
                if 'amc-insight-config.yml' in rtn_dict['stdout'] and 'amc-config.yml' in rtn_dict['stdout']:
                    return True
                else:
                    obj_utils.progressbar_k(5)
                    timeout = timeout + 1
                    continue

    def deploy_amc(self, all_config):
        user = all_config['user']
        main_amc_ip = all_config['amc_ip']
        amc_num = all_config['amc_num']
        ip_range = all_config['ip_range']
        amc_username = all_config['login_config']['username']
        amc_password = all_config['login_config']['password']
        usx_version = all_config['usx_version']
        ovf_path = all_config['usx_build_path']
        vcs = all_config['vcs']
        testbed_name = all_config['testbed_name']
        stretch_cluster = all_config['stretch_cluster']
        
        vc_ip = vcs.keys()[0]
        vc_user = vcs[vc_ip]['username']
        vc_pwd = vcs[vc_ip]['password']
        gateway = vcs[vc_ip]['gateway']
        datacenter = vcs[vc_ip]['dcs'].keys()[0]
        hosts = vcs[vc_ip]['dcs'][datacenter][0]['hosts']
        host_list = hosts.keys()
        host_num = len(host_list)
        
        if stretch_cluster == 'true':
            site1_host_list = []
            site2_host_list = []
            
            for n in range(host_num):
                if n < host_num/2:
                    site1_host_list.append(host_list[n])
                else:
                    site2_host_list.append(host_list[n])

           
        clustername = vcs[vc_ip]['dcs'][datacenter][0]['clustername']

        temp_list = gateway.split('.')

        amc_ip_list = []
        amc_ip_list.append(main_amc_ip)

        if amc_num != 1:
            tmp_ip_list = ip_range.split('-')
            ip_start_segment = tmp_ip_list[0].split('.')
            ip_end_segment = tmp_ip_list[1].split('.')
            ip_start = int(ip_start_segment[1])
            ip_end = int(ip_end_segment[1])
            ip_segment = ip_start_segment[0]
            ip_num = ip_end - ip_start + 1
            j = 1
            for i in range(ip_start, ip_start + amc_num-1):
                if j > ip_num:
                    obj_log.debug('IP num insufficient.')
                    return False
                tmp_amc_ip = temp_list[0] + '.' + temp_list[1] + '.' + ip_segment + '.' + str(i)
                amc_ip_list.append(tmp_amc_ip)
                j = j + 1

        tmp_list = ovf_path.split('/')
        tmp_list_leng = len(tmp_list)

        build = tmp_list[tmp_list_leng-2]
         
        pattern2 = '[\d+.]+[\d]+'
        rtn_tmp = re.search(pattern2, build)

        usx_version = rtn_tmp.group()

        rtn_tmp_dict = {}
        amc_ip_name_dict = {}

        amc_name_list = []
        
        obj_log.debug('Start deploy amc...')
        k = 0
        for amc_ip in amc_ip_list:
            if k == host_num:
                k = 0
                
            pattern1 = '\d+$'
            rtn_tmp = re.search(pattern1, amc_ip)
            rtn1 = rtn_tmp.group()
            hostname = 'AMC' + rtn1
              
            amc_name = user + '-AMC-' + usx_version + '-' + testbed_name + '-' + rtn1
            amc_ip_name_dict[amc_ip] = amc_name
            amc_name_list.append(amc_name)
            
            if stretch_cluster == 'true':
                if k == 0:
                    host = random.choice(site1_host_list)
                elif k == 1:
                    host = random.choice(site2_host_list)
                else:
                    break
                
                obj_log.debug('stretch_cluster %s' % host)
                
                datastore = hosts[host]['disk'][0]
                cmd = 'ovftool --acceptAllEulas --noSSLVerify --datastore=' + datastore + ' --powerOn --prop:AMC.hostname.setup=' + hostname +' --prop:AMC.eth0.setup=' + amc_ip + ' --prop:AMC.netmask.setup=255.255.0.0 --prop:AMC.gateway.setup=' + gateway + ' --name=' + amc_name +' ' + ovf_path + ' vi://' + vc_user + ':' + vc_pwd + '@' + vc_ip + '/' + datacenter + '/host/' + clustername + '/' + host
            else:
                host = host_list[k]

                if hosts[host]['disk']:
                    datastore = hosts[host]['disk'][0]
                else:
                    if vcs[vc_ip]['sharestorages']['disk']:
                        datastore = vcs[vc_ip]['sharestorages']['disk'][0]
                    else:    
                        datastore = vcs[vc_ip]['sharestorages']['ssd'][0]
                
                if clustername == '':
                    cmd = 'ovftool --acceptAllEulas --noSSLVerify --datastore=' + datastore + ' --powerOn --prop:AMC.hostname.setup=' + hostname +' --prop:AMC.eth0.setup=' + amc_ip + ' --prop:AMC.netmask.setup=255.255.0.0 --prop:AMC.gateway.setup=' + gateway + ' --name=' + amc_name +' ' + ovf_path + ' vi://' + vc_user + ':' + vc_pwd + '@' + vc_ip + '/' + datacenter + '/host/' + host
                else:
                    cmd = 'ovftool --acceptAllEulas --noSSLVerify --datastore=' + datastore + ' --powerOn --prop:AMC.hostname.setup=' + hostname +' --prop:AMC.eth0.setup=' + amc_ip + ' --prop:AMC.netmask.setup=255.255.0.0 --prop:AMC.gateway.setup=' + gateway + ' --name=' + amc_name +' ' + ovf_path + ' vi://' + vc_user + ':' + vc_pwd + '@' + vc_ip + '/' + datacenter + '/host/' + clustername + '/' + host
            
                # deploy sinple 10g network amc
                if len(ip_range.split('-')) > 2 and ip_range.split('-')[-1] == 'single' and '10.116' in gateway:
                    for datacenter, item_list in vcs[vc_ip]['dcs'].items():
                        for items in item_list:
                            for host_ip, host_info in items['hosts'].items():
                                networkname = host_info['network']['10g']


                    cmd = 'ovftool --acceptAllEulas --noSSLVerify --datastore=' + datastore + ' --network="' + networkname + '" --powerOn --prop:AMC.hostname.setup=' + hostname +' --prop:AMC.eth0.setup=' + amc_ip + ' --prop:AMC.netmask.setup=255.255.0.0 --prop:AMC.gateway.setup=' + gateway + ' --name=' + amc_name +' ' + ovf_path + ' vi://' + vc_user + ':' + vc_pwd + '@' + vc_ip + '/' + datacenter + '/host/' + clustername + '/' + host

            obj_log.info(cmd)

            obj_rtn_tmp = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            rtn_tmp_dict[amc_ip] = obj_rtn_tmp
            
            k = k + 1

        obj_rtn_tmp.wait()
        self.progressbar_k(120)

        for amc_ip, obj_rtn in rtn_tmp_dict.items():

            stdout_rtn = obj_rtn.stdout.read()
            stderr_rtn = obj_rtn.stderr.read()

            if 'Completed successfully' in stdout_rtn:
                obj_log.debug('Deploy amc done.\n')
                obj_log.debug('Wait amc power on...')

                # The first time login
                obj_tools = Tools(amc_ip)
                # get the main version e.g 3.6.0
                usx_version = obj_tools.get_usx_version()
                main_usx_version = '.'.join(usx_version.split('.')[:-1])
                if main_usx_version in ['3.6.0']:
                    obj_tools.set_usxaccess('true')

                obj_log.debug('AMC power on done.\n')

            else:
                obj_log.debug(stdout_rtn)
                obj_log.debug(stderr_rtn)
                return False

        obj_utils.progressbar_k(30)

        if all_config['usx_version'] == '2.1':
            obj_log.debug('Modify amc port...')
            amc_port = ''
            while len(amc_port) < 5:
                temp = str(random.randint(1, 9))
                amc_port = amc_port.join(['', temp])

            for amc_ip in amc_ip_list:
                self.modify_amc_port(amc_ip, amc_port)
            obj_log.debug('Modify amc port done.\n')
        else:
            if amc_num != 1 and main_usx_version >= '3.1.2':
                obj_log.debug('Join AMC Cluster start...')
                for amc_ip in amc_ip_list:
                    if amc_ip != main_amc_ip:
                        obj_tools = Tools(main_amc_ip)           # login master amc
                        onetimekey = obj_tools.get_onetimekey()  # get master amc onetimekey
                        obj_log.info(onetimekey)
                        obj_log.debug(onetimekey)
                        obj_tools = Tools(amc_ip)                # login slave amc
                        join_rtn = obj_tools.join_amc_cluster_onetimekey(main_amc_ip, onetimekey.split('\"')[1])
                        if join_rtn == False:
                            obj_log.debug('Join AMC Cluster fail.')
                            return False
            elif amc_num != 1:
                obj_log.debug('Join AMC Cluster start...')
                for amc_ip in amc_ip_list:
                    if amc_ip != main_amc_ip:
                        obj_tools = Tools(amc_ip)
                        join_rtn = obj_tools.join_amc_cluster(main_amc_ip)
                        if join_rtn == False:
                            obj_log.debug('Join AMC Cluster fail.')
                            return False
            if amc_num != 1:
                obj_utils.progressbar_k(10)
                # server.connect(vc_ip, vc_user, vc_pwd)
                # obj_multi.reboot_vm(server, amc_name_list)

                for amc_ip in amc_ip_list:
                    check_rtn = self.check_amc_status(amc_ip, amc_username, amc_password, main_usx_version)
                    if check_rtn == False:
                        obj_log.debug('AMC Power on fail')
                        return False
                    if obj_tools.retry_to_check_jobstatus_msg("Successfully installed DB Replication"):
                        obj_log.debug(amc_ip + ' join AMC Cluster done.')
                        return True
                    else:
                        return False
        return True

    def amc_update_migration(self, all_config, version=None):
        # if version is not None, will use the specify version 
        obj_log.debug('=============================')
        obj_log.debug('Start deploy migration amc')
        obj_log.debug('=============================')
        user = all_config['user']
        main_amc_ip = all_config['amc_ip']
        amc_username = all_config['login_config']['username']
        amc_password = all_config['login_config']['password']
        vcs = all_config['vcs']
        testbed_name = all_config['testbed_name']
        vc_ip = vcs.keys()[0]
        vc_user = vcs[vc_ip]['username']
        vc_pwd = vcs[vc_ip]['password']
        gateway = vcs[vc_ip]['gateway']
        datacenter = vcs[vc_ip]['dcs'].keys()[0]
        hosts = vcs[vc_ip]['dcs'][datacenter][0]['hosts']
        host_list = hosts.keys()
        host = random.choice(host_list)
        clustername = vcs[vc_ip]['dcs'][datacenter][0]['clustername']

        if hosts[host]['disk']:
            datastore = hosts[host]['disk'][0]
        else:
            if vcs[vc_ip]['sharestorages']['disk']:
                datastore = vcs[vc_ip]['sharestorages']['disk'][0]
            else:
                datastore = vcs[vc_ip]['sharestorages']['ssd'][0]
        datastore = hosts[host]['disk'][0]

        # change the migration amc ip from orginal xxx.xxx.xxx.250
        amc_ip_segment = main_amc_ip.split('.')
        amc_ip_segment[3] = '250'
        amc_ip = '.'.join(amc_ip_segment)

        pattern1 = '\d+$'
        rtn_tmp = re.search(pattern1, amc_ip)
        rtn1 = rtn_tmp.group()
        hostname = 'AMC' + rtn1
        amc_name = user + '-AMC' + '-migrate' + '-' + testbed_name + '-' + rtn1

        if version:
            ovf_path = "/mnt/build/FLEXCLOUD/%s/USX/USX-%s-Full/USX-%s-Full.ovf" % (version[:5],version,version)
            main_usx_version = '.'.join(version.split('.')[:-1])
        else:
            ovf_path = self.all_config['migration_usx_build_path']
            temp_version = ovf_path.split('/')[-2].replace('-Full', '')
            main_usx_version = '.'.join(temp_version.split('.')[:-1]).replace('USX-', '')

        cmd = 'ovftool --acceptAllEulas --noSSLVerify' + \
            ' --datastore=' + datastore + \
            ' --powerOn --prop:AMC.hostname.setup=' + hostname + \
            ' --prop:AMC.eth0.setup=' + amc_ip + \
            ' --prop:AMC.netmask.setup=255.255.0.0' + \
            ' --prop:AMC.gateway.setup=' + gateway + \
            ' --prop:AMC.orig_ip.Migration=' + main_amc_ip + \
            ' --prop:AMC.orig_login.Migration=admin' + \
            ' --prop:AMC.orig_pwd.Migration=poweruser' + \
            ' --name=' + amc_name + ' ' + \
            ovf_path + ' vi://' + vc_user + ':' + vc_pwd + '@' + vc_ip + '/' + datacenter + '/host/' + clustername + '/' + host
        obj_log.info(cmd)
        rtn_tmp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rtn_tmp.wait()
        stdout_rtn = rtn_tmp.stdout.read().strip()
        stderr_rtn = rtn_tmp.stderr.read().strip()

        if 'Completed successfully' in stdout_rtn:
            obj_log.debug('Deploy migration amc done.\n')
            obj_log.debug('Wait migration amc ...')
            self.progressbar_k(120)
            if main_usx_version in ['3.6.0']:
                obj_tools = Tools(amc_ip)
                obj_tools.set_usxaccess('true')
            else:
                obj_log.debug('Check the migration result in orginal AMC IP')
                check_rtn = self.check_amc_status(main_amc_ip, amc_username, amc_password)
            # check migration log
            check_migration_status = self.check_migration_status(main_amc_ip, amc_username, amc_password)

            if check_rtn is False or check_migration_status is False:
                return False
            obj_log.debug('AMC Migration done.\n')
            obj_log.info("Start remove old host key")
            cmd = 'ssh-keygen -f "/root/.ssh/known_hosts" -R ' + main_amc_ip
            rnt = self.run_cmd(cmd)
            obj_log.debug(rnt)
            return True

        else:
            obj_log.debug(stdout_rtn)
            obj_log.debug(stderr_rtn)
            return False

    def verify_ha_status(self, ip, username="poweruser", password="poweruser"):
        cmd = 'crm_mon -1'
        rtn = self.ssh_cmd(ip, username, password, cmd)
        return rtn['stdout']

    def send_mail(self, subject, addressee_list, cc_list, log_file, attachment=None):
        addressees = ','.join(addressee_list)
        ccs = ','.join(cc_list)

        if attachment != None:
            cmd = 'mutt -s "' + subject + '" ' + addressees + ' -c ' + ccs + ' -a ' + attachment + ' < ' + log_file
        else:
            cmd = 'mutt -s "' + subject + '" ' + addressees + ' -c ' + ccs + ' < ' + log_file
        obj_log.debug(cmd)

        rtn = self.run_cmd(cmd)
        obj_log.debug(rtn)
        obj_log.debug('****send mail***')

    def exit_sys(self,remote_path, local_path):
        mail_service_ip = '10.21.122.10'
        user_name = 'root'
        pass_word = 'P@ssword1'
        self.remote_scp(mail_service_ip, remote_path, local_path, user_name, pass_word)
        self.send_mail(remote_path)
        sys.exit(0)

    def progressbar_k(self, sleep_time):
        # widgets = ['Progress: ', Percentage(), ' ', Bar(marker=RotatingMarker('>-=')),' ', ETA()]
        # pbar = ProgressBar(widgets=widgets, maxval=sleep_time).start()
        # for i in range(sleep_time):
        #     pbar.update(1*i+1)
        #     time.sleep(1)
        # pbar.finish()
        obj_log.debug('Will wait for {0} seconds'.format(sleep_time))
        time.sleep(sleep_time)

    def get_default_gateway(self, server, host):
        host_mor = self.__get_host_mor(server, host)
        props = VIProperty(server, host_mor)
        default_gateway = props.config.network.ipRouteConfig.defaultGateway

        return default_gateway

    def ssh_cmd_list(self, ip, username, password, cmd_list, timeout=None):
        rtn_dict = {}
        rtn_dict['error'] = None
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, 22, username, password, timeout=timeout)
        except paramiko.ssh_exception.AuthenticationException:   # workround for ssh for usx change username from 'amdin' ==> 'usxadmin' in USX-3.6.0
            if username == 'admin':
                username = 'usxadmin'
            elif username == 'usxadmin':
                username = 'admin'
            ssh.connect(ip, 22, username, password, timeout=timeout)
        except Exception as e:
            rtn_dict['error'] = e
            return rtn_dict

        for cmd in cmd_list:
            rtn_dict[cmd] = {}
            stdin, stdout, stderr = ssh.exec_command(cmd)
            rtn_dict[cmd]['stdout'] = stdout.read()
            rtn_dict[cmd]['stderr'] = stderr.read()
        ssh.close()

        return rtn_dict
    
    def ssh_cmd(self, ip, username, password, cmd, sync_run=True, timeout=None):
        rtn_dict = {}
        rtn_dict['error'] = None
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, 22, username, password, timeout=timeout)
        except paramiko.ssh_exception.AuthenticationException:   # workround for ssh for usx exchange username 'amdin' <==> 'usxadmin' in USX-3.6.0
            if username == 'admin':
                username = 'usxadmin'
            elif username == 'usxadmin':
                username = 'admin'
            ssh.connect(ip, 22, username, password, timeout=timeout)

        except Exception as e:
            rtn_dict['error'] = e
            rtn_dict['stderr'] = e
            return rtn_dict
        
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        if sync_run != True:
            time.sleep(30)
            return True

        rtn_dict['stdout'] = stdout.read()
        rtn_dict['stderr'] = stderr.read()
        ssh.close()

        return rtn_dict

    def remote_scp(self, host_ip,remote_path,local_path,username,password):
        t = paramiko.Transport((host_ip,22))
        t.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.put(local_path, remote_path)
        t.close()

    def remote_scp_get(self, host_ip,remote_path,local_path,username,password):
        t = paramiko.Transport((host_ip,22))
        t.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.get(remote_path, local_path)
        t.close()

    def stop_amc_service(self, amc_ip, username='admin', password='poweruser'):
        cmd = 'service amc stop'
        rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd)
        obj_log.debug('stop_amc_service', rtn_dict)
        if rtn_dict['error'] == None and rtn_dict['stderr'] == '':
            return True
        else:
            return False

    def start_amc_service(self, amc_ip, username='admin', password='poweruser'):
        cmd = 'service amc start'
        rtn = self.ssh_cmd(amc_ip, username, password, cmd, False)
        if rtn == True:
            cmd1 = "ps -ef|grep amc"
            flag = 0
            while True:
                if flag == 100:
                    return False

                rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd1)
                obj_log.debug(rtn_dict)
                if 'amc-insight-config.yml' in rtn_dict['stdout'] and 'amc-config.yml' in rtn_dict['stdout']:
                    return True
                else:
                    time.sleep(3)
                    flag = flag + 1
                    continue
        else:
            return False

    def restart_amc_service(self, amc_ip, username='admin', password='poweruser'):
        cmd = 'service amc restart'
        rtn = self.ssh_cmd(amc_ip, username, password, cmd, False)
        if rtn == True:
            cmd1 = "ps -ef|grep amc"
            flag = 0
            while True:
                if flag == 100:
                    return False

                rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd1)
                obj_log.debug(rtn_dict)
                if 'amc-insight-config.yml' in rtn_dict['stdout'] and 'amc-config.yml' in rtn_dict['stdout']:
                    return True
                else:
                    time.sleep(3)
                    flag = flag + 1
                    continue
        else:
            return False

    def reboot_amc(self, amc_ip, username='admin', password='poweruser'):
        usx_version = self.get_usx_version(amc_ip, username, password)
        
        cmd = 'reboot'
        rtn = self.ssh_cmd(amc_ip, username, password, cmd, False)
        
        if rtn == True:
            check_rtn = self.check_amc_status(amc_ip, username, password, usx_version)
            return check_rtn
        else:
            return False
    
    def _check_amc_status(self, new_ip):
        cmd = "ps -ef|grep java|grep -v grep|awk '{print $1}'"
        result = self.utils.ssh_cmd(new_ip, 'admin', 'poweruser', cmd)['stdout'].strip()
        if len(result) >= 3:
            return True
        else:
            return False

    def get_usx_version(self, amc_ip, username='admin', password='poweruser'):
        cmd = 'cat /opt/amc/version.txt'
        for _ in range(20):
            rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd)
            if rtn_dict['error'] != None or rtn_dict['stderr'] != '':
                obj_log.debug(rtn_dict)
                self.progressbar_k(5)
            else:
                for tmp in rtn_dict['stdout'].split('\n'):
                    if 'amc=' in tmp:
                        small_usx_version = tmp.split('=')[1]
                        tmp_list = small_usx_version.split('.')
                        del tmp_list[-1]
                        usx_version = '.'.join(tmp_list)
                        return usx_version
        return False


    def clean_amc_db(self, amc_ip, username='admin', password='poweruser'):
        cmd = 'rm -f /opt/amc_db/*'
        rtn_dict = self.ssh_cmd(amc_ip, username, password, cmd)
        if rtn_dict['error'] != None:
            return False
        else:
            self.restart_amc_service(amc_ip)

    def modify_amc_port(self, ip, amc_port, username='admin', password='poweruser'):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 22, username, password)

        cmd1 = 'sed -i s/multicast-port\>.*\</multicast-port\>' + amc_port + '\</ /opt/amc/server/config/amc-grid.xml'
        stdin, stdout, stderr = ssh.exec_command(cmd1)
        time.sleep(5)

        cmd1= 'bash /opt/amc/server/bin/amc_server_stop.sh'
        stdin, stdout, stderr = ssh.exec_command(cmd1)
        time.sleep(5)

        cmd2 = 'bash /opt/amc/server/bin/amc_server_start.sh'
        stdin, stdout, stderr = ssh.exec_command(cmd2)
        time.sleep(30)

        ssh.close()

    def get_new_usx_build(self, usx_build_path = '/mnt/nas/Private-Build/2.0/'):
        cmd = 'ls -t ' + usx_build_path

        rtn = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        stdout_rtn_list = rtn.stdout.readlines()

        new_usx_build_path_temp = usx_build_path + stdout_rtn_list[0] + '/' + stdout_rtn_list[0] + '.ovf'

        new_usx_build_path = new_usx_build_path_temp.replace('\n','')

        return new_usx_build_path

    def get_ssd_vc_info(self, vc_list) :
        obj_log.debug("Please wait for get ssd vCenter info...")
        m = 1
        VCInfo = {}
        for vc in vc_list :
            server = VIServer()
            server.connect(vc, "root", "vmware")
            temp = vc.split(".")
            VCInfo['VC'+str(m)] = {}
            VCInfo['VC'+str(m)]['VCName'] = "VC" + temp[2] + temp[3]
            VCInfo['VC'+str(m)]['VCIP'] = vc
            VCInfo['VC'+str(m)]['esxHost'] = {}
            i = 1
            for host_ip in server.get_hosts().values():
                if host_ip == '10.21.2.60':
                    continue
                ssd_ds_list = self.get_ssd_datastore(host_ip,'root','password')
                VCInfo['VC'+str(m)]['esxHost']['host'+str(i)] = {}
                VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostIP'] = host_ip
                VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS'] = {}
                j = 1
                for ssd_ds in ssd_ds_list:
                    datastore_info_dict = self.get_datastore_info(server, host_ip, ssd_ds)
                    if int(datastore_info_dict['free_space'])/1024/1024/1024 > 300 and datastore_info_dict['accessible'] == True:
                        VCInfo['VC'+str(m)]['esxHost']['host'+str(i)]['hostDS']['DS' + str(j)] = ssd_ds
                        j = j + 1
                i += 1
            m += 1
            server.disconnect()
        obj_log.debug("Get ssd vCenter info done.")
        return VCInfo

    def verify_node_crash(self, ip, username="poweruser", password="poweruser"):
        cmd = 'ls /var/crash/'
        rtn = self.ssh_cmd(ip, username, password, cmd)
        obj_log.debug(ip, rtn)
        m = re.search("crash",rtn['stdout'])
        if m != None:
            return True
        else :
            return False

#     def verify_raid(self, ip, service_vm_num=3, username="poweruser", password="poweruser"):
#         pattern_list = ['\[_..+\]','\[._.+\]','\[.._+\]']
#         cmd_list = ['cat /proc/mdstat']
#         rtn = self.ssh_cmd(ip, username, password, cmd_list)
#         obj_log.debug(ip + ' mdstat info: ')
#         obj_log.debug(rtn[cmd_list[0]]['stdout'])
#         for pattern in pattern_list:
#             m = re.search(pattern, rtn[cmd_list[0]]['stdout'])
#             if m != None:
#                 return False
#             else:
#                 continue
#
#         return True

    def check_resource(self, ip, username="poweruser", password="poweruser"):
        pattern = '/exports/\w+.+ type dedup'
        cmd = 'mount'
        
        timeout_flag = 0
        while True:
            if timeout_flag > 1200:
                return False
            rtn = self.is_reachable(ip)
            if rtn == True:
                break
            else:
                time.sleep(1)
                timeout_flag = timeout_flag + 1
        
        rtn = self.ssh_cmd(ip, username, password, cmd)

        if rtn['error'] != None:
            return False

        out = rtn['stdout']

        m = re.search(pattern, out)
        if m == None:
            rtn_val = False
        else:
            obj_log.info(m.group())
            obj_log.info('check ' + ip + ' resource successful.')
            rtn_val = True

        return rtn_val

    def check_volume_status(self, ip, username="poweruser", password="poweruser"):
        cmd = "ifconfig eth0| grep inet|awk '{print $2}'|awk -F ':' '{print $2}'"
        for i in range(500):
            rtn = self.ssh_cmd(ip, username, password, cmd)
            if rtn['error'] != None:
                obj_log.info('Volume is powering on...')
                time.sleep(10)
                continue
            else:
                volume_ip = rtn['stdout'].rstrip()
                if volume_ip == ip:
                    obj_log.info('Volume status normal.')
                    return True
        return False

    def call_rest_api(self, API_URL, req_type, obj_json=None, cookies=None, header=True, get_err_msg=False, timeout=None):
        retry_num = 100
        retry_interval_time = 5
        cnt = 0
        while cnt < retry_num:
            if cookies is not None:
                if '?' in API_URL:
                    API_URL_NEW = API_URL + "&api_key=" + cookies
                else:
                    API_URL_NEW = API_URL + "?api_key=" + cookies
            else:
                API_URL_NEW = API_URL
            conn = urllib2.Request(API_URL_NEW)
            if header == True:
                conn.add_header('Content-type', 'application/json')
            else:
                conn.add_header("Accept","application/json")

            conn.get_method = lambda: req_type
            try:
                if obj_json != None:
                    res = urllib2.urlopen(conn, obj_json, timeout=timeout)
                else:
                    res = urllib2.urlopen(conn, timeout=timeout)

            except Exception as e:
                if get_err_msg == True:
                    try:
                        return e.read()
                    except Exception:
                        return e

                obj_log.error('============Exception===========')
                obj_log.error(e)
                try:
                    obj_log.debug(e.read())
                except Exception:
                    obj_log.debug(e)

                
                cnt += 1
                obj_log.error('Exception caught, retry count: %d' % cnt)
                obj_log.error("Error for request addr:{0}".format(API_URL_NEW))
                time.sleep(retry_interval_time)
                
                if 'HTTP Error 401' in str(e):
                    pattern = '\d+\.\d+\.\d+\.\d+'
                    m = re.search(pattern, API_URL_NEW)
                    amc_ip = m.group()
                    obj_log.debug('111111111111111 %s' % amc_ip)
                    obj_tools = Tools(amc_ip)
                    cookies = obj_tools.cookies
                    obj_log.info('new cookies created ' + cookies)

                continue
            if str(res.code) == "200" or str(res.code) == "0":
                rtn = res.read()
                res.close()
                return rtn
            else:
                obj_log.debug("ERROR : Failed to REST API!")
                time.sleep(retry_interval_time)
                cnt += 1
                obj_log.debug('retry: %d' % cnt)
                res.close()

        return False

    def get_vm_info(self, server, vm_name, datacenter=None):
        vm_info = {}

        obj_vm = server.get_vm_by_name(vm_name, datacenter)
        vm_info['cpu_num'] = obj_vm.properties.config.hardware.numCPU
        vm_info['memory'] = obj_vm.properties.config.hardware.memoryMB
        vm_info['cpu_reservation'] = obj_vm.properties.config.cpuAllocation.reservation
        vm_info['memory_reservation'] = obj_vm.properties.config.memoryAllocation.reservation
        vm_info['cpu_usage'] = obj_vm.properties.summary.quickStats.overallCpuUsage
        vm_info['memory_usage'] = obj_vm.properties.summary.quickStats.hostMemoryUsage

        for obj in obj_vm.properties.config.hardware.device:

            if 'Hard disk' in obj.deviceInfo.label:
                vm_info[obj.deviceInfo.label] = obj.deviceInfo.summary

        return vm_info

    def get_file_list(self, server, datastore, path="/", case_insensitive=True, folders_first=True, match_patterns=[]):
        ds = [k for k,v in server.get_datastores().items() if v == datastore][0]
        ds_browser = VIProperty(server, ds).browser._obj

        request = VI.SearchDatastore_TaskRequestMsg()
        _this = request.new__this(ds_browser)
        _this.set_attribute_type(ds_browser.get_attribute_type())
        request.set_element__this(_this)
        request.set_element_datastorePath("[%s] %s" % (datastore, path))

        search_spec = request.new_searchSpec()

        query = [VI.ns0.FloppyImageFileQuery_Def('floppy').pyclass(),
                 VI.ns0.FolderFileQuery_Def('folder').pyclass(),
                 VI.ns0.IsoImageFileQuery_Def('iso').pyclass(),
                 VI.ns0.VmConfigFileQuery_Def('vm').pyclass(),
                 VI.ns0.TemplateConfigFileQuery_Def('template').pyclass(),
                 VI.ns0.VmDiskFileQuery_Def('vm_disk').pyclass(),
                 VI.ns0.VmLogFileQuery_Def('vm_log').pyclass(),
                 VI.ns0.VmNvramFileQuery_Def('vm_ram').pyclass(),
                 VI.ns0.VmSnapshotFileQuery_Def('vm_snapshot').pyclass()]
        search_spec.set_element_query(query)
        details = search_spec.new_details()
        details.set_element_fileOwner(True)
        details.set_element_fileSize(True)
        details.set_element_fileType(True)
        details.set_element_modification(True)
        search_spec.set_element_details(details)
        search_spec.set_element_searchCaseInsensitive(case_insensitive)
        search_spec.set_element_sortFoldersFirst(folders_first)
        search_spec.set_element_matchPattern(match_patterns)
        request.set_element_searchSpec(search_spec)
        response = server._proxy.SearchDatastore_Task(request)._returnval
        task = VITask(response, server)
        if task.wait_for_state([task.STATE_ERROR, task.STATE_SUCCESS]) == task.STATE_ERROR:
            raise Exception(task.get_error_message())

        info = task.get_result()

        if not hasattr(info, "file"):
            return []

        file_list = []
        for fi in info.file:
            if fi.path != 'lost+found':
                file_list.append(fi.path)

        return file_list

    def get_vm_in_ds_list(self, server, datastore):
        file_list = self.get_file_list(server, datastore)
        vm_list = []
        for file in file_list:
            try:
                deep_file_list = self.get_file_list(server, datastore, file)
                for deep_file in deep_file_list:
                    if 'vmdk' in deep_file:
                        vm_list.append(file)
                        break
            except Exception:
                pass

        return vm_list

    def modify_vm_cpu(self, server, vm_name, cpu_num):
        obj_vm = server.get_vm_by_name(vm_name)
        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(obj_vm._mor)
        _this.set_attribute_type(obj_vm._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()

        spec.set_element_numCPUs(cpu_num)

        request.set_element_spec(spec)
        ret = server._proxy.ReconfigVM_Task(request)._returnval

        #Wait for the task to finish
        task = VITask(ret, server)
        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            obj_log.info("VM successfully reconfigured")
            return True
        elif status == task.STATE_ERROR:
            obj_log.error("Error reconfiguring vm: %s" % task.get_error_message())
            return False

    def modify_vm_memory(self, server, vm_name, memory_size):
        obj_vm = server.get_vm_by_name(vm_name)
        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(obj_vm._mor)
        _this.set_attribute_type(obj_vm._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()

        spec.set_element_memoryMB(memory_size)

        request.set_element_spec(spec)
        ret = server._proxy.ReconfigVM_Task(request)._returnval

        #Wait for the task to finish
        task = VITask(ret, server)
        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            obj_log.info("VM successfully reconfigured")
            return True
        elif status == task.STATE_ERROR:
            obj_log.error("Error reconfiguring vm: %s" % task.get_error_message())
            return False

    def get_config(self, section, key, configfile):
        config = configparser.ConfigParser()
        path = (os.path.split(os.path.realpath(__file__)))[0] + '/' + configfile
        config.read(path)

        rtn = config.get(section, key)

        return rtn

    def set_config(self, section, key, value, configfile):
        config = configparser.ConfigParser()
        path = (os.path.split(os.path.realpath(__file__)))[0] + '/' + configfile
        config.read(path)

        config.set(section, key, value)
        fp = open(configfile, "w")
        config.write(fp)

        fp.close()

    def get_raid1_info(self, amc_ip):
        cmd_list = ['cat /proc/mdstat', 'ibdmanager -r a -s get']
        obj_tools = Tools(amc_ip)
        all_node_info = obj_tools.get_all_node_info()
        service_vm_info = all_node_info['service_vm_info']
        volume_info = all_node_info['volume_info']

        raid_name_dict = {}
        for volume in volume_info:
            volume_eth0 = volume_info[volume]['eth0']
            volume_name = volume_info[volume]['name']
            volume_type = volume_info[volume]['type']
            if 'SIMPLE' in volume_type:
                continue

            rtn = self.ssh_cmd_list(volume_eth0, 'poweruser', 'poweruser', cmd_list)
            md_stat = rtn[cmd_list[0]]['stdout']
            ibd_stat = rtn[cmd_list[1]]['stdout']
            md_stat_list = md_stat.split('\n')

            temp_list = []

            for temp in md_stat_list:
                if 'md' in temp and 'raid' in temp:
                    temp_list.append(temp)

            raid_ibd_dict = {}
            raid_ibd_dict[volume_name] = {}
            pattern_md = 'md\d+'
            pattern_ibd = 'ibd\w+'
            for temp in temp_list:
                m_md = re.search(pattern_md, temp)
                temp_ibd = re.findall(pattern_ibd, temp)
                if 'raid1' in temp:
                    raid_ibd_dict[volume_name][m_md.group()] = temp_ibd

            temp_dict = {}
            ibd_stat_list = ibd_stat.split('Service Agent Channel:')

            pattern_ip = 'ip:.\w.+'
            pattern_dev = 'devname:.\w.+'

            for temp in ibd_stat_list:
                if 'ip' in temp and 'devname' in temp:
                    m_ip = re.search(pattern_ip, temp)
                    m_dev = re.search(pattern_dev, temp)
                    temp_dict[m_dev.group()] = m_ip.group()

            ibd_ip_dict = {}
            for ibd,ip in temp_dict.items():
                pattern1 = 'ibd\w+'
                pattern2 = '\d.+'
                m1 = re.search(pattern1, ibd)
                m2 = re.search(pattern2, ip)
                ibd_ip_dict[m1.group()] = m2.group()

            ibd_name_dict = {}

            for ibd,ip in ibd_ip_dict.items():
                for sv in service_vm_info.keys():
                    sv_name = service_vm_info[sv]['containername']
                    sv_eth1 = service_vm_info[sv]['eth1']
                    if ip == sv_eth1:
                        ibd_name_dict[ibd] = sv_name
                        break

            raid_name_dict[volume_name] = {}

            for temp in raid_ibd_dict[volume_name].keys():
                raid_name_dict[volume_name][temp] = []
                temp_ibd_list = raid_ibd_dict[volume_name][temp]
                for temp_ibd in temp_ibd_list:
                    for ibd,name in ibd_name_dict.items():
                        if ibd in temp_ibd:
                            raid_name_dict[volume_name][temp].append(name)
                            break

        return raid_name_dict

    def is_reachable(self, ip):
        cmd = 'ping -c1 ' + ip
        rtn_dict = self.run_cmd(cmd)
        if rtn_dict['returncode'] == 0:
            obj_log.info(ip + ' is Reachable')
            return True
        else:
            obj_log.error(ip + ' is NotReachable')
            return False

    def is_poweron(self, ip):
        for i in range(360):
            rtn = self.is_reachable(ip)
            if rtn == True:
                return True
            else:
                time.sleep(5)
        else:
            obj_log.info(ip + 'poweron timeout')
            return False

    def check_vm_power_status(self, server, vm_name):
        rtn = {}
        rtn['error'] = ''
        rtn['status'] = 0
        vm_obj = server.get_vm_by_name(vm_name)
        if vm_obj.is_powered_on() :
            rtn['status'] = 1
        return rtn

    def get_vm_health(self, server, vm_name):
        ip = None
        vm_obj = server.get_vm_by_name(vm_name)

        if vm_obj.is_powered_on() :
            ip = vm_obj.get_property('ip_address', from_cache=False)

        if ip != None:
            stat = self.is_reachable(ip)
            if stat == False:
                rtn = False
            else:
                rtn = True
        else :
            rtn = False

        return rtn

    def get_filesize(self, ip, username, password, filepath):
        cmd = 'du -b ' + filepath
        rtn = self.ssh_cmd(ip, username, password, cmd)
        if rtn['error'] != None:
            return False
        else:
            if rtn['stderr'] != '':
                return False
            else:
                pattern = '\d+'
                m = re.search(pattern, rtn['stdout'])
                filesize = m.group()

        return filesize

    def ceph_write(self, node_ip, filepath, node_username='poweruser', node_password='poweruser'):
        rtn_dict = {}
        rtn_dict[filepath] = {}

        randnum = random.randint(0,10)
        offset = 4096 * randnum
        rtn_dict[filepath]['volumeid'] = randnum
        rtn_dict[filepath]['offset'] = offset

        cmd1 = 'dd if=/dev/urandom of=' + filepath + ' bs=1M count=10'
        obj_log.debug(cmd1)

        rtn = self.ssh_cmd(node_ip, node_username, node_password, cmd1)

        cmd2 = 'md5sum ' + filepath
        rtn2 = self.ssh_cmd(node_ip, node_username, node_password, cmd2)
        pattern = '\w+'
        m = re.search(pattern, rtn2['stdout'])
        md5 = m.group()

        rtn_dict[filepath]['md5'] = md5

        cmd3 = 'find / -name ms-demo'
        rtn3 = self.ssh_cmd(node_ip, node_username, node_password, cmd3)
        msdemp = rtn3['stdout'].strip('\n')
        cmd4 = msdemp + ' -w ' + filepath + ' -v ' + str(randnum) + ' -o ' + str(offset)
        obj_log.debug(cmd4)
        rtn4 = self.ssh_cmd(node_ip, node_username, node_password, cmd4)
        if rtn4['error'] != None:
            obj_log.debug(rtn4)
            return False

        return rtn_dict

    def ceph_read(self, node_ip, filepath, volumeid, offset , node_username='poweruser', node_password='poweruser'):
        rtn_dict = {}
        cephread_filepath = filepath + 'cephread'
        filelength = self.get_filesize(node_ip, node_username, node_password, filepath)

        cmd1 = 'find / -name ms-demo'
        rtn1 = self.ssh_cmd(node_ip, node_username, node_password, cmd1)
        msdemp = rtn1['stdout'].strip('\n')
        cmd2 = msdemp + ' -r ' + cephread_filepath + ' -v ' + str(volumeid) + ' -o ' + str(offset) + ' -l ' + filelength
        obj_log.debug(cmd2)
        rtn2 = self.ssh_cmd(node_ip, node_username, node_password, cmd2)
        if rtn2['error'] != None:
            obj_log.debug(rtn2)
            return False

        cmd3 = 'md5sum ' + cephread_filepath
        rtn3 = self.ssh_cmd(node_ip, node_username, node_password, cmd3)
        pattern = '\w+'
        m = re.search(pattern, rtn3['stdout'])
        md5 = m.group()
        rtn_dict[cephread_filepath] = md5

        return rtn_dict

    def clean_ceph(self, ip, node_username='poweruser', node_password='poweruser'):
        cmd = 'rados -p mstestpool cleanup --prefix node'
        rtn = self.ssh_cmd(ip, node_username, node_password, cmd)
        if rtn['error'] != None:
            obj_log.debug(rtn)
            return False

        return True

    def clean_cassandra(self, ip, serverip, node_username='poweruser', node_password='poweruser'):
        cmd = 'cqlsh -f ./cqlcmd ' + serverip
        rtn = self.ssh_cmd(ip, node_username, node_password, cmd)
        if rtn['error'] != None:
            obj_log.debug(rtn)
            return False

        return True

    def delete_duplicated_list(self, listdata):
        return sorted(set(listdata), key = listdata.index)

    def get_lists_difference(self, lista, listb):
        return list(set(lista).symmetric_difference(set(listb)))

    def invert_dict(self, d):
        rtn_dict = {}
        for k, v in d.items():
            rtn_dict[v] = k

        return rtn_dict


    # Use memoize pattern to init allconfig just once
    @memoize
    def init_allconfig(self, configfile):
        user = self.get_config('main', 'username', configfile)
        vcs = eval(self.get_config('main', 'vcs', configfile))
        raid_plan = self.get_config('main', 'raid_plan', configfile)
        memory_allocation = self.get_config('main', 'memory_allocation', configfile)
        disk_allocation = self.get_config('main', 'disk_allocation', configfile)
        flash_allocation = self.get_config('main', 'flash_allocation', configfile)
        testbed_count = self.get_config('main', 'testbed_count', configfile)
        hypervisor_num = int(self.get_config('main', 'hypervisor_num', configfile))
        reservation = self.get_config('main', 'reservation', configfile)
        usx_version = self.get_config('main', 'usx_version', configfile)
        platform = self.get_config('main', 'platform', configfile)
        xenservers = eval(self.get_config('main', 'xenservers', configfile))
        deploy_usxm = self.get_config('main', 'deploy_usxm', configfile)
        config_usxm = self.get_config('main', 'config_usxm', configfile)
        amc_ip = self.get_config('main', 'amc_ip', configfile)
        amc_num = int(self.get_config('main', 'amc_num', configfile))
        tiebreaker_ip = self.get_config('main', 'tiebreaker_ip', configfile)
        stretch_cluster = self.get_config('main', 'stretch_cluster', configfile)
        robo = self.get_config('main', 'robo', configfile)
        deploy_tiebreaker = self.get_config('main', 'deploy_tiebreaker', configfile)
        ip_range = self.get_config('main', 'ip_range', configfile)
        deploy_volume = self.get_config('main', 'deploy_volume', configfile)

        hybrid_num = int(self.get_config('hybrid', 'num', configfile))
        hybrid_exporttype = self.get_config('hybrid', 'exporttype', configfile)
        hybrid_exportfstype = self.get_config('hybrid', 'exportfstype', configfile)
        hybrid_fs_sync = self.get_config('hybrid', 'fs_sync', configfile)
        hybrid_raidtype = self.get_config('hybrid', 'raidtype', configfile)
        hybrid_snapshot = self.get_config('hybrid', 'snapshot', configfile)
        hybrid_size = int(self.get_config('hybrid', 'size', configfile))
        hybrid_directio = self.get_config('hybrid', 'directio', configfile)
        hybridratio = self.get_config('hybrid', 'hybridratio', configfile)
        hybrid_preferflashforcapacity = self.get_config('hybrid', 'preferflashforcapacity', configfile)
        hybrid_preferflashformemory = self.get_config('hybrid', 'preferflashformemory', configfile)
        hybrid_prefersharedstorageforexports = self.get_config('hybrid', 'prefersharedstorageforexports', configfile)
        hybrid_fastsync = self.get_config('hybrid', 'fastsync', configfile)
        hybrid_prefersharedstorageforvmdisk = self.get_config('hybrid', 'prefersharedstorageforvmdisk', configfile)

        allflash_num = int(self.get_config('allflash', 'num', configfile))
        allflash_exporttype = self.get_config('allflash', 'exporttype', configfile)
        allflash_exportfstype = self.get_config('allflash', 'exportfstype', configfile)
        allflash_fs_sync = self.get_config('allflash', 'fs_sync', configfile)
        allflash_raidtype = self.get_config('allflash', 'raidtype', configfile)
        allflash_snapshot = self.get_config('allflash', 'snapshot', configfile)
        allflash_size = int(self.get_config('allflash', 'size', configfile))
        allflash_directio = self.get_config('allflash', 'directio', configfile)
        allflash_prefersharedstorageforexports = self.get_config('allflash', 'prefersharedstorageforexports', configfile)
        allflash_prefersharedstorageforvmdisk = self.get_config('allflash', 'prefersharedstorageforvmdisk', configfile)

        inmemory_num = int(self.get_config('inmemory', 'num', configfile))
        inmemory_exporttype = self.get_config('inmemory', 'exporttype', configfile)
        inmemory_exportfstype = self.get_config('inmemory', 'exportfstype', configfile)
        inmemory_fs_sync = self.get_config('inmemory', 'fs_sync', configfile)
        inmemory_raidtype = self.get_config('inmemory', 'raidtype', configfile)
        inmemory_snapshot = self.get_config('inmemory', 'snapshot', configfile)
        inmemory_size = int(self.get_config('inmemory', 'size', configfile))
        inmemory_directio = self.get_config('inmemory', 'directio', configfile)
        inmemory_prefersharedstorageforvmdisk = self.get_config('inmemory', 'prefersharedstorageforvmdisk', configfile)

        only_infrastructure = self.get_config('hyperconverge', 'only_infrastructure', configfile)
        hyperconverge_num = int(self.get_config('hyperconverge', 'num', configfile))
        hyperconverge_exporttype = self.get_config('hyperconverge', 'exporttype', configfile)
        hyperconverge_exportfstype = self.get_config('hyperconverge', 'exportfstype', configfile)
        hyperconverge_fs_sync = self.get_config('hyperconverge', 'fs_sync', configfile)
        hyperconverge_raidtype = self.get_config('hyperconverge', 'raidtype', configfile)
        hyperconverge_snapshot = self.get_config('hyperconverge', 'snapshot', configfile)
        hyperconverge_type = self.get_config('hyperconverge', 'type', configfile)
        hyperconverge_cluster = self.get_config('hyperconverge', 'cluster', configfile)
        hyperconverge_size = int(self.get_config('hyperconverge', 'size', configfile))
        hyperconverge_directio = self.get_config('hyperconverge', 'directio', configfile)
        hyperconvergeratio = self.get_config('hyperconverge', 'hybridratio', configfile)
        hyperconverge_preferflashforcapacity = self.get_config('hyperconverge', 'preferflashforcapacity', configfile)
        hyperconverge_prefersharedstorageforexports = self.get_config('hyperconverge', 'prefersharedstorageforexports', configfile)
        hyperconverge_fastsync = self.get_config('hyperconverge', 'fastsync', configfile)
        hyperconverge_preferflashformemory = self.get_config('hyperconverge', 'preferflashformemory', configfile)
        hyperconverge_prefersharedstorageforvmdisk = self.get_config('hyperconverge', 'prefersharedstorageforvmdisk', configfile)

        simplehybrid_num = int(self.get_config('simplehybrid', 'num', configfile))
        simplehybrid_exporttype = self.get_config('simplehybrid', 'exporttype', configfile)
        simplehybrid_exportfstype = self.get_config('simplehybrid', 'exportfstype', configfile)
        simplehybrid_fs_sync = self.get_config('simplehybrid', 'fs_sync', configfile)
        simplehybrid_snapshot = self.get_config('simplehybrid', 'snapshot', configfile)
        simplehybrid_size = int(self.get_config('simplehybrid', 'size', configfile))
        simplehybridratio = self.get_config('simplehybrid', 'hybridratio', configfile)
        simplehybrid_preferflashforcapacity = self.get_config('simplehybrid', 'preferflashforcapacity', configfile)
        simplehybrid_preferflashformemory = self.get_config('simplehybrid', 'preferflashformemory', configfile)
        simplehybrid_prefersharedstorageforexports = self.get_config('simplehybrid', 'prefersharedstorageforexports', configfile)
        simplehybrid_prefersharedstorageforvmdisk = self.get_config('simplehybrid', 'prefersharedstorageforvmdisk', configfile)

        simpleallflash_num = int(self.get_config('simpleallflash', 'num', configfile))
        simpleallflash_exporttype = self.get_config('simpleallflash', 'exporttype', configfile)
        simpleallflash_exportfstype = self.get_config('simpleallflash', 'exportfstype', configfile)
        simpleallflash_fs_sync = self.get_config('simpleallflash', 'fs_sync', configfile)
        simpleallflash_snapshot = self.get_config('simpleallflash', 'snapshot', configfile)
        simpleallflash_size = int(self.get_config('simpleallflash', 'size', configfile))
        simpleallflash_prefersharedstorageforexports = self.get_config('simpleallflash', 'prefersharedstorageforexports', configfile)
        simpleallflash_prefersharedstorageforvmdisk = self.get_config('simpleallflash', 'prefersharedstorageforvmdisk', configfile)

        simpleinmemory_num = int(self.get_config('simpleinmemory', 'num', configfile))
        simpleinmemory_exporttype = self.get_config('simpleinmemory', 'exporttype', configfile)
        simpleinmemory_exportfstype = self.get_config('simpleinmemory', 'exportfstype', configfile)
        simpleinmemory_fs_sync = self.get_config('simpleinmemory', 'fs_sync', configfile)
        simpleinmemory_snapshot = self.get_config('simpleinmemory', 'snapshot', configfile)
        simpleinmemory_size = int(self.get_config('simpleinmemory', 'size', configfile))
        simpleinmemory_prefersharedstorageforvmdisk = self.get_config('simpleinmemory', 'prefersharedstorageforvmdisk', configfile)

        usx_build_path = self.get_config('ovf_path', 'usx_build_path', configfile)

        migration_usx_build_path = self.get_config('migration_ovf_path', 'migration_usx_build_path', configfile)
        
        mount_tool_path = self.get_config('vvol', 'mount_tool_path', configfile)
        provider_tool_path = self.get_config('vvol', 'provider_tool_path', configfile)

        temp_list = amc_ip.split('.')
        multicastip = '226.2.' + temp_list[2] + '.' + temp_list[3]

        all_config = {}
        all_config['user'] = user
        all_config['amc_ip'] = amc_ip
        all_config['amc_num'] = amc_num
        all_config['tiebreaker_ip'] = tiebreaker_ip
        all_config['reservation'] = reservation
        all_config['usx_build_path'] = usx_build_path
        all_config['testbed_count'] = testbed_count
        all_config['hypervisor_num'] = hypervisor_num
        all_config['stretch_cluster'] = stretch_cluster
        all_config['robo'] = robo
        all_config['deploy_tiebreaker'] = deploy_tiebreaker
        all_config['login_config'] = {}
        all_config['login_config']['username'] = 'usxadmin'
        all_config['login_config']['password'] = 'poweruser'
        all_config['usx_version'] = usx_version
        all_config['memory_allocation'] = memory_allocation
        all_config['disk_allocation'] = disk_allocation
        all_config['flash_allocation'] = flash_allocation
        all_config['platform'] = platform
        all_config['xenservers'] = xenservers
        all_config['deploy_usxm'] = deploy_usxm
        all_config['deploy_volume'] = deploy_volume
        all_config['config_usxm'] = config_usxm
        all_config['raid_plan'] = raid_plan
        all_config['hyperconverge_type'] = hyperconverge_type
        all_config['hyperconverge_cluster'] = hyperconverge_cluster
        all_config['hybridratio'] = hybridratio
        all_config['multicastip'] = multicastip
        all_config['only_infrastructure'] = only_infrastructure
        all_config['testbed_name'] = 'Testbed' + testbed_count
        all_config['ip_range'] = ip_range
        all_config['vcs'] = vcs
        all_config['vvol'] = {}
        all_config['vvol']['mount_tool_path'] = mount_tool_path
        all_config['vvol']['provider_tool_path'] = provider_tool_path
        all_config['migration_usx_build_path'] = migration_usx_build_path

        all_config['volume_config'] = {}
        if hybrid_num != 0:
            for i in range(1, hybrid_num+1):
                all_config['volume_config']['volume' + str(i)] = {}
                all_config['volume_config']['volume' + str(i)]['volumetype'] = 'HYBRID'
                all_config['volume_config']['volume' + str(i)]['hybridratio'] = hybridratio
                all_config['volume_config']['volume' + str(i)]['snapshot'] = hybrid_snapshot
                all_config['volume_config']['volume' + str(i)]['exporttype'] = hybrid_exporttype
                all_config['volume_config']['volume' + str(i)]['exportfstype'] = hybrid_exportfstype
                all_config['volume_config']['volume' + str(i)]['fs_sync'] = hybrid_fs_sync
                all_config['volume_config']['volume' + str(i)]['raidtype'] = hybrid_raidtype
                all_config['volume_config']['volume' + str(i)]['directio'] = hybrid_directio
                all_config['volume_config']['volume' + str(i)]['fastsync'] = hybrid_fastsync
                all_config['volume_config']['volume' + str(i)]['volumesize'] = hybrid_size
                all_config['volume_config']['volume' + str(i)]['prefersharedstorageforvmdisk'] = hybrid_prefersharedstorageforvmdisk
                all_config['volume_config']['volume' + str(i)]['preferflashforcapacity'] = hybrid_preferflashforcapacity
                all_config['volume_config']['volume' + str(i)]['preferflashformemory'] = hybrid_preferflashformemory
                all_config['volume_config']['volume' + str(i)]['prefersharedstorageforexports'] = hybrid_prefersharedstorageforexports
        else:
            i = 0

        if allflash_num != 0:
            for j in range(i+1, allflash_num+i+1):
                all_config['volume_config']['volume' + str(j)] = {}
                all_config['volume_config']['volume' + str(j)]['volumetype'] = 'ALL_FLASH'
                all_config['volume_config']['volume' + str(j)]['exporttype'] = allflash_exporttype
                all_config['volume_config']['volume' + str(j)]['exportfstype'] = allflash_exportfstype
                all_config['volume_config']['volume' + str(j)]['fs_sync'] = allflash_fs_sync
                all_config['volume_config']['volume' + str(j)]['raidtype'] = allflash_raidtype
                all_config['volume_config']['volume' + str(j)]['snapshot'] = allflash_snapshot
                all_config['volume_config']['volume' + str(j)]['directio'] = allflash_directio
                all_config['volume_config']['volume' + str(j)]['volumesize'] = allflash_size
                all_config['volume_config']['volume' + str(j)]['prefersharedstorageforvmdisk'] = allflash_prefersharedstorageforvmdisk
                all_config['volume_config']['volume' + str(j)]['prefersharedstorageforexports'] = allflash_prefersharedstorageforexports
        else:
            j = i

        if inmemory_num != 0:
            for k in range(j+1, inmemory_num+j+1):
                all_config['volume_config']['volume' + str(k)] = {}
                all_config['volume_config']['volume' + str(k)]['volumetype'] = 'MEMORY'
                all_config['volume_config']['volume' + str(k)]['exporttype'] = inmemory_exporttype
                all_config['volume_config']['volume' + str(k)]['exportfstype'] = inmemory_exportfstype
                all_config['volume_config']['volume' + str(k)]['fs_sync'] = inmemory_fs_sync
                all_config['volume_config']['volume' + str(k)]['raidtype'] = inmemory_raidtype
                all_config['volume_config']['volume' + str(k)]['snapshot'] = inmemory_snapshot
                all_config['volume_config']['volume' + str(k)]['directio'] = inmemory_directio
                all_config['volume_config']['volume' + str(k)]['volumesize'] = inmemory_size
                all_config['volume_config']['volume' + str(k)]['prefersharedstorageforvmdisk'] = inmemory_prefersharedstorageforvmdisk
        else:
            k = j

        if simplehybrid_num != 0:
            for m in range(k+1, simplehybrid_num+k+1):
                all_config['volume_config']['volume' + str(m)] = {}
                all_config['volume_config']['volume' + str(m)]['volumetype'] = 'SIMPLE_HYBRID'
                all_config['volume_config']['volume' + str(m)]['hybridratio'] = simplehybridratio
                all_config['volume_config']['volume' + str(m)]['snapshot'] = simplehybrid_snapshot
                all_config['volume_config']['volume' + str(m)]['exporttype'] = simplehybrid_exporttype
                all_config['volume_config']['volume' + str(m)]['exportfstype'] = simplehybrid_exportfstype
                all_config['volume_config']['volume' + str(m)]['fs_sync'] = simplehybrid_fs_sync
                all_config['volume_config']['volume' + str(m)]['volumesize'] = simplehybrid_size
                all_config['volume_config']['volume' + str(m)]['prefersharedstorageforvmdisk'] = simplehybrid_prefersharedstorageforvmdisk
                all_config['volume_config']['volume' + str(m)]['preferflashforcapacity'] = simplehybrid_preferflashforcapacity
                all_config['volume_config']['volume' + str(m)]['preferflashformemory'] = simplehybrid_preferflashformemory
                all_config['volume_config']['volume' + str(m)]['prefersharedstorageforexports'] = simplehybrid_prefersharedstorageforexports
        else:
            m = k

        if simpleinmemory_num != 0:
            for n in range(m+1, simpleinmemory_num+m+1):
                all_config['volume_config']['volume' + str(n)] = {}
                all_config['volume_config']['volume' + str(n)]['volumetype'] = 'SIMPLE_MEMORY'
                all_config['volume_config']['volume' + str(n)]['exporttype'] = simpleinmemory_exporttype
                all_config['volume_config']['volume' + str(n)]['exportfstype'] = simpleinmemory_exportfstype
                all_config['volume_config']['volume' + str(n)]['fs_sync'] = simpleinmemory_fs_sync
                all_config['volume_config']['volume' + str(n)]['snapshot'] = simpleinmemory_snapshot
                all_config['volume_config']['volume' + str(n)]['volumesize'] = simpleinmemory_size
                all_config['volume_config']['volume' + str(n)]['prefersharedstorageforvmdisk'] = simpleinmemory_prefersharedstorageforvmdisk
        else:
            n = m

        if usx_version != '2.1':
            if simpleallflash_num !=0:
                for p in range(n+1, simpleallflash_num+n+1):
                    all_config['volume_config']['volume' + str(p)] = {}
                    all_config['volume_config']['volume' + str(p)]['volumetype'] = 'SIMPLE_FLASH'
                    all_config['volume_config']['volume' + str(p)]['exporttype'] = simpleallflash_exporttype
                    all_config['volume_config']['volume' + str(p)]['exportfstype'] = simpleallflash_exportfstype
                    all_config['volume_config']['volume' + str(p)]['fs_sync'] = simpleallflash_fs_sync
                    all_config['volume_config']['volume' + str(p)]['snapshot'] = simpleallflash_snapshot
                    all_config['volume_config']['volume' + str(p)]['volumesize'] = simpleallflash_size
                    all_config['volume_config']['volume' + str(p)]['prefersharedstorageforvmdisk'] = simpleallflash_prefersharedstorageforvmdisk
                    all_config['volume_config']['volume' + str(p)]['prefersharedstorageforexports'] = simpleallflash_prefersharedstorageforexports
            else:
                p = n

            if hyperconverge_num != 0:
                for q in range(p+1, hyperconverge_num+p+1):
                    all_config['volume_config']['volume' + str(q)] = {}
                    all_config['volume_config']['volume' + str(q)]['hyperconvergedvolume'] = 'true'
                    all_config['volume_config']['volume' + str(q)]['exporttype'] = hyperconverge_exporttype
                    all_config['volume_config']['volume' + str(q)]['exportfstype'] = hyperconverge_exportfstype
                    all_config['volume_config']['volume' + str(q)]['fs_sync'] = hyperconverge_fs_sync
                    all_config['volume_config']['volume' + str(q)]['raidtype'] = hyperconverge_raidtype
                    all_config['volume_config']['volume' + str(q)]['volumesize'] = hyperconverge_size
                    all_config['volume_config']['volume' + str(q)]['snapshot'] = hyperconverge_snapshot
                    all_config['volume_config']['volume' + str(q)]['prefersharedstorageforvmdisk'] = hyperconverge_prefersharedstorageforvmdisk
                    all_config['volume_config']['volume' + str(q)]['hybridratio'] = hyperconvergeratio
                    all_config['volume_config']['volume' + str(q)]['directio'] = hyperconverge_directio
                    all_config['volume_config']['volume' + str(q)]['fastsync'] = hyperconverge_fastsync
                    all_config['volume_config']['volume' + str(q)]['preferflashforcapacity'] = hyperconverge_preferflashforcapacity
                    all_config['volume_config']['volume' + str(q)]['preferflashformemory'] = hyperconverge_preferflashformemory
                    all_config['volume_config']['volume' + str(q)]['prefersharedstorageforexports'] = hyperconverge_prefersharedstorageforexports
                    if usx_version in ['3.0.1', '3.1.0', '3.1.1', '3.1.2', '3.2.0']:
                        if hyperconverge_type == 'hybrid':
                            all_config['volume_config']['volume' + str(q)]['volumetype'] = 'HYBRID'
                        else:
                            all_config['volume_config']['volume' + str(q)]['volumetype'] = 'ALL_FLASH'
                    else:
                        all_config['volume_config']['volume' + str(q)]['volumetype'] = 'HYBRID'

        return all_config

    def config_amc(self, all_config):
        obj_tools = Tools(all_config['amc_ip'])
        
        # if all_config['usx_version'] not in ['3.1.2', '3.2.0']:
        #     if all_config['robo'] == 'true':
        #         obj_log.debug('Set robo start...')
        #         rtn = obj_tools.set_robo('true')
        #         if rtn == False:
        #             obj_log.debug('Set robo fail.')
        #             return False
        #         obj_log.debug('Set robo done.')
        
        if all_config['platform'] != 'XEN':
            obj_log.debug("Add vCenter...")
            add_vc_rtn = obj_tools.add_vc(all_config['vcs'])
            time.sleep(10)
            if add_vc_rtn == True:
                obj_log.debug("Add vc done.\n")
            else:
                obj_log.debug("Add vc fail.\n")
                return False
        else:
            obj_log.debug("Add Xenserver...")
            add_xen_rtn = obj_tools.add_xenserver(all_config['xenservers'])
            obj_log.debug('addxenrtn', add_xen_rtn)
            time.sleep(10)
            if add_xen_rtn == True:
                obj_log.debug("Add Xenserver done.\n")
            else:
                obj_log.debug("Add Xenserver fail.\n")
                return False
        
        if all_config['stretch_cluster'] == 'true':
            if all_config['deploy_tiebreaker'] == 'true':
                obj_tools = Tools(all_config['amc_ip'])
                # rtn = obj_tools.deploy_tiebreaker(all_config['user'], all_config['testbed_name'], all_config['vcs'], all_config['tiebreaker_ip'])
                rtn = obj_tools.deploy_tiebreaker(all_config)
                if rtn == False:
                    return False
        
        if all_config['usx_version'] != '2.1':
            if all_config['raid_plan'] == 'raid15':
                rtn = obj_tools.set_raid_plan('true')
                if rtn != False:
                    obj_log.debug('Set raid plan successfully.')
            elif all_config['raid_plan'] == 'raid5':
                rtn = obj_tools.set_raid_plan('false')
                if rtn != False:
                    obj_log.debug('Set raid plan successfully.')
            else:
                rtn = obj_tools.set_raid_plan('true')
                if rtn != False:
                    obj_log.debug('Set raid plan successfully.')

        obj_log.debug('Set allocation start...')
        set_allocation_rtn = obj_tools.set_allocation(all_config['memory_allocation'], all_config['disk_allocation'], all_config['flash_allocation'])
        if set_allocation_rtn == True:
            obj_log.debug('Set allocation done.\n')
        else:
            obj_log.debug(set_allocation_rtn)
            obj_log.debug('Set allocation fail.')
            return False

        #set reservation
        obj_log.debug('Set reservation start...')
        set_reservation_rtn = obj_tools.set_reservation(all_config['reservation'])
        if set_reservation_rtn == True:
            obj_log.debug('Set reservation done.\n')
        else:
            obj_log.debug(set_reservation_rtn)
            obj_log.debug('Set reservation fail.')
            return False

        obj_log.debug('Set multicastip start...')
        set_multicastip_rtn = obj_tools.set_multicastip(all_config['multicastip'])
        if set_multicastip_rtn == True:
            obj_log.debug('Set multicastip done.\n')
        else:
            obj_log.debug(set_multicastip_rtn)
            obj_log.debug('Set multicastip fail.')
            return False

        obj_log.debug('Configurator hypervisors start...')
        # configurator hypervisors
        conf_hypervisors_rtn = obj_tools.conf_hypervisors(all_config['vcs'], all_config['platform'])
        if conf_hypervisors_rtn == True:
            obj_log.debug('Configurator hypervisors done.\n')
        else:
            obj_log.debug('conf_hypervisors_rtn', conf_hypervisors_rtn)
            return False
        
        if all_config['stretch_cluster'] == 'true':
            obj_log.debug('Config stretch cluster start...')
            rtn = obj_tools.set_stretch_cluster('true')
            rtn = obj_tools.set_raid_plan('true')
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False
            
            rtn = obj_tools.create_site_tag()
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False
            
            rtn = obj_tools.set_tiebreakerip(all_config['tiebreaker_ip'])
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False
            
            rtn = obj_tools.set_sharedstorageforvmdisk('false')
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False
            
            rtn = obj_tools.conf_site_group(all_config['vcs'])
            if rtn == False:
                obj_log.debug('Config stretch cluster fail.')
                return False
            
            obj_log.debug('Config stretch cluster done.')
        
        obj_log.debug('Configurator datastore start...')
        conf_storage_rtn = obj_tools.conf_storage(all_config['vcs'], all_config['disk_allocation'], all_config['flash_allocation'], all_config['platform'])

        if conf_storage_rtn == True:
            obj_log.debug('Configurator datastore done.\n')
        else:
            obj_log.debug('conf_storage_rtn', conf_storage_rtn)
            return False
        
        obj_log.debug('Configurator network start...')
        # configurator network profiles
        conf_network_rtn = obj_tools.conf_network(all_config['vcs'], all_config['ip_range'])
        if conf_network_rtn == False:
            return False
        obj_log.debug('Configurator network done.\n')
 
        obj_log.debug('Configurator network mapping start...')
        # configurator network profiles mapping
        conf_network_mapping_rtn = obj_tools.conf_network_mapping(all_config['vcs'], all_config['platform'], conf_network_rtn)
        if conf_network_mapping_rtn == True:
            obj_log.debug('Configurator network mapping done.\n')
        else:
            obj_log.debug('Configurator network mapping fail.')
            return False
 
        obj_log.debug('Add name template start...')
        conf_name_template_rtn = obj_tools.create_servicevm_template(all_config['user'], all_config['testbed_name'])
        if conf_name_template_rtn == True:
            obj_log.debug('Add service vm name template done.\n')
        else:
            obj_log.debug('Add service vm name template fail.')
            return False
 
        if all_config['usx_version'] != '2.1':
            conf_name_template_rtn = obj_tools.create_volume_template(all_config['user'], all_config['testbed_name'])
            if conf_name_template_rtn == True:
                obj_log.debug('Add volume name template done.\n')
            else:
                obj_log.debug('Add volume name template fail.\n')
                return False
 
            if all_config['usx_version'] >= '3.0.1':
                conf_name_template_rtn = obj_tools.create_volume_service_template(all_config['user'], all_config['testbed_name'])
                if conf_name_template_rtn == True:
                    obj_log.debug('Add volume service name template done.\n')
                else:
                    obj_log.debug('Add volume service name template fail.\n')
                    return False

        return True

    def check_ip_conflict(self, all_config):
        amc_ip = all_config['amc_ip']
        while self.is_reachable(amc_ip):
            obj_log.error("AMC IP is reachable please wait or change the AMC IP")
            self.progressbar_k(1000)

            # temp_ip_list = amc_ip.split('.')
            # last = int(temp_ip_list[-1]) + 20
            # if last > 230:
            #     last = 10
            # temp_ip_list[-1] = str(last)
            # amc_ip = '.'.join(temp_ip_list)

            # # format ip range by amc_ip
            # ip_range_temp = re.split('\.|-', ip_range)
            # ip_range_temp[1] = str(last + 1)
            # ip_range_temp[3] = str(last + 20)

            # if len(ip_range_temp) == 4:
            #     ip_range = '{0}.{1}-{2}.{3}'.format(ip_range_temp[0],
            #                                         ip_range_temp[1],
            #                                         ip_range_temp[2],
            #                                         ip_range_temp[3])
            # elif len(ip_range_temp) > 4:
            #     ip_range = '{0}.{1}-{2}.{3}-{4}'.format(ip_range_temp[0],
            #                                         ip_range_temp[1],
            #                                         ip_range_temp[2],
            #                                         ip_range_temp[3],
            #                                         ip_range_temp[4])

    def deploy_usx(self, all_config):

        if all_config['deploy_usxm'] == 'true':
            # change ip and ip range to avoid ip conflict
            self.check_ip_conflict(all_config)
            
            deploy_amc_rtn = self.deploy_amc(all_config)
            if deploy_amc_rtn == False:
                return False

            # get version from USX 2017-4-18 14:57:53
            usx_version = obj_utils.get_usx_version(all_config['amc_ip'])
            all_config['usx_version'] = usx_version

        if all_config['deploy_usxm'] == 'true' and all_config['config_usxm'] == 'false':
            deploy_volume = 'false'
        else:
            deploy_volume = all_config['deploy_volume']

        if all_config['config_usxm'] == 'true':
            config_amc_rtn = self.config_amc(all_config)
            if config_amc_rtn == False:
                return False

        if deploy_volume == 'true':
            obj_tools = Tools(all_config['amc_ip'])
            obj_log.debug("Start deploy volume...")

            hypervisor_num = 0

            for vc_ip in all_config['vcs'].keys():
                for items in all_config['vcs'][vc_ip]['dcs'].values():
                    for item in items:
                        hypervisor_num = hypervisor_num + len(item['hosts'].keys())
                
            if hypervisor_num > 3:
                set_hypervisorlayout_rtn = obj_tools.set_hypervisorlayout(hypervisor_num)
                if 'true' in set_hypervisorlayout_rtn:
                    obj_log.debug('set hypervisor layout for volume successfully.')
                else:
                    obj_log.debug('set hypervisor layout for volume fail', set_hypervisorlayout_rtn)
                    return False

            user = all_config['user']
            testbed_name = all_config['testbed_name']

            for volume_temp in all_config['volume_config']:
                volumetype = all_config['volume_config'][volume_temp]['volumetype']
                volumesize = all_config['volume_config'][volume_temp]['volumesize']
                exporttype = all_config['volume_config'][volume_temp]['exporttype']
                exportfstype = all_config['volume_config'][volume_temp]['exportfstype']
                fs_sync = all_config['volume_config'][volume_temp]['fs_sync']
                prefersharedstorageforvmdisk = all_config['volume_config'][volume_temp]['prefersharedstorageforvmdisk']
                snapshot_option = all_config['volume_config'][volume_temp]['snapshot']
                stretch_cluster = all_config['stretch_cluster']
                robo = all_config['robo']
                
                if 'SIMPLE' not in volumetype:
                    directio = all_config['volume_config'][volume_temp]['directio']
                    raidtype = all_config['volume_config'][volume_temp]['raidtype']
                if 'MEMORY' not in volumetype:
                    prefersharedstorageforexports = all_config['volume_config'][volume_temp]['prefersharedstorageforexports']
                if 'HYBRID' in volumetype:
                    hybridratio = all_config['volume_config'][volume_temp]['hybridratio']
                    preferflashforcapacity = all_config['volume_config'][volume_temp]['preferflashforcapacity']
                    preferflashformemory = all_config['volume_config'][volume_temp]['preferflashformemory']

                if volumetype == 'HYBRID':
                    fastsync = all_config['volume_config'][volume_temp]['fastsync']
                    if all_config['volume_config'][volume_temp].has_key('hyperconvergedvolume') == False:
                        deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,sharestorageforvmdisk=prefersharedstorageforvmdisk, \
                            directio=directio,exporttype=exporttype,hybridratio=hybridratio,fastsync=fastsync,prefersharedstorageforexports=prefersharedstorageforexports, \
                            preferflashforcapacity=preferflashforcapacity,preferflashformemory=preferflashformemory,usx_version=usx_version,snapshot=snapshot_option, \
                            stretch_cluster=stretch_cluster,robo=robo,exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
                    else:
                        hyperconverge_cluster = all_config['hyperconverge_cluster']
                        hyperconvergedvolume = all_config['volume_config'][volume_temp]['hyperconvergedvolume']
                        only_infrastructure = all_config['only_infrastructure']
                        deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,hyperconverge_cluster,hyperconvergedvolume,\
                            only_infrastructure=only_infrastructure,sharestorageforvmdisk=prefersharedstorageforvmdisk, directio=directio,exporttype=exporttype,\
                            hybridratio=hybridratio,fastsync=fastsync,prefersharedstorageforexports=prefersharedstorageforexports,preferflashforcapacity=preferflashforcapacity,\
                            preferflashformemory=preferflashformemory,usx_version=usx_version,snapshot=snapshot_option,stretch_cluster=stretch_cluster,robo=robo,\
                            exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
                elif volumetype == 'ALL_FLASH':
                    if all_config['volume_config'][volume_temp].has_key('hyperconvergedvolume') == False:
                        deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,sharestorageforvmdisk=prefersharedstorageforvmdisk, directio=directio,\
                            exporttype=exporttype,prefersharedstorageforexports=prefersharedstorageforexports,usx_version=usx_version,snapshot=snapshot_option,\
                            stretch_cluster=stretch_cluster,robo=robo,exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
                    else:
                        # hyperconverge_cluster = all_config['volume_config'][volume_temp]['hyperconverge_cluster']     # yuzhenjie
                        hyperconverge_cluster = all_config['hyperconverge_cluster']
                        hyperconvergedvolume = all_config['volume_config'][volume_temp]['hyperconvergedvolume']
                        only_infrastructure = all_config['only_infrastructure']
                        deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,hyperconverge_cluster,hyperconvergedvolume,\
                            only_infrastructure=only_infrastructure,sharestorageforvmdisk=prefersharedstorageforvmdisk, directio=directio,exporttype=exporttype,\
                            prefersharedstorageforexports=prefersharedstorageforexports,usx_version=usx_version,snapshot=snapshot_option,stretch_cluster=stretch_cluster,robo=robo,\
                            exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
                elif volumetype == 'MEMORY':
                    deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,sharestorageforvmdisk=prefersharedstorageforvmdisk, directio=directio,\
                        exporttype=exporttype,usx_version=usx_version,snapshot=snapshot_option,stretch_cluster=stretch_cluster,robo=robo,
                        exportfstype=exportfstype,fs_sync=fs_sync,raidtype=raidtype)
                elif volumetype == 'SIMPLE_HYBRID':
                    deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,sharestorageforvmdisk=prefersharedstorageforvmdisk,exporttype=exporttype,\
                        hybridratio=hybridratio,prefersharedstorageforexports=prefersharedstorageforexports,preferflashforcapacity=preferflashforcapacity,\
                        preferflashformemory=preferflashformemory,usx_version=usx_version,snapshot=snapshot_option, exportfstype=exportfstype,fs_sync=fs_sync)
                elif volumetype == 'SIMPLE_FLASH':
                    deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,sharestorageforvmdisk=prefersharedstorageforvmdisk,exporttype=exporttype,\
                        prefersharedstorageforexports=prefersharedstorageforexports,usx_version=usx_version,snapshot=snapshot_option,exportfstype=exportfstype,fs_sync=fs_sync)
                elif volumetype == 'SIMPLE_MEMORY':
                    deploy_rtn = obj_tools.deploy_volume(user,testbed_name,volumetype,volumesize,sharestorageforvmdisk=prefersharedstorageforvmdisk,exporttype=exporttype,\
                        usx_version=usx_version,snapshot=snapshot_option,exportfstype=exportfstype,fs_sync=fs_sync)

                if deploy_rtn == True:
                    if all_config['volume_config'][volume_temp].has_key('hyperconvergedvolume') == True:
                        obj_log.debug('Deploy Hyperconverge successfully.')
                    else:
                        obj_log.debug('Deploy ' + all_config['volume_config'][volume_temp]['volumetype'] + ' successfully.')
                else:
                    obj_log.debug("Deployed failed")
                    return False

            obj_log.debug("Deploy volume done.\n")

        return True

    def clean_testbed(self, vcs, testbed_name, user):
        try:
            # create a CLEAN_FALSE.flg in /root/, if you don't want to clean testbed
            if os.path.exists('/root/CLEAN_FALSE.flg'):
                obj_log.info("CLEAN_FALSE.flg exist. Will not clean testbed")
                return True
            all_poweroff_vm_dict = {}
            all_delete_vm_name_dict = {}
            all_umount_ds_dict = {}
            for vc_ip in vcs.keys():
                vc_user = vcs[vc_ip]['username']
                vc_pwd = vcs[vc_ip]['password']
                server.connect(vc_ip, vc_user, vc_pwd)
                vm_list = server.get_registered_vms()

                all_umount_ds_dict[vc_ip] = {}
                all_delete_vm_name_dict[vc_ip] = []
                all_poweroff_vm_dict[vc_ip] = []

                for vm_path in vm_list:
                    if testbed_name in vm_path and user in vm_path:
                        obj_vm = server.get_vm_by_path(vm_path)
                        vm_name = obj_vm.get_property('name')
                        all_delete_vm_name_dict[vc_ip].append(vm_name)
                        vm_status = obj_vm.get_status()
                        if vm_status != 'POWERED OFF':
                            all_poweroff_vm_dict[vc_ip].append(vm_name)

                for host_mor, hostname in server.get_hosts().items():
                    all_umount_ds_dict[vc_ip][hostname] = []
                    props = VIProperty(server, host_mor)
                    for ds_mor in props.datastore:
                        if testbed_name in ds_mor.info.name and user in ds_mor.info.name:
                            all_umount_ds_dict[vc_ip][hostname].append(ds_mor.info.name)

            obj_log.debug('Power off vms...')
            for vc_ip in vcs.keys():
                vc_user = vcs[vc_ip]['username']
                vc_pwd = vcs[vc_ip]['password']
                # poweroff volume and ha first
                obj_log.debug("Power off and delete by order WINDOWS===>VOLUME&HA")
                volume_and_ha_list = []
                win_clone_list = []
                for volume_ha in all_delete_vm_name_dict[vc_ip]:
                    if "WIN" in volume_ha or "FastClone" in volume_ha:
                        win_clone_list.append(volume_ha)
                    elif "-VOLUME-" in volume_ha:
                        volume_and_ha_list.append(volume_ha)
                if win_clone_list != []:
                    obj_log.debug(win_clone_list)
                    obj_multi.poweroff_vm(server, win_clone_list)
                    obj_multi.delete_vm(server, win_clone_list)
                    for volume_ha in win_clone_list:
                        all_delete_vm_name_dict[vc_ip].remove(volume_ha)
                        if volume_ha in all_poweroff_vm_dict[vc_ip]:
                            all_poweroff_vm_dict[vc_ip].remove(volume_ha)

                obj_log.debug('Umount datastores...')
                for host_name, ds_name_list in all_umount_ds_dict[vc_ip].items():
                    if ds_name_list == []:
                        continue
                    for ds_name in ds_name_list:
                        umount_rtn = self.umount_nfs(server, host_name, ds_name)

                if volume_and_ha_list != []:
                    obj_log.debug(volume_and_ha_list)
                    obj_multi.poweroff_vm(server, volume_and_ha_list)
                    obj_multi.delete_vm(server, volume_and_ha_list)
                    for volume_ha in volume_and_ha_list:
                        all_delete_vm_name_dict[vc_ip].remove(volume_ha)
                        if volume_ha in all_poweroff_vm_dict[vc_ip]:
                            all_poweroff_vm_dict[vc_ip].remove(volume_ha)

                poweroff_rtn = obj_multi.poweroff_vm(server, all_poweroff_vm_dict[vc_ip])

            obj_log.debug('Delete vms...')
            for vc_ip in vcs.keys():
                vc_user = vcs[vc_ip]['username']
                vc_pwd = vcs[vc_ip]['password']
                delete_rtn = obj_multi.delete_vm(server, all_delete_vm_name_dict[vc_ip])
                if delete_rtn == False:
                    return False

            server.disconnect()

            return True
        except Exception as e:
            obj_log.error("Clean test bed failed. Error:" + str(e))
    
    def register_vasa_provider(self, vc_ip, vc_user, vc_pwd, amc_ip, amc_user='admin', amc_pwd='poweruser'):
        vasa_name = 'Autovasa-' + amc_ip
        cmd = 'java -jar "/root/vvol/ProviderTools.jar" --url https://' + vc_ip + ':443/sdk --username ' + vc_user + ' --password ' + vc_pwd + ' --operate add --vasaName ' + vasa_name + ' --provUsername ' + amc_user + ' --provPassword ' + amc_pwd + ' --provUrl https://' + amc_ip + ':7443/vasa/version.xml'
        rtn = self.run_cmd(cmd)
        
        if 'Register Provider successful' in rtn['stdout']:
            return True
        else:
            obj_log.debug(rtn)
            return False
        
    def delete_vasa_provider(self, vc_ip, vc_user, vc_pwd, amc_ip):
        vasa_name = 'Autovasa-' + amc_ip
        cmd = 'java -jar "/root/vvol/ProviderTools.jar" --url https://' + vc_ip + ':443/sdk --username ' + vc_user + ' --password ' + vc_pwd + ' --operate delete --vasaName ' + vasa_name
        rtn = self.run_cmd(cmd)
        obj_log.debug(rtn)
        
        if 'Unregister Provider successful' in rtn['stdout']:
            return True
        else:
            obj_log.debug(rtn)
            return False
    
    def get_vasa_provider(self, vc_ip, vc_user, vc_pwd):
        vasa_provider_info = []
        tmp_dict = {}
        cmd = 'java -jar "/root/vvol/ProviderTools.jar" --url https://' + vc_ip + ':443/sdk --username ' + vc_user + ' --password ' + vc_pwd + ' --operate get'
        rtn = self.run_cmd(cmd)
        tmp_list = rtn['stdout'].split('\n')
        
        for tmp in tmp_list:
            if 'Querying all providers' in tmp:
                continue
            elif 'Found provider' in tmp:
                vasa_provider_info.append(tmp_dict)
                continue
            elif tmp == '':
                continue
            else:
                pattern = ':.+'
                m = re.search(pattern, tmp)
                tmp1 = m.group().lstrip(': ')
                if 'Name' in tmp:
                    tmp_dict['vasaname'] = tmp1
                elif 'Url' in tmp:
                    tmp_dict['url'] = tmp1
                elif 'Status' in tmp:
                    tmp_dict['status'] = tmp1
        
        return vasa_provider_info
    
    def mount_vvol(self, vc_ip, vc_user, vc_pwd, mount_host, volume_resource_name, amc_ip):
        obj_tools = Tools(amc_ip)
        vvol_uuid_dict = obj_tools.get_vvol_uuid()
        vvol_uuid = vvol_uuid_dict[volume_resource_name]
        cmd = 'perl "/root/vvol/esxcfg-ds.pl" --url https://' + vc_ip + ':443/sdk --username ' + vc_user + ' --password ' + vc_pwd + ' -vihost ' + mount_host + ' --addvvol -share ' + volume_resource_name + ' --container vvol:' + vvol_uuid
        
        rtn = self.run_cmd(cmd)
        
        if 'created and connected' in rtn['stdout']:
            return True
        else:
            obj_log.debug(rtn)
            return False
    
    def get_vm_list_by_wildcard(self, vcs, wildcard, exception=''):
        vms = []

        for vc_ip in vcs.keys():
            vc_user = vcs[vc_ip]['username']
            vc_pwd = vcs[vc_ip]['password']

        server.connect(vc_ip, vc_user, vc_pwd)
        vm_list = server.get_registered_vms()
        for path in vm_list :
            if exception:
                if exception in path:
                    continue
            if wildcard in path:
                try:
                    vm = server.get_vm_by_path(path)
                    vmname = vm.get_property('name')
                    vms.append(vmname)
                except:
                    obj_log.debug("Could not find vm by path " + path)
        server.disconnect()

        return vms

    def poweron_all_vm_by_wildcard(self, vcs, wildcard, exception='', datacenter=None, sync_run='True'):
        ret = []

        vms = self.get_vm_list_by_wildcard(vcs,wildcard,exception)
        for vc_ip in vcs.keys():
            vc_user = vcs[vc_ip]['username']
            vc_pwd = vcs[vc_ip]['password']

        server.connect(vc_ip, vc_user, vc_pwd)

        for vmname in vms :
            vm = server.get_vm_by_name(vmname)
            try:
                if not vm.is_powered_on():
                    vm.power_on(sync_run)
                else:
                    obj_log.debug(vmname + ' is already power on, skip')
                    ret.append(vm)
            except Exception as e:
                obj_log.debug('Power on ' + vmname + str(e))
            else:
                obj_log.debug('Power on <' + vmname + '> successfully')
                ret.append(vm)

        server.disconnect()

        return ret

    def get_vm_host_ip(self, server, vm_name):
        obj_vm = server.get_vm_by_name(vm_name)
        return obj_vm.properties.runtime.host.name

    def get_ip_by_vmname(self, server, vm_name):
        vm_obj = server.get_vm_by_name(vm_name)
        if vm_obj.is_powered_on():
            ip = vm_obj.get_property('ip_address', from_cache=False)
        return ip

    def get_vmname_by_ip(self, server, ip):
        vm_list = server.get_registered_vms()
        for path in vm_list:
            try:
                vm = server.get_vm_by_path(path)
                vmname = vm.get_property('name')
                vm_ip = vm.get_property('ip_address')
                if vm_ip == ip:
                    return vmname
                else:
                    obj_log.debug('can not find the vmname ip is <' + ip + '>')
            except Exception as e:
                obj_log.debug(str(e))

class Xen_vm_operation():
    def poweron_vm(self, vm_name, xenserver, xen_user, xen_pwd):
        session = XenAPI.Session('http://' + xenserver)
        session.login_with_password(xen_user, xen_pwd)
        vms = session.xenapi.VM.get_all()
        for vm in vms:
            record = session.xenapi.VM.get_record(vm)
            if record['name_label'] == vm_name:
                session.xenapi.VM.start(vm, False, False)
                session.logout()

                rtn = 'Power on vm <' + vm_name + '> successfully.'
                return rtn

        rtn = 'Power on vm <' + vm_name + '> fail.'
        return rtn

    def poweroff_vm(self, vm_name, xenserver, xen_user, xen_pwd):
        session = XenAPI.Session('http://' + xenserver)
        session.login_with_password(xen_user, xen_pwd)
        vms = session.xenapi.VM.get_all()
        for vm in vms:
            record = session.xenapi.VM.get_record(vm)
            if record['name_label'] == vm_name:
                session.xenapi.VM.hard_shutdown(vm)
                session.logout()

                rtn = 'Power off vm <' + vm_name + '> successfully.'
                return rtn

        rtn = 'Power off vm <' + vm_name + '> fail.'
        return rtn

    def shutdown_vm(self, vm_name, xenserver, xen_user, xen_pwd):
        session = XenAPI.Session('http://' + xenserver)
        session.login_with_password(xen_user, xen_pwd)
        vms = session.xenapi.VM.get_all()
        for vm in vms:
            record = session.xenapi.VM.get_record(vm)
            if record['name_label'] == vm_name:
                session.xenapi.VM.clean_shutdown(vm)
                session.logout()

                return True

        return False

    def reset_vm(self, vm_name, xenserver, xen_user, xen_pwd):
        session = XenAPI.Session('http://' + xenserver)
        session.login_with_password(xen_user, xen_pwd)
        vms = session.xenapi.VM.get_all()
        for vm in vms:
            record = session.xenapi.VM.get_record(vm)
            obj_log.debug('----', record['name_label'])
            if record['name_label'] == vm_name:
                session.xenapi.VM.hard_reboot(vm)
                session.logout()

                obj_log.info('Reset vm <' + vm_name + '> successfully.')
                return True

        obj_log.error('Reset vm <' + vm_name + '> fail.')
        return False

    def reboot_vm(self, vm_name, xenserver, xen_user, xen_pwd):
        session = XenAPI.Session('http://' + xenserver)
        session.login_with_password(xen_user, xen_pwd)
        vms = session.xenapi.VM.get_all()
        for vm in vms:
            record = session.xenapi.VM.get_record(vm)
            if record['name_label'] == vm_name:
                session.xenapi.VM.clean_reboot(vm)
                session.logout()

                rtn = 'Reboot vm <' + vm_name + '> successfully.'
                return rtn

        rtn = 'Reboot vm <' + vm_name + '> fail.'
        return rtn

    def clone_vm(self, src_vm, des_vm, sr, xenserver, xen_user, xen_pwd):
        session = XenAPI.Session('http://' + xenserver)
        session.login_with_password(xen_user, xen_pwd)
        vms = session.xenapi.VM.get_all()
        for vm in vms:
            disk = (session.xenapi.SR.get_by_name_label(sr))[0]
            record = session.xenapi.VM.get_record(vm)
            if record['name_label'] == src_vm:
                session.xenapi.VM.copy(vm, des_vm, disk)
                session.logout()

                rtn = 'Clone vm <' + src_vm + '> successfully.'
                return rtn

        rtn = 'Clone vm <' + src_vm + '> fail.'
        return rtn

#============================================================================================
obj_utils = Utils()
obj_xen = Xen_vm_operation()
class Multi_clone_vm(threading.Thread):
    def __init__(self, server, vm_name, vm_template, host, datastore, poweron=True):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
        self.vm_template = vm_template
        self.host = host
        self.datastore = datastore
        self.poweron = poweron
    def run(self):
        self.rtn = obj_utils.clone_vm(self.server, self.vm_name, self.vm_template, self.host, self.datastore, self.poweron)
    def get_return(self):
        return self.rtn

class Multi_create_snapshot(threading.Thread):
    def __init__(self, server, vm_name, snapshot_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
        self.snapshot_name = snapshot_name
    def run(self):
        self.rtn = obj_utils.create_snapshot(self.server, self.vm_name, self.snapshot_name)
    def get_return(self):
        return self.rtn

class Multi_delete_snapshot(threading.Thread):
    def __init__(self, server, vm_name, snapshot_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
        self.snapshot_name = snapshot_name
    def run(self):
        self.rtn = obj_utils.delete_snapshot(self.server, self.vm_name, self.snapshot_name)
    def get_return(self):
        return self.rtn

class Multi_shutdown_vm(threading.Thread):
    def __init__(self, server, vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.shutdown_vm(self.server, self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_modify_vm_cpu(threading.Thread):
    def __init__(self, server, vm_name, cpu_num):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
        self.cpu_num = cpu_num
    def run(self):
        self.rtn = obj_utils.modify_vm_cpu(self.server, self.vm_name, self.cpu_num)
    def get_return(self):
        return self.rtn

class Multi_power_on_vm(threading.Thread):
    def __init__(self, server, vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.poweron_vm(self.server,self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_power_off_vm(threading.Thread):
    def __init__(self, server, vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.poweroff_vm(self.server,self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_delete_vm(threading.Thread):
    def __init__(self, server, vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.delete_vm(self.server,self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_mount_export(threading.Thread):
    def __init__(self, server, host, ds_name, ip, path):
        threading.Thread.__init__(self)
        self.server = server
        self.host = host
        self.ds_name = ds_name
        self.ip = ip
        self.path = path
    def run(self):
        self.rtn = obj_utils.mount_nfs(self.server, self.host, self.ds_name, self.ip, self.path)
    def get_return(self):
        return self.rtn

class Multi_umount_export(threading.Thread):
    def __init__(self, server, host, ds_name):
        threading.Thread.__init__(self)
        self.server = server
        self.host = host
        self.ds_name = ds_name
    def run(self):
        self.rtn = obj_utils.umount_nfs(self.server, self.host, self.ds_name)
    def get_return(self):
        return self.rtn

class Multi_reset_vm(threading.Thread):
    def __init__(self, server, vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.reset_vm(self.server, self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_reboot_vm(threading.Thread):
    def __init__(self, server, vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.reboot_vm(self.server, self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_verify_raid(threading.Thread):
    def __init__(self, ip, count):
        threading.Thread.__init__(self)
        self.ip = ip
        self.count = count
    def run(self):
        self.rtn = obj_utils.verify_raid(self.ip, self.count)
    def get_return(self):
        return self.rtn

class Multi_xen_shutdown_vm(threading.Thread):
    def __init__(self, xenserver, vm_name):
        threading.Thread.__init__(self)
        self.xenserver = xenserver
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_xen.shutdown_vm(self.xenserver, self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_call_reset_api(threading.Thread):
    def __init__(self, API_URL, req_type, obj_json, cookies, header):
        threading.Thread.__init__(self)
        self.API_URL = API_URL
        self.req_type = req_type
        self.obj_json = obj_json
        self.cookies = cookies
        self.header = header
    def run(self):
        self.rtn = obj_utils.call_rest_api(self.API_URL, self.req_type, self.obj_json, self.cookies, self.header)
    def get_return(self):
        return self.rtn

class Multi_scp(threading.Thread):
    def __init__(self, host_ip, remote_path, local_path, username, password):
        threading.Thread.__init__(self)
        self.host_ip = host_ip
        self.remote_path = remote_path
        self.local_path = local_path
        self.username = username
        self.password = password
    def run(self):
        self.rtn = obj_utils.remote_scp(self.host_ip, self.remote_path, self.local_path, self.username, self.password)

class Multi_get_vm_health(threading.Thread):
    def __init__(self,server,vm_name):
        threading.Thread.__init__(self)
        self.server = server
        self.vm_name = vm_name
    def run(self):
        self.rtn = obj_utils.get_vm_health(self.server, self.vm_name)
    def get_return(self):
        return self.rtn

class Multi_umount_nfs(threading.Thread):
    def __init__(self,server,host,ds_name):
        threading.Thread.__init__(self)
        self.server = server
        self.host = host
        self.ds_name = ds_name
    def run(self):
        self.rtn = obj_utils.umount_nfs(self.server, self.host, self.ds_name)
    def get_return(self):
        return self.rtn

class Multi_ceph_write(threading.Thread):
    def __init__(self, node_ip, filepath):
        threading.Thread.__init__(self)
        self.node_ip = node_ip
        self.filepath = filepath
    def run(self):
        self.rtn = obj_utils.ceph_write(self.node_ip, self.filepath)
    def get_return(self):
        return self.rtn

class Multi_ceph_read(threading.Thread):
    def __init__(self, node_ip, filepath, volumeid, offset):
        threading.Thread.__init__(self)
        self.node_ip = node_ip
        self.filepath = filepath
        self.volumeid = volumeid
        self.offset = offset
    def run(self):
        self.rtn = obj_utils.ceph_read(self.node_ip, self.filepath, self.volumeid, self.offset)
    def get_return(self):
        return self.rtn

class Multi_change_network_status(threading.Thread):
    def __init__(self, server, name, device_name, status):
        threading.Thread.__init__(self)
        self.server = server
        self.name = name
        self.device_name = device_name
        self.status = status
    def run(self):
        self.rtn = obj_utils.change_network_device_connect_status(self.server, self.name,
            self.device_name, self.status)
    def get_return(self):
        return self.rtn

class Multi():
    def multi_ceph_write(self, node_ip, filepath_list):
        rtn_list = []
        thread_list = []
        for filepath in filepath_list:
            t = Multi_ceph_write(node_ip, filepath)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()

            if rtn == False:
                return False
            else:
                rtn_list.append(rtn)

        return rtn_list

    def multi_ceph_read(self, node_ip, file_info):
        rtn_list = []
        thread_list = []
        for item in file_info:
            for filepath in item.keys():
                volumeid = item[filepath]['volumeid']
                offset = item[filepath]['offset']
                t = Multi_ceph_read(node_ip, filepath, volumeid, offset)
                thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()

            if rtn == False:
                return False
            else:
                rtn_list.append(rtn)

        return rtn_list

    def multi_umount_nfs(self, server, host, ds_name_list, worker=None):
        thread_list = []

        for ds_name in ds_name_list:
            t = Multi_delete_vm(server, host, ds_name)
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
                return False

        return True

    def get_vms_health(self, server, vm_list):
        thread_list = []

        for vm in vm_list:
            t = Multi_get_vm_health(server,vm)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()

            if rtn == False:
                return False

        return True

    def multi_scp(self, host_ip_list, remote_path, local_path, username, password):
        thread_list = []

        for host_ip in host_ip_list:
            t = Multi_scp(host_ip, remote_path, local_path, username, password)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

    def multi_call_reset_api(self, API_URL, req_type, json_list, cookies=None, header=True):
        thread_list = []
        rtn_dict = {}
        rtn_dict['stderr'] = []
        rtn_dict['stdout'] = []

        for temp_json in json_list:
            t = Multi_call_reset_api(API_URL, req_type, temp_json, cookies, header)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()
            if rtn != False:
                rtn_dict['stdout'].append(rtn)
            else:
                rtn_dict['stderr'].append(rtn)

        return rtn_dict

    def multi_create_snapshot(self, server, vm_list, snapshot_name, worker=None):
        thread_list = []
        rtn_dict = {}
        rtn_dict['error'] = []
        rtn_dict['success'] = []

        for vm in vm_list:
            t = Multi_create_snapshot(server, vm, snapshot_name)
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
            if 'successfully' in rtn:
                rtn_dict['success'].append(rtn)
            else:
                rtn_dict['error'].append(rtn)

        return rtn_dict

    def multi_delete_snapshot(self, server, vm_list, snapshot_name, worker=None):
        thread_list = []
        rtn_dict = {}
        rtn_dict['error'] = []
        rtn_dict['success'] = []

        for vm in vm_list:
            t = Multi_delete_snapshot(server, vm, snapshot_name)
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
            if 'successfully' in rtn:
                rtn_dict['success'].append(rtn)
            else:
                rtn_dict['error'].append(rtn)

        return rtn_dict

    def mount_export(self, server, volume_info):
        i = 0
        rtn_dict = {}
        rtn_dict['error'] = []
        rtn_dict['success'] = []
        host_list = server.get_hosts().values()
        thread_list = []
        for volume in volume_info.keys():
            if i >= len(host_list):
                i = 0
            volume_name = volume_info[volume]['name']
            path = volume_info[volume]['mountpoint']

            if 'SIMPLE' in volume_info[volume]['type']:
                mount_ip = volume_info[volume]['eth1']
            else:
                mount_ip = volume_info[volume]['serviceip']

            t = Multi_mount_export(server, host_list[i], volume_name, mount_ip, path)
            thread_list.append(t)
            i = i + 1

        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()

        time.sleep(5)

        for mount_thread in thread_list:
            rtn = mount_thread.get_return()
            if 'successfully' in rtn:
                rtn_dict['success'].append(rtn)
            else:
                rtn_dict['error'].append(rtn)

        return rtn_dict

    def multi_shutdown_vm(self, server, vm_list, worker=None):
        thread_list = []
        
        for vm in vm_list:
            t = Multi_shutdown_vm(server, vm)
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
            if rtn == False:
                return False
                
        return True
        
    def multi_modify_vm_cpu_num(self, server, vm_list, cpu_num, worker=None):
        thread_list = []
        rtn_dict = {}
        rtn_dict['error'] = []
        rtn_dict['success'] = []

        for vm in vm_list:
            t = Multi_modify_vm_cpu(server, vm, cpu_num)
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
            if 'successfully' in rtn:
                rtn_dict['success'].append(rtn)
            else:
                rtn_dict['error'].append(rtn)

        return rtn_dict

    def clone_vm(self, amc_ip, vcs, clone_num=1, worker=None, poweron=True, containername=None):
        obj_tools = Tools(amc_ip)
        all_node_info = obj_tools.get_all_node_info()

        vc_hypervisor_dict = obj_tools.get_vc_hypervisors()

        volume_info = all_node_info['volume_info']
        for volume in volume_info.keys():
            if (containername != None and (volume_info[volume]['containername'] != containername)):
                    continue
            if volume_info[volume]['mounthost'] == None:
                obj_log.debug('Please mount ' + volume_info[volume]['name'])
                return False

        thread_dict = {}

        for vc_ip in vcs.keys():
            thread_dict[vc_ip] = []

        for vc_ip in vcs.keys():
            for volume in volume_info.keys():
                if (containername != None and (volume_info[volume]['containername'] != containername)):
                    continue
                if  volume_info[volume].has_key('infrastructurevolume'):
                    if volume_info[volume]['infrastructurevolume']:
                        continue
                host = volume_info[volume]['mounthost'][0]
                ds = volume_info[volume]['datastorename']
                volume_name = volume_info[volume]['name']

                if host in vc_hypervisor_dict[vc_ip]:
                    vc_user = vcs[vc_ip]['username']
                    vc_pwd = vcs[vc_ip]['password']
                    server.connect(vc_ip, vc_user, vc_pwd)
                else:
                    break

                for vc_tmp,ddvm in vc_vm_template_dict.items():
                    if vc_ip == vc_tmp:
                        vm_template = ddvm
                        break

                for j in range(1,clone_num + 1):
                    time_flag_tmp = str(time.time())
                    time_flag = time_flag_tmp.split('.')[0]
                    name = 'WIN7-' + volume_name + '-' + time_flag
                    t = Multi_clone_vm(server, name, vm_template, host, ds, poweron=poweron)
                    thread_dict[vc_ip].append(t)

            if worker == None:
                for thread in thread_dict[vc_ip]:
                    thread.start()

                for thread in thread_dict[vc_ip]:
                    thread.join()
            else:
                k = 0
                thread_count = len(thread_dict[vc_ip])
                m = thread_count/worker
                n = thread_count%worker
                count = 0
                for flag in range(m):
                    count = k + worker
                    for i in range(k , count):
                        thread_dict[vc_ip][i].start()
                    thread_dict[vc_ip][i].join()
                    k = count
                    if flag < (m-1) :
                        count = count + worker

                for p in range(count, count + n):
                    thread_dict[vc_ip][p].start()

                for p in range(count, count + n):
                    thread_dict[vc_ip][p].join()

            for thread in thread_dict[vc_ip]:
                rtn = thread.get_return()
                if rtn == False:
                    return False

        return True
    
    def multi_verify_raid(self, ip_list, count):
        thread_list = []

        for ip in ip_list:
            t = Multi_verify_raid(ip, count)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()
            if rtn == False:
                return rtn
            else:
                continue

        return True

    def multi_check_mdstat(self, volume_info, count):
        volume_ip_list = []

        for volume in volume_info.keys():
            if 'SIMPLE' in volume_info[volume]['type']:
                continue
            else:
                volume_ip_list.append(volume_info[volume]['eth0'])

        for i in range(500):
            verify_rtn = self.multi_verify_raid(volume_ip_list, count)
            if verify_rtn == True:
                return True
            else:
                time.sleep(10)
                continue

        return False

    def poweron_vm(self, server, vm_list, worker=None):
        thread_list = []

        for vm in vm_list:
            t = Multi_power_on_vm(server, vm)
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
                return False

        return True

    def poweroff_vm(self, server, vm_list, worker=None):
        thread_list = []

        for vm in vm_list:
            t = Multi_power_off_vm(server, vm)
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
                return False

        return True

    def reset_vm(self, server, vm_list, worker=None):
        thread_list = []

        for vm in vm_list:
            t = Multi_reset_vm(server, vm)
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
                return False

        return True

    def reboot_vm(self, server, vm_list, worker=None):
        thread_list = []

        for vm in vm_list:
            t = Multi_reboot_vm(server, vm)
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
                return False

        return True

    def delete_vm(self, server, vm_list, worker=None):
        thread_list = []

        for vm in vm_list:
            t = Multi_delete_vm(server, vm)
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
                return False

        return True

    def multi_xen_shutdown_vm(self, xenserver, vm_list):
        rtn_dict = {}
        rtn_dict['success'] = []
        rtn_dict['error'] = []
        thread_list = []

        for vm in vm_list:
            t = Multi_xen_shutdown_vm(xenserver, vm)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()
            if 'successfully' in rtn:
                rtn_dict['success'].append(rtn)
            else:
                rtn_dict['error'].append(rtn)

        return rtn_dict

    def multi_change_network_status(self, server, vm_list, status=True):
        rtn_dict = {}
        rtn_dict['success'] = []
        rtn_dict['error'] = []
        thread_list = []

        for vm in vm_list:
            t = Multi_change_network_status(server, vm['containername'],
                vm['device_name'],
                status=status)
            thread_list.append(t)

        for thread in thread_list:
            thread.start()

        for thread in thread_list:
            thread.join()

        for thread in thread_list:
            rtn = thread.get_return()
            if rtn is not True:
                return False
        return True
#============================================================================================================

obj_multi = Multi()


class Tools(Singleton):
    def __init__(self, amc_ip, amc_user='admin', amc_pwd='poweruser'):
        self.amc_ip = amc_ip
        obj_log.info('Login AMC...')
        rtn = self.login_amc(amc_user, amc_pwd)
        if rtn == False:
            obj_log.error('Login AMC ' + self.amc_ip + ' Fail.')
            obj_log.error(rtn)
            sys.exit(0)
        else:
            self.cookies = rtn
            obj_log.info('Login AMC ' + self.amc_ip + ' done.')

    def login_amc(self, username='admin', password='poweruser'):
        temp_dict = {}
        temp_dict['username'] = username
        temp_dict['password'] = password

        login_amc_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/user/login?istempkey=false'

        req_type = 'PUT'

        rtn_temp = obj_utils.call_rest_api(API_URL, req_type, obj_json=login_amc_json)
        if 'serverinfo' in rtn_temp:
            rtn_dict = json.loads(rtn_temp)
            rtn = rtn_dict['serverinfo']['api_key']
        else:
            obj_log.debug(rtn_temp)
            rtn = False

        return rtn

    def get_usx_version(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usxmanager?sortby=usxuuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        rtn_dict_tmp = json.loads(rtn)
        usx_version = rtn_dict_tmp['items'][0]['patchinfo']['patchversion']
        obj_log.info('Get USX version {0}'.format(usx_version))
        return usx_version

    def get_vc_hypervisors(self):
        vmmanager_name_dict = self.get_vmmanagername()
        
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/hypervisors?page=0&pagesize=100&cachekey=&isrefresh=true'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        rtn_dict = {}

        rtn_dict_tmp = json.loads(rtn)
        
        for vmmanager_ip, vmmanagername in vmmanager_name_dict.items():
            rtn_dict[vmmanager_ip] = []
            for tmp_dict in rtn_dict_tmp['items']:
                if tmp_dict['accessible'] == True:
                    if tmp_dict['vmmanagername'] == vmmanagername:
                        rtn_dict[vmmanager_ip].append(tmp_dict['hypervisorname'])

        return rtn_dict

    def get_all_hypervisors_uuid(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/hypervisors?page=0&pagesize=100&cachekey=&isrefresh=true'
        req_type = 'GET'
        rtn_dict = {}
        
        timeout = 0
        while True:
            if timeout > 60:
                obj_log.debug('Get hypervisor info time out.')
                return False
            
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
                
            rtn_dict_tmp = json.loads(rtn)
            if rtn_dict_tmp['items'] == []:
                time.sleep(1)
                timeout = timeout + 1
                continue
            else:
                break
        
        for tmp_dict in rtn_dict_tmp['items']:
            if tmp_dict['accessible'] == True:
                rtn_dict[tmp_dict['hypervisorname']] = tmp_dict['uuid']

        return rtn_dict

    def get_all_datastore_uuid(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/hypervisors?page=0&pagesize=100&cachekey=&isrefresh=true'
        req_type = 'GET'
        rtn_dict = {}
        
        timeout = 0
        while True:
            if timeout > 60:
                obj_log.debug('Get datastore info time out.')
                return False
            
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
            
            rtn_dict_tmp = json.loads(rtn)
            if rtn_dict_tmp['items'] == []:
                time.sleep(1)
                timeout = timeout + 1
                continue
            else:
                break
            
        for tmp_dict in rtn_dict_tmp['items']:

            if tmp_dict.has_key('datastores') == True:

                for tmp_dict_1 in tmp_dict['datastores']:
                    if tmp_dict_1['accessible'] == True:
                        rtn_dict[tmp_dict_1['datastorename']] = tmp_dict_1['uuid']

        return rtn_dict

    def get_all_node_info(self):
        vc_info = {}
        sv_dict = {}
        volume_dict = {}
        ha_dict = {}
        all_node_dict = {}
        #get vc info
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/vmmanagers?sortby=uuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        i = 1
        for item in rtn_dict['items']:
            vc_info['vc' + str(i)] = {}
            vc_info['vc' + str(i)]['name'] = item['name']
            vc_info['vc' + str(i)]['ip'] = item['ipaddress']
            i = i + 1

        all_node_dict['vc_info'] = vc_info

        #get serivce vm info
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/servicevm/containers?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)

        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        i = 1
        for item in rtn_dict['items']:
            sv_dict['sv' + str(i)] = {}
            sv_dict['sv' + str(i)]['containername'] = item['usxvm']['vmname']
            sv_dict['sv' + str(i)]['host'] = item['usxvm']['hypervisorname']
            sv_dict['sv' + str(i)]['vmmanagername'] = item['vmmanagername']
            for vc in vc_info.keys():
                if sv_dict['sv' + str(i)]['vmmanagername'] == vc_info[vc]['name']:
                    sv_dict['sv' + str(i)]['vcip'] = vc_info[vc]['ip']

            if len(item['nics']) == 1:
                sv_dict['sv' + str(i)]['eth0'] = item['nics'][0]['ipaddress']
                sv_dict['sv' + str(i)]['eth1'] = item['nics'][0]['ipaddress']
            else:
                for item_nics in item['nics']:
                    if item_nics['storagenetwork'] == False:
                        sv_dict['sv' + str(i)]['eth0'] = item_nics['ipaddress']
                    else:
                        sv_dict['sv' + str(i)]['eth1'] = item_nics['ipaddress']

            i = i + 1

        all_node_dict['service_vm_info'] = sv_dict

        #get volume and ha info
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/containers?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        i = 1

        for item in rtn_dict['items']:
            volume_dict['volume' + str(i)] = {}
            volume_dict['volume' + str(i)]['containername'] = item['usxvm']['vmname']
            volume_dict['volume' + str(i)]['host'] = item['usxvm']['hypervisorname']
            volume_dict['volume' + str(i)]['vmmanagername'] = item['vmmanagername']
            volume_dict['volume' + str(i)]['containeruuid'] = item['uuid']
            for vc in vc_info.keys():
                if volume_dict['volume' + str(i)]['vmmanagername'] == vc_info[vc]['name']:
                    volume_dict['volume' + str(i)]['vcip'] = vc_info[vc]['ip']

            if len(item['nics']) == 1:
                volume_dict['volume' + str(i)]['eth0'] = item['nics'][0]['ipaddress']
                volume_dict['volume' + str(i)]['eth1'] = item['nics'][0]['ipaddress']
            else:
                for item_nics in item['nics']:
                    if item_nics['storagenetwork'] == False:
                        volume_dict['volume' + str(i)]['eth0'] = item_nics['ipaddress']
                    else:
                        volume_dict['volume' + str(i)]['eth1'] = item_nics['ipaddress']

            i = i + 1

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        for item in rtn_dict['items']:
            for volume in volume_dict.keys():
                if item['containeruuid'] == volume_dict[volume]['containeruuid']:
                    volume_dict[volume]['uuid'] = item['uuid']
                    volume_dict[volume]['name'] = item['volumeservicename']
                    volume_dict[volume]['mounthost'] = []
                    volume_dict[volume]['mountpoint'] = item['dedupfsmountpoint']
                    if item['infrastructurevolume'] == True:
                        volume_dict[volume]['type'] = 'INFRA'
                    elif item['hyperconverged'] == True:
                        volume_dict[volume]['type'] = 'HYPERCONVERGE'
                    else:
                        volume_dict[volume]['type'] = item['volumetype']
                    
                    volume_dict[volume]['exportsize'] = item['volumesize']

                    if len(item['export']['hypervisornames']) != 0:
                        volume_dict[volume]['mounthost'].extend(item['export']['hypervisornames'])
                        volume_dict[volume]['datastorename'] = item['export']['datastorename']
                    else:
                        volume_dict[volume]['mounthost'] = None

                    if 'SIMPLE' not in item['volumetype']:
                        volume_dict[volume]['serviceip'] = item['serviceip']
                        volume_dict[volume]['infrastructurevolume'] = item['infrastructurevolume']
                        volume_dict[volume]['hyperconverged'] = item['hyperconverged']

        j = 1
        for volume in volume_dict.keys():
            if volume_dict[volume].has_key('mountpoint') == False:
                ha_dict['ha' + str(j)] = {}
                ha_dict['ha' + str(j)] = copy.deepcopy(volume_dict[volume])

                for vc in vc_info.keys():
                    if ha_dict['ha' + str(j)]['vmmanagername'] == vc_info[vc]['name']:
                        ha_dict['ha' + str(j)]['vcip'] = vc_info[vc]['ip']

                del volume_dict[volume]

                j = j + 1

        all_node_dict['volume_info'] = volume_dict

        all_node_dict['ha_info'] = ha_dict

        return all_node_dict

    def get_cluster_uuid(self):
        cluster_uuid_dict = {}

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/tags?sortby=uuid&order=ascend'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            cluster_uuid_dict[item['tagname']] = item['uuid']

        return cluster_uuid_dict

    def get_container_volume_uuid(self):
        volume_dict = {}

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/containers?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        for item in rtn_dict['items']:
            volume_dict[item['usxvm']['vmname']] = item['uuid']

        return volume_dict

    def get_volume_uuid(self):

        volume_dict = {}

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/containers?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        for item in rtn_dict['items']:
            if item.has_key("volumeresourceuuids"):    # skip ha volume
                volume_dict[item['usxvm']['vmname']] = item['uuid']

        API_URL_1 = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL_1, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        for item in rtn_dict['items']:
            for volume in volume_dict.keys():
                if item['containeruuid'] == volume_dict[volume]:
                    volume_dict[volume] = item['uuid']

        return volume_dict

    def get_amc_member_ip_list(self):

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/grid/member/memberips'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_list = json.loads(rtn)
        obj_log.debug('Amc member ip list =========>>>> %s' % rtn_list)

        return rtn_list 
    
    def get_volume_mountpoint(self):
        volume_mountpoint_dict = {}
        
        API_URL_1 = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL_1, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        
        rtn_dict = json.loads(rtn)
        
        for item in rtn_dict['items']:
            volume_mountpoint_dict[item['volumeservicename']] = item['dedupfsmountpoint']
        
        return volume_mountpoint_dict
    
    def get_vvol_uuid(self):
        vvol_dict = {}
        volume_mountpoint_dict = obj_utils.invert_dict(self.get_volume_mountpoint())
        
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/vvol/containers?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        
        rtn_dict = json.loads(rtn)
        
        for item in rtn_dict['items']:
            tmp_list = item['uuid'].split('-')
            vvol_uuid = tmp_list[0] + tmp_list[1] + tmp_list[2] + '-' + tmp_list[3] + tmp_list[4]
            vvol_dict[volume_mountpoint_dict[item['filesystempath']]] = vvol_uuid
            
        return vvol_dict
        
    def get_all_resource_volume_name(self):
        all_resource_volume_name = {}
        all_resource_volume_name['hybrid'] = []
        all_resource_volume_name['allflash'] = []
        all_resource_volume_name['inmemory'] = []
        all_resource_volume_name['hyperconverge'] = []

        API_URL_1 = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL_1, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        for item in rtn_dict['items']:
            if item['infrastructurevolume'] != True:
                if item['hyperconverged'] == True:
                    all_resource_volume_name['hyperconverge'].append(item['volumeservicename'])
                elif item['volumetype'] == 'HYBRID':
                    all_resource_volume_name['hybrid'].append(item['volumeservicename'])
                elif item['volumetype'] == 'MEMORY':
                    all_resource_volume_name['inmemory'].append(item['volumeservicename'])
                elif item['volumetype'] == 'ALL_FLASH':
                    all_resource_volume_name['allflash'].append(item['volumeservicename'])

        return all_resource_volume_name

    def get_resource_volume_uuid(self):
        volume_resource_dict = {}

        API_URL_1 = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL_1, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        for item in rtn_dict['items']:
            # if item['infrastructurevolume'] != True:  # remarked by raidy 20151208
            volume_resource_dict[item['volumeservicename']] = item['uuid']

        return volume_resource_dict

    def get_volume_num(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict_tmp = json.loads(rtn)

        rtn_dict = {}
        rtn_dict['hybrid'] = 0
        rtn_dict['allflash'] = 0
        rtn_dict['inmemory'] = 0
        rtn_dict['infrastructure'] = 0
        rtn_dict['hyperconverge'] = 0

        for item in rtn_dict_tmp['items']:
            if item['volumetype'] == 'HYBRID':
                if item['infrastructurevolume'] == True:
                    rtn_dict['infrastructure'] = rtn_dict['infrastructure'] + 1
                elif item['hyperconverged'] == True:
                    rtn_dict['hyperconverge'] = rtn_dict['hyperconverge'] + 1
                else:
                    rtn_dict['hybrid'] = rtn_dict['hybrid'] + 1

            elif item['volumetype'] == 'ALL_FLASH':
                if item['infrastructurevolume'] == True:
                    rtn_dict['infrastructure'] = rtn_dict['infrastructure'] + 1
                elif item['hyperconverged'] == True:
                    rtn_dict['hyperconverge'] = rtn_dict['hyperconverge'] + 1
                else:
                    rtn_dict['allflash'] = rtn_dict['allflash'] + 1
            elif item['volumetype'] == 'MEMORY':
                rtn_dict['inmemory'] = rtn_dict['inmemory'] + 1

        return rtn_dict

    def get_volume_vm(self):
        rtn_dict = {}

        volume_uuid_dict = self.get_volume_uuid()

        req_type = 'GET'

        for volume_name, volume_uuid in volume_uuid_dict.items():
            rtn_dict[volume_name] = []

            API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/vms/' + volume_uuid
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)

            if rtn == '[]':
                rtn_dict[volume_name] = None
                continue

            rtn_dict_tmp = json.loads(rtn)

            for item_tmp in rtn_dict_tmp:
                tmp_dict = {}
                tmp_dict['vmname'] = item_tmp['vmname']
                tmp_dict['hypervisorname'] = item_tmp['hypervisorname']
                tmp_dict['vmmanagername'] = item_tmp['vmmanagername']
                tmp_dict['powerstatus'] = item_tmp['powerstatus']
                rtn_dict[volume_name].append(tmp_dict)

        return rtn_dict

    def delete_volume_vm(self, vm_name, vmmanagername, vmhypervisor):
        temp_dict={}
        temp_dict["vmname"] = vm_name
        temp_dict["vmmanagername"] = vmmanagername
        temp_dict["hypervisorname"] = vmhypervisor

        delete_json = json.dumps(temp_dict, indent=4)
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/vms/delete'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, delete_json, cookies=self.cookies)
        
    def add_vc(self, vcs):

        vc_json_list = []

        for vc_ip, items in vcs.items():

            temp_dict={}
            temp = vc_ip.split(".")
            vc_name = "VC" + temp[2] + temp[3]
            temp_dict["name"] = vc_name
            temp_dict["vmmhostname"] = vc_ip
            temp_dict["username"] = items['username']
            temp_dict["password"] = items['password']
            temp_dict["vmmanagertype"] = "VCENTER"

            vc_json = json.dumps(temp_dict, indent=4)

            vc_json_list.append(vc_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/vmmanagers'
        req_type = 'POST'

        rtn_dict = obj_multi.multi_call_reset_api(API_URL, req_type, vc_json_list, cookies=self.cookies)
        if len(rtn_dict['stderr']) == 0:
            return True
        else:
            obj_log.debug(rtn_dict['stderr'])
            return False

    def add_xenserver(self, xenservers):
        error_rtn = False

        vc_json_list = []

        for xenserver_ip, items in xenservers.items():

            temp_dict={}
            temp = xenserver_ip.split(".")
            xenserver_name = "Xenserver" + temp[2] + temp[3]
            temp_dict["name"] = xenserver_name
            temp_dict["vmmhostname"] = xenserver_ip
            temp_dict["username"] = items['username']
            temp_dict["password"] = items['password']
            temp_dict["vmmanagertype"] = "XENSERVER"

            xenserver_json = json.dumps(temp_dict, indent=4)

            vc_json_list.append(xenserver_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/vmmanagers'
        req_type = 'POST'

        rtn_dict = obj_multi.multi_call_reset_api(API_URL, req_type, vc_json_list, cookies=self.cookies)
        if len(rtn_dict['stderr']) == 0:
            obj_log.debug(rtn_dict['stdout'])
            return True
        else:
            obj_log.debug(rtn_dict['stderr'])
            return error_rtn

    def get_vmmanagername(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/vmmanagers?sortby=uuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        rtn_dict_tmp = json.loads(rtn)

        vmmanager_name_dict = {}

        for item in rtn_dict_tmp['items']:
            vmmanager_name_dict[item['ipaddress']] = item['name']
        
        timeout = 0
        while True:
            if timeout > 300:
                obj_log.debug('Get vm manager info time out.')
                return False
             
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
            
            rtn_dict_tmp = json.loads(rtn)
            for item in rtn_dict_tmp['items']:
                if item.has_key('hypervisoruuids') == False:
                    obj_utils.progressbar_k(30)
                    timeout = timeout + 1
                    break
            else:
                break
        
        return vmmanager_name_dict
    
#     def get_network(self):
#         error_rtn = False
#         error_message = 'Get network uuid fail.'
#         API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/hypervisors?isrefresh=false&isassigned=false&sortby=uuid&order=ascend&page=0&pagesize=100'
#         req_type = 'GET'
#         
#         rtn_dict = {}
#         
#         rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
#         
#         rtn_dict_tmp = json.loads(rtn)
#         
#         cmd1 = 'ifconfig'
#         cmd2 = 'xe network-list'
#         
#         pattern1 = 'inet.*addr:\d\S+'
#         pattern2 = '\d\S+'
#         pattern3 = 'name-label.*\(.*RW\):.\w.+'
#         pattern4 = "(?<=:\s).+?(?=$)"
#         
#         eth0 = 'xenbr0'
#         eth1 = 'xenbr1'
#         
#         
#         tmp_dict = {}
#         
#         for item in rtn_dict_tmp['items']:
#             
#             tmp_dict[item['hypervisorname']] = {}
#             rtn_dict[item['hypervisorname']] = {}
#             
#             ssh_rtn1 = obj_utils.ssh_cmd(item['ipaddress'], 'root', 'password', cmd1)
#             
#             network_rtn_tmp1 = ssh_rtn1['stdout'].split("\n\n")
#             
#             for network_rtn1 in network_rtn_tmp1:
#                 if eth0 in network_rtn1:
#                     m = re.search(pattern1, network_rtn1)
#                     if m == None:
#                         continue
#                     m1 = re.search(pattern2, m.group())
#                         
#                 elif eth1 in network_rtn1:
#                     m = re.search(pattern1, network_rtn1)
#                     if m == None:
#                         continue
#                     
#                     m2 = re.search(pattern2, m.group())
#             
#             if len(m1.group().split('.')[1]) > len(m2.group().split('.')[1]):
#                 tmp_dict[item['hypervisorname']][eth0] = '10g'
#                 tmp_dict[item['hypervisorname']][eth1] = '1g'
#             else:
#                 tmp_dict[item['hypervisorname']][eth0] = '1g'
#                 tmp_dict[item['hypervisorname']][eth1] = '10g'
#             
#             ssh_rtn2 = obj_utils.ssh_cmd(item['ipaddress'], 'root', 'password', cmd2)
#             
#             network_rtn_tmp2 = ssh_rtn2['stdout'].split("\n\n")
#                         
#             for network_rtn2 in network_rtn_tmp2:
#                 
#                 if eth0 in network_rtn2:                    
#                     m = re.search(pattern3, network_rtn2)
#                     if m == None:
#                         continue
#                     
#                     m3 = re.search(pattern4, m.group())
#                     
#                     if m3.group() in item['networks']:
#                         rtn_dict[item['hypervisorname']][tmp_dict[item['hypervisorname']][eth0]] = m3.group()
#                     else:
#                         obj_log.debug('This networ is not exist.')
#                         sys.exit(0)
#                          
#                 elif eth1 in network_rtn2:
#                     m = re.search(pattern3, network_rtn2)
#                     if m == None:
#                         continue
#                     
#                     m4 = re.search(pattern4, m.group())
#                     
#                     if m4.group() in item['networks']:
#                         rtn_dict[item['hypervisorname']][tmp_dict[item['hypervisorname']][eth1]] = m4.group()
#                     else:
#                         obj_log.debug('This networ is not exist.')
#                         sys.exit(0)
#                                 
#         if rtn == False:
#             obj_log.debug(error_message)
#             return error_rtn
#         else:
#             return rtn_dict
    
    def get_vmmanager_cluster(self):
        vmmanager_name_dict = self.get_vmmanagername()
        
        # get hypervisor info
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/hypervisors?isrefresh=false&isassigned=false&sortby=uuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'

        rtn_dict = {}
        rtn_tmp1 = {}

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)

        rtn_dict_tmp = json.loads(rtn)
        
        for vmmanagerip, vmmanagername in vmmanager_name_dict.items():
            rtn_tmp1[vmmanagername] = []
            for item in rtn_dict_tmp['items']:
                if item['vmmanagername'] != vmmanagername:
                    continue

                if item['accessible'] == False:
                    continue

                if item.has_key('cluster') == True:
                    rtn_tmp1[vmmanagername].append(item['cluster'])
                    continue


        for vmmanagername, item in rtn_tmp1.items():
            rtn_dict[vmmanagername] = obj_utils.delete_duplicated_list(item)

        return rtn_dict

    def get_vc_info_by_api(self):
        vmmanager_name_dict = self.get_vmmanagername()
        vmmnager_cluster_dict = self.get_vmmanager_cluster()

        # get hypervisor info
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/vmm/hypervisors?isrefresh=false&isassigned=false&sortby=uuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'

        rtn_dict = {}

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)

        rtn_dict_tmp = json.loads(rtn)

        i = 1
        
        for vmmanagerip, vmmanagername in vmmanager_name_dict.items():
            
            rtn_dict[vmmanagerip] = {}
#             rtn_dict[vmmanagerip]['VCIP'] = vmmanagerip
            rtn_dict[vmmanagerip]['esxHost'] = {}
            rtn_dict[vmmanagerip]['cluster_num'] = len(vmmnager_cluster_dict[vmmanagername])
            rtn_dict[vmmanagerip]['VCName'] = vmmanagername

            j = 1
            if vmmnager_cluster_dict[vmmanagername] != []:
                for cluster_name in vmmnager_cluster_dict[vmmanagername]:
                    rtn_dict[vmmanagerip]['esxHost'][cluster_name] = {}

                    for item in rtn_dict_tmp['items']:

                        if item['vmmanagername'] != vmmanagername:
                            continue

                        if item['accessible'] == False:
                            continue

                        if item['cluster'] != cluster_name:
                            continue

                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)] = {}
                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS'] = {}
                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS']['ssd'] = {}
                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS']['nonssd'] = {}
                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS']['nfs'] = {}
                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostIP'] = item['hypervisorname']

                        k = 1

                        for datastore_item in item['datastores']:

                            if datastore_item['accessible'] == True:
                                if datastore_item['multiplehostaccess'] == True and datastore_item['freecapacity'] > (50*1024*1024*1024):
                                    rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS']['nfs']['DS' + str(k)] = datastore_item['datastorename']
                                elif datastore_item['multiplehostaccess'] == False and datastore_item['freecapacity'] > (100*1024*1024*1024):
                                    if datastore_item['ssd'] == True:
                                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS']['ssd']['DS' + str(k)] = datastore_item['datastorename']
                                    else:
                                        rtn_dict[vmmanagerip]['esxHost'][cluster_name]['host' + str(j)]['hostDS']['nonssd']['DS' + str(k)] = datastore_item['datastorename']

                                k = k + 1
                        j = j + 1

            else:
                for item in rtn_dict_tmp['items']:
                    if item['vmmanagername'] != vmmanagername:
                        continue

                    if item['accessible'] == False:
                        continue

                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)] = {}
                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS'] = {}
                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS']['ssd'] = {}
                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS']['nonssd'] = {}
                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS']['nfs'] = {}
                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostIP'] = item['hypervisorname']

                    k = 1

                    for datastore_item in item['datastores']:

                        if datastore_item['accessible'] == True:
                            if datastore_item['multiplehostaccess'] == True and datastore_item['freecapacity'] > (50*1024*1024*1024):
                                rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS']['nfs']['DS' + str(k)] = datastore_item['datastorename']
                            elif datastore_item['multiplehostaccess'] == False and datastore_item['freecapacity'] > (100*1024*1024*1024):
                                if datastore_item['ssd'] == True:
                                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS']['ssd']['DS' + str(k)] = datastore_item['datastorename']
                                else:
                                    rtn_dict[vmmanagerip]['esxHost']['host' + str(j)]['hostDS']['nonssd']['DS' + str(k)] = datastore_item['datastorename']

                            k = k + 1

                    j = j + 1

            i = i + 1

        return rtn_dict

    def get_volume_mount_host(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        volume_mount_info = {}

        for item in rtn_dict['items']:
            if item['infrastructurevolume'] != True:
                volume_mount_info[item['volumeservicename']] = []
                volume_mount_info[item['volumeservicename']].extend(item['export']['hypervisornames'])

        return volume_mount_info

    def mount_volume(self, volume_resource_name, host_list=None):
        volume_uuid_dict = self.get_resource_volume_uuid()

        temp_dict = {}
        temp_dict['hypervisornames'] = []

        if host_list == None:
            tmp_host_list = self.get_all_hypervisors_uuid().keys()
            host_num = len(tmp_host_list)
            randnum = random.randint(0, host_num-1)
            temp_dict['hypervisornames'].append(tmp_host_list[randnum])
        elif host_list == 'all':
            tmp_host_list = self.get_all_hypervisors_uuid().keys()
            temp_dict['hypervisornames'].extend(tmp_host_list)
        else:
            temp_dict['hypervisornames'].extend(host_list)

        temp_dict['datastorename'] = volume_resource_name + '-ds'
        temp_dict['volumeresourceuuid'] = volume_uuid_dict[volume_resource_name]
        temp_dict['shared'] = 'true'

        mount_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/deploy/mount'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, mount_json, cookies=self.cookies)

        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        # USX-3.5.571 mount return info changed
        if 'Mounted successfully' in rtn or 'Successfully' in rtn_dict['msg']:
            return True
        else:
            return False

    def umount_volume(self, volume_resource_name, host_list):
        volume_uuid_dict = self.get_resource_volume_uuid()

        temp_dict = {}
        temp_dict['hypervisornames'] = []

        if host_list == 'all':
            volume_mount_info = self.get_volume_mount_host()
            temp_dict['hypervisornames'].extend(volume_mount_info[volume_resource_name])
        else:
            temp_dict['hypervisornames'].extend(host_list)

        temp_dict['volumeresourceuuid'] = volume_uuid_dict[volume_resource_name]

        umount_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/deploy/unmount'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, umount_json, cookies=self.cookies)

        if rtn == False:
            return False

        if 'Unmount datastore failed' in rtn:
            return False
        else:
            return True

    def delete_volume_by_api(self, volume_resource_name, is_resource, force_delete='true', get_err_msg=False, timeout=300):
        if is_resource == 'true':
            volume_uuid_dict = self.get_resource_volume_uuid()
        else:
            volume_uuid_dict = self.get_container_volume_uuid()

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/manage/volume/' + volume_uuid_dict[volume_resource_name] + '?forcedelete=' + force_delete + '&isresource=' + is_resource
        req_type = 'DELETE'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False, get_err_msg=get_err_msg, timeout=timeout)
        
        if get_err_msg == True:
            return rtn
        else:
            if rtn == 'true':
                return True
            else:
                return False


    def add_fastclone_template(self, all_config):
        type_list = {
            # "SVM": "SERVICE_VM",
            # "VVM": "VOLUME",
            # "VM": "VOLUME_SERVICE",
            "FastClone": "FASTCLONE"
        }

        for i, v in type_list.items():
            temp_dict = {}
            temp_dict["templatename"] = i
            temp_dict["componenttype"] = v

            temp_dict["elements"] = []
            tmp1 = all_config['user'] + "-" + temp_dict["templatename"] + "-" +  all_config['testbed_name'] + "-"
            temp_dict["elements"].append(tmp1)
            tmp_dict = {}
            tmp_dict["startingnumber"] = 1
            tmp_dict["numberofdigits"] = 3
            temp_dict["elements"].append(tmp_dict)
            tmp2 = ""
            temp_dict["elements"].append(tmp2)

        name_template_json = json.dumps(temp_dict, indent=4)

        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/configurator/nametemplates"
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=name_template_json, cookies=self.cookies)
        if rtn == False:
            obj_log.error("Add fastclone template failed")
        else:
            rtn_dict = json.loads(rtn)

        return rtn_dict['uuid']


    def create_vm_group(self, resource_list, groupname, num):
        temp_dict = {}
        volume_resource_dict = self.get_resource_volume_uuid()
        vms = []

        for vm in resource_list:
            t_d = {}
            t_d['volumeresourceuuid'] = volume_resource_dict[vm]
            t_d['vmuuids'] = [""] if not num else \
                    self.get_vms_by_volume_uuid(volume_resource_dict[vm], ret_vmuuid=True)[:num]
            vms.append(t_d)
        temp_dict['vms'] = vms
        temp_dict["type"] = "VOLUME" if not num else "VM"
        temp_dict['name'] = groupname
        obj_log.debug(temp_dict)

        allocation_json = json.dumps(temp_dict, indent=4)
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/vmgroup"
        req_type = "POST"
        rtn = obj_utils.call_rest_api(API_URL, req_type, allocation_json, cookies=self.cookies)
        if rtn is False:
            obj_log.error("Create VM Group Failed")
            return False
        else:
            rtn_dict = json.loads(rtn)
            obj_log.info(rtn_dict)
            if 'successfully' in rtn_dict['msg']:
                return rtn_dict['details']
            else:
                return False

    def delete_vm_group(self, vmgroupuuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/vmgroup/" + vmgroupuuid
        req_type = 'DELETE'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)

        if rtn is False:
            obj_log.error("Delete Failed")
            return False
        else:
            rtn_dict = json.loads(rtn)
            obj_log.info(rtn_dict)
            if 'VM group was deleted successfully' in rtn_dict['msg']:
                return True
            else:
                return False

    def setup_vmschedul(self, vmgroup_uuid, schedule,
                        targetvolume, target_ip, req_type='POST', checktarget=False):
        temp_dict = {}
        temp_dict["targetvolumename"] = targetvolume
        temp_dict["targetvolumeip"] = target_ip
        temp_dict["checktarget"] = False
        temp_dict["vmgroupuuid"] = vmgroup_uuid
        temp_dict["schedule"] = schedule
        temp_dict['checktarget'] = checktarget

        allocation_json = json.dumps(temp_dict, indent=4)
        if req_type == "POST":
            API_URL = "https://" + self.amc_ip + ":8443/usxmanager/policies/dataservices/vmgroup/replication"
        else:
            replicationpolicyuuids = self.get_vmgroup_status(vmgroup_uuid)['replicationpolicyuuids'][0]
            API_URL = "https://" + self.amc_ip + ":8443/usxmanager/policies/dataservices/vmgroup/" + replicationpolicyuuids

        rtn = obj_utils.call_rest_api(API_URL, req_type, allocation_json, cookies=self.cookies, get_err_msg=checktarget)
        if rtn == False:
            return False
        else:
            return json.loads(rtn)

    def disable_vmschedul(self, vmgroupuuid):
        vmgrouppolicyuuid = self.get_vmgroup_status(vmgroupuuid)['replicationpolicyuuids'][0]
        API_URL = "https://" + self.amc_ip + \
         ":8443/usxmanager/policies/dataservices/vmgroup/disable/" + vmgrouppolicyuuid
        req_type = "PUT"
        if not obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies):
            return False
        else:
            return True

    def vmreplication_now(self, vmgroupuuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/vmgroup/" + vmgroupuuid + "/replication"
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if not rtn:
            return False
        else:
            return self.get_vmgroup_jobs(vmgroupuuid)

    def get_vmgroup_status(self, vmgroupuuid):
        API_URL = "https://"+ self.amc_ip + ":8443/usxmanager/usx/vmgroup"
        req_type = "GET"

        rtn = obj_utils.call_rest_api(API_URL, req_type)
        if  rtn:
            rtn_list = json.loads(rtn)['items']
            for r in rtn_list:
                if r["uuid"] == vmgroupuuid:
                    return r
            else:
                obj_log.warning("Not fing %s, return all" % vmgroupuuid)            
        else:
            return False


    def get_vmgroup_task_count(self, vmgroupuuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/vmgroup/" + vmgroupuuid + "/jobstatus?sortby=starttimestamp&order=descend&page=0&pagesize=100"
        req_type = 'GET'

        try:
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
            return json.loads(rtn)['count']
        except Exception as e:
            raise e

    def get_vmgroup_jobs(self, vmgroupuuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/vmgroup/" + vmgroupuuid + "/jobstatus?sortby=starttimestamp&order=descend&page=0&pagesize=100"
        req_type = 'GET'
        tms = 200
        while tms:
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
            rtn_dic = json.loads(rtn)

            if len(rtn_dic["items"]) and "tasks" not in rtn_dic["items"][0]:
                obj_log.debug("Wait for replication start!")
                continue

            try:
                task = rtn_dic['items'][0]["tasks"][-1]
            except Exception as e:
                obj_log.info("Continue to run")
                continue
            obj_log.info(task["taskname"] + "  " + task["message"])
            if "Failed" in task['message']:
                for i in rtn_dic['items'][0]['tasks']:
                    obj_log.error(i["taskname"] + "  " + i["message"])
                return False
            elif "Replication Completed" in task['message']:
                return True

            obj_utils.progressbar_k(10)
            tms -= 1
        return False

    def teleport_vm(self, volume_resource_uuid, target_volume_uuid):
        temp_dict = {}
        temp_dict['srcusxresourceuuid'] = volume_resource_uuid
        temp_dict['dstusxresourceuuid'] = target_volume_uuid
        temp_dict['operation'] = 'TELEPORT'
        vm_list = []
        temp_dict['vmnamelist'] = []

        vm_list = self.get_vms_by_volume_uuid(volume_resource_uuid)
        if vm_list:
            temp_dict['vmnamelist'].append(vm_list[0])
        else:
            print ("no vms in volume:%s" % volume_resource_uuid)
            return False
        schedule_json = json.dumps(temp_dict,indent=4)
        obj_log.info("teleport_json:%s" % schedule_json)
        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/usx/teleport/vms'
        rtn = obj_utils.call_rest_api(API_URL, req_type="POST", obj_json=schedule_json, cookies=self.cookies)

        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)
        if "successfully" in rtn_dict['msg']:
            obj_log.info(rtn_dict['msg'])
            jobrefid = rtn_dict['jobrefid']
            flag = 1
            while True:
                task_list_tmp = self.get_job_status(jobrefid)
                if task_list_tmp == [] or task_list_tmp == False:
                    continue
                if 'Successfully' in task_list_tmp[0]:
                    print('Successfully teleport!')
                    return True
                else:
                    obj_utils.progressbar_k(10)
                    flag = flag + 1

                if flag == 36000:
                    print('Teleported failed.')
                    return False
        else:
            obj_log.error(rtn_dict)
            return False


    def backup_vm(self, volume_resource_uuid, target_volume_uuid):
        temp_dict = {}
        temp_dict['srcusxresourceuuid'] = volume_resource_uuid
        temp_dict['dstusxresourceuuid'] = target_volume_uuid
        temp_dict['operation'] = 'BACKUP'
        vm_list = []
        temp_dict['vmnamelist'] = []

        vm_list = self.get_vms_by_volume_uuid(volume_resource_uuid)
        if vm_list:
            temp_dict['vmnamelist'].append(vm_list[0])
        else:
            print ("no vms in volume:%s" % volume_resource_uuid)
            return False
        schedule_json = json.dumps(temp_dict,indent=4)
        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/usx/teleport/vms?format=json'
        rtn = obj_utils.call_rest_api(API_URL, req_type="POST", obj_json=schedule_json, cookies=self.cookies)

        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)
        if "successfully" in rtn_dict['msg']:
            obj_log.info(rtn_dict['msg'])
            jobrefid = rtn_dict['jobrefid']
            flag = 1
            while True:
                task_list_tmp = self.get_job_status(jobrefid)
                if task_list_tmp == [] or task_list_tmp == False:
                    continue
                if 'Successfully' in task_list_tmp[0]:
                    print('Successfully backup vm!')
                    return True
                else:
                    obj_utils.progressbar_k(10)
                    flag = flag + 1

                if flag == 36000:
                    print('Backup vm failed.')
                    return False
        else:
            obj_log.error(rtn_dict)
            return False

    def fastclone(self, resourcename, src_vm_name, fastclone_num, fastclone_uuid_dict):
        all_node_info = self.get_all_node_info()
        volume_info = all_node_info['volume_info']
        error_rtn = False
        error_message = 'Fastclone fail'
        temp_dict = {}
        volume_resource_dict = self.get_resource_volume_uuid()
        obj_log.debug(volume_resource_dict)

        temp_dict['usxresourceuuid'] = volume_resource_dict[resourcename]
        temp_dict['srcvmname'] = src_vm_name[0]
        temp_dict['fastclonetemplateuuid'] = fastclone_uuid_dict
        temp_dict['numberofvms'] = fastclone_num

        fastclone_template_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/fastclone'
        req_type = 'POST'
        obj_log.info("fastclone_json:%s" % fastclone_template_json)
        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=fastclone_template_json, cookies=self.cookies)
        if rtn == False:
            return False
        else:
            rtn_dict = json.loads(rtn)
            jobrefid = rtn_dict['jobrefid']
            flag = 1
            while True:
                task_list_tmp = self.get_job_status(jobrefid)
                if task_list_tmp == [] or task_list_tmp == False:
                    continue
                if 'Successfully registered VM(s)' in task_list_tmp[0]:
                    print('Successfully fastclone!')
                    return True
                else:
                    obj_utils.progressbar_k(10)
                    flag = flag + 1

                if flag == 36000:
                    print('Fastclone failed.')
                    return False

    def enable_ha(self, volume_resource_name, get_err_msg=False):
        volume_resource_dict = self.get_resource_volume_uuid()

        error_message = 'Enable <' + volume_resource_name + '> ha fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/volume/' + volume_resource_dict[volume_resource_name] + '/enableha'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False, get_err_msg=get_err_msg)

        if get_err_msg is True:
            return rtn

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            rtn_dict = json.loads(rtn)
            jobrefid = rtn_dict['jobrefid']
            flag = 1
            while True:
                task_list_tmp = self.get_job_status(jobrefid)
                if task_list_tmp == [] or task_list_tmp == False:
                    continue
                
                obj_log.debug(task_list_tmp)

                # if 'HA enabled on HA Service VM' in task_list_tmp or 'Reuse HA VM.' in task_list_tmp:
                for task_tmp in task_list_tmp:
                    if 'Configured HA resources' in task_tmp:
                        return True
                    elif 'HA resources have been configured' in task_tmp:  # USX 2.2.3
                        return True
                    elif 'HA resources have not been configured' in task_tmp:
                        return False
                time.sleep(10)
                flag = flag + 1

                if flag == 540:
                    obj_log.debug('Enable HA time out.')
                    return False

    def disable_ha(self,volume_resource_name):
        volume_resource_dict = self.get_resource_volume_uuid()

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/deploy/disable/ha/resources/' + volume_resource_dict[volume_resource_name]
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        time.sleep(5)

        if rtn == False:
            obj_log.error('disable <' + volume_resource_name + '> ha fail.')
            return False
        else:
            return True
    
    def set_robo(self, option):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=raid1enabled&value=' + option
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == 'true':
            return True
        else:
            return False
    
    def set_stretch_cluster(self, option):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=stretchcluster&value=' + option
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == 'true':
            return True
        else:
            return False
    
    def create_site_tag(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/tags'
        req_type = 'POST'
        
        for i in range(1,3):
            temp_dict = {}
            temp_dict['tagtype'] = 'USX_SITE'
            temp_dict['tagname'] = 'site' + str(i)
            temp_dict['tagattributes'] = {}
            temp_dict['tagattributes']['attributes'] = {}
            temp_dict['tagattributes']['attributes']['ui_site_id'] = 'site_' + str(i)
            
            create_site_tag_json = json.dumps(temp_dict,indent=4)
            
            rtn = obj_utils.call_rest_api(API_URL, req_type, create_site_tag_json, self.cookies)
                
            if rtn == False:
                return False
        
        return True
    
    def set_tiebreakerip(self, tiebreakerip):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=tiebreakerip&value=' + tiebreakerip
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == 'true':
            obj_log.info("Set tiebreakerip to {0} successfully !".format(tiebreakerip))
            return True
        else:
            obj_log.error("Set tiebreakerip to {0} Failed !".format(tiebreakerip))
            return False

    def set_shared_ha(self, option):
        error_rtn = False
        error_message = 'Set shared ha fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=ishashared&value=' + option
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            if rtn == 'true':
                return True
            else:
                return False

    def set_always_deploy_ha(self, option):
        error_message = 'Set set always deploy ha fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=deploystandbyalways&value=' + option
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            if rtn == 'true':
                return True
            else:
                return False

    def set_volumememory(self, memory_size):
        error_rtn = False
        error_message = 'Set volumememory fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=volumememory&value=' + str(memory_size)
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            if rtn == 'true':
                return True
            else:
                return False

    def set_maxnodepercluster(self, maxnode_num):
        error_rtn = False
        error_message = 'Set maxnodespercluster failed'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=maxvolumeperhacluster&value=' + str(maxnode_num)
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            if rtn == 'true':
                return True
            else:
                return False

    def set_preferssdforvmdisk(self, option):
        error_rtn = False
        error_message = 'Set preferssdforvmdisk fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=preferssdforvmdisk&value=' + option
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            if rtn == 'true':
                return True
            else:
                return False

    def set_usxaccess(self, option):
        error_rtn = False
        error_message = 'Set usxaccess fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/user/inventory/usx/ssh/access?sshpasswordauth=' + option
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            obj_log.info('Set usx access {0} successfully!'.format(option))
            return True

    def enable_vvol(self, volume_resource_name):
        volume_resource_dict = self.get_resource_volume_uuid()
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources/' + volume_resource_dict[volume_resource_name] + '/vvol?isvvol=true&thickreserved=false&cleanup=false'
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(rtn)
            return False
        else:
            if rtn == 'true':
                return True
            else:
                return False
            
    def disable_vvol(self, volume_resource_name):
        volume_resource_dict = self.get_resource_volume_uuid()
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/inventory/volume/resources/' + volume_resource_dict[volume_resource_name] + '/vvol?isvvol=false&thickreserved=false&cleanup=false'
        req_type = 'PUT'
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(rtn)
            return False
        else:
            if rtn == 'true':
                return True
            else:
                return False
    
    def set_allocation(self, memory_allocation, disk_allocation, flash_allocation):
        error_rtn = False
        error_message = 'Set allocation fail.'

        temp_dict = {}
        temp_dict['settings'] = {}
        temp_dict['settings']['key'] = 'CONFIGURATOR'
        temp_dict['settings']['maxmemoryallocation'] = memory_allocation
        temp_dict['settings']['maxlocaldiskallocation'] = disk_allocation
        temp_dict['settings']['maxlocalflashallocation'] = flash_allocation

        allocation_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/CONFIGURATOR'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, allocation_json, self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            return True

    def set_raid_plan(self, option):
        error_rtn = False
        error_message = 'Set raid plan fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=maximizeresilience&value=' + option
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            return True

    def get_vms_by_volume(self):
        all_node_info = self.get_all_node_info()
        volume_info = all_node_info['volume_info']
        #get vms list on volume storage.
        obj_temp_dict = {}
        for volume in volume_info.keys():
            volume_uuid = volume_info[volume]['uuid']
            cmd = 'curl -k -X GET https://' + self.amc_ip + ':8443/usxmanager/vmm/vms/' + volume_uuid + '  -H "Cookie: JSESSIONID=' + self.cookies + '"'
            obj_rtn = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            obj_temp_dict[volume] = obj_rtn

        obj_rtn.wait()

        volume_vm_dict = {}
        for volume, obj_rtn_temp in obj_temp_dict.items():
            vm_list = []
            rtn_temp = obj_rtn_temp.stdout.read()
            vms = json.loads(rtn_temp)
            for vm in vms:
                vm_list.append(vm["vmname"])

            volume_vm_dict[volume] = vm_list

        return volume_vm_dict

    def get_vms_by_volume_uuid(self, volume_uuid, ret_vmuuid=False):
        API_URL = "https://" + self.amc_ip + ':8443/usxmanager/vmm/vms/' + volume_uuid
        req_type = 'GET'
        vm_list = []
        vm_uuid_list = []
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        if rtn == False:
            obj_log.debug("Get vm from volume failed")
            return False
        else:
            vms = json.loads(rtn)
            for vm in vms:
                vm_list.append(vm["vmname"])
                vm_uuid_list.append(vm["uuid"])
        obj_log.info("vm_list:%s , volume_uuid:%s" % (vm_list, volume_uuid))
        return vm_list if not ret_vmuuid else vm_uuid_list

    def get_onetimekey(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usxmanager/usxm/onetimekey'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            return rtn

    def join_amc_cluster_onetimekey(self, main_amc_ip, onetimekey):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/grid/member/join?ipaddress=' + main_amc_ip + '&port=5701&otk=' + onetimekey + '&multicast=false'
        obj_log.debug(API_URL)
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        obj_log.debug(rtn)
        if "successfully" in rtn or rtn == 'true':
            return True
        else:
            return False

    def join_amc_cluster(self, main_amc_ip):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/grid/member/join?ipaddress=' + main_amc_ip + '&port=5701&multicast=false'
        obj_log.debug(API_URL)
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        obj_log.debug(rtn)
        if "successfully" in rtn or rtn == 'true':
            return True
        else:
            return False

    def get_all_name_temp(self):
        error_message = 'get all name template fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/nametemplates?sortby=uuid&order=ascend'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            rtn_dict_tmp = json.loads(rtn)
            rtn_dict = {}
            rtn_dict['volume'] = None
            rtn_dict['sv'] = None
            rtn_dict['fastclone'] = None
            for item in rtn_dict_tmp['items']:
                if 'Default' in item['uuid']:
                    continue
                if item['componenttype'] == 'VOLUME':
                    rtn_dict['volume'] = item['uuid']
                elif item['componenttype'] == 'SERVICE_VM':
                    rtn_dict['sv'] = item['uuid']
                elif item['componenttype'] == 'VOLUME_SERVICE':
                    rtn_dict['volumeservice'] = item['uuid']
                elif item['componenttype'] == 'FASTCLONE':
                    rtn_dict['fastclone'] = item['uuid']

            return rtn_dict

    def delete_all_name_temp(self):
        item_uuid = []
        all_name_temp_cmd = 'curl -k -X GET https://' + self.amc_ip + ':8443/usxmanager/configurator/nametemplates?sortby=uuid&order=ascend -H "Content-Type:application/json" -H "Cookie: JSESSIONID=' + self.cookies + '"'
        obj_rtn = subprocess.Popen(all_name_temp_cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        rtn = obj_rtn.stdout.read()
        temp = eval(rtn)
        for item in temp["items"]:
            if item["componenttype"] == "FASTCLONE" and item["templatename"] != "Default-FASTCLONE" :
                item_uuid.append(item["uuid"])
                uuid = item["uuid"].replace('#','%23')
                delete_name_temp_cmd = 'curl -k -X DELETE https://' + self.amc_ip + ':8443/usxmanager/configurator/nametemplates/' + uuid + ' -H "Content-Type:application/json" -H "Cookie: JSESSIONID=' + self.cookies + '"'
                obj_rtn = subprocess.Popen(delete_name_temp_cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                rtn = obj_rtn.stdout.read()

    def set_reservation(self, reservation):
        error_message = 'Set reservation fail.'

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=reservation&value=' + reservation
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            return True

    def set_multicastip(self, multicastip):
        error_message = 'Set multicastip fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=multicastip&value=' + multicastip
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            return True

    def set_sharedstorageforvmdisk(self, option):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=prefersharedstorageforvmdisk&value=' + option

        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == 'true':
            return True
        else:
            return False

    def set_sharedstorageforvolume(self, option):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=prefersharedstorageforexport&value=' + option

        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        
        if rtn == 'true':
            return True
        else:
            return False

    def extend_volume(self, volume_resourcename, volumesize):
        error_message = 'Extend volume fail.'

        volume_resourcename_uuid_dict = self.get_resource_volume_uuid()

        if volume_resourcename not in volume_resourcename_uuid_dict.keys():
            obj_log.debug('Volume is not exist.')
            return False

        volume_uuid = volume_resourcename_uuid_dict[volume_resourcename]

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/volume/' + volume_uuid + '/extend?volumesize=' + str(volumesize)

        req_type = 'POST'

        rtn_tmp = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn_tmp == False:
            obj_log.debug(error_message)
            return False
        else:
            rtn_dict_tmp = json.loads(rtn_tmp)
            while True:
                rtn = self.get_job_status(rtn_dict_tmp['jobrefid'])
                obj_log.debug(rtn[-1])
                time.sleep(10)
                if 'Complete' in rtn[-1]:
                    return True
                elif 'Failed' in rtn [-1]:
                    obj_log.debug(rtn)
                    return False

    def replace_sv(self, hypervisor):
        all_hypervisors_uuid = self.get_all_hypervisors_uuid()
        
        error_message = 'Replace serivce vm fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/deploy/hypervisor/replace/' + all_hypervisors_uuid[hypervisor]
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        if rtn == False:
            obj_log.error(error_message)
            return False
        else:
            obj_log.info('Replace svm successful.')
            return True

    def set_hypervisorlayout(self, hypervisor_num):
        error_rtn = False
        error_message = 'Set hypervisorlayout fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/RECOMMENDER?entry=hypervisorlayoutsforvolume&value=' + str(hypervisor_num)
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.debug(error_message)
            return error_rtn
        else:
            return rtn

    def conf_hypervisors(self, vcs, platform):
        vm_managers = self.get_vmmanagername()
        all_hypervisors_uuid = self.get_all_hypervisors_uuid()

        error_message = 'Conf hypervisors fail.'
        hypervisors_weight = '5'
        temp_list = []

        if platform != 'XEN':
            for vc_ip in vcs.keys():
                for items in vcs[vc_ip]['dcs'].values():
                    for item in items:
                        for host_ip in item['hosts'].keys():
                            temp_dict = {}
                            temp_dict['vmmanagername'] = vm_managers[vc_ip]
                            temp_dict['hypervisoruuid'] = all_hypervisors_uuid[host_ip]
                            temp_dict['weight'] = hypervisors_weight
                            temp_dict['clustertagname'] = item['clustername']
                            temp_list.append(temp_dict)
        
        hypervisors_json = json.dumps(temp_list, indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/hypervisorprofiles/batch'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=hypervisors_json, cookies=self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            return True
    
    def conf_site_group(self, vcs):
        site_tag_uuid_dict = self.get_site_tag_uuid()
        hypervisorprofile_uuid_dict = self.get_hypervisorprofile_uuid()
        vm_managers = self.get_vmmanagername()
        all_hypervisors_uuid = self.get_all_hypervisors_uuid()
        
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/hypervisorprofiles/batch'
        req_type = 'PUT'
        
        temp_list = []
        hypervisors_weight = '5'
        
        for vc_ip in vcs.keys():
            for items in vcs[vc_ip]['dcs'].values():
                for item in items:
                    host_list = item['hosts'].keys()
                    host_num = len(host_list)
                    half_num = host_num/2
                    i = 0
                    for site_tag_uuid in site_tag_uuid_dict.values():
                        for j in range(half_num):
                            host_ip = host_list[i]
                            temp_dict = {}
                            temp_dict['vmmanagername'] = vm_managers[vc_ip]
                            temp_dict['hypervisoruuid'] = all_hypervisors_uuid[host_ip]
                            temp_dict['weight'] = hypervisors_weight
                            temp_dict['clustertagname'] = item['clustername']
                            temp_dict['uuid'] = hypervisorprofile_uuid_dict[host_ip]
                            temp_dict['taguuids'] = []
                            temp_dict['taguuids'].append(site_tag_uuid)
                            temp_list.append(temp_dict)
                            i = i + 1
                    break
                break
            break
        
        site_group_json = json.dumps(temp_list, indent=4)
        
        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=site_group_json, cookies=self.cookies)

        if rtn == False:
            return False
        else:
            return rtn

    def delete_hypervisors_profiles(self):
        hypervisorprofileuuids = self.get_hypervisorprofile_uuid()
        if len(hypervisorprofileuuids.values()) < 1:
            obj_log.debug("No hypervisors profiles to delete from USX")
            return True
        else:
            hypervisorprofileuuids_json = json.dumps(hypervisorprofileuuids.values())
            API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/hypervisorprofiles/batch'
            req_type = "DELETE"

            rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=hypervisorprofileuuids_json, cookies=self.cookies)
            if rtn is False:
                return False
            rtn_list = json.loads(rtn)
            obj_log.debug(rtn_list)
            for result_dict in rtn_list:
                if result_dict["status"] is not True:
                    obj_log.error("delete {0} failed error message {1}".format(result_dict['uuid'], result_dict['message']))
                    return False
                else:
                    obj_log.info("delete {0} succeed message {1}".format(result_dict['uuid'], result_dict['message']))
            return True

    def delete_storage_profiles(self):
        storage_profiles_uuid = self.get_storageprofile_uuid()
        if len(storage_profiles_uuid) < 1:
            obj_log.debug("No storage profiles to delete from USX")
            return True
        storageprofilesuuids_json = json.dumps(storage_profiles_uuid)
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/storageprofiles/batch'
        req_type = "DELETE"

        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=storageprofilesuuids_json, cookies=self.cookies)
        if rtn is False:
            return False
        rtn_list = json.loads(rtn)
        obj_log.debug(rtn_list)
        for result_dict in rtn_list:
            if result_dict["status"] is not True:
                obj_log.error("delete {0} failed error message {1}".format(result_dict['uuid'], result_dict['message']))
                return False
            else:
                obj_log.info("delete {0} succeed message {1}".format(result_dict['uuid'], result_dict['message']))
        return True

    def conf_storage(self, vcs, disk_allocation, flash_allocation, platform):
        vm_managers = self.get_vmmanagername()
        all_datastore_uuid = self.get_all_datastore_uuid()

        error_message = 'Conf storage fail.'
        disk_maxallocation = disk_allocation
        flash_maxallocation = flash_allocation
        datastore_weight = '5'
        temp_list = []

        if platform != 'XEN':
            for vc_ip in vcs.keys():
                for items in vcs[vc_ip]['dcs'].values():
                    for item in items:
                        for host_ip, datastores in item['hosts'].items():
                            if datastores['disk'] != []:
                                for disk_ds in datastores['disk']:
                                    temp_dict = {}
                                    temp_dict['vmmanagername'] = vm_managers[vc_ip]
                                    temp_dict['maxallocation'] = disk_maxallocation
                                    temp_dict['weight'] = datastore_weight
                                    temp_dict['datastoreuuid'] = all_datastore_uuid[disk_ds]
                                    temp_dict['datastorename'] = disk_ds
                                    temp_dict['ssd'] = 'false'
                                    temp_list.append(temp_dict)
                            if datastores['ssd'] != []:
                                for ssd_ds in datastores['ssd']:
                                    temp_dict = {}
                                    temp_dict['vmmanagername'] = vm_managers[vc_ip]
                                    temp_dict['maxallocation'] = flash_maxallocation
                                    temp_dict['weight'] = datastore_weight
                                    temp_dict['datastoreuuid'] = all_datastore_uuid[ssd_ds]
                                    temp_dict['datastorename'] = ssd_ds
                                    temp_dict['ssd'] = 'true'
                                    temp_list.append(temp_dict)

                if vcs[vc_ip]['sharestorages']['disk'] != []:
                    for share_disk in vcs[vc_ip]['sharestorages']['disk']:
                        temp_dict = {}
                        temp_dict['vmmanagername'] = vm_managers[vc_ip]
                        temp_dict['maxallocation'] = disk_maxallocation
                        temp_dict['weight'] = datastore_weight
                        temp_dict['datastoreuuid'] = all_datastore_uuid[share_disk]
                        temp_dict['datastorename'] = share_disk
                        temp_dict['ssd'] = 'false'
                        temp_list.append(temp_dict)

                if vcs[vc_ip]['sharestorages']['ssd'] != []:
                    for share_ssd in vcs[vc_ip]['sharestorages']['ssd']:
                        temp_dict = {}
                        temp_dict['vmmanagername'] = vm_managers[vc_ip]
                        temp_dict['maxallocation'] = flash_maxallocation
                        temp_dict['weight'] = datastore_weight
                        temp_dict['datastoreuuid'] = all_datastore_uuid[share_ssd]
                        temp_dict['datastorename'] = share_ssd
                        temp_dict['ssd'] = 'true'
                        temp_list.append(temp_dict)

        datastore_json = json.dumps(temp_list,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/storageprofiles/batch'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=datastore_json, cookies=self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            return True

    def conf_network(self, vcs, ip_range):
        json_list = []
        temp_dict = {}

        config_single_network = False
        tmp_ip_range = ip_range.split('-')
        tmp_ip_list = tmp_ip_range[:2]

        if len(tmp_ip_range) == 2:
            managenetwork_mode = 'static'
            storagenetwork_mode = 'static'
        elif tmp_ip_range[-1] == 'mdhcp':
            managenetwork_mode = 'dhcp'
            storagenetwork_mode = 'static'
        elif tmp_ip_range[-1] == 'sdhcp':
            managenetwork_mode = 'static'
            storagenetwork_mode = 'dhcp'
        elif tmp_ip_range[-1] == 'dhcp':
            managenetwork_mode = 'dhcp'
            storagenetwork_mode = 'dhcp'
        elif tmp_ip_range[-1] == 'single':
            storagenetwork_mode = 'static'
            config_single_network = True

        network_dict = {}
        if not config_single_network:
            network_dict['managenetwork'] = {}
        network_dict['storagenetwork'] = {}

        for vc_ip in vcs.keys():
            gateway = vcs[vc_ip]['gateway']
            tmp_list = gateway.split('.')
            if not config_single_network:
                managenetwork = 'managenetwork-' + tmp_list[1]
                network_dict['managenetwork'][gateway] = managenetwork
            storagenetwork = 'storagenetwork-' + tmp_list[1]
            network_dict['storagenetwork'][gateway] = storagenetwork

        for networktype, item in network_dict.items():
            for gateway, networkname in item.items():
                temp_list = gateway.split('.')
                temp_dict['networkprofilename'] = networkname
                temp_dict['defaultnetworkname'] = networkname
                if networktype == 'managenetwork':
                    ip_segment = temp_list[0] + '.' + temp_list[1]
                    temp_dict['storagenetwork'] = 'false'

                    if tmp_ip_range[-1] == 'mdhcp' or tmp_ip_range[-1] == 'dhcp':
                        temp_dict['gateway'] = None
                        temp_dict['mode'] = 'dhcp'
                        temp_dict['netmask'] = None

                        temp_dict['ipranges'] = []                
                        temp_dict['ipranges'].append('-')

                    else:
                        temp_dict['gateway'] = gateway
                        temp_dict['mode'] = managenetwork_mode
                        temp_dict['netmask'] = '255.255.0.0'

                        ip_start = ip_segment + '.' + tmp_ip_list[0]
                        ip_end = ip_segment + '.' + tmp_ip_list[1]
                        complete_ip_range = ip_start + '-' + ip_end
                        temp_dict['ipranges'] = []         
                        temp_dict['ipranges'].append(complete_ip_range)
                elif not config_single_network:
                    ip_segment = temp_list[0] + '.1' + temp_list[1]
                    temp_dict['storagenetwork'] = 'true'
                    temp_dict['gateway'] = '0.0.0.0'
                    temp_dict['mode'] = storagenetwork_mode
                    temp_dict['netmask'] = '255.255.0.0'

                    ip_start = ip_segment + '.' + tmp_ip_list[0]
                    ip_end = ip_segment + '.' + tmp_ip_list[1]
                    complete_ip_range = ip_start + '-' + ip_end
                    temp_dict['ipranges'] = []                
                    temp_dict['ipranges'].append(complete_ip_range)

                elif config_single_network:
                    ip_segment = temp_list[0] + '.' + temp_list[1]
                    temp_dict['storagenetwork'] = 'true'
                    temp_dict['gateway'] = gateway
                    temp_dict['mode'] = storagenetwork_mode
                    temp_dict['netmask'] = '255.255.0.0'

                    ip_start = ip_segment + '.' + tmp_ip_list[0]
                    ip_end = ip_segment + '.' + tmp_ip_list[1]
                    complete_ip_range = ip_start + '-' + ip_end
                    temp_dict['ipranges'] = []                
                    temp_dict['ipranges'].append(complete_ip_range)

                obj_log.debug('temp dict is : %s' % temp_dict)
                network_json = json.dumps(temp_dict, indent=4)
                json_list.append(network_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/networkprofiles'
        req_type = 'POST'

        rtn_dict = obj_multi.multi_call_reset_api(API_URL, req_type, json_list, cookies=self.cookies)
        if rtn_dict['stderr'] != []:
            return False
        else:
            for conf_network_rtn in rtn_dict['stdout']:
                if 'uuid' not in conf_network_rtn:
                    obj_log.debug('conf_network_rtn', conf_network_rtn)
                    return False

        return network_dict

    def conf_network_mapping(self, vcs, platform, network_dict):
        json_list = []
        temp_list = []
        vm_managers = self.get_vmmanagername()
        all_hypervisors_uuid = self.get_all_hypervisors_uuid()

        networkprofile_uuid_dict = self.get_networkprofile_uuid()

        network_uuid_dict = {}

        for networktype, gateway_networkname_dict in network_dict.items():
            network_uuid_dict[networktype] = {}
            for gateway, networkname in gateway_networkname_dict.items():
                network_uuid = networkprofile_uuid_dict[networktype][networkname]
                network_uuid_dict[networktype][gateway] = network_uuid

        if platform != 'XEN':

            for networktype, gateway_networkuuid_dict in network_uuid_dict.items():
                for gateway, network_uuid in gateway_networkuuid_dict.items():
                    for vc_ip in vcs.keys():
                        vc_gateway = vcs[vc_ip]['gateway']

                        if vc_gateway != gateway:
                            continue

                        for datacenter, item_list in vcs[vc_ip]['dcs'].items():
                            for items in item_list:
                                for host_ip, host_info in items['hosts'].items():
                                    temp_dict = {}
                                    temp_dict['vmmanagername'] = vm_managers[vc_ip]
                                    temp_dict['hypervisoruuid'] = all_hypervisors_uuid[host_ip]
                                    temp_dict['networkprofileuuid'] = network_uuid
                                    if networktype == 'managenetwork':
                                        temp_dict['networkname'] = host_info['network']['1g']
                                    else:
                                        temp_dict['networkname'] = host_info['network']['10g']

                                    temp_list.append(temp_dict)

            netwrok_mapping_json = json.dumps(temp_list,indent=4)
            json_list.append(netwrok_mapping_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/networkprofiles/mapping/batch'
        req_type = 'POST'

        rtn_dict = obj_multi.multi_call_reset_api(API_URL, req_type, json_list, cookies=self.cookies)
        if len(rtn_dict['stderr']) == 0:
            return True
        else:
            obj_log.debug(rtn_dict['stderr'])
            return False

    def get_snapclone_enable_status(self, vol_res_uuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/inventory/volume/resources/" + vol_res_uuid + "?composite=false"
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        obj_log.debug(API_URL)
        rtn_dict = json.loads(rtn)
        status = rtn_dict["data"].get("snapcloneenabled", None)
        if status is not None:
            return status
        else:
            obj_log.error(rtn_dict["data"]["metrics"])
            return None

    def get_snapclone_activate_status(self, vol_res_uuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/inventory/volume/resources/" + vol_res_uuid + "?composite=false"
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        obj_log.debug(API_URL)
        rtn_dict = json.loads(rtn)
        status = rtn_dict["data"].get("snapcloneactivated", None)
        if status is not None:
            return status
        else:
            obj_log.error(rtn_dict["data"]["metrics"])
            return None


    def snapclone_ratio_size(self):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/settings/RECOMMENDER"
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        obj_log.debug(API_URL)
        rtn_dict = json.loads(rtn)
        snapclone_size = rtn_dict["snapclonesizeratio"]
        if snapclone_size is not False:
            return snapclone_size
        else:
            obj_log.error(rtn_dict)
            return False


    def delete_network_profile(self, network_uuid):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/networkprofiles/' + network_uuid
        req_type = 'DELETE'
        rtn = obj_utils.call_rest_api(API_URL, req_type, self.cookies)
        # rtn_dict = json.loads(rtn)
        # obj_log.debug(rtn_dict)
        obj_log.debug(API_URL)
        if rtn == 'true':
            return True
        else:
            obj_log.error(rtn)
            return False

    def create_servicevm_template(self, username, testbed_name):
        error_message = 'Create servicevm template fail.'

        temp_dict = {}
        temp_dict['templatename'] = 'SV'
        temp_dict['componenttype'] = 'SERVICE_VM'

        temp_dict['elements'] = []
        tmp1 = username + '-' + temp_dict['templatename'] + '-' + testbed_name + '-'
        temp_dict['elements'].append(tmp1)
        tmp_dict = {}
        tmp_dict['startingnumber'] = 1
        tmp_dict['numberofdigits'] = 3
        temp_dict['elements'].append(tmp_dict)
        tmp2 = ''
        temp_dict['elements'].append(tmp2)

        name_template_json = json.dumps(temp_dict,indent=4)
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/nametemplates'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, name_template_json, self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            if 'uuid' not in rtn:
                obj_log.debug(rtn)
                return False

            return True

    def create_volume_template(self, username, testbed_name):
        error_message = 'Create Volume template fail.'

        temp_dict = {}
        temp_dict['templatename'] = 'VOLUME'
        temp_dict['componenttype'] = 'VOLUME'

        temp_dict['elements'] = []
        tmp1 = username + '-' + temp_dict['templatename'] + '-' + testbed_name + '-'
        temp_dict['elements'].append(tmp1)
        tmp_dict = {}
        tmp_dict['startingnumber'] = 1
        tmp_dict['numberofdigits'] = 3
        temp_dict['elements'].append(tmp_dict)
        tmp2 = ''
        temp_dict['elements'].append(tmp2)

        name_template_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/nametemplates'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, name_template_json, self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            if 'uuid' not in rtn:
                obj_log.debug(rtn)
                return False

            return True

    def create_volume_service_template(self, username, testbed_name):
        error_message = 'Create Volume Service template fail.'

        temp_dict = {}
        temp_dict['templatename'] = 'VOLUMESERVICE'
        temp_dict['componenttype'] = 'VOLUME_SERVICE'

        temp_dict['elements'] = []
        tmp1 = username + '-' + temp_dict['templatename'] + '-' + testbed_name + '-'
        temp_dict['elements'].append(tmp1)
        tmp_dict = {}
        tmp_dict['startingnumber'] = 1
        tmp_dict['numberofdigits'] = 3
        temp_dict['elements'].append(tmp_dict)
        tmp2 = ''
        temp_dict['elements'].append(tmp2)

        name_template_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/nametemplates'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, name_template_json, self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            if 'uuid' not in rtn:
                obj_log.debug(rtn)
                return False

            return True

    def delete_all_jobstatus(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/model/jobstatus'
        req_type = 'DELETE'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        if rtn == 'true':
            return True
        else:
            return False

    def get_job_status(self, jobrefid):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/jobstatus/inventory?sortby=starttimestamp&order=descend&page=0&pagesize=100'
        req_type = 'GET'
        task_list = []
         
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            obj_log.debug('Get job status fail.')
            return False
        else:
            rtn_dict = json.loads(rtn)
            for job_status_info in rtn_dict['items']:
                if job_status_info.has_key('jobrefid') == True:
                    if job_status_info['jobrefid'] == jobrefid:
                        # if job_status_info.has_key('message') == True:
                        #     task_list.append(job_status_info['message'])
                        if job_status_info.has_key('tasks'):
                            if job_status_info['tasks'][-1].has_key('message'):
                                task_list.append(job_status_info['tasks'][-1]['message'])
             
            return task_list

    # warning just get the newest message
    # uuid can be resource or container uuid
    def get_jobid_by_string(self, key_string, uuid=None):
        if uuid is None:
            API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/jobstatus/inventory?sortby=starttimestamp&order=descend&page=0&pagesize=100'
        else:
            API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/jobstatus/inventory?query=usxuuid%3A' + uuid + '&sortby=starttimestamp&order=descend&page=0&pagesize=100'
        req_type = 'GET'
 
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            obj_log.debug('Get job status fail.')
            return False
        else:
            rtn_dict = json.loads(rtn)
            for job_status_info in rtn_dict['items']:
                # if job_status_info.has_key('jobrefid') == True:     # 3.6.0.654 the REST API change amc_ip has changed there is no jobreid in jobstatus
                if job_status_info.has_key('message'):
                    if key_string in job_status_info['message']:
                        obj_log.info(job_status_info['message'])
                        if job_status_info.has_key('jobrefid') == True:
                            return job_status_info['jobrefid']
                        else:
                            return True
                    else:
                        obj_log.warning(job_status_info['message'])
                        break

        return False

    def retry_to_check_jobstatus_msg(self, msg, uuid=None, retry_num=200):
        tms = retry_num
        while tms:
            jobid = self.get_jobid_by_string(msg, uuid)
            if jobid:
                obj_log.info("get message[%s] jobid ===> %s" % (msg, jobid))
                return True
            else:
                tms -= 1
                obj_log.info("sleep 5s")
                time.sleep(5)
                if tms == 0:
                    obj_log.error("get msg[%s] failed with timeout" % msg)
                    return False

    def get_usx_status(self, uuid):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/status/all?sortby=usxuuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'

        status_dict = {}

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            obj_log.debug('Get usx status fail.')
            return False
        else:
            rtn_dict = json.loads(rtn)
            for status_info in rtn_dict['items']:
                if status_info.has_key('usxuuid') == True:
                    if status_info['usxuuid'] == uuid:
                        if status_info['usxstatuslist']:
                            for item in status_info['usxstatuslist']:
                                status_dict[item['name']] = item['value']
                            return status_dict

        return False


    def get_networkprofile_uuid(self):
        networkprofile_uuid_dict = {}
        networkprofile_uuid_dict['storagenetwork'] = {}
        networkprofile_uuid_dict['managenetwork'] = {}

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/networkprofiles?sortby=uuid&order=ascend'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        rtn_dict_tmp = json.loads(rtn)


        for item in rtn_dict_tmp['items']:
            if item['storagenetwork'] == True:
                networkprofile_uuid_dict['storagenetwork'][item['networkprofilename']] = item['uuid']
            else:
                networkprofile_uuid_dict['managenetwork'][item['networkprofilename']] = item['uuid']

        return networkprofile_uuid_dict

    def get_networkprofile_config(self):
        '''
        networkprofile_config_dict = {"storagenetwork":{"networkname":"", "netmask":"", "gateway":""}, "managenetwork":{"networkname":"", "netmask":"", "gateway":""}}
        '''

        networkprofile_config_dict = {}
        networkprofile_config_dict['storagenetwork'] = {}
        networkprofile_config_dict['managenetwork'] = {}

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/networkprofiles?sortby=uuid&order=ascend'
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        rtn_dict_tmp = json.loads(rtn)


        for item in rtn_dict_tmp['items']:
            if item['storagenetwork'] == True:
                networkprofile_config_dict['storagenetwork']["networkname"] = item['networkprofilename']
                networkprofile_config_dict['storagenetwork']["netmask"] = item["netmask"]
                networkprofile_config_dict['storagenetwork']["gateway"] = item["gateway"]
            else:
                networkprofile_config_dict['managenetwork']["networkname"] = item['networkprofilename']
                networkprofile_config_dict['managenetwork']["netmask"] = item["netmask"]
                networkprofile_config_dict['managenetwork']["gateway"] = item["gateway"]

        return networkprofile_config_dict

    def get_infrastructure_name(self, clustername):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/deploy/infrastructurevolume/' + clustername
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        if rtn == False:
            return False
        else:
            return rtn

    def deploy_infrastructure(self, username, testbed_name, clustername, usx_version,stretch_cluster='false',robo='false'):
        error_message = 'Deploy infrastructure fail.'

        time_flag_tmp = str(time.time())
        time_flag = time_flag_tmp.split('.')[0]

        all_name_temp_dict = self.get_all_name_temp()
        volumenametemplateuuid = all_name_temp_dict['volume']
        servicevmnametemplateuuid = all_name_temp_dict['sv']

        networkprofile_uuid_dict = self.get_networkprofile_uuid()
        storagenetworkname_list = networkprofile_uuid_dict['storagenetwork'].keys()
        managenetworkname_list = networkprofile_uuid_dict['managenetwork'].keys()

        for managenetworkname in managenetworkname_list:
            tmp_manage_list = managenetworkname.split('-')
            tmp1 = tmp_manage_list[1]
            for storagenetworkname in storagenetworkname_list:
                tmp_storage_list = storagenetworkname.split('-')
                tmp2 = tmp_storage_list[1]
                if tmp2 == tmp1:
                    managernetwork_uuid = networkprofile_uuid_dict['managenetwork'][managenetworkname]
                    storagenetwork_uuid = networkprofile_uuid_dict['storagenetwork'][storagenetworkname]
                    break

            break

        temp_dict={}
        temp_dict['servicevmnametemplateuuid'] = servicevmnametemplateuuid
        temp_dict['storagenetworkprofileuuid'] = storagenetwork_uuid
        temp_dict['managementnetworkprofileuuid'] = managernetwork_uuid
        temp_dict['infrastructurevolume'] = 'true'
        temp_dict['attributes'] = {}
        temp_dict['attributes']['exporttype'] = 'NFS'

        if usx_version != '2.2.0' and usx_version != '2.1':
            temp_dict['volumename'] = username + '-Infra-' + testbed_name + '-' + time_flag
            temp_dict['volumeservicename'] = username + '-Infra-Ser-' + testbed_name + '-' + time_flag
            cluster_uuid_dict = self.get_cluster_uuid()
            temp_dict['attributes']['clustertaguuid'] = cluster_uuid_dict[clustername]
            if usx_version == '2.2.2':
                temp_dict['prefersharedstorageforexports'] = 'false'
            elif usx_version in ['3.0.1', '3.1.0', '3.1.1', '3.1.2', '3.2.0']:
                temp_dict['attributes']['volumehavmname'] = username + '-Infra-HA-' + testbed_name + '-' + time_flag
                temp_dict['snapshotenabled'] = 'true'
            if usx_version in ['3.1.0', '3.1.1', '3.1.2', '3.2.0']:
                if stretch_cluster == 'true':
                    temp_dict['attributes']['stretchcluster'] = stretch_cluster
                if usx_version in ['3.1.2', '3.2.0']:
                    temp_dict['raid1enabled'] = robo
            
        else:
            infrastructurename = self.get_infrastructure_name(clustername)
            temp_dict['volumename'] = infrastructurename
            temp_dict['volumetype'] = 'HYBRID'
            temp_dict['fastsync'] = 'false'
            temp_dict['directio'] = 'false'
            temp_dict['hybridratio'] = '15'
            temp_dict['prefersharedstorageforexports'] = 'false'
            temp_dict['attributes']['preferflashforcapacity'] = 'false'
            temp_dict['attributes']['preferflashformemory'] = 'false'
            temp_dict['clustertagname'] = clustername

        volume_json = json.dumps(temp_dict,indent=4)
        obj_log.debug(volume_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/volume/autodeploy'
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, volume_json, cookies=self.cookies)

        if rtn == False:
            obj_log.debug(error_message)
            return False
        else:
            rtn_dict = json.loads(rtn)
            jobrefid = rtn_dict['jobrefid']
            flag = 1
            while True:
                task_list_tmp = self.get_job_status(jobrefid)
                if task_list_tmp == [] or task_list_tmp == False:
                    continue
                
                obj_log.debug(task_list_tmp)

                for task_tmp in task_list_tmp:
                    if 'Configured HA resources' in task_tmp:
                        return True

                time.sleep(5)
                flag = flag + 1

                if flag == 540:
                    obj_log.debug('Deploy USX Node time out.')
                    return False

    def deploy_volume(self,username,testbed_name,volumetype,volumesize,hyperconverge_cluster=None,hyperconvergedvolume=None,only_infrastructure='false',\
        sharestorageforvmdisk='false',directio='false',exporttype='NFS',hybridratio='15',fastsync='false',prefersharedstorageforexports='false',\
        preferflashforcapacity='false',preferflashformemory='false',usx_version='3.6.0',snapshot='true',stretch_cluster='false', robo='false', \
        enable_snapclone='true', exportfstype='dedup',fs_sync='false',raidtype='RAID_5'):
        temp_dict={}
        time_flag_tmp = str(time.time())
        time_flag = time_flag_tmp.split('.')[0]

        all_name_temp_dict = self.get_all_name_temp()
        servicevmnametemplateuuid = all_name_temp_dict['sv']
        if usx_version >= '3.0.1':
            volumeservicenametemplateuuid = all_name_temp_dict['volumeservice']

        if usx_version != '2.1':
            volumenametemplateuuid = all_name_temp_dict['volume']
            temp_dict['volumenametemplateuuid'] = volumenametemplateuuid

        networkprofile_uuid_dict = self.get_networkprofile_uuid()

        storagenetworkname_list = networkprofile_uuid_dict['storagenetwork'].keys()
        managenetworkname_list = networkprofile_uuid_dict['managenetwork'].keys()

        for storagenetworkname in storagenetworkname_list:
            tmp_storage_list = storagenetworkname.split('-')
            tmp1 = tmp_storage_list[1]
            # Single network managenetworkname_list is []
            if not managenetworkname_list:
                managernetwork_uuid = None
                storagenetwork_uuid = networkprofile_uuid_dict['storagenetwork'][storagenetworkname]
                break

            for managenetworkname in managenetworkname_list:
                tmp_manage_list = managenetworkname.split('-')
                tmp2 = tmp_manage_list[1]
                if tmp2 == tmp1:
                    managernetwork_uuid = networkprofile_uuid_dict['managenetwork'][managenetworkname]
                    storagenetwork_uuid = networkprofile_uuid_dict['storagenetwork'][storagenetworkname]
                    break

            break

        rtn = self.set_sharedstorageforvmdisk(sharestorageforvmdisk)

        error_message = 'Deploy Volume fail.'

        temp_dict['volumesize'] = volumesize
        temp_dict['managementnetworkprofileuuid'] = managernetwork_uuid
        temp_dict['storagenetworkprofileuuid'] = storagenetwork_uuid
        temp_dict['attributes'] = {}
        temp_dict['attributes']['exporttype'] = exporttype
        if temp_dict['attributes']['exporttype'] == 'iSCSI':
            temp_dict['iscsiexportsize'] = 250         #raidy++

        if usx_version >= '3.6.0':
            temp_dict['attributes']['exportfstype'] = exportfstype
            temp_dict['attributes']['fs_sync'] = fs_sync

        if hyperconvergedvolume != None:
            volume_num_dict = self.get_volume_num()
            infrastructure_num = volume_num_dict['infrastructure']
            cluster_uuid_dict = self.get_cluster_uuid()
            cluster_uuid = cluster_uuid_dict[hyperconverge_cluster]

            if infrastructure_num == 0:
                deploy_infra_rtn = self.deploy_infrastructure(username, testbed_name, hyperconverge_cluster, usx_version, stretch_cluster=stretch_cluster, robo=robo)
                if deploy_infra_rtn == False:
                    obj_log.debug(deploy_infra_rtn)
                    return False
                else:
                    time.sleep(5)

                if only_infrastructure == 'true':
                    return True

            temp_dict['attributes']['hyperconvergedvolume'] = hyperconvergedvolume
            if usx_version != '2.2.0' and usx_version != '2.1':
                temp_dict['attributes']['clustertaguuid'] = cluster_uuid
            else:
                volumetype = 'HYBRID'
                temp_dict['clustertagname'] = hyperconverge_cluster

        temp_dict['volumetype'] = volumetype

        if 'MEMORY' in volumetype:
            temp_dict['attributes']['preferflashformemory'] = 'false'
        else:
            temp_dict['prefersharedstorageforexports'] = prefersharedstorageforexports
            # for 3.2.x sharestorage setting in preferences
            # self.set_sharedstorageforvolume(prefersharedstorageforexports)  # raidy ++ 2016-3-25 17:39:07

        if 'HYBRID' in volumetype:
            if 'SIMPLE' not in volumetype:
                temp_dict['fastsync'] = fastsync
            else:
                temp_dict['fastsync'] = 'false'

            temp_dict['hybridratio'] = hybridratio
            temp_dict['attributes']['preferflashforcapacity'] = preferflashforcapacity
            temp_dict['attributes']['preferflashformemory'] = preferflashformemory

        if usx_version >= '3.0.0':
            temp_dict['vvol'] = 'false'
            temp_dict['snapshotenabled'] = 'true'
            temp_dict['attributes']['enablesnapshot'] = snapshot

        if 'SIMPLE' in volumetype:
            temp_dict['directio'] = 'false'
            API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/volume/batchdeploy'
            if volumetype == "SIMPLE_MEMORY":
                temp_dict["attributes"]["snapcloneenabled"] = enable_snapclone
                temp_dict["attributes"]["snapclonediskprovisioningtype"] = "THIN"
                temp_dict["attributes"]["snapcloneactivated"] = enable_snapclone

        else:
            if usx_version >= '3.1.0':
                if stretch_cluster == 'true':
                    temp_dict['attributes']['stretchcluster'] = stretch_cluster
                if usx_version >= '3.1.2':
                    temp_dict['raid1enabled'] = robo

                if usx_version >= '3.6.0':
                    temp_dict['raidtype'] = raidtype
                    if raidtype == 'RAID_1':
                        temp_dict['raid1enabled'] = 'true'
                
            temp_dict['servicevmnametemplateuuid'] = servicevmnametemplateuuid
            temp_dict['directio'] = directio
            API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/volume/autodeploy'

        if usx_version == '2.1' or usx_version == '2.2.0':
            if hyperconvergedvolume == None:
                temp_dict['volumename'] = username + '-' + volumetype + '-' + testbed_name + '-' + time_flag
            else:
                temp_dict['volumename'] = username + '-HyperCon-' + testbed_name + '-' + time_flag
        else:
            if hyperconvergedvolume == None:
                if 'SIMPLE' in volumetype and usx_version >= '3.0.1':
                    temp_dict['volumeservicenametemplateuuid'] = volumeservicenametemplateuuid
                else:
                    temp_dict['volumeservicename'] = username + '-' + volumetype + '-' + testbed_name + '-' + time_flag
            else:
                temp_dict['volumeservicename'] = username + '-HyperCon-' + testbed_name + '-' + time_flag

        volume_json = json.dumps(temp_dict,indent=4)
        obj_log.debug(volume_json)

        req_type = 'POST'

        for _ in range(3):
            rtn = obj_utils.call_rest_api(API_URL, req_type, volume_json, cookies=self.cookies)

            if rtn == False:
                obj_log.debug(error_message)
                return False
            else:
                rtn_dict = json.loads(rtn)
                jobrefid = rtn_dict['jobrefid']
                retry_flag = False
                flag = 540
                while flag:
                    task_list_tmp = self.get_job_status(jobrefid)
                    if task_list_tmp == [] or task_list_tmp == False:
                        continue

                    obj_log.debug(task_list_tmp)
                    for task_tmp in task_list_tmp:
                        if 'Successfully configured bootstrap for USX node with role VOLUME' in task_tmp or 'Successfully performed bootstrap configure for USX Node with role=VOLUME' in task_tmp:
                            return True
                        elif 'Aborted Bootstrap' in task_tmp:
                            return False
                        elif 'com.vmware.vim25.ManagedObjectNotFound' in task_tmp:
                            obj_log.warning("com.vmware.vim25.ManagedObjectNotFound")
                            retry_flag = True   # retry deploy when there is vim25 error
                            break
                        elif 'no hypervisor configured for USX' in task_tmp:
                            obj_log.warning('no hypervisor configured for USX')
                            retry_flag = True   # sometimes AMC is not ready after reboot retry it
                            break
                        elif 'exception happened when deploying vm' in task_tmp:
                            obj_log.warning('exception happened when deploying vm')
                            retry_flag = True   # retry if exception happened
                            break
                        elif 'Generate Plan Failed' in task_tmp:
                            return False

                    time.sleep(5)
                    if retry_flag:
                        obj_utils.progressbar_k(60)
                        break
                    flag = flag - 1

                    if flag == 0:
                        obj_log.debug('Deploy USX Node time out.')
                        return False
        return False
    
    def get_amc_name(self):
        pass
    
    def deploy_tiebreaker(self, all_config, tiebreaker_ip=None):
        username = all_config['user']
        testbed_name = all_config['testbed_name']
        vcs = all_config['vcs']
        if tiebreaker_ip is None:
            tiebreaker_ip = all_config['tiebreaker_ip']

        time_flag_tmp = str(time.time())
        time_flag = time_flag_tmp.split('.')[0]
        vmmanager_name_dict = self.get_vmmanagername()
        vc_ip = vcs.keys()[0]
        gateway = vcs[vc_ip]['gateway']
        datacenter = vcs[vc_ip]['dcs'].keys()[0]
        hosts = vcs[vc_ip]['dcs'][datacenter][0]['hosts']
        host = hosts.keys()[0]
        datastore = hosts[host]['disk'][0]
        
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/witnessvm'
        req_type = 'POST'
        
        temp_dict= {}
        
        temp_dict['vmmanagername'] = vmmanager_name_dict[vc_ip]
        temp_dict['hypervisor'] = host
        temp_dict['usxvm'] = {}
        temp_dict['usxvm']['usxname'] = username + '-Tiebreaker-' + testbed_name + '-' + time_flag
        temp_dict['usxvm']['datastorename'] = datastore
        temp_dict['network'] = []
        temp_dict1 = {}
        temp_dict1['netmask'] = '255.255.0.0'
        temp_dict1['gateway'] = gateway
        temp_dict1['ipaddress'] = tiebreaker_ip
        temp_dict['network'].append(temp_dict1)
        
        tiebreaker_json = json.dumps(temp_dict,indent=4)
        obj_log.debug(tiebreaker_json)

        rtn = obj_utils.call_rest_api(API_URL, req_type, tiebreaker_json, cookies=self.cookies)
        
        if 'Successfully deployed' in rtn:
            rtn_dict = json.loads(rtn)
            obj_log.debug(rtn_dict['messages'])
            return True
        else:
            obj_log.debug(rtn)
            return False
        
    def get_site_tag_uuid(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/tags?sortby=uuid&order=ascend'
        
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        
        site_tag_uuid_dict = {}
        
        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            if item['tagtype'] == 'USX_SITE':
                site_tag_uuid_dict[item['tagname']] = item['uuid']
                
        return site_tag_uuid_dict
    
    def get_hypervisorprofile_uuid(self):
        all_hypervisors_uuid = obj_utils.invert_dict(self.get_all_hypervisors_uuid())
        
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/hypervisorprofiles?sortby=uuid&order=ascend'
        
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        
        hypervisorprofile_uuid_dict = {}
        
        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            hypervisorprofile_uuid_dict[all_hypervisors_uuid[item['hypervisoruuid']]] = item['uuid']
                
        return hypervisorprofile_uuid_dict

    def get_site_host_dict(self):
        side_tag_uuid = self.get_site_tag_uuid()
        all_hypervisors_uuid = obj_utils.invert_dict(self.get_all_hypervisors_uuid())

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/hypervisorprofiles?sortby=uuid&order=ascend'
        
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        
        site_host_dict = {}

        rtn_dict = json.loads(rtn)
        for side_tag in side_tag_uuid:
            site_host_dict[side_tag] = []
            for item in rtn_dict['items']:
                if side_tag_uuid[side_tag] == item['taguuids'][1]:
                    site_host_dict[side_tag].append(all_hypervisors_uuid[item['hypervisoruuid']])

        return site_host_dict

    def get_storageprofile_uuid(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/configurator/storageprofiles?sortby=uuid&order=ascend'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        storageprofile_uuid_list = []
        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            storageprofile_uuid_list.append(item['uuid'])
        return storageprofile_uuid_list

    # ==========================================Rest API for Snapshot & Replicaition==========================================
    def set_snapshot(self, option):
        error_message = 'Set snapshot in preferences fail.'
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/settings/DEPLOYMENT?entry=enablesnapshot&value=' + option
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)

        if rtn == False:
            obj_log.error(error_message)
            return False
        else:
            if rtn == 'true':
                obj_log.info("set snapshot %s done" % option)
                return True
            else:
                return False

    def create_snapshot(self, snapshotname, volume_resource_name):
        error_message = 'create_snapshot <' + volume_resource_name + '> fail.'
        volume_resource_dict = self.get_resource_volume_uuid()
        temp_dict={}
        temp_dict['snapshotname'] = snapshotname
        temp_dict['volumeresourceuuid'] = volume_resource_dict[volume_resource_name]
        snapshot_json = json.dumps(temp_dict, indent=4)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/dataservice/snapshot/'
        req_type = 'POST'
        rtn = obj_utils.call_rest_api(API_URL, req_type, snapshot_json, cookies=self.cookies)

        if rtn == False:
            return False
        else:
            rtn_dict = json.loads(rtn)

            obj_log.info(rtn_dict['msg'])
            jobrefid = rtn_dict['jobrefid']
            flag = 1
            while jobrefid:
                task_list_tmp = self.get_job_status(jobrefid)
                if not task_list_tmp:
                    if flag != 30:
                        flag += 1
                        time.sleep(5)
                        continue
                    else:
                        obj_log.error("There is no task info, Please Check")
                        break
                obj_log.debug(task_list_tmp)

                if 'Successfully created snapshot' in task_list_tmp:
                    return True       # 3.5.1 build
                elif 'Successfully create snapshot' in task_list_tmp:
                    return True       # 3.5.0 build and before
                elif 'Failed to created snapshot' in task_list_tmp:
                    obj_log.error(task_list_tmp)
                    return False
                elif 'Failed to create snapshot' in task_list_tmp:
                    obj_log.error(task_list_tmp)
                    return False
                else:
                    obj_log.debug("wait for 5 second")
                    time.sleep(5)
                    flag = flag + 1

                if flag == 200:
                    obj_log.debug('Create snapshot time out.')
                    return False
            obj_log.error("No jobrefid, Task not submit, Please Check!!")
            return False


    def get_all_snapshot_info(self):

        volume_resource_dict = self.get_resource_volume_uuid()
        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/usx/dataservice/snapshots?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
    
        rtn_dict = json.loads(rtn)
        all_snapshot_info = {}
        for volume in volume_resource_dict:
            i = 1
            all_snapshot_info[volume] = {}    
            for item in rtn_dict['items']:
                if volume_resource_dict[volume] == item['volumeresourceuuid']:
                    all_snapshot_info[volume]['snap' + str(i)] = {}
                    all_snapshot_info[volume]['snap' + str(i)]['ctime'] = item['ctime']
                    all_snapshot_info[volume]['snap' + str(i)]['uuid'] = item['uuid']
                    all_snapshot_info[volume]['snap' + str(i)]['name'] = item['snapshotname']
                    if item.has_key('mountedpoint') and item['mountedpoint'] != '':
                        all_snapshot_info[volume]['snap' + str(i)]['mountedpoint'] = item['mountedpoint']
                    else:
                        all_snapshot_info[volume]['snap' + str(i)]['mountedpoint'] = None
                    i = i + 1
        return all_snapshot_info

    def snapshot_ratio(self, ratio=0):
        URL = "https://" + self.amc_ip + ":8443/usxmanager/settings/RECOMMENDER"
        API_URL = URL if not ratio else URL + "?entry=snapshotsizeratio&value=" + str(ratio)
        req_type = "GET" if not ratio else "PUT"

        error_message = "" if not ratio%5 and ratio/5 in range(4,11) else "ratio available!!"
        if not ratio and not error_message:
            obj_log.error(error_message)
            return False

        if ratio:
            rtn = obj_utils.call_rest_api(API_URL, req_type,header=False, cookies=self.cookies)
            if rtn == False:
                obj_log.debug(error_message)
                return error_rtn
            else:
                return True if rtn=='true' else False
        else:
            rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
            response = json.loads(rtn)
            return response["snapshotsizeratio"]

    def export_snapshot(self, snapshot_uuid):

        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/usx/dataservice/snapshots/export/' + snapshot_uuid
        req_type = 'PUT'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            obj_log.error("export snapshot fail")
            return False
        else:
            rtn_dict = json.loads(rtn)
            if 'Failed' in rtn_dict['msg']:
                obj_log.error(rtn_dict['msg'])
                return False
            else:
                obj_log.info(rtn_dict['msg'])
                jobrefid = rtn_dict['jobrefid']
                flag = 1
                while True:
                    task_list_tmp = self.get_job_status(jobrefid)
                    if task_list_tmp == [] or task_list_tmp == False:
                        continue
                    
                    obj_log.debug(task_list_tmp)

                    if 'Successfully exported snapshot' in task_list_tmp:
                        return True
                    elif 'Successfully export snapshot' in task_list_tmp:
                        return True
                    else:
                        obj_log.debug("wait for 5 second")
                        time.sleep(5)
                        flag = flag + 1

                    if flag == 540:
                        obj_log.debug('export snapshot time out.')
                        return False

    def unexport_snapshot(self, snapshot_uuid):
 
        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/usx/dataservice/snapshots/unexport/' + snapshot_uuid
        req_type = 'PUT'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            obj_log.error("unexport snapshot fail")
            return False
        else:
            rtn_dict = json.loads(rtn)
            obj_log.debug(rtn_dict)

            if 'successfully' in rtn_dict['msg']:
                obj_log.info(rtn_dict['msg'])
                return True
            else:
                obj_log.error(rtn_dict['msg'])
                return False
                
    def delete_snapshot(self, volume_resource_name, snapshot_uuid_list):
        volume_resource_dict = self.get_resource_volume_uuid()
        delete_snapshot_json = json.dumps(snapshot_uuid_list, indent=4)

        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/usx/dataservice/volume/resource/snapshots/' + volume_resource_dict[volume_resource_name]
        req_type = 'DELETE'
        rtn = obj_utils.call_rest_api(API_URL, req_type, delete_snapshot_json, cookies=self.cookies)
        rtn_dict = json.loads(rtn)
        obj_log.debug(rtn_dict)
        obj_log.debug(API_URL)
        if "successfully" in rtn_dict['msg']:
            obj_log.info(rtn_dict['msg'])
            return True
        else:
            obj_log.error(rtn)
            return False

    def rollback_snapshot(self, snapshot_uuid):

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usx/dataservice/snapshots/rollback/' + snapshot_uuid
        req_type = 'PUT'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        else:
            rtn_dict = json.loads(rtn)
            if 'Failed' in rtn_dict['msg']:
                obj_log.error(rtn_dict['msg'])
                return False
            else:
                obj_log.info(rtn_dict['msg'])
                jobrefid = rtn_dict['jobrefid']
                flag = 1
                while True:
                    task_list_tmp = self.get_job_status(jobrefid)
                    if task_list_tmp == [] or task_list_tmp == False:
                        continue
                    
                    obj_log.debug(task_list_tmp)

                    if 'Successfully rolled back snapshot' in task_list_tmp:
                        return True
                    else:
                        obj_log.debug("wait for 5 second")
                        time.sleep(5)
                        flag = flag + 1

                    if flag == 200:
                        obj_log.debug('rollback snapshot time out.')
                        return False


    def modify_schedule_snapclone(self, volres_uuid, schedule):
        obj_log.info("enter modify snapclone schedule")
        policy_uuid = self.get_snapclone_policy_uuid(volres_uuid)
        if not policy_uuid:
            return False
        temp_dict = {}
        temp_dict['volumeresourceuuid'] = volres_uuid
        temp_dict['schedule'] = schedule
        schedule_json = json.dumps(temp_dict,indent=4)

        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/policies/dataservices/snapclone/' + policy_uuid
        req_type = "PUT"
        rtn = obj_utils.call_rest_api(API_URL, req_type, schedule_json, cookies=self.cookies)
        if rtn:
            return self.enable_snapclone(volres_uuid)
        else:
            obj_log.error("modify snapclone schedule failed:%s" % rtn)
            return False


    def enable_snapclone(self, volres_uuid):
        obj_log.info("enter enable_snapclone")
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/dataservice/snapclone/" + volres_uuid + "/enable"
        req_type = "PUT"
        rtn = obj_utils.call_rest_api(API_URL, req_type, header=False, cookies=self.cookies)
        rtn_dict =json.loads(rtn)
        if "Snapclone has been activated successfully" in rtn_dict["msg"]:
            return True
        else:
            return False

    def disable_snapclone(self, volres_uuid):
        obj_log.info("enter disable_snapclone")
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/dataservice/snapclone/" + volres_uuid + "/disable"
        req_type = "PUT"
        rtn = obj_utils.call_rest_api(API_URL, req_type, header=False, cookies=self.cookies)
        
        rtn_dict =json.loads(rtn)
        if "Snapclone has been deactivated successfully" in rtn_dict["msg"]:
            return True
        else:
            return False


    def create_schedule_snapshot(self, volume_resource_name, schedule, maxsnapshot=3, req_type='POST'):
        volume_resource_dict = self.get_resource_volume_uuid()

        temp_dict = {}
        temp_dict['maxsnapshot'] = maxsnapshot
        temp_dict['schedule'] = schedule
        temp_dict['volumeresourceuuid'] = volume_resource_dict[volume_resource_name]
        schedule_json = json.dumps(temp_dict,indent=4)


        API_URL = 'https://' + self.amc_ip +':8443/usxmanager/policies/dataservices/snapshots/volume?format=json'
        req_type = req_type
        rtn = obj_utils.call_rest_api(API_URL, req_type, schedule_json, cookies=self.cookies)

        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)
        obj_log.debug(rtn_dict)
        if rtn_dict['active'] == True:
            obj_log.info(rtn_dict['schedule'])
            return True
        else:
            obj_log.error(rtn_dict)
            return False

    def schedule_replication(self, schedule, volume_resource_name, target_volume_ip, target_volume_name, req_type='POST', get_err_msg=False):
        volume_resource_dict = self.get_resource_volume_uuid()
        resource_volume_uuid = volume_resource_dict[volume_resource_name]

        temp_dict = {}
        temp_dict['schedule'] = schedule
        temp_dict['targetvolumeip'] = target_volume_ip
        temp_dict['targetvolumename'] = target_volume_name
        temp_dict['volumeresourceuuid'] = resource_volume_uuid
        replication_json = json.dumps(temp_dict, indent=4)
        obj_log.debug(replication_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/policies/dataservices/replication/volume?format=json'
        req_type = req_type
        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=replication_json, cookies=self.cookies, get_err_msg=get_err_msg)
        if get_err_msg == True:
            return rtn

        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)

        if rtn_dict['active'] == True:
            obj_log.info(rtn_dict['schedule'])
            return True
        else:
            obj_log.error(rtn_dict)
            return False

    def failover_volume(self, volume_resource_uuid, volume_container_uuid):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/workflows/volume/failover'
        req_type = 'POST'
        temp_dict = {}
        temp_dict['list'] = [volume_container_uuid]
        failover_json = json.dumps(temp_dict, indent=4)
        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=failover_json, cookies=self.cookies)

        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)
        obj_log.warning(rtn_dict)
        for msg in rtn_dict["messages"]:
            if "Successfully reboot USX" in msg:
                tms = 50
                while tms:
                    jobid = self.get_jobid_by_string("Volume completed failover", volume_resource_uuid)
                    if jobid:
                        obj_log.info("get jobid ===> %s" % jobid)
                        obj_log.info("Failover by failover button successfully")
                        return True
                    else:
                        tms -= 1
                        obj_utils.progressbar_k(10)
                        if tms == 0:
                            obj_log.error("Failover by failover button time out")
                            return False
        return False



    def have_replication_policy(self, volume_uuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/policies/dataservices/replication?sortby=uuid&order=ascend"
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        rtn_dict_tmp = json.loads(rtn)
        obj_log.info(rtn_dict_tmp)
        if rtn_dict_tmp.has_key("items"):
            for policy in rtn_dict_tmp["items"]:
                if policy["metadata"]["volumeresourceuuid"] == volume_uuid:
                    return True
        else:
            return False


    def replication_now(self, vol_res_uuid, target_volume_name, target_ip):
        data_dict = {}
        data_dict["volumeresourceuuid"] = vol_res_uuid
        data_dict["targetvolumename"] = target_volume_name
        data_dict["targetvolumeip"] = target_ip

        data_json = json.dumps(data_dict)
        url = "https://" + self.amc_ip + ":8443/usxmanager/usx/dataservice/replica"
        rtn_dict = obj_utils.call_rest_api(url, req_type="POST", obj_json = data_json, cookies=self.cookies)
        if (rtn_dict == False):
            return False

        rtn_dict = json.loads(rtn_dict)
        jobrefid = rtn_dict["jobrefid"]
        retry_count = 0
        while(retry_count < 50):
            message_list = self.get_job_status(jobrefid)
            for message in message_list:
                if "Successfully replicated volume" in message:
                    obj_log.info("Successfully replicated volume")
                    return True
            time.sleep(10)
            retry_count += 1
            obj_log.info("chechk replication status: %d times" % retry_count)
        return False

    def get_usx_uuid(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usxmanager?sortby=usxuuid&order=ascend&page=0&pagesize=100'
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
       
        usx_uuid_dict = {}
       
        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            usx_uuid_dict[item['ipaddress']] = item['uuid']
        obj_log.info(usx_uuid_dict)
        return usx_uuid_dict

    def change_usx_ip(self, new_ip=None, netmask=None, gateway=None, dhcp=False, dns=None):
        usx_uuid_dict = self.get_usx_uuid()
        usx_uuid = usx_uuid_dict[self.amc_ip]
        temp_dict = {}
        temp_dict['uuid'] = usx_uuid
        temp_dict['vmNetwork'] = ""
        if new_ip is not None:
            temp_dict['ip'] = new_ip
            obj_log.info("USX ip will change " + self.amc_ip + " ===>" + new_ip)
        else:
            temp_dict['ip'] = ""
        if netmask is not None:
            temp_dict['netmask'] = netmask
        else:
            temp_dict['netmask'] = ""
        if netmask is not None:
            temp_dict['gateway'] = gateway
        else:
            temp_dict['gateway'] = ""
        if dns is not None:
            temp_dict['dns'] = dns
        else:
            temp_dict['dns'] = ""
        if dhcp is True:
            temp_dict['dhcp'] = 'true'
            obj_log.info("USX ip will change " + self.amc_ip + " ===> DHCP")
        else:
            temp_dict['dhcp'] = 'false'
        change_usx_ip_json = json.dumps(temp_dict, indent=4)
        obj_log.debug(change_usx_ip_json)

        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/usxmanager/changeip?format=json'
        req_type = 'POST'
        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=change_usx_ip_json, cookies=self.cookies, get_err_msg=True, timeout=20)
        obj_log.debug(rtn)
        return rtn

    def change_volume_manage_ip(self, container_uuid, ip, netmask="", gateway="", old_manage_ip="", old_storage_ip="", power_cycle=False):
        '''
            old_storage_config = {"network_ip":"", "gateway":"", "netmask":"", "power_cycle":False};
        '''
        network_config_dict = self.get_networkprofile_config()  # network_config_dict = {"storagenetwork":{"networkname":"", "netmask":"", "gateway":""}, "managenetwork":{"networkname":"", "netmask":"", "gateway":""}}
        manage_network = ""
        storage_network = ""

        if not netmask:
            netmask = network_config_dict["managenetwork"]["netmask"]
        if not gateway:
            gateway = network_config_dict["managenetwork"]["gateway"]

        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/vmm/vms/changeips"
        req_type = "POST"
        data_dict = {
            "type": "volume_container",
            "uuid": container_uuid,
            "oldManagementIP": old_manage_ip,
            "oldStorageIP": old_storage_ip,
            "enablePowerCycle":power_cycle,
            "nics":[{"type":"storage","ip":old_storage_ip,"netmask":network_config_dict["storagenetwork"]["netmask"],"gateway":"","vmnetwork":network_config_dict["storagenetwork"]["networkname"]},
                    {"type":"management","ip":ip,"netmask":netmask,"gateway":gateway,"vmnetwork":network_config_dict["managenetwork"]["networkname"]}]
            }

        data_json = json.dumps(data_dict, indent=4)
        rtn_dict = obj_utils.call_rest_api(API_URL, req_type, obj_json=data_json, cookies=self.cookies)
        if (rtn_dict == False):
            return False
        else:
            obj_log.info("wait for 2min to finish")
            if self.retry_to_check_jobstatus_msg("Successfully changed IP address.") is False:
                return False
            retry_num = 120
            while(retry_num):
                if obj_utils.is_reachable(ip):
                    cmd = "cat /etc/network/interfaces"
                    rtn_dict = obj_utils.ssh_cmd(ip, "poweruser", "poweruser", cmd)
                    if rtn_dict['error'] != None or rtn_dict['stderr'] != '':
                        if "refused" in rtn_dict['error']:
                            retry_num -= 1
                            time.sleep(2)
                            continue
                        print "execute {} with error {}".format(cmd, rtn_dict['error'])
                        return False
                    else:
                        info = rtn_dict["stdout"]
                        obj_log.debug("check ip info:%s" % info)
                        if netmask in info:
                            return True
                        else:
                            return False
                else:
                    obj_log.debug("retry times:%d times" % (120-retry_num))
                    retry_num -= 1
                    time.sleep(2)
            obj_log.error("%s is not reachable" % ip)
            return False


    def change_volume_storage_ip(self, container_uuid, ip, netmask="", gateway="", old_manage_ip="", old_storage_ip="", power_cycle=False):
        '''
            old_manage_config = {"n
            etwork_ip":"", "gateway":"", "netmask":"", "power_cycle":False};
        '''
        network_config_dict = self.get_networkprofile_config()  # network_config_dict = {"storagenetwork":{"networkname":"", "netmask":"", "gateway":""}, "managenetwork":{"networkname":"", "netmask":"", "gateway":""}}
        if not netmask:
            netmask = network_config_dict["storagenetwork"]["netmask"]
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/vmm/vms/changeips"
        req_type = "POST"
        data_dict = {
            "type": "volume_container",
            "uuid": container_uuid,
            "oldManagementIP": old_manage_ip,
            "oldStorageIP": old_storage_ip,
            "enablePowerCycle":power_cycle,
            "nics":[{"type":"storage","ip":ip,"netmask":netmask,"gateway":"","vmnetwork":network_config_dict["storagenetwork"]["networkname"]},
                    {"type":"management","ip":old_manage_ip,"netmask":network_config_dict["managenetwork"]["netmask"],"gateway":network_config_dict["managenetwork"]["gateway"],"vmnetwork":network_config_dict["managenetwork"]["networkname"]}]
            }

        data_json = json.dumps(data_dict, indent=4)
        rtn_dict = obj_utils.call_rest_api(API_URL, req_type, obj_json=data_json, cookies=self.cookies)
        if (rtn_dict == False):
            return False
        else:
            obj_log.info("wait for 2min to finish")
            if self.retry_to_check_jobstatus_msg("Successfully changed IP address.") is False:
                return False
            retry_num = 120
            while(retry_num):
                if obj_utils.is_reachable(ip):
                    cmd = "cat /etc/network/interfaces"
                    rtn_dict = obj_utils.ssh_cmd(ip, "poweruser", "poweruser", cmd)
                    if rtn_dict['error'] != None or rtn_dict['stderr'] != '':
                        print "execute {} error".format(cmd)
                        return False
                    else:
                        info = rtn_dict["stdout"]
                        obj_log.debug("check ip info:%s" % info)
                        if netmask in info:
                            return True
                        else:
                            return False
                else:
                    obj_log.debug("retry times:%d times" % (120-retry_num))
                    retry_num -= 1
            obj_log.error("%s is not reachable" % ip)
            return False


    def get_policy_uuid(self):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/upgrades/policies?sortby=uuid&order=ascend'
        
        req_type = 'GET'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        
        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            if item['policytype'] == 'patch_offline_policy':
                policy_uuid = item['uuid']
        return policy_uuid

    def get_snapclone_policy_uuid(self, volres_uuid):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/policies/dataservices/snapclone?sortby=uuid&order=ascend"
        req_type = 'GET'
        policy_uuid = None
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        for item in rtn_dict['items']:
            try:
                if item['metadata']['volumeresourceuuid'] == volres_uuid and item['policytype'] == 'snapclone_policy':
                    policy_uuid = item['uuid']
            except KeyError:
                pass
        if policy_uuid is None:
            return False
        return policy_uuid


    def enable_policy(self, policyuuid):
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/upgrades/policies/enable/' + policyuuid
        
        req_type = 'PUT'
        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn is False:
            obj_log.error('enable upgrade policy failed')
            return False
        return True

    def get_upgrade_by_log(self):
        get_log_cmd = "tail -1 /var/log/usxm-upgrade.log"
        while True:
            rtn_log = obj_utils.ssh_cmd(self.amc_ip, "admin","poweruser",get_log_cmd)['stdout']
            if "END UPGRADE PROCEDURE" in rtn_log:
                obj_log.info(rtn_log)
                return True
            elif "ERROR" in rtn_log:
                obj_log.warning(rtn_log)
                return False
            else:
                obj_log.info(rtn_log)
                time.sleep(30)


    def upgrade(self, upgradeZipPath):
        upgradeName = upgradeZipPath.split('/')[-1].strip()
        obj_log.debug(upgradeName)
        cmd_upload = "curl -k --form file=@/" + upgradeZipPath + \
            " --form masterUpload=true --form press=OK" + \
            " https://"+self.amc_ip+":8443/usxmanager/upgrades/patches/upload?api_key=" + self.cookies

        obj_log.info('Start upload ZIP file ...')
        obj_log.debug(cmd_upload)
        rtn_upload = obj_utils.run_cmd(cmd_upload)

        rtn_dict = json.loads(rtn_upload['stdout'])
        obj_log.debug(rtn_dict)
        obj_log.debug(rtn_dict["msg"])
        if 'Successfully' in rtn_dict["msg"]:
            obj_log.info('Upload ZIP file done ...')
        else:
            obj_log.error('Upload ZIP file failed')
            obj_log.error(rtn_upload['stdout'])
            return False


        obj_log.info('Start upgrade all node ...')
        policyuuid = self.get_policy_uuid()

        # enable policy
        self.enable_policy(policyuuid)
        # start update schedule now

        temp_dict = {'starttime': None,
                    'endtime': 0,
                    'scheduleformat': "SIMPLE",
                    'repeatcount': 1,
                    'repeatinterval': 1,
                    'cron': "",
                    'unit': "hours"}
        upgrade_json = json.dumps(temp_dict, indent=4)
        API_URL = 'https://' + self.amc_ip + ':8443/usxmanager/upgrades/policies/schedule/' + policyuuid
        req_type = 'POST'
        rtn = obj_utils.call_rest_api(API_URL, req_type, obj_json=upgrade_json, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        if 'scheduleformat' not in rtn_dict:
            return False
        # get task jobid by string
        for i in range(10):
            jobid = self.get_jobid_by_string("Started to unzip patch file")
            if jobid:
                obj_log.info("get jobid ===> %s" % jobid)
                break
            else:
                obj_utils.progressbar_k(10)
                if i == 9:
                    obj_log.warning('Get upgrade task job ID timeout ...')
        # delay for AMC upgrading
        obj_utils.progressbar_k(500)
        # Wait upgrade
        amc_version_split = os.path.basename(upgradeZipPath).split(".")
        amc_version_int = int(amc_version_split[0][-1] + amc_version_split[1] + amc_version_split[2])
        if amc_version_int >= 360:
            self.set_usxaccess('true')

        if not jobid:
            return self.get_upgrade_by_log()
        for i in range(5000):
            task_list_tmp = self.get_job_status(jobid)
            if task_list_tmp == [] or task_list_tmp is False:
                continue
            obj_log.debug(task_list_tmp)
            for task_tmp in task_list_tmp:
                if 'Finish upgrading from version' in task_tmp:
                    obj_log.info(task_tmp)
                    return True
                elif 'Failed' in task_list_tmp:
                    obj_log.error(task_list_tmp)
                    return False
                else:
                    time.sleep(10)
                    if i == 5000:
                        obj_log.error('Upgrade timeout...')
                        return False

        return True

    def delete_volume_and_ha(self):
        all_node_info = self.get_all_node_info()
        volume_info = all_node_info["volume_info"]
        ha_info = all_node_info["ha_info"]
        # obj_log.info("all_node_info:%s" % all_node_info)

        for volume in volume_info:
            uuid = volume_info[volume]["uuid"]
            url = "https://" + self.amc_ip + ":8443/usxmanager/usx/manage/volume/" + uuid + "?isresource=true&forcedelete=true"
            obj_utils.call_rest_api(url, req_type="DELETE", cookies=self.cookies, header=False)
        for ha in ha_info:
            uuid = ha_info[ha]["containeruuid"]
            url = "https://" + self.amc_ip + ":8443/usxmanager/usx/manage/volume/" + uuid + "?isresource=false&forcedelete=true"
            obj_utils.call_rest_api(url, req_type="DELETE", cookies=self.cookies, header=False)


    def delete_AMC_cluster(self):
        amc_uuid = None
        usx_dict = self.get_usx_uuid()
        for usx in usx_dict:
            if self.amc_ip != usx:
                amc_uuid = usx_dict[usx]

        # start to delete AMC cluster
        if amc_uuid is not None:
            API_URL = "https://" + self.amc_ip + ":8443/usxmanager/grid/member/delete/member?uuid=" + amc_uuid
            obj_log.info(API_URL)
            rtn = obj_utils.call_rest_api(API_URL, req_type="DELETE", cookies=self.cookies, header=False)
            if rtn == False:
                obj_log.error("delete secondray AMC cluster failed on %s" % rtn)
                return False
            if not self.retry_to_check_jobstatus_msg("Removed replication target"):
                return False
            obj_log.info("delete AMC cluster successful")
            return True
        else:
            return False


    def change_slave_amc_to_master(self, slave_amc_ip):
        API_URL = "https://" + slave_amc_ip + ":8443/usxmanager/usxmanager/master"
        req_type = 'PUT'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies, header=False)
        time.sleep(10)
        if rtn == False:
            obj_log.error('change slave amc to master <' + slave_amc_ip + '> fail.')
            return False
        else:
            obj_log.info("check amc whether is master or not?")
            time.sleep(60)
            return self.amc_is_master(slave_amc_ip)


    def amc_is_master(self, amc_ip):
        API_URL = "https://" + amc_ip + ":8443/usxmanager/usxmanager?sortby=usxuuid&order=ascend&page=0&pagesize=100"
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)
        if rtn_dict["count"] != 2:
            obj_log.error("AMC count %d is not correct" % rtn_dict["count"])
            return False

        amc_list = rtn_dict["items"]
        for amc in amc_list:
            if amc_ip == amc["ipaddress"]:
                return amc["isdbserver"] == True
        return False

    def create_snapclone(self, volres_uuid, get_return_msg=False):
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/usx/dataservice/snapclone/" + volres_uuid
        req_type = 'POST'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)

        if get_return_msg:
            return rtn_dict["msg"]

        if "Creating Snapclone command has been manually executed successfully" in rtn_dict["msg"]:
            return True
        else:
            time.sleep(10)
            if "successfully" in rtn_dict["msg"]:
                return True
            print "return rtn_dcit:{0}".format(rtn_dict)
            return False

    def pre_upgrade_check(self):
        # get uuid first
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/checks/upgrades/?sortby=uuid&order=ascend&page=0&pagesize=100&composite=false&refresh=false"
        req_type = 'GET'

        rtn = obj_utils.call_rest_api(API_URL, req_type, cookies=self.cookies)
        if rtn == False:
            return False
        rtn_dict = json.loads(rtn)
        items_list = rtn_dict["items"]
        uuid = items_list[0]["uuid"]
        data_json_format = {"uuid": uuid, "checks":
           [{"selected": True, "id": "SSH_RELATIONSHIP"},
            {"selected": True, "id": "MIGRATION"},
            {"selected": True, "id": "DISK_SPACE"},
            {"selected": True, "id": "VM_HEALTH"},
            {"selected": True, "id": "VM_REBOOT"}]}

        # settings
        API_URL = "https://" + self.amc_ip + ":8443/usxmanager/checks/upgrades/"
        req_type = "PUT"
        data_dump_json = json.dumps(data_json_format,indent=4)

        rtn = obj_utils.call_rest_api(API_URL, req_type, data_dump_json, cookies=self.cookies)
        if rtn == False:
            return False

        rtn_dict = json.loads(rtn)
        checks = rtn_dict["checks"]
        rtn_dict = {}
        for check_item in checks:
            rtn_dict[check_item["id"]] = check_item["result"]
        if "Failure" in rtn_dict.values():
            obj_log.error("pre upgrade check fail:{0}".format(rtn_dict))
            return False
        return True