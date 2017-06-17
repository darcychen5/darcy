import re
import time
import subprocess

QUEUE_PATH = '/var/tmp/queue.txt'
JSON_STATE_FILE_PATH = '/var/lib/rundeck/logs/rundeck/'
MAIL_PROCESS = '/root/tis33/Mail.py'
PROJECT_DICT = {'HA_AUTOMATION':
                {'Failover_Sanity': 'd84c543b-78f4-4646-81e2-9d1b9a849348'},
                'HA_SANITY_AUTOMATION':
                {'S0_SANITY_TEST': '558f4d9d-84f2-4d04-946a-f7d10f9935b7'},
                'HA_S1_AUTOMATION':
                {'USX-79716--Enable_HA_Ctitical': 'b3cff0b9-1a57-4fc3-a2c5-e7a0fdc3a21e'}
                }
EXECUTION_ID_JOB_DICT = {}


def run_cmd(cmd, timeout=600):
    rtn_dict = {}
    obj_rtn = subprocess.Popen(
        cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
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


def main():
    while True:
        print 'check the rd-queue of the node'
        for project in PROJECT_DICT:
            try:
                ret = run_cmd(
                    "/usr/bin/rd-queue -p %s | grep '\[*\]'" % project)
            except Exception as e:
                continue
            if ret['stdout'] != "":
                print ret['stdout']
                for job in ret['stdout'].strip().split('\n'):
                    m = re.search('\[(.*)\]\s(.*)\s', job)
                    execution_id = m.group(1)
                    jobname = m.group(2)
                    print execution_id
                    print jobname
                    if execution_id not in EXECUTION_ID_JOB_DICT:
                        EXECUTION_ID_JOB_DICT[execution_id] = jobname

            if EXECUTION_ID_JOB_DICT:
                for execution_id in EXECUTION_ID_JOB_DICT:
                    ret1 = run_cmd('find %s -name %s.state.json' %
                                   (JSON_STATE_FILE_PATH, execution_id))
                    if ret1['stdout'] != "":
                        jobname = EXECUTION_ID_JOB_DICT.pop(execution_id)
                        jsonlog = ret1['stdout'].strip()
                        print jsonlog
                        project_name = jsonlog.split('/')[6]
                        try:
                            print "Start send mail"
                            rtn = run_cmd('python %s -p %s -j %s -e %s -l %s' %
                                          (MAIL_PROCESS, project_name, jobname, execution_id, jsonlog))
                            print rtn
                        except Exception as e:
                            print "Exception %s" % e
                        break
        time.sleep(10)


if __name__ == '__main__':
    main()
