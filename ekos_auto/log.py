# 2016.12.14 02:45:55 EST
# Embedded file name: ./libs/atlas/log.py
import datetime
import sys
import os
LOG_FILENAME = "/var/log/ekos-automation.log"

def set_log_file(fname):
    global LOG_FILENAME
    LOG_FILENAME = fname


def debug(*args):
    msg = ' '.join([ str(x) for x in args ])
    FORMAT = '[%m-%d-%Y %H:%M:%S]'
    d = datetime.datetime.now().strftime(FORMAT)
    pid = os.getpid()
    message = '%s [%s]: %s' % (d, pid, msg)
    f = open(LOG_FILENAME, 'a')
    f.write('%s\n' % message)
    f.flush()
    f.close()


def info(*args):
    msg = ' '.join([ str(x) for x in args ])
    try:
        print msg
    except:
        pass


def error(*args):
    msg = ' '.join([ str(x) for x in args ])
    FORMAT = '[%m-%d-%Y %H:%M:%S]'
    d = datetime.datetime.now().strftime(FORMAT)
    pid = os.getpid()
    message = '%s [%s]: %s' % (d, pid, msg)
    try:
        print msg
    except:
        pass

    f = open(LOG_FILENAME, 'a')
    f.write('%s\n' % message)
    f.flush()
    f.close()


def warn(*args):
    msg = ' '.join([ str(x) for x in args ])
    FORMAT = '[%m-%d-%Y %H:%M:%S]'
    d = datetime.datetime.now().strftime(FORMAT)
    pid = os.getpid()
    message = '%s [%s]: %s' % (d, pid, msg)
    try:
        print msg
    except:
        pass

    f = open(LOG_FILENAME, 'a')
    f.write('%s\n' % message)
    f.flush()
    f.close()
# okay decompyling log.pyc 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2016.12.14 02:45:55 EST
