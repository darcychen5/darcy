#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      Raidy
#
# Created:     19/10/2016
# Copyright:   (c) Raidy 2016
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import requests


class Template(object):

    REPORT_TMPL = r"""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <title>HA Automation</title>
        <meta name="generator" content="HTMLTestRunner 0.8.2"/>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>

    <style type="text/css" media="screen">
    body        { font-family: verdana, arial, helvetica, sans-serif; font-size: 80%; }
    table       { font-size: 100%; }
    pre         { }

    /* -- heading ---------------------------------------------------------------------- */
    h1 {
        font-size: 16pt;
        color: gray;
    }
    .heading {
        margin-top: 0ex;
        margin-bottom: 1ex;
    }

    .heading .attribute {
        margin-top: 1ex;
        margin-bottom: 0;
    }

    .heading .description {
        margin-top: 4ex;
        margin-bottom: 2ex;
    }

    /* -- css div popup ------------------------------------------------------------------------ */
    a.popup_link {
    }

    a.popup_link:hover {
        color: red;
    }

    .popup_window {
        display: none;
        position: relative;
        left: 0px;
        top: 0px;
        /*border: solid #627173 1px; */
        padding: 10px;
        background-color: #E6E6D6;
        font-family: "Lucida Console", "Courier New", Courier, monospace;
        text-align: left;
        font-size: 8pt;
        width: 500px;
    }

    }
    /* -- report ------------------------------------------------------------------------ */
    #show_detail_line {
        margin-top: 3ex;
        margin-bottom: 1ex;
    }
    #result_table {
        width: 80%;
        border-collapse: collapse;
        border: 1px solid #777;
    }
    #header_row {
        font-weight: bold;
        color: white;
        background-color: #777;
    }
    #result_table td {
        border: 1px solid #777;
        padding: 2px;
    }
    #total_row  { font-weight: bold; }
    .passClass  { background-color: #6c6; }
    .failClass  { background-color: #c60; }
    .errorClass { background-color: #c00; }
    .passCase   { color: #6c6; }
    .failCase   { color: #c60; font-weight: bold; }
    .errorCase  { color: #c00; font-weight: bold; }
    .hiddenRow  { display: none; }
    .testcase   { margin-left: 2em; }


    /* -- ending ---------------------------------------------------------------------- */
    #ending {
    }

    </style>

    </head>
    <body>
    """

    HEAD_TMPL = """
    <div class='heading'>
    <h1>%(feature)s</h1>
    <p class='attribute'><strong>Start Time:</strong> %(starttime)s</p>
    <p class='attribute'><strong>Duration:</strong> %(duration)s</p>
    <p class='attribute'><strong>Build:</strong> %(build)s</p>
    <p class='attribute'><strong>Total:</strong> %(total)s</p>
    <p class='attribute'><strong>Passed:</strong> %(passed)s</p>
    <p class='attribute'><strong>Failed:</strong> %(failed)s</p>

    <p class='description'>Detail infomation as below</p>
    </div>

    <table id='result_table'>
    <colgroup>
    <col align='left' />
    <col align='right' />
    <col align='right' />
    <col align='right' />
    <col align='right' />
    <col align='right' />
    </colgroup>

    <tr id='header_row'>
        <td>Test case</td>
        <td>Pass</td>
        <td>Fail</td>
        <td>Duration</td>
        <td>Summary</td>
    </tr>

    %(table)s

    </table>
    <div id='ending'>&nbsp;</div>

    </body>
    </html>
    """

    TABEL_TMPL = """
    <tr id='total_row'>
        <td class={0}>{1}</td>
        <td>{2}</td>
        <td>{3}</td>
        <td>{4}</td>
        <td>{5}</td>
    </tr>
    """

    END_TMPL = """
    </table>
    <div id='ending'>&nbsp;</div>

    </body>
    </html>
    """

    @classmethod
    def add_table(cls, Testcase, Duration, Summary=None, Pass=None, Fail=None):
        if Pass is not None:
            Style = 'testcase'
        else:
            Style = 'errorCase'
        TABEL_NEW = cls.TABEL_TMPL.format(Style, Testcase, Pass, Fail, Duration, Summary)
        return TABEL_NEW


# ============================JIRA==================================
class JIRA(object):
    def __init__(self):
        self.url_api = 'http://10.15.2.93:8080/rest/api/2'
        self.headers = {'Content-type': 'application/json'}
        self.auth = ('tis7', 'P@ssword1')

    def getsummary(self, jiraID):
        url = self.url_api + '/issue/' + jiraID + '?fields=summary'
        r = requests.get(url, auth=self.auth, headers=self.headers)
        if r.status_code == 200:
            rtn = r.json()
            title = rtn['fields']['summary']
            return title
        return ""

    def searchbyjql(self, jql):
        url = self.url_api + '/search?'
        r = requests.get(url, auth=self.auth, headers=self.headers, params=jql)
        if r.status_code == 200:
            rtn = r.json()
            return rtn
        return False

    def getjiraIDbyjql(self, jql):
        # jql = {'jql': "'TC Template' ~ USX-10226 AND parent = USX-60949"}
        rtn = self.searchbyjql(jql)
        jiraID_list = []
        # the jiraID has project name, ps USX-1234
        if rtn is not False and 'issues' in rtn and len(rtn['issues']) > 0:
            try:
                for jira in rtn['issues']:
                    jiraID = jira['key']
                    jiraID_list.append(jiraID)
                return jiraID_list
                # print("Successfully get jira ID list {}".format(jiraID_list))
            except Exception as e:
                print(e)
                return False
        print('Error: Can not get the jiraID by {0}'.format(jql))
        return False

    def getTransitions(self, jiraID):
        url = self.url_api + '/issue/' + jiraID + '/transitions?transitionId'
        r = requests.get(url, auth=self.auth, headers=self.headers)
        if r.status_code == 200:
            rtn = r.json()
            return rtn
        return False

    def addcomment(self, jiraID, comment):
        url = self.url_api + '/issue/' + jiraID + '/comment'
        comment = {'body': comment}
        r = requests.post(url, auth=self.auth, headers=self.headers, json=comment)
        print comment
        print jiraID
        print r.status_code
        if r.status_code == 201:
            print("Add {0} comment <{1}> successfully".format(jiraID, comment['body']))
            return True
        else:
            print("Add comment failed")
            return False

    def getfiltername(self, filterID):
        url = url = self.url_api + '/filter/' + filterID
        r = requests.get(url, auth=self.auth, headers=self.headers)
        if r.status_code == 200:
            rtn = r.json()
            filtername = rtn['name']
            return filtername
        return ""

    def renamefilter(self, filterID, newname):
        url = self.url_api + '/filter/' + filterID
        rename_dict = {"name": newname}
        r = requests.put(url, auth=self.auth, headers=self.headers, json=rename_dict)
        if r.status_code == 200:
            print("Rename {0} filter name to {1}".format(filterID, newname))
            return True
        else:
            print("Rename filter name failed")
            return False

    def setsummary(self, jiraID, summary):
        url = self.url_api + '/issue/' + jiraID
        setsummary_dict = {"update": {"summary": [{"set": summary}]}}
        r = requests.put(url, auth=self.auth, headers=self.headers, json=setsummary_dict)
        if r.status_code == 204:
            print("Set {0} summary to <{1}> successfully".format(jiraID, summary))
            return True
        else:
            print("Set summary failed")
            return False

    def setstatus(self, jiraID, status):
        """
        Transitions name reference
        1. Pass
        2. Fail
        3. Run Again
        4. Reset Status
        5. Set to Open
        6. Start Test
        7. Pending
        8. Will Not Run
        9. Not Supported
        10. Blocked
        11. Clear Counts
        12. Set Version Tested
        """
        url = self.url_api + '/issue/' + jiraID + '/transitions?expand=transitions.fields'

        transitions = self.getTransitions(jiraID)
        transitions_list = transitions["transitions"] if "transitions" in transitions else []
        for status_items in transitions_list:
            if status in status_items["name"]:
                statusID = status_items["id"]
                break
        else:
            print("Can not set status to <{0}> in current status".format(status))
            return False

        transition_dict = {"transition":{"id": statusID}}
        r = requests.post(url, auth=self.auth, headers=self.headers, json=transition_dict)
        if r.status_code == 204:
            print("Set {0} status to <{1}> successfully!".format(jiraID, status))
            return True
        else:
            print("Set status failed")
            return True
