#!/usr/bin/python3

import requests
import json


class ZabbixApiJsonData:
    #   zabbix api data content

    def __init__(self, method, params, id, is_auth, auth):
        """参数：动作，数据，会话id，是否已认证, 身份识别码"""
        if is_auth is True:
            self.data = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": id,
                "auth": auth
            }
        elif is_auth is False or auth == '':
            # no auth
            self.data = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": id
            }
        else:
            print("is_auth state has not defined.")

    def Get_Content(self):
        Content = json.dumps(self.data)
        return Content

    def Is_Json(self, params):
        pass


class ZabbixApiConnector:
    # link to zabbix api
    def __init__(self, url, method, params, id, is_auth, auth=''):
        """参数：zabbix api url, 动作，数据，会话id，是否已认证，身份识别码"""

        data = ZabbixApiJsonData(method, params, id, is_auth,
                                 auth).Get_Content()
        self.response = json.loads(self.Send_Request(url, data).text)

    def Send_Request(self, url, data):
        headers = {'content-type': 'application/json-rpc'}
        r = requests.post(url, headers=headers, data=data)
        return r

    def Get_Result(self):
        # get result value
        if 'result' in self.response:
            return self.response['result']
        elif 'error' in self.response:
            return self.response['error']
        else:
            return 'zabbix api no response.'


class ZabbixApiWorkFlow:
    workflowid = 0
    joblist = []
    is_auth = False

    # zabbix api mission control
    def __init__(self, url, user, password):
        self.url = url
        auth_params = self.Create_Auth_Params(user, password)
        auth_result = ZabbixApiConnector(self.url, 'user.login', auth_params,
                                         self.workflowid,
                                         self.is_auth).Get_Result()
        if type(auth_result).__name__ == 'str':
            print('authentication success! ' + auth_result)
            self.is_auth = True
            self.auth = auth_result
        else:
            print('authentication failed! ' + str(auth_result))

    def Create_Auth_Params(self, user, password):
        # input zabbix frontend user and password for authentication.
        auth_params = {"user": user, "password": password}
        return auth_params

    def Run_Job(self):
        if self.is_auth:
            for i in range(len(self.joblist)):
                self.workflowid += 1
                print(self.joblist[i])  # test
                result = ZabbixApiConnector(self.url,
                                            self.joblist[i]['method'],
                                            self.joblist[i]['params'],
                                            self.workflowid, self.is_auth,
                                            self.auth).Get_Result()
                print(result)
        else:
            print("no auth yet.")

    def Add_Job(self, jobdata):
        # add job into joblist
        self.joblist.append(jobdata)


def job_List_Hosts():
    jobdata = {}
    jobdata['method'] = 'host.get'
    jobdata['params'] = {
        "output": ["hostid", "host"],
    }
    return jobdata


def job_List_Host_BY_Name(hostname):
    jobdata = {}
    jobdata['method'] = "host.get"
    jobdata['params'] = {
        "output": ["hostid", "name"],
        "selectGroups": ["groupid", "name"],
        "selectInterfaces": ["interfaceid", "ip"],
        "filter": {
            "host": [hostname]
        }
    }
    return jobdata


def job_List_Groups():
    jobdata = {}
    jobdata["method"] = "hostgroup.get"
    jobdata["params"] = {"output": ["groupid", "name"]}
    return jobdata


def job_List_Group_By_Name(group):
    jobdata = {}
    jobdata["method"] = "hostgroup.get"
    jobdata["params"] = {
        "output": ["groupid", "name"],
        "filter": {
            "name": group
        }
    }
    return jobdata


def job_List_Template_By_Name(template):
    jobdata = {}
    jobdata["method"] = "template.get"
    jobdata["params"] = {
        "output": ["templateid", "host"],
        "filter": {
            "host": template
        }
    }
    return jobdata


def job_Add_Host(host, interfaces, groups, templates, name=""):
    """参数：主机名称，Interfaces，群组，模板，可见名称"""
    jobdata = {}
    jobdata['method'] = 'host.create'
    jobdata['params'] = {
        "host": host,
        "name": name,
        "interfaces": interfaces,
        "groups": groups,
        "templates": templates,
    }
    return jobdata


def create_Interfaces_Params(typeid, mainid, useip, ip, dns, port):
    """
    typeid: 1-agent,2-SNMP,3-IPMI,4-JMX
    mainid: 0-not default,1-default
    useip: 0-usedns,1-useip
    """

    interfaces = [{
        "type": typeid,
        "main": mainid,
        "useip": useip,
        "ip": ip,
        "dns": dns,
        "port": port
    }]
    return interfaces


def create_Groups_Params(*groupid):
    """参数可变，可加入多个字符串格式群组id"""
    groups = []
    for gid in groupid:
        g = {"groupid": gid}
        groups.append(g)
    return groups


def create_Templates_Params(*templateid):
    """参数可变，可加入多个字符串格式模板id"""
    templates = []
    for tid in templateid:
        t = {"templateid": tid}
        templates.append(t)
    return templates


# example

# url = "http://192.168.0.2/api_jsonrpc.php"
# zaw = ZabbixApiWorkFlow(url, "Admin", "zabbix")
# host = "192.168.0.1"
# name = "TEST"
# interfaces = create_Interfaces_Params(1, 1, 1, "192.168.0.1", "", "10050")
# groups = create_Groups_Params("2")
# templates = create_Templates_Params("10284")
# zaw.Add_Job(job_Add_Host(host, interfaces, groups, templates, name))
# zaw.Add_Job(job_List_Hosts())
# zaw.Add_Job(job_List_Host_BY_Name('192.168.0.1'))
# zaw.Add_Job(
#    job_List_Template_By_Name("Template OS Linux by Zabbix agent active"))
# zaw.Add_Job(job_List_Groups())
# zaw.Run_Job()
