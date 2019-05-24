#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2019 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
               
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import sys
import requests
from collections import OrderedDict
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def login(vmanage_ip, username, password):
    # Login to vmanage
    session = {}

    base_url_str = 'https://%s/'%vmanage_ip

    login_action = '/j_security_check'

    # Format data for loginForm
    login_data = {'j_username' : username, 'j_password' : password}

    # Url for posting login data
    login_url = base_url_str + login_action

    url = base_url_str + login_url

    sess = requests.session()

    # If the vmanage has a certificate signed by a trusted authority change verify to True
    login_response = sess.post(url=login_url, data=login_data, verify=False)
    try:
        if login_response.status_code == 200:
            session[vmanage_ip] = sess
            # global sessions
            # sessions = session[vmanage_ip]
            return session[vmanage_ip]
        elif '<html>' in login_response.content:
            print "Login Failed"
            sys.exit(0)
        else:
            print("Unknown exception")
    except Exception as err:
        return


def fetch_device_template_names(ip, uname, pwd):
    # Get name of device templates
    global sessions
    global vmanage_ip
    sessions = login(ip, uname, pwd)
    url = 'https://'+ip+'/dataservice/template/device'
    r = sessions.get(url, verify=False)
    response = json.loads(r.content, object_pairs_hook=OrderedDict)
    device_data = response["data"]
    device_template_list = []
    return [device["templateName"] for device in device_data if not device["configType"] == "file"]

def get_id(ip, uname, password):
    # Fetch Device Template ID
    global sessions
    global vmanage_ip
    sessions = login(ip, uname, password)
    url = 'https://' + ip + '/dataservice/template/device'
    r = sessions.get(url, verify=False)
    response = json.loads(r.content, object_pairs_hook=OrderedDict)
    device_data = response["data"]
    device_dict = {}
    for device in device_data:
        if not device["configType"] == "file":
            device_dict_val = {device["templateId"] : str(device["devicesAttached"])}
            device_dict.update(device_dict_val)
    return device_dict

def get_feature_id(ip,name,password):
    # Fetch feature template ID
    device_template_list = fetch_device_template_names(ip,name,password)
    url = 'https://'+ip+'/dataservice/template/device'
    r = sessions.get(url, verify=False)
    response = json.loads(r.content, object_pairs_hook=OrderedDict)
    data = response["data"]
    device_template_id = OrderedDict()
    device_policy_id = OrderedDict()
    for device_temp in data:
        if device_temp['templateName'] in device_template_list:
            device_template_id[device_temp['templateName']] = device_temp['templateId']
    device_templates = OrderedDict({"templates": []})
    device_feature_id = []
    feature_ids = []
    for key, value in device_template_id.iteritems():
        url = 'https://'+ip+'/dataservice/template/device/object/%s'%value
        r = sessions.get(url, verify=False)
        device_data = json.loads(r.content, object_pairs_hook=OrderedDict)

        # Check If policy required
        if "policyId" in device_data and device_data["policyId"]:
            if not key in device_policy_id:
                device_policy_id[key] = []
            device_policy_id[key].append(device_data["policyId"])
        if not key in device_feature_id:
            device_feature_id = []
        template_id_list = []
        for feature in device_data["generalTemplates"]:
            device_feature_id.append(feature["templateId"])
            # handle case where subTemplates itself has subTemplates
            if "subTemplates" in feature:
                for sub_temp in feature["subTemplates"]:
                    if "subTemplates" in sub_temp:
                        for template in sub_temp["subTemplates"]:
                            device_feature_id.append(template["templateId"])
                    device_feature_id.append(sub_temp["templateId"])
        if "featureTemplateUidRange" in device_data and device_data["featureTemplateUidRange"]:
            for add_template in device_data["featureTemplateUidRange"]:
                device_feature_id.append(add_template["templateId"])
        for i in range(device_feature_id.__len__()):
            if device_feature_id[i] not in feature_ids:
                feature_ids.append(device_feature_id[i])
    return feature_ids


def delete_device_template(ip, temp_id):
    # Delete Device Templates
    url = 'https://' + ip + '/dataservice/template/device/'+temp_id
    r = sessions.delete(url, verify=False)
    return r.status_code

def delete_feature_template(ip, feature_id_list):
    # Delete Feature Templates
    url = 'https://' + ip + '/dataservice/template/feature/'+feature_id_list
    r = sessions.delete(url, verify=False)
    return r.status_code

if __name__ == '__main__':
    vm_ip = raw_input("Enter vManage IP: ")
    uname = raw_input("Enter vManage username: ")
    password = raw_input("Enter vManage password: ")
    temp_ids = get_id(vm_ip,uname,password)
    feature_id_list = get_feature_id(vm_ip,uname,password)
    for key, value in temp_ids.iteritems():
        if (value.__eq__("0")):
            delete_device_template(vm_ip, key)
            print "Device template ID "+key+" deleted!!"
        else:
            print("Device is attached to the template. Cannot delete template ID "+key)
    print " "
    print "Note: Kindly verify if all the device templates are deleted before proceeding with deleting feature template"
    print " "
    del_feature_template= raw_input("Do you want to go ahead with deleting feature templates (Y/N): ")
    if(del_feature_template == "y" or del_feature_template == "Y"):
        print "Deleting Feature Templates in Progress...... "
        print " "
        for i in feature_id_list:
            delete_feature_template(vm_ip, i)
        print "Feature Templates deleted!!"
