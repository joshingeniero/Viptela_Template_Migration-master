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
import datetime
import os
import tarfile
import shutil
import glob
from copy import deepcopy
from collections import OrderedDict
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import urllib3


app = Flask(__name__)
app.secret_key = 'some_secret'
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@app.route('/')
def index():
    return render_template('index.html')


def load_json_from_file(fp):
    with open(fp) as f:
        return json.load(f, object_pairs_hook=OrderedDict)


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
            print("Login Failed")
            sys.exit(0)
        else:
            print("Unknown exception")
    except Exception as err:
        return redirect("/")


def get_device_template_names():
    # Get name of device templates
    global sessions
    global vmanage_ip
    vmanage_ip = request.form['textip']
    username = request.form['textuname']
    password = request.form['password1']
    sessions = login(vmanage_ip, username, password)
    url = 'https://' + vmanage_ip + '/dataservice/template/device'
    r = sessions.get(url, verify=False)
    response = json.loads(r.content, object_pairs_hook=OrderedDict)
    device_data = response["data"]
    device_template_list = []
    return [device["templateName"] for device in device_data if not device["configType"] == "file"]


@app.route('/export', methods=['POST'])
def template_export():
    # Export template from test environment
    dir_path = os.getcwd()
    device_template_list = get_device_template_names()
    url = 'https://' + vmanage_ip + '/dataservice/template/device'
    r = sessions.get(url, verify=False)
    response = json.loads(r.content, object_pairs_hook=OrderedDict)
    data = response["data"]
    device_template_id = OrderedDict()
    file_path = os.path.join(dir_path, "templates1")
    if os.path.exists(file_path):
        shutil.rmtree(file_path)
    os.makedirs(file_path)
    device_template_json_file = os.path.join(file_path, "device_template.json")
    for device_temp in data:
        if device_temp['templateName'] in device_template_list:
            device_template_id[device_temp['templateName']] = device_temp['templateId']
    device_templates = OrderedDict({"templates": []})
    device_feature_id = OrderedDict()
    device_policy_id = OrderedDict()
    for key, value in device_template_id.items():
        url = 'https://' + vmanage_ip + '/dataservice/template/device/object/%s'%value
        r = sessions.get(url, verify=False)
        device_data = json.loads(r.content, object_pairs_hook=OrderedDict)

        # Check If policy required
        if "policyId" in device_data and device_data["policyId"]:
            if not key in device_policy_id:
                device_policy_id[key] = []
            device_policy_id[key].append(device_data["policyId"])
        if not key in device_feature_id:
            device_feature_id[key] = []
        template_id_list = []
        for feature in device_data["generalTemplates"]:
            device_feature_id[key].append(feature["templateId"])
            # handle case where subTemplates itself has subTemplates
            if "subTemplates" in feature:
                for sub_temp in feature["subTemplates"]:
                    if "subTemplates" in sub_temp:
                        for template in sub_temp["subTemplates"]:
                            device_feature_id[key].append(template["templateId"])
                    device_feature_id[key].append(sub_temp["templateId"])
        if "featureTemplateUidRange" in device_data and device_data["featureTemplateUidRange"]:
            for add_template in device_data["featureTemplateUidRange"]:
                device_feature_id[key].append(add_template["templateId"])
        device_templates["templates"].append(device_data)
    # Writing device_Template data to file
    with open(device_template_json_file, 'w') as f:
        json.dump(device_templates, f)
    for device_name, template_id_list in device_feature_id.items():
        feature_template_json_file = os.path.join(file_path, "%s_features.json"%device_name)
        feature_template_data = OrderedDict()
        for template_id in template_id_list:
            url = 'https://' + vmanage_ip + '/dataservice/template/feature/object/%s'%template_id
            r = sessions.get(url, verify=False)
            feature_data = json.loads(r.content, object_pairs_hook=OrderedDict)
            feature_template_data[template_id] = feature_data
        with open(feature_template_json_file, 'w') as f:
            json.dump(feature_template_data, f)
    if device_policy_id:
        for device_name, policy_id_list in device_policy_id.items():
            policy_template_json_file = os.path.join(file_path, "%s_policy.json"%device_name)
            policy_template_data = OrderedDict()
            url = 'https://' + vmanage_ip + '/dataservice/template/policy/vedge/'
            r = sessions.get(url, verify=False)
            policy_data = json.loads(r.content, object_pairs_hook=OrderedDict)
            policy_data = policy_data["data"]
            for policy in policy_data:
                if policy["policyId"] == policy_id_list[0]:
                    policy_template_data[policy["policyId"]] = policy
            with open(policy_template_json_file, 'w') as f:
                json.dump(policy_template_data, f)
    tar = tarfile.open(os.path.join(dir_path, "templates_archive.tar.gz"), "w:gz")
    for file_name in glob.glob(os.path.join(file_path, "*")):
        tar.add(file_name, os.path.basename(file_name))
    tar.close()
    shutil.rmtree(file_path)
    flash('Successfully Exported the templates as templates_archive.tar.gz in the dir path %s'%(dir_path), 'success')
    print("Successfully Exported the templates as templates_archive.tar.gz in the dir path %s"%(dir_path))
    # return redirect(url_for('index'))
    return send_from_directory(dir_path, filename='templates_archive.tar.gz', as_attachment=True)

@app.route('/import', methods=['POST'])
def template_import():
    # Import template to prod environment
    vmanage_ip = request.form['textip_import']
    username = request.form['textuname_import']
    password = request.form['password_import']
    sessions = login(vmanage_ip, username, password)
    count = 0

    # Get Filepath by searching the file system
    try:
        f = request.form['file']
        for root, dirs, files in os.walk('/Users'):
            for name in files:
                if name == f and count==0:
                    print(os.path.abspath(os.path.join(root, name)))
                    count = count + 1
                    file_path = os.path.abspath(os.path.join(root, name))
    except Exception as err:
        flash('Unexpected error, make sure correct file is selected - %s' % (err), 'warning')

    def check_policy(policy_name):
        url = 'https://' + vmanage_ip + '/dataservice/template/policy/vedge/'
        r = sessions.get(url, verify=False)
        policy_data = json.loads(r.content, object_pairs_hook=OrderedDict)
        policy_data = policy_data["data"]
        for policy in policy_data:
            if policy['policyName'] == policy_name:
                return policy['policyId']
        return False

    def check_feature_template_exists(feature_template_name):
        url = 'https://' + vmanage_ip + '/dataservice/template/feature'
        r = sessions.get(url, verify=False)
        feature_data = json.loads(r.content, object_pairs_hook=OrderedDict)
        feature_data = feature_data["data"]
        for feature in feature_data:
            if feature_template_name == feature["templateName"]:
                return feature["templateId"]
        return False

    def return_feature_template_names_and_ids():
        url = 'https://' + vmanage_ip + '/dataservice/template/feature'
        r = sessions.get(url, verify=False)
        feature_data = json.loads(r.content, object_pairs_hook=OrderedDict)
        feature_data = feature_data["data"]
        if feature_data:
            feature_template_id_map = {}
            for feature in feature_data:
                feature_template_id_map[feature["templateName"]] = feature["templateId"]
            return feature_template_id_map

    def check_device_template_exists(device_template_name):
        url = 'https://' + vmanage_ip + '/dataservice/template/device'
        r = sessions.get(url, verify=False)
        device_data = json.loads(r.content, object_pairs_hook=OrderedDict)
        device_data = device_data["data"]
        for device in device_data:
            if device_template_name == device["templateName"]:
                return True
        return False
    try:
        tar = tarfile.open(file_path)
        dest_dir_path = os.path.join(os.getcwd(), "templates1")
    except Exception as err:
        flash('Unexpected error, make sure the correct file is selected for Importing', 'warning')
        return redirect("/")

    if os.path.exists(dest_dir_path):
        shutil.rmtree(dest_dir_path)
    os.makedirs(dest_dir_path)
    tar.extractall(path=dest_dir_path)
    tar.close()
    device_template_json_file = os.path.join(dest_dir_path, "device_template.json")
    feature_keys = ["templateName", "templateDescription", "templateType", "templateMinVersion", "deviceType","factoryDefault","templateDefinition"]
    policy_keys = ["policyName", "policyDescription", "policyDefinition"]
    device_template_keys = ["templateName","templateDescription","deviceType","configType","factoryDefault","policyId","featureTemplateUidRange","generalTemplates"]
    device_template_data = load_json_from_file(device_template_json_file)
    for device_template in device_template_data["templates"]:
        template_id_mapping = {}
        feature_template_file = os.path.join(dest_dir_path, "%s_features.json"%device_template['templateName'])
        if not os.path.exists(feature_template_file):
            print("No feature templates")
        feature_data = load_json_from_file(feature_template_file)
        template_id_list = list(feature_data.keys())
        url = 'https://' + vmanage_ip + '/dataservice/template/feature'
        headers = {'Content-Type': 'application/json'}
        feature_template_id_map = return_feature_template_names_and_ids()
        for template_id in template_id_list:
            if template_id in feature_data:
                fd = feature_data[template_id]
                for key in list(fd.keys()):
                    if not key in feature_keys:
                        fd.pop(key, None)
                if feature_template_id_map and fd["templateName"] in feature_template_id_map:
                    new_template_id = feature_template_id_map[fd["templateName"]]
                else:
                    post_response = sessions.post(url, data=json.dumps(fd), headers=headers, auth=requests.auth.HTTPBasicAuth(username, password), verify=False) #session.post_request(url, fd)
                    if post_response:
                        res = json.loads(post_response.content, object_pairs_hook=OrderedDict)
                        new_template_id = res['templateId']
                template_id_mapping[template_id] = new_template_id
        new_device_template = deepcopy(device_template)
        for feature in new_device_template["generalTemplates"]:
            feature['templateId'] = template_id_mapping[feature['templateId']]
            if "subTemplates" in feature:
                for sub_temp in feature["subTemplates"]:
                    if "subTemplates" in sub_temp:
                        for template in sub_temp["subTemplates"]:
                            template["templateId"] = template_id_mapping[template["templateId"]]
                    sub_temp["templateId"] = template_id_mapping[sub_temp["templateId"]]
        if "featureTemplateUidRange" in new_device_template and new_device_template["featureTemplateUidRange"]:
            for add_template in new_device_template["featureTemplateUidRange"]:
                add_template["templateId"] = template_id_mapping[add_template["templateId"]]

        if "policyId" in device_template and device_template['policyId']:
            policy_file = os.path.join(dest_dir_path, "%s_policy.json"%device_template['templateName'])
            policy_data = load_json_from_file(policy_file)
            policy_id = device_template["policyId"]
            if not policy_id in policy_data:
                print("Policy data missing in backup")
            headers = {'Content-Type': 'application/json'}
            pd = policy_data[policy_id]
            ch = check_policy(pd['policyName'])
            if ch is False:
                for key in list(pd.keys()):
                    if not key in policy_keys:
                        pd.pop(key, None)
                url = 'https://' + vmanage_ip + '/dataservice/template/policy/vedge/'
                response = sessions.post(url, data=json.dumps(pd), headers=headers, verify=False)
                new_policy_id = check_policy(pd['policyName'])
            else:
                new_policy_id = ch
            new_device_template['policyId']  = new_policy_id
        for key in list(new_device_template.keys()):
            if not key in device_template_keys:
                new_device_template.pop(key, None)
        url = 'https://' + vmanage_ip + '/dataservice/template/device/feature/'
        check_device = check_device_template_exists(new_device_template["templateName"])
        if not check_device:
            new_device_template = json.dumps(new_device_template)
            post_response = sessions.post(url, data=new_device_template, headers=headers, verify=False) #session.post_request(url, new_device_template)
        else:
            print("Skipping %s"%new_device_template["templateName"])
    shutil.rmtree(dest_dir_path)
    flash('Successfully imported the templates from templates_archive.tar.gz to %s'%(vmanage_ip), 'success')
    print("Successfully imported the templates from templates_archive.tar.gz to %s"%(vmanage_ip))
    return redirect(url_for('index'))


app.run("0.0.0.0")
