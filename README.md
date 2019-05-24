# Viptela_Template_Migration
Project aims to demonstrate the automation of migration of templates from vManage test instance to a production instance.

The project retrieves all the templates from the vManage test instance through a web portal and writes it into a tar file. The tar file is then accessed to fetch the templates and the same is added to the vManage prod instance. This automation helps in reducing the time taken to migrate templates from test environment to the production environmen thereby avoiding human errors.

#### Author:

* Abhijith R (abhr@cisco.com)
*  Feb 2019
***

## Prerequisites
* Python 2.7
* PyCharm/Any text editor
* Flask

#### API Reference/Documentation:
* [vManage REST APIs](https://sdwan-docs.cisco.com/Product_Documentation/Command_Reference/vManage_REST_APIs/vManage_REST_APIs_Overview)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
