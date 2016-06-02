#Author: Alex Vranceanu
#Date: 07.03.2014

#import the necessary libraries
import json
import urllib
import argparse
import getpass

import httplib2

import ConfigParser
from os.path import expanduser, isfile
from os import getlogin

#Configuration default values
NS_servers = ['192.168.1.1']


def read_config(user_config_file):
    config = ConfigParser.ConfigParser()
    config.read(user_config_file)
    try:
        username = config.get('Authentication', 'username')
    except:
        username = ''
    try:
        password = config.get('Authentication', 'password')
    except:
        password = ''

    return username, password


def write_config(user_config_file, username, password):
    try:
        cfgfile = open(user_config_file, 'w')
    except Exception as e:
        print("%s" % e)
        return

    config = ConfigParser.ConfigParser()
    config.add_section('Authentication')
    config.set('Authentication', 'username', username)
    config.set('Authentication', 'password', password)
    config.write(cfgfile)
    cfgfile.close()

    print "Saved config to %s." % user_config_file

#NS Login function (parameters: NetscalerIP, NetscalerUsername, NetscalerPassword)
#TODO: Connection error handling
def NS_login(NS_server, username, password):
    #set the headers and the base URL
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    url = 'http://' + NS_server + '/nitro/v1/config/'

    #contruct the payload with URL encoding
    payload = {"object": {"login": {"username": username, "password": password}}}
    payload_encoded = urllib.urlencode(payload)

    #create a HTTP object, and use it to submit a POST request
    http = httplib2.Http()
    response, content = http.request(url, 'POST', body=payload_encoded, headers=headers)
    content = json.loads(content)

    #Check error code (0 - successful), exit if unsuccessful
    if content['errorcode'] > 0:
        print content['message']
        write_config(expanduser("~/.lb-status"), '', '')
        exit(content['errorcode'])
    else:
        #Return the sessionid
        return content['sessionid']

#Function which retrieves the status of a node (parameters: NetscalerIP, sessionid, NODE)
def get_node_status(NS, NS_sessionid, NODE):
    #set the headers and the base URL
    headers = {'Content-type': 'application/x-www-form-urlencoded', 'Cookie': "sessionid=" + NS_sessionid}
    url = 'http://' + NS + '/nitro/v1/config/server/' + NODE + '?attrs=state'

    #create a HTTP object, and use it to submit a POST request
    http = httplib2.Http()
    response, content = http.request(url, 'GET', headers=headers)
    content = json.loads(content)

    #Check error code (0 - successful)
    if content['errorcode'] > 0:
        print ("Node not found: %s" % NODE)
    else:
        print("%s: %s" % (NODE, content['server'][0]['state']))

#Function which enables a node (parameters: NetscalerIP, sessionid, NODE)
def enable_node(NS, NS_sessionid, NODE):
    #set the headers and the base URL
    headers = {'Content-type': 'application/x-www-form-urlencoded', 'Cookie': 'sessionid=' + NS_sessionid}
    url = 'http://' + NS + '/nitro/v1/config/'

    #contruct the payload with URL encoding
    #payload = {"object":{"params":{"action":"enable"},"sessionid":NS_sessionid,"server":{"name":NODE}}}
    payload = {"object": {"params": {"action": "enable"}, "server": {"name": NODE}}}
    payload_encoded = urllib.urlencode(payload)

    #create a HTTP object, and use it to submit a POST request
    http = httplib2.Http()
    response, content = http.request(url, 'POST', body=payload_encoded, headers=headers)
    content = json.loads(content)

    #Check error code (0 - successful), exit if unsuccessful
    if content['errorcode'] > 0:
        print content['message']
    else:
        get_node_status(NS, NS_sessionid, NODE)

#Function which disables a node (parameters: NetscalerIP, sessionid, NODE)
def disable_node(NS, NS_sessionid, NODE):
    #set the headers and the base URL
    headers = {'Content-type': 'application/x-www-form-urlencoded', 'Cookie': 'sessionid=' + NS_sessionid}
    url = 'http://' + NS + '/nitro/v1/config/'

    #contruct the payload with URL encoding
    payload = {"object": {"params": {"action": "disable"}, "server": {"name": NODE}}}
    payload_encoded = urllib.urlencode(payload)

    #create a HTTP object, and use it to submit a POST request
    http = httplib2.Http()
    response, content = http.request(url, 'POST', body=payload_encoded, headers=headers)
    content = json.loads(content)

    #Check error code (0 - successful), exit if unsuccessful
    if content['errorcode'] > 0:
        print content['message']
    else:
        get_node_status(NS, NS_sessionid, NODE)


def main():
    global username
    global password
    global NS_servers

    #Read config file
    user_config_file = expanduser("~/.lb-status")
    (username, password) = read_config(user_config_file)

    #Check if username is not defined in config file, set it to current username
    if not username:
        username = getlogin()

    #Initiate argument parser
    parser = argparse.ArgumentParser(description='NS LB Node Status Tool')

    #Define standard options
    parser.add_argument('-u', '--user', nargs=1, action='store', dest='user',
                        help='NS username. Will use current user if not provided.', default=[username], required=False,
                        metavar='User')
    parser.add_argument('-p', '--password', nargs=1, action='store', dest='password',
                        help='NS password. Will prompt if not provided.', default=[password], required=False,
                        metavar='Password')
    parser.add_argument('-S', '--servers', nargs='+', action='store', dest='NS_servers', help='NS servers',
                        default=NS_servers, required=False, metavar='NSServers')
    parser.add_argument('-w', '--write-config', action='store_const', dest='write_config', const="true",
                        help='Write settings to config file (currently just username)', required=False,
                        metavar="WriteConfig")
    #    parser.add_argument('-v', '--verbose', action='store_true', help="Print more messages", default=False,
    #                        required=False)

    #Definle exclusive options (either -o or -f, cannot be used together)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--enable', action='store_const', dest='NS_action', const="enable", help='Enable nodes',
                       required=False, metavar='Enable')
    group.add_argument('-d', '--disable', action='store_const', dest='NS_action', const="disable", help='Disable nodes',
                       required=False, metavar="Disable")
    group.add_argument('-s', '--status', action='store_const', dest='NS_action', const="status",
                       help='Get the status of a node', required=False, metavar="Status")

    #Add the nodes positional argument
    parser.add_argument('NS_nodes', metavar='Nodes', type=str, nargs='+', help="Nodes")

    #Parse arguments
    args = parser.parse_args()

    #Set username specified in arguments
    if args.user[0]:
        username = args.user[0]
    print ("Using username: %s" % username)

    #Read NS servers if not defined
    if not args.NS_servers:
        args.NS_servers = raw_input("NS Servers (s1 s2 ...): ").split(' ')
        while not args.NS_servers[0]:
            args.NS_servers = raw_input("NS Servers (s1 s2 ...): ").split(' ')
    NS_servers = args.NS_servers

    #Read user password if not specified in arguments or config file
    if not args.password[0]:
        args.password = [getpass.getpass()]
        while not args.password[0]:
            args.password = [getpass.getpass()]
        password = args.password[0]

    #Initialize the NS controller
    for NS in NS_servers:

        #Login to the NS appliance
        NS_sessionid = NS_login(NS, username, password)

        #Print each NS server we connect to
        print ("-"*30)
        print ("NS %s: " % NS)

        #Verify which action was chosen
        if args.NS_action == "status":
            for NODE in args.NS_nodes:
                get_node_status(NS, NS_sessionid, NODE)
        if args.NS_action == "enable":
            print ("Enabling nodes: %s" % args.NS_nodes)
            for NODE in args.NS_nodes:
                enable_node(NS, NS_sessionid, NODE)
        if args.NS_action == "disable":
            print ("Disabling nodes: %s" % args.NS_nodes)
            for NODE in args.NS_nodes:
                disable_node(NS, NS_sessionid, NODE)

    if args.write_config or not isfile(user_config_file):
        write_config(user_config_file, username, '')


if __name__ == "__main__":
    main()

