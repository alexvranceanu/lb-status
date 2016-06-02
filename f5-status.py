#Author: Alex Vranceanu
#Date: 08.05.2014

#Import required libraries
import sys
import argparse
import getpass
import pycontrol.pycontrol as F5Controller

import ConfigParser
from os.path import expanduser, isfile
from os import getlogin

#Configuration default values
f5_servers = ["192.168.1.2"]

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

#F5 exception handler
def f5_exception(e, NODE):
    #Exit if authentication failed
    if e.args[0][0] == 401:
        sys.stderr.write("User or password incorrect.")
        exit(1)
    #Print if node does not exist
    elif e.fault.faultstring.find("01020036:3"):
        sys.stderr.write("Node not found: %s\n" % NODE)

#Function which retrieves the status of a node (parameters: F5 Connection Object, NODE string)
def get_node_status(F5, NODE):
    #Get and save the status of a node
    try:
        node_status = F5.LocalLB.NodeAddressV2.get_object_status([NODE])
        #Print status for a node
        print("%s %s, %s" % (NODE, node_status[0][0], node_status[0][1]))
    except Exception as e:
        f5_exception(e, NODE)

#Function which enables a node (parameters: F5 Connection Object, NODE string)
def enable_node(F5, NODE):
    try:
        F5.LocalLB.NodeAddressV2.set_session_enabled_state([NODE], ['STATE_ENABLED'])
        F5.LocalLB.NodeAddressV2.set_monitor_state([NODE], ['STATE_ENABLED'])
    except Exception as e:
        f5_exception(e, NODE)
    get_node_status(F5, NODE)

#Function which disables a node (parameters: F5 Connection Object, NODE string)
def disable_node(F5, NODE):
    try:
        F5.LocalLB.NodeAddressV2.set_session_enabled_state([NODE], ['STATE_DISABLED'])
        F5.LocalLB.NodeAddressV2.set_monitor_state([NODE], ['STATE_DISABLED'])
    except Exception as e:
        f5_exception(e, NODE)
    get_node_status(F5, NODE)


def main():
    global username
    global password
    global f5_servers

    #Read config file
    user_config_file = expanduser("~/.lb-status")
    (username, password) = read_config(user_config_file)

    #Check if username is not defined in config file, set it to current username
    if not username:
        username = getlogin()

    #Initiate argument parser
    parser = argparse.ArgumentParser(description='F5 LB Node Status Tool')

    #Define standard options
    parser.add_argument('-u', '--user', nargs=1, action='store', dest='user',
                        help='F5 username. Will prompt if not provided.', default=[username], required=False,
                        metavar='User')
    parser.add_argument('-p', '--password', nargs=1, action='store', dest='password',
                        help='F5 password. Will prompt if not provided.', default=[password], required=False,
                        metavar='Password')
    parser.add_argument('-S', '--servers', nargs='+', action='store', dest='f5_servers', help='F5 servers',
                        default=f5_servers, required=False, metavar='f5Servers')
    parser.add_argument('-w', '--write-config', action='store_const', dest='write_config', const="true",
                        help='Write settings to config file (currently just username)', required=False,
                        metavar="WriteConfig")
    #    parser.add_argument('-v', '--verbose', action='store_true', help="Print more messages", default=False,
    #                        required=False)

    #Definle exclusive options (either -o or -f, cannot be used together)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--enable', action='store_const', dest='f5_action', const="enable", help='Enable nodes',
                       required=False, metavar='Enable')
    group.add_argument('-d', '--disable', action='store_const', dest='f5_action', const="disable", help='Disable nodes',
                       required=False, metavar="Disable")
    group.add_argument('-s', '--status', action='store_const', dest='f5_action', const="status",
                       help='Get the status of a node', required=False, metavar="Status")

    #Add the nodes positional argument
    parser.add_argument('f5_nodes', metavar='Nodes', type=str, nargs='+', help="Nodes")

    #Parse arguments
    args = parser.parse_args()

    #Set username specified in arguments
    if args.user[0]:
        username = args.user[0]
    print ("Using username: %s" % username)

    #Read F5 servers if not defined
    if not args.f5_servers:
        args.f5_servers = raw_input("F5 Servers (s1 s2 ...): ").split(' ')
        while not args.f5_servers[0]:
            args.f5_servers = raw_input("F5 Servers (s1 s2 ...): ").split(' ')
    f5_servers = args.f5_servers

    #Read user password if not specified in arguments
    if not args.password[0]:
        args.password = [getpass.getpass()]
        while not args.password[0]:
            args.password = [getpass.getpass()]
        password = args.password[0]

    #Initialize the F5 controller, use local WSDL for faster connections
    for f5_server in [f5_servers[0]]:
        F5 = F5Controller.BIGIP(
            hostname=f5_server,
            username=username,
            password=password,
            fromurl=False,
            debug=False,
            directory='/Users/alex/work/lb-status',
            wsdls=['LocalLB.NodeAddressV2.wsdl']
        )

        #Print each F5 server we connect to
        print ("-" * 35)
        print ("F5 %s: " % f5_server)

        #Verify which action was chosen
        if args.f5_action == "status":
            for NODE in args.f5_nodes:
                get_node_status(F5, NODE)
        if args.f5_action == "enable":
            print ("Enabling nodes: %s" % args.f5_nodes)
            for NODE in args.f5_nodes:
                enable_node(F5, NODE)
        if args.f5_action == "disable":
            print ("Disabling nodes: %s" % args.f5_nodes)
            for NODE in args.f5_nodes:
                disable_node(F5, NODE)

    #Remove the first F5 server from the list
    f5_servers.remove(f5_server)

    #Iterate through the rest of the F5 servers and only retrieve status
    for f5_server in f5_servers:
        F5 = F5Controller.BIGIP(
            hostname=f5_server,
            username=username,
            password=password,
            fromurl=False,
            debug=False,
            directory='.',
            wsdls=['LocalLB.NodeAddressV2.wsdl']
        )

        #Print each F5 server we connect to
        print ("-" * 35)
        print ("F5 %s: " % f5_server)

        #Get the status from all other F5 servers
        for NODE in args.f5_nodes:
            get_node_status(F5, NODE)

    if args.write_config or not isfile(user_config_file):
        write_config(user_config_file, username, '')


if __name__ == "__main__":
    main()
