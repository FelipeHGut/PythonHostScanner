#!/usr/bin/env python
# -*- coding: utf-8 -*-


# =============================================================================
# Host Discovery Tool
# =============================================================================

# Created By:  Felipe H
# Date created: 20/06/2022
# Description:
# A script to find connected hosts in the same network as the host where the script is run.
# The script takes no arguments. The script allows you to save the results of any found hosts. 
# It also allows you to run a port scan on those host founds.
#
# Notes:
# The script requires administrative privileges to run
# Know issues:
# - Running in windows use still requires further testing - sometimes finds hosts sometimes misses
# - Manual interrupt still require to stop scanning a subnet.
# - 

# =============================================================================
"""An Educational tool to discover any hosts connected to the network."""

# =============================================================================
# Imports
# =============================================================================

import ipaddress
import os
import socket
import struct
import sys
import threading
import time
import subprocess
import re
import ctypes


# =============================================================================
# Set up and Functions
# =============================================================================


def checkAdmin():
    # Function checks if the script is being run with administrative privileges.
    # it first assumes it is being run on linux. If an exception is raised, then tries windows.
    # the value 
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin () != 0
    if is_admin == False:
        print(f"\nThe script { os.path.basename(sys.argv[0]) } requires Administrator Privileges to run.\nExiting...")
        exit()
    else:
        pass


def setupvariables():
    """
    Function to call global variables required for the script
    """
    global SUBNET, MESSAGE, complete_list_of_targets, banner, port_opens_results, operationalSystem
    global white, red,green, orange, blue, purple
    
    # Subnet variable that will be searched
    SUBNET = ''
    # Message sent in UDP scanner
    MESSAGE = 'thishostisalive'
    # list to add found hosts
    complete_list_of_targets = []
    # The program behaves differently depending on the operational system
    operationalSystem= str(os.name)
    # Ports open on targets
    port_opens_results = {}

    def coloronconsole(text):
        # Depending on the operational system, it will display colours on the terminal.
        return text if operationalSystem == 'posix' else ''

    # Colors variables for terminals.
    white  = coloronconsole( '\033[0m')   # white (normal)
    red    = coloronconsole('\033[31m')   # red
    green  = coloronconsole('\033[32m')   # green
    orange = coloronconsole('\033[33m')   # orange
    blue   = coloronconsole('\033[34m')   # blue
    purple = coloronconsole('\033[35m')   # purple


    # Banner displayed on the console 
    banner = f"""{green}
 
 ██╗  ██╗ ██████╗ ███████╗████████╗                                    
 ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝                                    
 ███████║██║   ██║███████╗   ██║                                       
 ██╔══██║██║   ██║╚════██║   ██║                                       
 ██║  ██║╚██████╔╝███████║   ██║                                       
 ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝                                       
 ██████╗ ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗   ██╗
 ██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝
 ██║  ██║██║███████╗██║     ██║   ██║██║   ██║█████╗  ██████╔╝ ╚████╔╝ 
 ██║  ██║██║╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝  
 ██████╔╝██║███████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   
 ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   
 ████████╗ ██████╗  ██████╗ ██╗                                        
 ╚══██╔══╝██╔═══██╗██╔═══██╗██║                                        
    ██║   ██║   ██║██║   ██║██║                                        
    ██║   ██║   ██║██║   ██║██║                                        
    ██║   ╚██████╔╝╚██████╔╝███████╗                                   
    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝                                   
                                                                                                                                                                                                                                                                             
{white}Tool created by Felipe H.
This tool was created for educational purposes.                                                                                                 
"""


def breakline(text):
    # function to create printed line with text in the middle. 
    print(f"{blue}")
    print(f"{text}".center(85,"="))
    print(f"{white}")

class IP:
    """Class to handle packets"""
    def __init__(self, buff=None):
        # unpact using struct
        # <BBHHHBBH4s4s specifies the order of bytes within a binary number.
        # B - 1-byte unsigned char, H - 2-byte unsigned short,
        # and S - a byte array that requires width specification 4s means 4-bytes string
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]  # IP version
        self.len = header[2]  # HDR length
        self.id = header[3]  # Type of service
        self.offset = header[4]  # Offset
        self.ttl = header[5]  # time to live
        self.protocol_num = header[6]  # protocol
        self.sum = header[7]  # checksum
        self.src = header[8]  # IP source
        self.dst = header[9]  # Destination IP

        # The following creates a human-readable IP address

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map the protocol constants to their names

        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(
                f"{e} No protocol for {self.protocol_num}"
            )
            self.protocol = str(str(self.protocol_num))


class ICMP:
    """Opens ICMP packets 
    """
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]




def udp_sender():
    """ Function to send UDP datagrams with message. """
    # This sprays out UDP datagrams with our magic message to the port specified
    # In this case 65212
    # It goes through ipaddress using the ipaddress.ip_network(SUBNET).hosts()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))

class Scanner():
    
    # The scanner class creates a basic packet sniffer

    def __init__(self, host):

        # defines the HOST this will be given as an argument.
        self.host = host

        # nt refers if the local host is a Windows OS. This is due to how the socket
        # module communicates with the kernel.
        # Since we are using promiscuous mode we require to run python under administrative privileges

        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket_protocol)

        self.socket.bind((host, 0))

        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        host_up = set([f'{str(self.host)} *'])

        try:

            while True:
                
                # read a packet
                raw_buffer = self.socket.recvfrom(65535)[0]

                # create an IP header from the first 20 bytes
                ip_header = IP(raw_buffer[0:20])

                # if it is ICMP we want it:
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)

                    # check for type 3 and code

                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            a = str(ip_header.src_address)
                            # make sure it has our magic message
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in host_up:
                                    host_up.add(str(ip_header.src_address))
                                    print(f'{green}Host up: {tgt}{white}')

        # Handle CTRL -C which will terminate the scanner
        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            print("\n User interrupted, moving onto next subnet or exiting")
        if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)       
        if host_up:
            # for any host found the it will print a summary.
            print(f'\n\n{purple}Summary: hostups on {SUBNET}{white}\n')
            for host in sorted(host_up):
                if host == f"{self.host} *":
                    print(f"{host} - Local IP")
                else:
                    print(f'{green}{host}{white}')
                if self.host != host and host[-1] != "*":
                    complete_list_of_targets.append(f"{host}")
            print('')

def network_find():
    """ Function to find any networks connected with the host. The program behaves differently depending on the Operational System"""
    # The programs check the OS stored in the variable operational system.
    #

    if operationalSystem == 'nt':
        import psutil
        network_information = psutil.net_if_addrs()
        network_call = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        network_call.connect(("8.8.8.8",80))
        local_ip = network_call.getsockname()[0]
        for items in network_information:
            for item in network_information[items]:
                if re.search(local_ip,item[1]) != None:
                      network_with_cidr = ipaddress.IPv4Network(f"{item[1]}/{item[2]}", strict=False)
        return [[local_ip,f"{network_with_cidr.with_prefixlen}"]]
    
    
    elif operationalSystem == 'posix':

        # find all the available local networks connected to the host using subprocess
        # running ifconfig -a and passing the results as a string
        connected = str(subprocess.check_output(
            ['ifconfig', "-a"]).decode('utf-8'))

        # using regex extract the IP address the host is under as well as the subnet
        connected_networks = list(re.findall(
            "inet [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}", connected))
        connected_subnets = list(re.findall(
            "netmask [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}", connected))

        # however this includes the loopback
        loopback_location = connected_networks.index("inet 127.0.0.1")

        # remove the loopback IP address
        connected_networks.pop(loopback_location)
        connected_subnets.pop(loopback_location)

        # removes and only leaves the ip address and subnetmask
        connected_networks = [ip.split()[1] for ip in connected_networks]
        connected_subnets = [net.split()[1] for net in connected_subnets]

        # Now that we have the list we can iterate throught the list
        local_ips = connected_networks
        # We first declare a list that we will return from the function
        network_addresses = []

        # using the length we can iterate throught the network and the subnets
        for number in range(len(connected_networks)):
            # using the ipaddress module we can convert the strings to check if they are IPV4 and use further with the package.
            network = ipaddress.IPv4Network(
                f"{connected_networks[number]}/{connected_subnets[number]}", strict=False)

            # by location the network we can view it with CIDR attached
            network_to_add = f"{network.with_prefixlen}"

            network_addresses.append(network_to_add)

        # return the network addresses and CIDR
        return list(zip(local_ips, network_addresses))

    else:
        return None

def save_to_file(results):
    # Function to allow user to save results to a txt file

    while True:
        print("Would you like to save your result to a text file?")
        print("y/n?")
        user_input = str(input("->")).lower()

        if user_input[0] == "y":

            results_file = "results.txt"

            print(
                f"\nResults file will be saved as {orange}{results_file}{white} in the local folder.")

            current_directory = str(os.getcwd())

            with open(results_file, "w") as file_to_save:
                file_to_save.writelines(f"{ip}\n" for ip in results)

            print(f"\nResults file located in")

            print(f"\n{current_directory}/{results_file}")
            break

        elif user_input[0] == "n":
            break

        else:
            "incorrect input - please enter yes or no"


def port_scanner(target):
    try:
        found = []
    # will scan ports between 1 to 65,535
        for port in range(1, 65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # the timeout below sets the parameter to drops socket for the time below.
            socket.setdefaulttimeout(1)

            # we chose socket.connect_ex as it can be asynchronous connections. It will return a 0 if the connection has succeeded
            result = s.connect_ex((target, port))

            # If receiving a suceeded we will print out the target and port found
            if result == 0:
                print("Target: {} Port {} is open".format(target, port))
                found.append(port)

            port_opens_results[target] = found
            s.close()

    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")

    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")

    except socket.error:
        print("\ Server not responding !!!!")


def run_port_scans(targets):
    while True:
        print("\nWould you like to scan open ports on results?")
        print("y/n?")
        user_input = str(input("->")).lower()
        if user_input[0] == "y":
            print(f"\n{orange}Scanning for Open Ports{white}\n")
            for target in targets:
                pt = threading.Thread(target=port_scanner(target), daemon=True)
                pt.start()
            break
        elif user_input[0] == "n":
            break

        else:
            "incorrect input - please enter yes or no\n"


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':

    checkAdmin() # functions checks if script is being run with admin priveleges. 

    setupvariables() # call global variables
    
    print()
    print(banner)
    breakline("START")
    
    if not network_find():
        # checks if the network find results is empty. If so we are not connected to any networks
        print(f"{orange}Please check your connections, looks like your are not connected\nto any networks.{white}\n")
    else:
        for local_ip, subnet_with_cidr in network_find():
    
            print(
                f"Press {orange}Control+C{white} to move on to the next subnet or exit\n")
            SUBNET = subnet_with_cidr

            print(
                f"You are currently scanning {blue}{subnet_with_cidr}{white}")
            print(f"Your local IP for this network is {local_ip}")

            # Use the class scanner to define the packet sniffer using the local ip
            s = Scanner(local_ip)

            time.sleep(1)

            # Define the thread that will send the UDP messages using the subnet with CIDR
            # We use daemon as it will be a thread that is not dependant on others
            t = threading.Thread(
                target=udp_sender, name=f'{subnet_with_cidr}', daemon=True)

            print(
                f"\nStarting to send messages to subnet: {subnet_with_cidr}\n")

            t.start()

            # Start sniffer looking for specific ICMP messages with rejections from HOST including the Message Defined.
            s.sniff()

            print()

        breakline(f"{orange}Completed Scanning Network\s{white}{blue}")
        print()

        if complete_list_of_targets:
            #
            save_to_file(complete_list_of_targets)

            run_port_scans(complete_list_of_targets)

        else:
            print(f"{orange}Results:{white} No other hosts found")

    if port_opens_results:
        print()
        print(f"{blue}Summary of ports open found{white}")
        for items in port_opens_results.keys():
            print("Host", items, "ports open :",
                  f"None" if not port_opens_results[items] else f"{orange}{port_opens_results[items]}{white}")

    print("")
    breakline("END")
    sys.exit()
