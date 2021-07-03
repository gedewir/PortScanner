#!/usr/bin/env python
"""
SYNOPSIS
          PortScanner.py
          The scapy and sys modules are required in order to execute the program
          Program needs to be exectued in the command lines and the arguements needed is
          the IP address, domain name and slash notation if user wishes

DESCRIPTION

          This script will individually scan and filters the ports 21, 22, 23, 25, 53, 80,
          110, 135, 137, 138, 139, 443, 1433, 1434 and 8080 for TCP on your target IP address
          or domain name or even all IP addressses in a subnet if you enter a slash notation,
          and determine whether it is closed or open.

          Other arguements:

          -verbose               Verbose mode: Gives more information regarding sending and recieveing of packets
          -help               Help: Provides inforamtion about how to operate the script
          
EXAMPLES

        *On your command line or PowerShell*
        $ python3 PortScanner.py 1.1.1.1
        or
        $ python3 PortScanner.py 1.1.1.1/24
        or
        $ python3 PortScanner.py google.com

        OUTPUT:
        142.250.70.238 with port number 80 is being SCANNED
        142.250.70.238 with port number 80 is OPEN
        ...
	
AUTHOR

        Gede Wirayuda <30037137@tafe.wa.edu.au

LICENSE

    This script is the exclusive and proprietary property of
    TiO2 Minerals Consultants Pty Ltd. It is only for use and
    distribution within the stated organisation and its
    undertakings.

VERSION

    Version 0.1
"""

#Scenario 1 Code#

#importing the sys module
import sys
#importing the scapy module and making its function and methods callable without using scapy.example
from scapy.all import *

#verbose mode function for later use
def VerboseMode(destinationID):
    #using Net to give a range of IPs within the subnet range if user uses notation in the end    
    destinationID = Net(destinationID)
    #empty list used to store the IP address contained in a subnet
    destList = []
    #destination  port numbers which will be used in the packet
    scanningPorts = [21,22,23,25,53,80,110,135,137,138,139,443,1433,1434,8080]
    #iterating every IP address in the destination ID list so that every IP is added onto the list
    for x in destinationID:
        destList.append(x)
    #iterating every new added IP in the destination list
    for destIP in destList:
        #iterating every port in the port list while nested in the destination IP list
        for Ports in scanningPorts:
            #packet details for the port scanning including the destination IP and destination port
            packet = IP(dst=destIP)/TCP(sport=RandShort(),dport=Ports)
            print('{}:{} is being SCANNED'.format(destIP, Ports))
            #sending and recieving one packet once withh timeout of 2 seconds and verbose mode turned on
            re,ans = sr1(packet, timeout=2.0, verbose=1)
            #informing the user if we get no response the port is closed
            if re == None:
                print('{}:{} has been filtered and is CLOSED \n'.format(destIP, Ports))
            #informing the user if we get a response the port is open
            else:
                print(re.getlayer(TCP).show())
                #print('{}:{} is OPEN \n'.format(destIP,Ports))

#verbose mode function for later use
def NormalMode(destinationID):
    #using Net to give a range of IPs within the subnet range if user uses notation in the end
    destinationID = Net(destinationID)
    #empty list used to store the IP address contained in a subnet
    destList = []
    #destination  port numbers which will be used in the packet
    scanningPorts = [21,22,23,25,53,80,110,135,137,138,139,443,1433,1434,8080]
    #iterating every IP address in the destination ID list so that every IP is added onto the list
    for x in destinationID:
        destList.append(x)
    #iterating every new added IP in the destination list
    for destIP in destList:
        #iterating every port in the port list while nested in the destination IP list
        for Ports in scanningPorts:
            #packet details for the port scanning including the destination IP and destination port
            packet = IP(dst=destIP)/TCP(sport=RandShort(),dport=Ports)
            print('{}:{} is being SCANNED'.format(destIP, Ports))
            #sending and recieving one packet once withh timeout of 2 seconds and verbose mode turned off
            re = sr1(packet, timeout=2.0, verbose=0)
            #informing the user if we get no response the port is closed
            if re == None:
                print('{}:{} has been filtered and is CLOSED \n'.format(destIP, Ports))
            #informing the user if we get a response the port is open
            else:
                print('{}:{} is OPEN \n'.format(destIP,Ports))
            
#making a loop in which the user is required to enter more than 1 arguement in the command line for program to continue
while True:
    #if the user only calls the program and does not input any other arguement, it asks them to repeat it and quits the program
    if len(sys.argv)==1:
        print('Please enter an IP address or domain name (with an subnet range if you wish) in the command line')
        sys.quit()
    #if the user enters an arguement in the command line it continues the program
    elif len(sys.argv) > 1:
        break

#if the user enters -help after calling the program, it will print out the information about how to run program 
if sys.argv[1] == '-help':
    print("""Welcome to the Port Scanner Program

             Version 0.1

             To run the program, please enter the following in the command line:

             $ python PortScanner.py 1.1.1.1/31

                         or
             $ python PortScaner.py google.com/31

             Other commands:

             -help          provides help information on the program
             -verbose       provides more information on the sending and recieving of packets in the program""")
#if the user inputs -verbose and destination ID after calling the program, it will perform the port scanning in verbose mode
elif sys.argv[1] == '-verbose':
    try:
        VerboseMode(sys.argv[2])
    #asks the user to put in a destination IP if they do not enter one after inputting -verbose in the command line
    except IndexError:
        print('Please enter a destination ID after entering -verbose')
#if the user inputs just their destination ID, it will perform the port scanning in normal mode
else:
    NormalMode(sys.argv[1])
