import socket
import platform
import subprocess
import sys
import time #Executuion time

#Obtain info about platform system
print("System: ", platform.system());

#Checking parameters
if len(sys.argv) < 3:
    sys.exit("Need at least ip start and ip end to make the scan")
if len(sys.argv[1]) < 4 or len(sys.argv[1]) > 12 or len(sys.argv[2]) < 4 or len(sys.argv[2]) > 12:
    sys.exit("IP length must be between 4 and 12")

#Obtain the ips
ipStart = sys.argv[1].split(".")
ipEnd = sys.argv[2].split(".")

#Check is that range its possible
if ipStart > ipEnd:
    sys.exit("IP range not possible")

#Begin cleaning the console
if platform.system() == "Linux":
    subprocess.run("clear", shell=True)
else:
    subprocess.run("cls", shell=True)


"""
Executing code:
python prgramName arg1 arg2 agr3
arg1 ipStart
agr2 ipEnd
arg3 type of scan

Type of scan:
-icmp icmp scan (ping echo)
-tcp do a tcp scan
if we add:
 -p makes a portScan if there are discovered systems
"""

#How many arguments
#print("Number of arguments, ", len(sys.argv), "arguments")
#print("Arguments: ", str(sys.argv))

#Get ip range:
print("\t","*"*70)
print("\t\t","Scanning hosts in range: ", sys.argv[1], " to ", sys.argv[2])
print("\t","*"*70)
t1 = time.time()

#ICMP echo (ping) used to be blocked by firewall
def ping(ipStart, ipEnd):
    ipRange = int(ipEnd[3]) - int(ipStart[3]);
    for ip in range(0,ipRange+1):

        newDir = int(ipStart[3])+ip
        ipCheck = ipStart[0]+"."+ipStart[1]+"."+ipStart[2]+"."+str(newDir)

        if platform.system() == "Linux":
            command = subprocess.run(["ping", "-c", "1", ipCheck], stdout=subprocess.PIPE, text=True)
        else:
            command = subprocess.run(["ping", "-n", "1", ipCheck], stdout=subprocess.PIPE, text=True)

        #Check output
        # print(command.returncode), if it's 0 ping worked, 1 ping didn't work
        if command.returncode == 0:
            print("IP: ", ipCheck, " OPEN") #If its open print ip
        else:
            print("IP: ", ipCheck, " NOT OPEN")

ping(ipStart, ipEnd)
