# Script will update and block the list of malicious log4j IP addresses based on the greynoise.io feed.
# Recommend running this as a cron job on a ~5 minute interval to keep up to date.
# https://crontab.guru/every-5-minutes

# ty @Andrew___Morris and the Greynoise team for the public service and solid intel. Absolute legends.

# Author takes no responsibility for adverse impact due to issues/problems as a result of 
# architectural caveats, misuse, etc. This is provided as a free, quick tool to protect yourself
# and should be tested thoroughly before deploying widely on any production devices. BE CAREFUL!

from secrets import username, password, api_key
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
import requests
import json

greynoise_ip_list = 'apache_log4j_malicious-ips.txt'
cisco_ios_commands_file = 'cisco_ios_nullroute_commands.txt'
arista_eos_commands_file = 'arista_eos_nullroute_commands.txt'

# Exceptions file is for any address in the GreyNoise list for CVE-2021-44228 to omit from ACL
exceptions_file = 'log4j_malicious-ips-exceptions.txt'

# Add the DNS names or IPs of your internet edge routers here.
# Make sure your credentials (secrets) work for netmiko.
edge_routers = ['r1', 'r2', 'r3', 'etc']

def get_greynoise_feed():
    ''' Get the Greynoise feed and write each IP to its own line. 
    API key is required. Free account works w/enterprise trial. '''

    url = "https://api.greynoise.io/v2/experimental/gnql?query=tags%3A%20Apache%20Log4j%20RCE%20Attempt%20classification%3A%20malicious&size=9001"
    
    headers = {
        "Accept": "application/json",
        "key": api_key,
        }

    response = requests.request("GET", url, headers=headers)
    response_json = json.loads(response.content)
    data = response_json["data"]
    
    check_exceptions = open(exceptions_file, 'r')
    exceptions_list = check_exceptions.readlines()

    with open(greynoise_ip_list, 'w') as file:
        for addr in data:
            if addr['ip'] not in exceptions_list:
                file.write(addr['ip'] + "\n")
            else:
                continue

    file.close()

def compile_null_routes():
    ''' This function will compile the null routes for Cisco routers'''

    inputFile = open(greynoise_ip_list, 'r')
    badaddrs = inputFile.readlines()
    
    # Generate cmd output for cisco_ios platform
    with open(cisco_ios_commands_file, 'w') as file:
        for ipaddr in badaddrs:
            ipaddr = ipaddr.strip("\n")
            file.write(f"ip route {ipaddr} 255.255.255.255 Null0 name log4jblock\n")
    file.close()

    # Generate cmd output for arista_eos platform
    with open(arista_eos_commands_file, 'w') as file:
        for ipaddr in badaddrs:
            ipaddr = ipaddr.strip("\n")
            file.write(f"ip route {ipaddr}/32 Null0 name log4jblock\n")
    file.close()

def configure_null_routes(username, password, edge_routers):
    ''' This will deploy and null route the Greynoise feed on all defined edge routers. '''

    for router in edge_routers:
        device = { 
            'device_type': 'autodetect', 
            'host': router, 
            'username': username, 
            'password': password, 
            }
 
        try:
            detect_platform = SSHDetect(**device)
            platform_type = detect_platform.autodetect()
            device['device_type'] = platform_type
            
            if platform_type == 'cisco_ios' or platform_type == 'arista_eos':
                net_connect = ConnectHandler(**device)
                net_connect.send_config_from_file(platform_type + '_nullroute_commands.txt')
            else:
                continue
        except:
            continue

def main():

    get_greynoise_feed()
    compile_null_routes()
    configure_null_routes(username, password, edge_routers)
 
if __name__ == "__main__":
    main()