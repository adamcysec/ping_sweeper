import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import textwrap
from colors import red, green
import ipaddress

def get_args():
    parser = argparse.ArgumentParser(
        description="Ping one or more IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Examples:
        py ping_sweeper.py -c "192.168.1.0/24"
        py ping_sweeper.py -ip "192.168.1.100"
        py ping_sweeper.py -ip "192.168.1.100, 192.168.1.6"
        py ping_sweeper.py -ip "192.168.1.1-20"
        py ping_sweeper.py -ip "192.168.1.100, 192.168.1.6, 192.168.1.1-20"
        py ping_sweeper.py -c "192.168.3.0/24" -ip "192.168.1.100, 192.168.1.6, 192.168.1.1-20"
        ''')
    )

    parser.add_argument('-c', '--cidr', action='store', type=str, required=False, help="cidr range")
    parser.add_argument('-ip', action='store', type=str, required=False, help="one or more target IPs in csv format")
    parser.add_argument('-src', action='store', type=str, required=False, help="source ip")
    parser.add_argument('--verbose', '-v', action='store_true', help="print verbose output")

    args = parser.parse_args() # parse arguments

    args_dict = vars(args)

    return args_dict

def main():
    args = get_args()
    cidr = args['cidr']
    ip = args['ip']
    src_ip = args['src']
    verbose = args['verbose']

    if ip:
        live_hosts = []
        ip_list = get_ip_list(ip)

        # if target ip contains a '-' (dash)
        for ip_target in ip_list:
            ip_parts = ip_target.split('.')
            if '-' in ip_parts[-1]:
                start, end = get_ip_range(ip)
                
                ip_target = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                
                for num in range(start, (end + 1)):
                    dst_ip = f"{ip_target}.{str(num)}"
                    live = ping_target(dst_ip, src_ip, verbose)
                    if live:
                        live_hosts.append(dst_ip)
            elif '-' in ip_target:
                raise Exception("ERROR: ip range must be specified in the last octet only")

            # target ip has no dash; send ping
            else:
                dst_ip = ip_target
                live = ping_target(dst_ip, src_ip, verbose)
                if live:
                    live_hosts.append(dst_ip)

    if cidr:
        cidr_range = ipaddress.ip_network(cidr)
        for ip_target in cidr_range:
            dst_ip = str(ip_target)
            live = ping_target(dst_ip, src_ip, verbose)
            if live:
                live_hosts.append(dst_ip)

    if live_hosts:
        print(live_hosts)

def get_ip_range(ipRange):
    """get the start and end numbers for ip range to scan
    
    the 'ip' parameter contained a '-' (dash),
    therefore return the range of ips to loop.

    Parameters:
    -----------
    ipRange : str
        ip address with a '-' (dash)

    Returns:
    --------
    start : int
        start number of ip range
    end : int
        last number of ip range
    """

    ip_parts = ipRange.split('.')
    last_octet = ip_parts[-1]
    octet_parts = last_octet.split('-')
    start = octet_parts[0]
    end = octet_parts[1]

    return int(start), int(end)

def get_ip_list(ips):
    """split supplied IPs into a list

    Parameters:
    -----------
    ips : str
        two or more IPs in csv format

    Returns:
    --------
    ip_list : list
        two or more IPs
    """
    
    ip_list = []
    
    parts = ips.split(',')
    for part in parts:
        ip = part.strip()
        ip_list.append(ip)
    
    return ip_list

def ping_target(dest_ip, src_ip, verbose):
    """ping target ip
    
    Parameters:
    -----------
    dest_ip : str
        target ip address
    src_ip : str
        source ip address

    Returns:
    --------
    host_live : boolean
        target host is online
    """

    host_live = False
    
    if src_ip:
        myping = IP(dst = dest_ip, src = src_ip)/ICMP()
    else:
        myping = IP(dst = dest_ip)/ICMP()

    if verbose:
        print(f"ping {dest_ip}")
    res = sr1(myping, timeout=1, verbose=0)

    if res == None:
        if verbose:
            print(red(f"{dest_ip} - no response"))
        host_live = False
    else:
        print(green(f"{dest_ip} - is up"))
        host_live = True
    
    return host_live

if __name__ == "__main__":
    main()