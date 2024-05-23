import ipaddress,threading,subprocess,sys,argparse,keyboard
import socket

from ColorLib import GREEN,RED,CYAN,YELLOW,GREEN
from tp_2 import get_ip_from_ip_conf_file,get_sub_mask,write_interface_in_file

def socket_scan(network):
    port_list = [80,443,22,23,8080,8888]
    active_hosts_ports = []

    for ip in ipaddress.IPv4Network(network).hosts():
        for port in port_list:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    active_hosts_ports.append((str(ip), port))
                s.close()
                sys.exit(0)
            except ValueError as e:
                print(f"{RED}Error: {e}")
    print(f"{GREEN}Active host ports: {CYAN}{active_hosts_ports}")

    with open('active_hosts_ports.txt', 'w') as f:
        for host in active_hosts_ports:
            f.write(host + "\n")

# Main function
def main():
    parser = argparse.ArgumentParser(description='PYTHON EXERCICES')
    parser.add_argument('-o', '--output', nargs='?', const='export_results.txt' ,help='Export the results to a file & display the result.')
    parser.add_argument('-p', '--ping', nargs='?', const='default', default=argparse.SUPPRESS, help='Scan with ping command')
    parser.add_argument('-s','--scan', action='store_true',help='Scan with Socket.')

    args = parser.parse_args()
    results = []
    write_interface_in_file()
    try:
        if args.scan:
            ip_list = get_ip_from_ip_conf_file()
            user_choice = input(f"{YELLOW}[?] Which interfaces do you choose  {ip_list} :" )

            if user_choice in ip_list:
                print(f"{GREEN}Scan with {CYAN}{user_choice} ")
                sub_list = get_sub_mask()
                index = ip_list.index(user_choice)
                sub_mask = sub_list[index]
                cidr_mask = sum(bin(int(x)).count('1') for x in sub_mask.split('.'))
                network = str(ipaddress.ip_network(f"{user_choice}/{cidr_mask}", strict=False))
                socket_scan(network)
        else:
            results = []
        if args.output is not None:
            with open(args.output, 'w') as file:
                for line in results:
                    file.write(line + "\n")
        else:
            for line in results:
                print(line)
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
