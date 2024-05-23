
import ipaddress,threading,subprocess,sys,argparse,keyboard

from ColorLib import GREEN,RED,YELLOW
from tp import write_interface_in_file

def get_ip_from_ip_conf_file():
    with open("info.txt", "r") as ipFile:
        file_conf = ipFile.readlines()
        ip_list = []
        for element in file_conf:
            if "IP:" in element in element:
                ip_with_suffix = element.split()[-1]
                clean_ip = ip_with_suffix.split('(')[0].split('/')[0]
                ip_list.append(clean_ip)
    return ip_list

def get_sub_mask():
    with open("info.txt", "r") as subFile:
        file_conf = subFile.readlines()
        sub_list = []
        for element in file_conf:
            if "Subnet Mask:" in element or "Mask:" in element:
                tmp = element.split()[-1]
                sub_list.append(tmp)
    return sub_list

def ping_network():
    ip_list = get_ip_from_ip_conf_file()
    sub_list = get_sub_mask()
    all_ip_sub = [ip_list, sub_list]

    for i, element in enumerate(all_ip_sub[0]):
        print(f"{i+1}. {element}")

    check_ip = False
    while not check_ip:
        try:
            choice_ip = input(f"{YELLOW}[?] Which network do you want to ping : ")
            if int(choice_ip) <= len(all_ip_sub[0]) and int(choice_ip) > 0:
                check_ip = True
            else:
                print(f"{RED}[⚠️] Please choose an available ip.")
                sys.exit(1)
        except ValueError:
            print(f"{RED}[⚠️] Please choose an available ip.") 
            sys.exit(1) 

    ip = all_ip_sub[0][int(choice_ip)-1]
    sub_mask = all_ip_sub[1][int(choice_ip)-1]
    cidr_mask = sum(bin(int(x)).count('1') for x in sub_mask.split('.'))

    network = str(ipaddress.ip_network(f"{ip}/{cidr_mask}", strict=False))
    print(f"{GREEN}[!] All Active host: {ipaddress.IPv4Network(network).num_addresses}")
   
    def ping_ip(ip):
            try : 
                res = subprocess.run(["ping","-c", "1", "-W", "1", str(ip)], capture_output=True)
                if res.returncode == 0:
                    print(f"{GREEN}[!] Active host: {ip}")
            except ValueError as e:
                print(f"{RED}[⚠️] Piging -> {ip}\nError: {e}")
    
    threads = []
    active_hosts = []

    for ip in ipaddress.IPv4Network(network).hosts():
            # Lambda => fonction anonym
            thread = threading.Thread(target=lambda: active_hosts.append(ping_ip(ip)))
            threads.append(thread)
            thread.start()

            for thread in threads :
                thread.join()

            with open('active_hosts.txt', 'w') as f:
                for host in active_hosts:
                    if host:
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
        if hasattr(args, 'ping'):
            ping_network()
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