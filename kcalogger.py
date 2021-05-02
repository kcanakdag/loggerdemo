import os
import subprocess
from datetime import datetime
import json


# netstat -antup – It shows you all the ports which are open and are listening. We can check for services which are
# running locally if they could be exploited or not.

# find / -perm -u=s -type f 2>/dev/null – It prints the executables which have SUID bit set

# sudo -l - Prints the commands which we are allowed to run as SUDO. Checking misconfigured sudo rights

class KcaLog:
    def __init__(self, log_path):
        if log_path[-1] != '/':
            log_path += '/'
        self.log_path = log_path
        self.create_log_file()
        pass

    @staticmethod
    def get_output(command):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                shell=True)
        return result.stdout

    def create_log_file(self):
        logfile_path = self.log_path + 'kcalogs.json'
        print(f"Using {logfile_path}")
        if os.path.isfile(logfile_path):
            # File exist
            with open(logfile_path, 'r') as logsfile:
                logs = json.load(logsfile)
                netstat_check, suid_check, sudo_check, scan_date = self.init_scan()
                logs[scan_date] = {'Netstat Check': netstat_check, 'SUID Check': suid_check,
                                   'SUDO -l Check': sudo_check}
            with open(logfile_path, 'w') as outfile:
                json.dump(logs, outfile)
            print(f"Saved logs in {logfile_path}")

        else:
            # File doesn't exist
            log_dict = {}
            netstat_check, suid_check, sudo_check, scan_date = self.init_scan()
            log_dict[scan_date] = {'Netstat Check': netstat_check, 'SUID Check': suid_check,
                                   'SUDO -l Check': sudo_check}
            with open(logfile_path, 'w') as outfile:
                json.dump(log_dict, outfile)
            print(f"Saved logs in {logfile_path}")

    def init_scan(self):
        check_services = self.get_output('netstat -antup').split('\n')
        check_suid = self.get_output('find / -perm -u=s -type f 2>/dev/null').split('\n')
        check_sudo = self.get_output('sudo -l').split('\n')
        now = datetime.now()
        dt_string = now.strftime('%d/%m/%Y %H:%M:%S')

        return check_services, check_suid, check_sudo, dt_string


if __name__ == '__main__':
    working_dir = './'
    run = KcaLog(working_dir)
