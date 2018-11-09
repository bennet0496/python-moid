# VMware MoID Python Script

The Script Generates an Overview for VMs in a vCenter and let's you directly connect to an VM via thier MoId

Sample output
```
Name                      | PowerState | MoID     | Path                     | IP             | Version | ToolsVersion | ToolsVersionStatus     | Guest OS                                    
--------------------------+------------+----------+--------------------------+----------------+---------+--------------+------------------------+---------------------------------------------
VM1                       | poweredOff | vm-1337  | /user                    | None           | vmx-13  | 2147483647   | guestToolsUnmanaged    | CentOS 7 (64 Bit)                           
VM2 with a very long name | poweredOff | vm-77777 | /user/subdir             | 192.168.13.37  | vmx-10  | None         | guestToolsCurrent      | FreeBSD (64 Bit)                            
VM3                       | poweredOff | vm-54321 | /otheruser               | None           | vmx-10  | 9354         | guestToolsNeedUpgrade  | Microsoft Windows 7 (64 Bit)                
```
## Usage
```
moid.py [-c vm-moid] [-r] [-v] [-l] [-h]
```
| Argument | Effect |
|----------|--------|
| |generate an overview table|
|--connect=vm-moid, -c vm-moid|Connect to VMRC console by VM MoId|
|--reset, -r|Reset the current configuration|
|--version, -v|Print version and exit|
|--licence, -l|Print Licence and exit|
|--help, -h|Print this help and exit|
    
the config is under ~/.pymoid/config.

The configuration is in JSON with the options:
 - "host" which is the hostname of the vCenter
 - "port" which is the port
 - "user" which is your username to login
 - and "pass" which is either your encrypted password or `KEYRING` to search your password in the systems keyring

 ### Dependencies
 the script needs openSSL bindings for python and the VMware Library [pyvmomi](https://github.com/vmware/pyvmomi)
 ```bash
 pip install pyOpenSSL # or
 apt install python3-openssl
 pip install pyvmomi
 ```

