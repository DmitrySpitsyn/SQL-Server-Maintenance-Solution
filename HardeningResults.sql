/*
	Version:
		2003.122203.01 - March, 2020
	Summary:  	
		This script was created in frames of CIS Microsoft SQL Server 2019 Benchmark (v1.0.0-11-27-2019)
		Any updates will be included in next release.

	Version Updates:
	16.03.2020: | Added by Dmitry Spitsyn
		# Configure structure with two tables as result


	16.03.2020: | Added by Dmitry Spitsyn
		# 1 Installation, Updates and Patches
		# 1.1	Ensure Latest SQL Server Service Packs and Hotfixes are Installed
		# 1.2	Ensure Single-Function Member Servers are Used
		# 2 Surface Area Reduction
		# 2.1	Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'
		# 2.2	Ensure 'CLR Enabled' Server Configuration Option is set to '0'
		# 2.3	Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'
		# 2.4	Ensure 'Database Mail XPs' Server Configuration Option is set to '0'
		# 2.5	Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'
		# 2.6	Ensure 'Remote Access' Server Configuration Option is set to '0'
		# 2.7	Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'
		# 2.8	Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'
		# 2.9	Ensure 'Trustworthy' Database Property is set to 'Off'
		# 2.10	Ensure Unnecessary SQL Server Protocols are set to 'Disabled'
		# 2.11	Ensure SQL Server is configured to use non-standard ports
		# 2.12	Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances
		# 2.13	Ensure the 'sa' Login Account is set to 'Disabled'
		# 2.14	Ensure the 'sa' Login Account has been renamed
		# 2.15	Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases
		# 2.16	Ensure no login exists with the name 'sa'
		# 2.17	Ensure 'xp_cmdshell' Server Configuration Option is set to '0' - until 2016
		# 3 Authentication and Authorization
		# 3.1	Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'
		# 3.2	Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases excluding the master, msdb and tempdb
		# 3.3	Ensure 'Orphaned Users' are Dropped From SQL Server Databases
		# 3.4	Ensure SQL Authentication is not used in contained databases
		# 3.5	Ensure the SQL Server’s MSSQL Service Account is Not an Administrator
		# 3.6	Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator
		# 3.7	Ensure the SQL Server’s Full-Text Service Account is Not an Administrator
		# 3.8	Ensure only the default permissions specified by Microsoft are granted to the public server role
		# 3.9	Ensure Windows BUILTIN groups are not SQL Logins
		# 3.10	Ensure Windows local groups are not SQL Logins
		# 3.11	Ensure the public role in the msdb database is not granted access to SQL Agent proxies
		# 4 Password Policies
		# 4.1	Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins
		# 4.2	Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role
		# 4.3	Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins
		# 5 Auditing and Logging
		# 5.1	Ensure 'Maximum number of error log files' is set to greater than or equal to '12'
		# 5.2	Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'
		# 5.3	Ensure 'Login Auditing' is set to 'failed logins'
		# 5.4	Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins'
		# 6 Application Development
		# 6.1	Ensure Database and Application User Input is Sanitized
		# 6.2	Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies
		# 7 Encryption
		# 7.1	Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases
		# 7.2	Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases
		# 8 Appendix: Additional Considerations
		# 8.1	Ensure 'SQL Server Browser Service' is configured correctly

	26.02.2020: | Added by Dmitry Spitsyn
		# 6.2 - change result in CLR Assembly Permission
		# 3.3 - exclude user 'MS_DataCollectorInternalUser'
	25.10.2019: | Added by Dmitry Spitsyn
		# 5.3 - check script functionality on different product versions
		# 5.4 - identify system configuration to issue a log entry and alert on unsuccessful logins to an administrative account
	11.10.2019: | Added by Dmitry Spitsyn
		# 2.16 - 'Auto Close' option - identify correct functionality
	27.09.2019: | Added by Dmitry Spitsyn
		# proved the case for options: "clr enabled","cross db ownership chaining","remote access","remote admin connections","default trace enabled"
	28.08.2019: | Added by Reiner Grosser
		Some topics are difficult to be selected depending on special verions, 
		due to unsharpness excluded or not displayed, for example regarding chapter 3. 
		- several "Authentication and Authorization" topics
		- Orphaned Users
		- Encryption
		Common Bayer Solution also discussed in ICS Audit reagarding SQL CCS Development/Integration and SQL Exception Solution.
	01.08.2019: | Added by Dmitry Spitsyn
		# New structure all queries
		# P.5.1  - extendet
		# P.2.16 - extendet
		# P.3.2  - extendet
		# P.3.4  - deleted (Database authentication applies only from: SQL Server 2012 (11.x))
	30.07.2019: | Added by Dmitry Spitsyn
		# 5 Auditing and Logging
		# 6 Application Development
		# 7 Encryption
	29.07.2019: | Added by Dmitry Spitsyn
		# 1 Installation, Updates and Patches
		# 2 Surface Area Reduction
		# 3 Authentication and Authorization
		# 4 Password Policies

	SQL Server Version: 2012/2014/2016/2017/2019

*/
SET NOCOUNT ON;
SET ANSI_WARNINGS OFF;
GO

	--------------------------------------------------------------------------------
	--| Declaring Variables
	--------------------------------------------------------------------------------
	DECLARE @HardeningResults BIT = 0
	--------------------------------------------------------------------------------
	--| END Declaring Variables
	--------------------------------------------------------------------------------

	IF OBJECT_ID('tempdb..#HardeningResultsSimple') IS NOT NULL
		DROP TABLE #HardeningResultsSimple;
	CREATE TABLE #HardeningResultsSimple (
		  [ID] INT IDENTITY(1, 1)
		, [CheckID] NVARCHAR(4)
		, [Name] NVARCHAR(MAX)
		, [Current Setting] NVARCHAR(128)
		, [Target Setting] NVARCHAR(128)
		, [Target Achieved] NVARCHAR(128)
	)

/*
	IF OBJECT_ID('tempdb..#HardeningResults') IS NOT NULL
		DROP TABLE #HardeningResults;
	IF @HardeningResults = 1
	BEGIN
		CREATE TABLE #HardeningResults (
			  [ID] INT IDENTITY(1, 1)
			, [FindingID] NVARCHAR(5)
			, [Severity] TINYINT
			, [Name] NVARCHAR(MAX)
			, [Current Setting] NVARCHAR(128)
			, [Target Setting] NVARCHAR(128)
			, [Target Achieved] NVARCHAR(128)
			, [Details] NVARCHAR(MAX)
		);
	END
*/

	IF OBJECT_ID('tempdb..#GlobalServerSettings') IS NOT NULL
		DROP TABLE #GlobalServerSettings;
	CREATE TABLE #GlobalServerSettings (
		  [name] NVARCHAR(128)
		, [DefaultValue] BIGINT
		, [CheckID] INT
		);
	INSERT INTO #GlobalServerSettings VALUES ( 'Ad Hoc Distributed Queries', 0, 21 );
	IF @@VERSION LIKE '%Microsoft SQL Server 2017%'
	BEGIN
		INSERT INTO #GlobalServerSettings VALUES ( 'clr enabled', 1, 22 );
	END
	ELSE
	BEGIN
		INSERT INTO #GlobalServerSettings VALUES ( 'clr enabled', 0, 22 );
	END
	INSERT INTO #GlobalServerSettings VALUES ( 'Database Mail XPs', 0, 24 );
	INSERT INTO #GlobalServerSettings VALUES ( 'default trace enabled', 1, 52 );
	INSERT INTO #GlobalServerSettings VALUES ( 'Ole Automation Procedures', 0, 25 );	
	INSERT INTO #GlobalServerSettings VALUES ( 'remote access', 1, 26 );
	INSERT INTO #GlobalServerSettings VALUES ( 'remote admin connections', 0, 27 );
	INSERT INTO #GlobalServerSettings VALUES ( 'scan for startup procs', 0, 28 );
	INSERT INTO #GlobalServerSettings VALUES ( 'xp_cmdshell', 0, 215 );

	/*	
		| 0.1 Information 
		|	Check Server Name and current patch level
	*/
	INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
	SELECT '-1', 'Server: ' + @@SERVERNAME + ' - Version: ' + CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(30)), '-', '-', '-'

	/*	
		| 1.1 Ensure Latest SQL Server Service Packs and Hotfixes are Installed (Not Scored)
	*/

	/*
		| 1.2 Ensure Single-Function Member Servers are Used (Not Scored)
	*/


	/*
		| 2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#AHDQ') IS NOT NULL
		DROP TABLE #AHDQ;
	CREATE TABLE #AHDQ (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #AHDQ (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.1', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #AHDQ ), CASE WHEN ( SELECT [Target] FROM #AHDQ ) = ( SELECT [ValueInUse] FROM #AHDQ ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries' DROP TABLE #AHDQ;
	END

	/*
		| 2.2 Ensure 'clr enabled' Server Configuration Option is set to '0'
	*/
	IF OBJECT_ID('tempdb..#CLRE') IS NOT NULL
		DROP TABLE #CLRE;
	CREATE TABLE #CLRE (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #CLRE (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'clr enabled'
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.2', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #CLRE ), CASE WHEN ( SELECT [Target] FROM #CLRE ) = ( SELECT [ValueInUse] FROM #CLRE ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'clr enabled' DROP TABLE #CLRE
	END

	/*
		| 2.3 Ensure 'cross db ownership chaining' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#CDBOC') IS NOT NULL
		DROP TABLE #CDBOC;
	CREATE TABLE #CDBOC (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #CDBOC (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'cross db ownership chaining'
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.3', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #CDBOC ), CASE WHEN ( SELECT [Target] FROM #CDBOC ) = ( SELECT [ValueInUse] FROM #CDBOC ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'cross db ownership chaining' DROP TABLE #CDBOC;
	END

	/*
		| 2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#DBXPs') IS NOT NULL
		DROP TABLE #DBXPs;
	CREATE TABLE #DBXPs (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #DBXPs (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'Database Mail XPs'
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.4', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #DBXPs ), CASE WHEN ( SELECT [Target] FROM #DBXPs ) = ( SELECT [ValueInUse] FROM #DBXPs ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'Database Mail XPs' DROP TABLE #DBXPs;
	END

	/*
		| 2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#OAP') IS NOT NULL
		DROP TABLE #OAP;
	CREATE TABLE #OAP (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #OAP (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'Ole Automation Procedures';
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.5', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #OAP ), CASE WHEN ( SELECT [Target] FROM #OAP ) = ( SELECT [ValueInUse] FROM #OAP ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'Ole Automation Procedures' DROP TABLE #OAP;
	END

	/*
		| 2.6 Ensure 'remote access' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#RASC') IS NOT NULL
		DROP TABLE #RASC;
	CREATE TABLE #RASC (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #RASC (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'remote access';
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.6', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #RASC ), CASE WHEN ( SELECT [Target] FROM #RASC ) = ( SELECT [ValueInUse] FROM #RASC ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'remote access' DROP TABLE #RASC;
	END

	/*
		| 2.7 Ensure 'remote admin connections' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#RACSC') IS NOT NULL
		DROP TABLE #RACSC;
	CREATE TABLE #RACSC (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #RACSC (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;
	END
	BEGIN
	IF SERVERPROPERTY('IsClustered') = 0
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			SELECT '2.7', name, CAST(value_in_use AS INT), ( SELECT [Target] FROM #RACSC ), CASE WHEN ( SELECT [Target] FROM #RACSC ) = ( SELECT [ValueInUse] FROM #RACSC ) THEN 'Yes' ELSE 'No' END
			FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;
		END
		ELSE
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			SELECT '2.7', name, CAST(value_in_use AS INT), 1, CASE WHEN 1 = ( SELECT [ValueInUse] FROM #RACSC ) THEN 'Yes' ELSE 'No' END
			FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 1;
		END DROP TABLE #RACSC;
	END

	/*
		| 2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#SFSP') IS NOT NULL
		DROP TABLE #SFSP;
	CREATE TABLE #SFSP (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #SFSP (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'scan for startup procs'
	END
	BEGIN
	/* IF Replication = True */
	IF EXISTS( 
		SELECT name, is_published, is_subscribed, is_merge_published, is_distributor FROM sys.databases WHERE is_published = 1 OR is_subscribed = 1 OR is_merge_published = 1 OR is_distributor = 1
		)
		BEGIN
			/* and other procedures then 'sp_ssis_startup' are activated at start up */
			IF ( SELECT name FROM sys.objects
			WHERE type = 'P' AND OBJECTPROPERTY(object_id, 'ExecIsStartup') = 1 ) <> 'sp_ssis_startup'
			BEGIN
				INSERT INTO #HardeningResultsSimple ([CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved])
					SELECT '2.8', name		--Replication requires this setting to be enabled (Target Achieved = 1)
						, CAST(value_in_use AS INT), ( SELECT [Target] FROM #SFSP ), CASE WHEN ( SELECT [Target] FROM #SFSP ) = ( SELECT [ValueInUse] FROM #SFSP ) THEN 'Yes' ELSE 'No' END
					FROM sys.configurations WHERE name = 'scan for startup procs'
			END
			ELSE
			BEGIN
				INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
					SELECT '2.8', name		-- Replication requires this setting to be enabled (Target Achieved = 1)
						, CAST(value_in_use AS INT), 1, CASE WHEN 1 = ( SELECT [ValueInUse] FROM #SFSP ) THEN 'Yes' ELSE 'No' END
					FROM sys.configurations WHERE name = 'scan for startup procs'
			END
		END
	END
	BEGIN
		IF ( SELECT name FROM sys.objects WHERE type = 'P' AND OBJECTPROPERTY(object_id, 'ExecIsStartup' ) = 1 ) <> 'sp_ssis_startup'
		BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			SELECT '2.8', name, CAST(value_in_use AS INT) , 1, CASE WHEN 1 = ( SELECT [ValueInUse] FROM #SFSP ) THEN 'Yes' ELSE 'No' END
			FROM sys.configurations WHERE name = 'scan for startup procs'
		END
		ELSE
		BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			SELECT '2.8', name, CAST( value_in_use AS INT ), ( SELECT [Target] FROM #SFSP ), CASE WHEN ( SELECT [Target] FROM #SFSP ) = ( SELECT [ValueInUse] FROM #SFSP ) THEN 'Yes' ELSE 'No' END
			FROM sys.configurations WHERE name = 'scan for startup procs'
		END DROP TABLE #SFSP;
	END

	/*
		| 2.9 Ensure 'Trustworthy' Database Property is set to 'Off' (Scored)
	*/
	IF OBJECT_ID('tempdb..#TDBP') IS NOT NULL
		DROP TABLE #TDBP;
	CREATE TABLE #TDBP (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #TDBP (
		  [ValueInUse]
		, [Target]
		)
		SELECT CASE WHEN (SELECT COUNT(name) FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb') > 0 THEN 1 ELSE 0 END, 0
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		VALUES ( '2.9', 'The Trustworthy database setting', (SELECT [ValueInUse] FROM #TDBP ), ( SELECT [Target] FROM #TDBP ), CASE WHEN ( SELECT [Target] FROM #TDBP ) = ( SELECT [ValueInUse] FROM #TDBP ) THEN 'Yes' ELSE 'No' END ) DROP TABLE #TDBP;
	END


	/*
		| 2.10 Ensure Unnecessary SQL Server Protocols are set to 'Disabled' (Not Scored)
	*/
	IF OBJECT_ID('tempdb..#USPNP') IS NOT NULL
		DROP TABLE #USPNP;
	CREATE TABLE #USPNP (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #USPNP (
		  [ValueInUse]
		, [Target]
		)
		SELECT CASE WHEN ( SELECT value_data FROM sys.dm_server_registry WHERE registry_key LIKE '%np' AND value_name = 'Enabled' ) = 1 THEN 1 ELSE 0 END, 0
	END
	IF OBJECT_ID('tempdb..#USPSM') IS NOT NULL
		DROP TABLE #USPSM;
	CREATE TABLE #USPSM (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #USPSM (
		  [ValueInUse]
		, [Target]
		)
		SELECT CASE WHEN ( SELECT value_data FROM sys.dm_server_registry WHERE registry_key LIKE '%sm' AND value_name = 'Enabled' ) = 1 THEN 1 ELSE 0 END, 1
	END
	IF OBJECT_ID('tempdb..#USPTCP') IS NOT NULL
		DROP TABLE #USPTCP;
	CREATE TABLE #USPTCP (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #USPTCP (
		  [ValueInUse]
		, [Target]
		)
		SELECT CASE WHEN ( SELECT value_data FROM sys.dm_server_registry WHERE registry_key LIKE '%tcp' AND value_name = 'Enabled' ) = 1 THEN 1 ELSE 0 END, 1
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		VALUES ( '2.10', 'Unnecessary SQL Server Protocols', CASE WHEN ( SELECT [ValueInUse] FROM #USPNP ) <> 0 OR ( SELECT [ValueInUse] FROM #USPSM) <> 1 OR ( SELECT [ValueInUse] FROM #USPTCP ) <> 1 THEN 1 ELSE 0 END, 0, CASE WHEN ( SELECT [ValueInUse] FROM #USPNP ) = 0 AND ( SELECT [ValueInUse] FROM #USPSM ) = 1 AND ( SELECT [ValueInUse] FROM #USPTCP ) = 1 THEN 'Yes' ELSE 'No' END ) DROP TABLE #USPTCP; DROP TABLE #USPNP; DROP TABLE #USPSM;
	END


	/*
		| 2.11 Ensure SQL Server is configured to use non-standard ports (Scored)
		| We will NOT follow the recommendation (see comment)
	*/
	/*
		| 2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored)
		| We will NOT follow the recommendation (see comment)
	*/
	/*
		| 2.13 Ensure 'sa' Login Account is set to 'Disabled' (Scored)
		| Created as example. It must be already done in LEV
	*/
	IF OBJECT_ID('tempdb..#SALA') IS NOT NULL
		DROP TABLE #SALA;
	CREATE TABLE #SALA (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #SALA (
		  [ValueInUse]
		, [Target]
		)
		VALUES(( SELECT is_disabled FROM sys.server_principals WHERE sid = 0x01 ), 1)
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		VALUES ( '2.13', '''sa'' Login Account is set to ''Disabled''', ( SELECT [ValueInUse] FROM #SALA), ( SELECT [Target] FROM #SALA ), CASE WHEN ( SELECT [Target] FROM #SALA ) = ( SELECT [ValueInUse] FROM #SALA ) THEN 'Yes' ELSE 'No' END ) DROP TABLE #SALA;
	END

	/*
		| 2.14 Ensure 'sa' Login Account has been renamed (Scored)
		| We will NOT follow the recommendation
	*/
	/*
		| 2.15 Ensure 'xp_cmdshell' Server Configuration Option is set to '0' (Scored)
	*/
	IF OBJECT_ID('tempdb..#XPSCO') IS NOT NULL
		DROP TABLE #XPSCO;
	CREATE TABLE #XPSCO (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #XPSCO (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 0 FROM sys.configurations WHERE name = 'xp_cmdshell'
	END
	BEGIN	
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '2.15', name, ( SELECT [ValueInUse] FROM #XPSCO), (SELECT [Target] FROM #XPSCO ), CASE WHEN ( SELECT [Target] FROM #XPSCO ) = ( SELECT [ValueInUse] FROM #XPSCO ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations WHERE name = 'xp_cmdshell'
	END DROP TABLE #XPSCO;

	/*
		| 2.16 Ensure 'AUTO_CLOSE OFF' is set on contained databases (Scored)
		| Beginning with SQL Server 2012 and beyond
	*/
	DECLARE @vACO VARCHAR(128) = ( SELECT name FROM sys.all_columns WHERE name = 'containment' AND object_id = OBJECT_ID('sys.databases' ) AND EXISTS ( SELECT name FROM sys.databases WHERE is_auto_close_on = 1 ))
	BEGIN
		IF @vACO IS NOT NULL
			BEGIN 
				INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
					SELECT '2.16', '''Auto Close'' Option on [' + name + ']', 1, 0, CASE WHEN name IS NULL THEN 'Yes' ELSE 'No' END FROM sys.databases WHERE is_auto_close_on = 1
			END 
		ELSE
			BEGIN
				INSERT INTO #HardeningResultsSimple ([CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved])
					SELECT '2.16', '''Auto Close'' Option on [' + name + ']', 0, 0, CASE WHEN name IS NOT NULL THEN 'Yes' ELSE 'No' END FROM sys.databases
			END
	END

	/*
		| 2.17 Ensure no login exists with the name 'sa' (Scored)
		|      We will NOT follow the recommendation
	*/
	/*
		| 3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' (Scored)
		|     Is default in LEV. Some application still need SQL Authentication
	*/
	/*
		| 3.2 Ensure CONNECT permissions on the 'guest user' is Revoked within
			  all SQL Server databases excluding the master, msdb and tempdb (Scored)
	*/
	EXEC dbo.sp_MSforeachdb 'USE [?];
	IF OBJECT_ID(''tempdb..#CPGU'') IS NOT NULL
		DROP TABLE #CPGU;
	CREATE TABLE #CPGU (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
		INSERT INTO #CPGU (
			  [ValueInUse]
			, [Target]
			)
			VALUES( CASE WHEN
				(
				SELECT COUNT(DB_NAME()) 
				FROM sys.database_permissions
				WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID(''guest'') AND [state_desc] LIKE ''GRANT%'' AND [permission_name] = ''CONNECT'' AND DB_NAME() NOT IN ( ''master'', ''tempdb'', ''msdb'' )) = 0 THEN 0 ELSE 1 END, 0
			)
	END
	INSERT INTO #HardeningResultsSimple ([CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved])
	SELECT ''3.2'', ''CONNECT permissions for ''''guest'''' user'', ''['' + DB_NAME() + '']'', ( SELECT [Target] FROM #CPGU ), CASE WHEN ( SELECT [Target] FROM #CPGU ) = ( SELECT [ValueInUse] FROM #CPGU ) THEN ''Yes'' ELSE ''No'' END
	FROM [?].sys.database_permissions WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID(''guest'') AND [state_desc] LIKE ''GRANT%'' AND [permission_name] = ''CONNECT'' AND DB_NAME() NOT IN ( ''master'', ''tempdb'', ''msdb'' ) DROP TABLE #CPGU'

	/*
		| 3.3 Ensure 'Orphaned Users' are Dropped From SQL Server Databases (Scored)
	*/
	IF OBJECT_ID('tempdb..#OU') IS NOT NULL
		DROP TABLE #OU;
	CREATE TABLE #OU (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
		INSERT INTO #OU (
			  [ValueInUse]
			, [Target]
			)
		VALUES( CASE WHEN ( SELECT COUNT(name) FROM sys.sysusers WHERE SID IS NOT NULL AND SID <> 0X0 AND ISLOGIN = 1 AND SID NOT IN (SELECT SID FROM sys.syslogins )) IS NULL	THEN 0 ELSE 1 END, 0 )
	END
	BEGIN
		EXEC sp_MSforeachdb 'USE [?];
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
				SELECT DISTINCT ''3.3'', ''Orphaned User'', ''['' + NAME + ''] in ['' + DB_NAME() + '']'', ( SELECT [Target] FROM #OU ), CASE WHEN ( SELECT [Target] FROM #OU ) = ( SELECT [ValueInUse] FROM #OU ) THEN ''Yes'' ELSE ''No'' END
				FROM [?].sys.sysusers WHERE SID IS NOT NULL AND SID <> 0X0 AND ISLOGIN = 1 AND SID NOT IN ( SELECT SID FROM sys.syslogins ) AND NAME <> ''MS_DataCollectorInternalUser'''
	END DROP TABLE #OU

	/*
		| 3.4 Ensure SQL Authentication is not used in contained databases (Scored)
		|     Currently contained DBs are not used in LEV
	*/
	/*
		| 3.5 Ensure the SQL Server?s MSSQL Service Account is Not an Administrator (Scored)
		|     This recommendation refers to WINDOWS administrators (not SQL Server sysadmins)
	*/
	/*
		| 3.6 Ensure the SQL Server?s SQLAgent Service Account is Not an Administrator (Scored)
		|     This recommendation refers to WINDOWS administrators (not SQL Server sysadmins)
	*/
	/*
		| 3.7 Ensure the SQL Server?s Full-Text Service Account is Not an Administrator (Scored)
		|     This recommendation refers to WINDOWS administrators (not SQL Server sysadmins)
	*/
	/*
		| 3.8 Ensure only the default permissions specified by Microsoft are granted to the public server role (Scored)
	*/
	IF OBJECT_ID('tempdb..#PGPSR') IS NOT NULL
		DROP TABLE #PGPSR;
	CREATE TABLE #PGPSR (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF NOT EXISTS( SELECT * FROM master.sys.server_permissions WHERE ( grantee_principal_id = SUSER_SID(N'public') AND state_desc LIKE 'GRANT%' )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'VIEW ANY DATABASE' AND class_desc = 'SERVER' )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 2 )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 3 )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 4 )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 5 )
		)
		BEGIN
			INSERT INTO #PGPSR (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #PGPSR (
				  [ValueInUse]
				, [Target]
				)
			VALUES (1, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ([CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved])
			VALUES ( '3.8', 'Default permissions for public server role', ( SELECT [ValueInUse] FROM #PGPSR ), ( SELECT [Target] FROM #PGPSR ), CASE WHEN ( SELECT [ValueInUse] FROM #PGPSR ) = ( SELECT [Target] FROM #PGPSR ) THEN 'Yes' ELSE 'No' END )
		END
	DROP TABLE #PGPSR;

	/*
		| 3.9 Ensure Windows BUILTIN groups are not SQL Logins (Scored)
	*/
	IF OBJECT_ID('tempdb..#WBI') IS NOT NULL
		DROP TABLE #WBI;
	CREATE TABLE #WBI (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF EXISTS( SELECT pr.[name], pe.[permission_name], pe.[state_desc]
		FROM sys.server_principals pr
			JOIN sys.server_permissions pe
				ON pr.principal_id = pe.grantee_principal_id
		WHERE pr.name LIKE 'BUILTIN%'
		)
		BEGIN
			INSERT INTO #WBI (
				  [ValueInUse]
				, [Target]
				)
			VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #WBI (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '3.9', 'Windows ''BUILTIN'' groups are SQL Logins', ( SELECT [ValueInUse] FROM #WBI ), ( SELECT [Target] FROM #WBI ), CASE WHEN ( SELECT [ValueInUse] FROM #WBI ) = ( SELECT [Target] FROM #WBI ) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #WBI;

	/*
		| 3.10 Ensure Windows local groups are not SQL Logins (Scored)
	*/
	IF OBJECT_ID('tempdb..#WLG') IS NOT NULL
		DROP TABLE #WLG;
	CREATE TABLE #WLG (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF EXISTS( SELECT pr.[name]
		, pe.[permission_name]
		, pe.[state_desc]
		FROM sys.server_principals pr JOIN sys.server_permissions pe
			ON pr.[principal_id] = pe.[grantee_principal_id]
		WHERE pr.[type_desc] = 'WINDOWS_GROUP'
			AND pr.[name] LIKE CAST(SERVERPROPERTY('MachineName') AS NVARCHAR) + '%'
		)
		BEGIN
			INSERT INTO #WLG (
				  [ValueInUse]
				, [Target]
				)
			VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #WLG (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ([CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved])
			VALUES ( '3.10', 'Windows local groups are SQL Logins', ( SELECT [ValueInUse] FROM #WLG ), ( SELECT [Target] FROM #WLG ), CASE WHEN ( SELECT [ValueInUse] FROM #WLG ) = ( SELECT [Target] FROM #WLG ) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #WLG;

	/*
		| 3.11 Ensure the public role in the msdb database is not granted access to SQL Agent proxies (Scored)
	*/
	IF OBJECT_ID('tempdb..#PRP') IS NOT NULL
		DROP TABLE #PRP;
	CREATE TABLE #PRP (
		  [ValueInUse] INT
		, [Target] INT
	)
	USE [msdb]
	GO
	IF EXISTS(
		SELECT sp.name AS proxyname FROM dbo.sysproxylogin spl JOIN sys.database_principals dp
			ON dp.sid = spl.sid JOIN sysproxies sp
			ON sp.proxy_id = spl.proxy_id
		WHERE principal_id = USER_ID('public')
		)
		BEGIN
			INSERT INTO #PRP (
				  [ValueInUse]
				, [Target]
				)
			VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #PRP (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '3.11', 'The ''public'' role in [msdb] database', ( SELECT [ValueInUse] FROM #PRP ), ( SELECT [Target] FROM #PRP ), CASE WHEN ( SELECT [ValueInUse] FROM #PRP ) = ( SELECT [Target] FROM #PRP ) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #PRP;

	/*
		| 4.1 Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Not Scored)
		|     Cannot be checked by CCS as this box is cleared after 1st PW change
		|     Can only be regulated via SOP
	*/
	/*
		| 4.2 Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored)
	*/
	IF OBJECT_ID('tempdb..#CEO') IS NOT NULL
		DROP TABLE #CEO;
	CREATE TABLE #CEO (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF EXISTS( SELECT l.[name], 'sysadmin membership' FROM sys.sql_logins AS l
		WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1
			AND l.is_expiration_checked <> 1
		UNION ALL
		SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
		FROM sys.sql_logins AS l JOIN sys.server_permissions AS p
			ON l.principal_id = p.grantee_principal_id
		WHERE p.type = 'CL' AND p.state IN ( 'G', 'W' )
			AND l.is_expiration_checked <> 1
		)
		BEGIN
			INSERT INTO #CEO (
				  [ValueInUse]
				, [Target]
				)
			VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #CEO (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '4.2', '''CHECK_EXPIRATION'' Option', ( SELECT [ValueInUse] FROM #CEO ), ( SELECT [Target] FROM #CEO ), CASE WHEN ( SELECT [ValueInUse] FROM #CEO ) = ( SELECT [Target] FROM #CEO ) THEN 'Yes' ELSE 'No' END )
		END
	DROP TABLE #CEO;

	/*
		| 4.3 Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins (Scored)
	*/
	IF OBJECT_ID('tempdb..#CPO') IS NOT NULL
		DROP TABLE #CPO;
	CREATE TABLE #CPO (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF EXISTS ( SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0 AND is_disabled != 1 )
		BEGIN
			INSERT INTO #CPO (
				  [ValueInUse]
				, [Target]
				)
			VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #CPO (
				  [ValueInUse]
				, [Target]
				)
				VALUES (0, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '4.3', '''CHECK_POLICY'' Option', ( SELECT [ValueInUse] FROM #CPO ), ( SELECT [Target] FROM #CPO ), CASE WHEN ( SELECT [ValueInUse] FROM #CPO ) = ( SELECT [Target] FROM #CPO ) THEN 'Yes' ELSE 'No' END )
		END
	DROP TABLE #CPO;

	/*
		| 5.1 Ensure 'Maximum number of error log files' is set to greater than or equal to '12' (Scored)
	*/
	IF OBJECT_ID('tempdb..#MNEL') IS NOT NULL
		DROP TABLE #MNEL;
	CREATE TABLE #MNEL (
		  [ValueInUse] INT
		, [Target] INT
	)
	DECLARE @NumErrorLogs INT;
	EXEC master.sys.xp_instance_regread
		  N'HKEY_LOCAL_MACHINE'
		, N'Software\Microsoft\MSSQLServer\MSSQLServer'
		, N'NumErrorLogs'
		, @NumErrorLogs OUTPUT;
	IF( SELECT ISNULL( @NumErrorLogs, -1 )) >= 12
		BEGIN
			INSERT INTO #MNEL (
				  [ValueInUse]
				, [Target]
				)
			VALUES (( SELECT ISNULL( @NumErrorLogs, -1 )), 99 )
		END
		ELSE
		BEGIN
			INSERT INTO #MNEL (
				  [ValueInUse]
				, [Target]
				)
			VALUES (( SELECT ISNULL( @NumErrorLogs, -1 )), 99 )
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '5.1', 'Maximum number of error log files', ( SELECT [ValueInUse] FROM #MNEL ), ( SELECT [Target] FROM #MNEL ), CASE WHEN ( SELECT [ValueInUse] FROM #MNEL ) = ( SELECT [Target] FROM #MNEL ) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #MNEL;

	/*
		| 5.2 Ensure 'default trace enabled' Server Configuration Option is set to '1' (Scored)
	*/
	IF OBJECT_ID('tempdb..#DTE') IS NOT NULL
		DROP TABLE #DTE;
	CREATE TABLE #DTE (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
	INSERT INTO #DTE (
		  [ValueInUse]
		, [Target]
		)
		SELECT CAST(value_in_use AS INT), 1
		FROM sys.configurations
		WHERE name = 'default trace enabled';
	END
	BEGIN
		INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
		SELECT '5.2', name
			, CAST( value_in_use AS INT ), ( SELECT [Target] FROM #DTE )
			, CASE WHEN ( SELECT [Target] FROM #DTE ) = ( SELECT [ValueInUse] FROM #DTE ) THEN 'Yes' ELSE 'No' END
		FROM sys.configurations
		WHERE name = 'default trace enabled';
	END DROP TABLE #DTE;

	/*
		| 5.3 Ensure 'Login Auditing' is set to 'failed logins' (Scored)
		| 0 - None | 1 - Successful logins only | 2 - Failed logins only | 3 - Both failed and successful logins
	*/
	IF OBJECT_ID('tempdb..#LAFL') IS NOT NULL
		DROP TABLE #LAFL;
	CREATE TABLE #LAFL (
		  [ValueInUse] INT
		, [Target] INT
	)
	DECLARE @NumAuditLevel INT;
	EXEC master.sys.xp_instance_regread
		  N'HKEY_LOCAL_MACHINE'
		, N'Software\Microsoft\MSSQLServer\MSSQLServer'
		, N'AuditLevel'
		, @NumAuditLevel OUTPUT;

	IF( SELECT ISNULL( @NumAuditLevel, -1 ) ) <> 3 -- see details above
		BEGIN
			INSERT INTO #LAFL ( [ValueInUse], [Target] )
			VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #LAFL ( [ValueInUse], [Target] )
			VALUES (0, 0)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ('5.3', 'Audit level', ( SELECT [ValueInUse] FROM #LAFL ), ( SELECT [Target] FROM #LAFL ), CASE WHEN ( SELECT [ValueInUse] FROM #LAFL ) = ( SELECT [Target] FROM #LAFL ) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #LAFL;

	/*
		| 5.4 Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins' (Scored)
	*/
	IF OBJECT_ID('tempdb..#AFSL') IS NOT NULL
		DROP TABLE #AFSL;
	CREATE TABLE #AFSL (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF ( SELECT SAD.audit_action_name
		FROM sys.server_audit_specification_details AS SAD
			JOIN sys.server_audit_specifications AS SA
				ON SAD.server_specification_id = SA.server_specification_id
			JOIN sys.server_audits AS S
				ON SA.audit_guid = S.audit_guid
		WHERE SAD.audit_action_id IN ( 'CNAU', 'LGFL', 'LGSD' ) 
			) NOT IN ( 'AUDIT_CHANGE_GROUP', 'FAILED_LOGIN_GROUP', CONVERT(INT,
				CASE WHEN ISNUMERIC( CONVERT(VARCHAR(28), 'SUCCESSFUL_LOGIN_GROUP' )) = 1 THEN CONVERT(VARCHAR(28), 'SUCCESSFUL_LOGIN_GROUP' ) END )
		)
		BEGIN
			INSERT INTO #AFSL ( [ValueInUse], [Target] )
			VALUES (( SELECT COUNT(SAD.audit_action_name)
					FROM sys.server_audit_specification_details AS SAD
						JOIN sys.server_audit_specifications AS SA
							ON SAD.server_specification_id = SA.server_specification_id
						JOIN sys.server_audits AS S
							ON SA.audit_guid = S.audit_guid
					WHERE SAD.audit_action_id IN ( 'CNAU', 'LGFL', 'LGSD' )), 1 )
		END
		ELSE
		BEGIN
			INSERT INTO #AFSL ( [ValueInUse], [Target] )
			VALUES (( SELECT COUNT(SAD.audit_action_name)
					FROM sys.server_audit_specification_details AS SAD
						JOIN sys.server_audit_specifications AS SA
							ON SAD.server_specification_id = SA.server_specification_id
						JOIN sys.server_audits AS S
							ON SA.audit_guid = S.audit_guid
					WHERE SAD.audit_action_id IN ( 'CNAU', 'LGFL', 'LGSD' )), 1 )
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '5.4', 'SQL Server Audit', ( SELECT [ValueInUse] FROM #AFSL ), ( SELECT [Target] FROM #AFSL ), CASE WHEN ( SELECT [ValueInUse] FROM #AFSL ) = ( SELECT [Target] FROM #AFSL ) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #AFSL;

	/*
		| 6.1 Ensure Sanitize Database and Application User Input is Sanitized (Not Scored)
		|     Must be controlled by the application owners
	*/
	/*
		| 6.2 Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies (Scored)
	*/
	IF OBJECT_ID('tempdb..#CLRA') IS NOT NULL
		DROP TABLE #CLRA;
	CREATE TABLE #CLRA (
		  [ValueInUse] INT
		, [Target] INT
	)
	IF NOT EXISTS( SELECT name, permission_set_desc
		FROM sys.assemblies
		WHERE is_user_defined = 1 )
		BEGIN
			INSERT INTO #CLRA (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #CLRA (
				  [ValueInUse]
				, [Target]
				)
			VALUES (0, 1)
		END
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
			VALUES ( '6.2', 'CLR Assembly Permission', ( SELECT [ValueInUse] FROM #CLRA ), ( SELECT [Target] FROM #CLRA ), CASE WHEN ( SELECT [ValueInUse] FROM #CLRA ) = ( SELECT [Target] FROM #CLRA) THEN 'Yes' ELSE 'No' END )
		END DROP TABLE #CLRA;

	/*
		| 7.1 Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Scored)
	*/
	IF OBJECT_ID('tempdb..#SKEA') IS NOT NULL
		DROP TABLE #SKEA;
	CREATE TABLE #SKEA (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
		INSERT INTO #SKEA (
			  [ValueInUse]
			, [Target]
			)
		VALUES( CASE WHEN ( SELECT COUNT(name) FROM sys.symmetric_keys WHERE algorithm_desc IN ( 'AES_128','AES_192','AES_256' ) AND DB_ID() > 4) IS NULL THEN 0 ELSE 1 END, 0 )
	END
	BEGIN
		EXEC sp_MSforeachdb 'USE [?];
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
				SELECT DISTINCT ''7.1'', ''Encryption algorithm for Symmetric Key'', ''['' + NAME + ''] in ['' + DB_NAME() + '']'', ( SELECT [Target] FROM #SKEA ), CASE WHEN ( SELECT [Target] FROM #SKEA ) = ( SELECT [ValueInUse] FROM #SKEA ) THEN ''Yes'' ELSE ''No'' END
				FROM sys.symmetric_keys
				WHERE algorithm_desc IN ( ''AES_128'',''AES_192'',''AES_256'' ) AND DB_ID() > 4'
	END DROP TABLE #SKEA;

	/*
		| 7.2 Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases (Scored)
	*/
	IF OBJECT_ID('tempdb..#AKS') IS NOT NULL
		DROP TABLE #AKS;
	CREATE TABLE #AKS (
		  [ValueInUse] INT
		, [Target] INT
	)
	BEGIN
		INSERT INTO #AKS (
			  [ValueInUse]
			, [Target]
			)
		VALUES( CASE WHEN ( SELECT COUNT(name) FROM sys.symmetric_keys WHERE key_length < 2048 AND DB_ID() > 4 ) IS NULL THEN 0 ELSE 1 END, 0 )
	END
	BEGIN
		EXEC sp_MSforeachdb 'USE [?];
		BEGIN
			INSERT INTO #HardeningResultsSimple ( [CheckID], [Name], [Current Setting], [Target Setting], [Target Achieved] )
				SELECT ''7.2'', ''Asymmetric Key size to low'', ''['' + NAME + ''] in ['' + DB_NAME() + '']'', ( SELECT [Target] FROM #AKS ), CASE WHEN ( SELECT [Target] FROM #AKS ) = ( SELECT [ValueInUse] FROM #AKS ) THEN ''Yes'' ELSE ''No'' END
				FROM sys.symmetric_keys
				WHERE key_length < 2048 AND DB_ID() > 4
		END'
	END DROP TABLE #AKS;

SELECT [Name], [Current Setting], [Target Setting], [Target Achieved]
FROM  #HardeningResultsSimple
ORDER BY [Target Achieved], [Name] ASC