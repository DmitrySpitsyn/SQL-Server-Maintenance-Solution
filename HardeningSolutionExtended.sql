/*
  Version:	2004.182804 - April, 2020
  Summary:
		This solution was created partly based on https://www.cisecurity.org (State: 31 July, 2019).
		Allows to completely lock down a server, except for the particular services that it requires to perform specific duties.
		Some of the features and services, provided by default, may not be necessary, and enabling them could adversely affect the security of the system.
		You should understand all hardening techniques available so that you can determine which hardening strategies work best for your organization. 
		Make sure that not every hardening technique works for everyone.
		Balancing operational consistency and performance monitoring is imperative for large SQL Server environments.
		Following solution introduced in order for SQL Server DBAs to streamline, prioritize, and simplify SQL Server monitoring.

		Explanation of priority levels:
		[FindingID]
		 10 -  70 - Instance level
		 71 - 100 - Database level
		101 - 150 - Objects level

		[Severity]
		  0 - Security risk		(High)
		  1 - Performance risk	(Middle)
		  2 - Performance might be proved
		  3 - Informational | non-standard configuration	(Low)

  Version Updates:
	29.01.2020: | Added by Dmitry Spitsyn
		# Logins without permissions
	24.01.2020: | Added by Dmitry Spitsyn
		# Prove failed logins 
	20.01.2020: | Added by Dmitry Spitsyn
		# Prove full backup's within past 24 hours
	14.01.2020: | Added by Dmitry Spitsyn
		# Extend maximum memory setting
	09.01.2020: | Added by Dmitry Spitsyn
		# Prove file configuration all databases
		# Securing Linked Server
	02.01.2020: | Added by Dmitry Spitsyn
		# Log initial information
		# Optimization check installed version of Maintenance Solution
	27.12.2019: | Added by Dmitry Spitsyn
		# Optimize search for Maintenance Solution objects
	18.12.2019: | Added by Dmitry Spitsyn
		# Definition Trace flags
	16.12.2019: | Added by Dmitry Spitsyn
		# Determine Virtual Log Files
		# Determine Evaluation Edition
		# Unusual Startup Option
		# Definition of priority levels
	15.12.2019: | Added by Dmitry Spitsyn
		# Prove file growth configuration
		# Detect HA endpoint account the same as the SQL Server service account
		# Detect database corruption
		# 32-bit SQL Server Installed
	13.12.2019: | Added by Dmitry Spitsyn
		# Detect database corruption
	12.12.2019: | Added by Dmitry Spitsyn
		# Determine failed jobs
	11.12.2019: | Added by Dmitry Spitsyn
		# Determine failed logins last 7 days
	06.12.2019: | Added by Dmitry Spitsyn
		# Aprove setting for the 'CLR Assembly Permission Set' to SAFE_ACCESS for All CLR Assemblies (Scored) | APM-Global Decision: Use CUSTOMIZED CCS Scanner. Not known what is exactly means in Hardening_details_MSSQL.xls and must be clarified.
		# Determine backup compression setting
		# Determine backup checksum setting
	04.12.2019: | Added by Dmitry Spitsyn
		# Column "Severity" inserted and adjusted (0 - High; 1 - Midium; 2 - Low priority) - logic adjusted
	28.11.2019: | Added by Dmitry Spitsyn
		# determine FILESTREAM setting
		# Prove uneven file growth settings in the filegroup
		# Prove existence multiple log files on the same drive
		# Prove if only one tempdb data file configured
		# Determine auto growth settings
	21.11.2019: | Added by Dmitry Spitsyn
		# Determine DBCC errors
		# Determine Service Account Isolation
		# Determine if the server instance is hidden
		# Detect logins without permissions on database and on server level
	11.11.2019: | Added by Dmitry Spitsyn
		# Determine current version of Maintenance Solution
		# Determine current MaxDOP configuration
		# Determine current 'Cost Threshold for Parallelism' settings
		# Determine current memory limit
		# Detect orphaned users in SQL Server based on missing SQL Server authentication logins
			  and solution to identify orphaned users in Data Warehouse environments | https://docs.microsoft.com/en-us/sql/sql-server/failover-clusters/troubleshoot-orphaned-users-sql-server?view=sql-server-ver15
		# Determine the case, that maximum number of error log files is set to 99
	25.10.2019: | Added by Dmitry Spitsyn
		# Check script functionality on different product versions
		# Identify system configuration to issue a log entry and alert on unsuccessful logins to an administrative account
	11.10.2019: | Added by Dmitry Spitsyn
		# 'Auto Close' option - identify correct functionality
	27.09.2019: | Added by Dmitry Spitsyn
		# proved the case for options: "clr enabled","cross db ownership chaining","remote access","remote admin connections","default trace enabled"
	--||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
	28.08.2019: | Added by Reiner Grosser
		Some topics are difficult to be selected depending on special verions, 
		due to unsharpness excluded or not displayed, for example regarding chapter 3. 
		- several "Authentication and Authorization" topics
		- Orphaned Users
		- Encryption
		Common Bayer Solution also discussed in ICS Audit reagarding SQL CCS Development/Integration and SQL Exception Solution.
	--||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
	01.08.2019: | Added by Dmitry Spitsyn
		# New queries structure 
	30.07.2019: | Added by Dmitry Spitsyn
		# Auditing and Logging
		# Application Development
		# Encryption
	29.07.2019: | Added by Dmitry Spitsyn
		# Installation, Updates and Patches
		# Surface Area Reduction
		# Authentication and Authorization
		# Password Policies

	SQL Server Version: 2008/2012/2014/2016/2017/2019
	Current version: 20.01 released on Jan 09 2020 14:17
*/

SET NOCOUNT ON;
SET ANSI_WARNINGS OFF;
GO

	--------------------------------------------------------------------------------
	--| Declaring Variables
	--------------------------------------------------------------------------------
	DECLARE @MsgLoginUsers VARCHAR(MAX)
	DECLARE @ListLoginName VARCHAR(MAX)
	DECLARE	@StartMessage NVARCHAR(MAX)
	DECLARE	@EndMessage NVARCHAR(MAX)
	DECLARE @StepNameConfigOption NVARCHAR(MAX)
	DECLARE @ColumnStoreIndexesInUse BIT
	DECLARE @ProductVersion NVARCHAR(128)
	DECLARE @ProductVersionMajor DECIMAL(10, 2)
	DECLARE @ProductVersionMinor DECIMAL(10, 2)
	DECLARE @CountUp INT
	DECLARE @ErrorMessage NVARCHAR(MAX)
	DECLARE @EndTime DATETIME
	DECLARE @StartTimeSec DATETIME
	DECLARE @StartTime DATETIME
	DECLARE @EndTimeSec DATETIME
	DECLARE @EmptyLine NVARCHAR(MAX) = CHAR(9)
	DECLARE @ErrorLogType TINYINT = 1
	DECLARE @HardeningResultsName NVARCHAR(MAX)
	DECLARE @ErrorLogCount INT
	--------------------------------------------------------------------------------
	--| END Declaring Variables
	--------------------------------------------------------------------------------

	SET @ProductVersion = CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128));
	SELECT @ProductVersionMajor = SUBSTRING(@ProductVersion, 1, CHARINDEX('.', @ProductVersion) + 1 )
		, @ProductVersionMinor = PARSENAME(CONVERT(VARCHAR(32), @ProductVersion), 2);

	IF OBJECT_ID('tempdb..#HardeningResults') IS NOT NULL
		DROP TABLE #HardeningResults;
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

	IF OBJECT_ID('tempdb..#GlobalServerSettings') IS NOT NULL
		DROP TABLE #GlobalServerSettings;
	CREATE TABLE #GlobalServerSettings (
		  [name] NVARCHAR(128)
		, [DefaultValue] BIGINT
		, [CheckID] INT
		);
	INSERT INTO #GlobalServerSettings VALUES ( 'access check cache bucket count', 0, 300 );
	INSERT INTO #GlobalServerSettings VALUES ( 'access check cache quota', 0, 301 );
	INSERT INTO #GlobalServerSettings VALUES ( 'Ad Hoc Distributed Queries', 0, 302 );
	INSERT INTO #GlobalServerSettings VALUES ( 'affinity I/O mask', 0, 303 );
	INSERT INTO #GlobalServerSettings VALUES ( 'affinity mask', 0, 304 );
	INSERT INTO #GlobalServerSettings VALUES ( 'affinity64 I/O mask', 0, 305 );					-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'affinity64 mask', 0, 306 );						-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'Agent XPs', 1, 307 );
	INSERT INTO #GlobalServerSettings VALUES ( 'allow polybase export', 0, 308 );				-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'allow updates', 0, 309 );
	INSERT INTO #GlobalServerSettings VALUES ( 'automatic soft-NUMA disabled', 0, 310 );		-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'backup checksum default', 0, 311 );				-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'backup compression default', 1, 312 );
	INSERT INTO #GlobalServerSettings VALUES ( 'blocked process threshold (s)', 0, 313 );
	INSERT INTO #GlobalServerSettings VALUES ( 'c2 audit mode', 0, 314 );
	IF @@VERSION LIKE '%Microsoft SQL Server 2017%'
	BEGIN
		INSERT INTO #GlobalServerSettings VALUES ( 'clr enabled', 1, 315 );						-- from 2017 = 1 (enabled)
		INSERT INTO #GlobalServerSettings VALUES ( 'clr strict security', 1, 316 );				-- from 2017 = 1 (enabled)
	END
	ELSE
	BEGIN
		INSERT INTO #GlobalServerSettings VALUES ( 'clr enabled', 0, 315 );						-- in 2008 = 0
		INSERT INTO #GlobalServerSettings VALUES ( 'clr strict security', 0, 316 );				-- not in 2008
	END
	INSERT INTO #GlobalServerSettings VALUES ( 'common criteria compliance enabled', 0, 317 );	-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'contained database authentication', 1, 318 );	-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'cost threshold for parallelism', 5, 319 );
	INSERT INTO #GlobalServerSettings VALUES ( 'cross db ownership chaining', 0, 320 );
	INSERT INTO #GlobalServerSettings VALUES ( 'cursor threshold', -1, 321 );
	INSERT INTO #GlobalServerSettings VALUES ( 'Database Mail XPs', 0, 322 );
	INSERT INTO #GlobalServerSettings VALUES ( 'default full-text language', 1031, 323 );
	INSERT INTO #GlobalServerSettings VALUES ( 'default language', 1, 324 );
	INSERT INTO #GlobalServerSettings VALUES ( 'default trace enabled', 1, 325 );
	INSERT INTO #GlobalServerSettings VALUES ( 'disallow results from triggers', 0, 326 );
	INSERT INTO #GlobalServerSettings VALUES ( 'EKM provider enabled', 0, 327 );				-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'external scripts enabled', 0, 328 );			-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'filestream access level', 0, 329 );
	INSERT INTO #GlobalServerSettings VALUES ( 'fill factor (%)', 0, 330 );
	INSERT INTO #GlobalServerSettings VALUES ( 'ft crawl bandwidth (max)', 100, 331 );
	INSERT INTO #GlobalServerSettings VALUES ( 'ft crawl bandwidth (min)', 0, 332 );
	INSERT INTO #GlobalServerSettings VALUES ( 'ft notify bandwidth (max)', 100, 333 );
	INSERT INTO #GlobalServerSettings VALUES ( 'ft notify bandwidth (min)', 0, 334 );
	INSERT INTO #GlobalServerSettings VALUES ( 'hadoop connectivity', 0, 335 );					-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'index create memory (KB)', 0, 336 );
	INSERT INTO #GlobalServerSettings VALUES ( 'in-doubt xact resolution', 0, 337 );
	INSERT INTO #GlobalServerSettings VALUES ( 'lightweight pooling', 0, 338 );
	INSERT INTO #GlobalServerSettings VALUES ( 'locks', 0, 339 );
	INSERT INTO #GlobalServerSettings VALUES ( 'max degree of parallelism', 0, 340);
	INSERT INTO #GlobalServerSettings VALUES ( 'max full-text crawl range', 4, 341 );
	INSERT INTO #GlobalServerSettings VALUES ( 'max server memory (MB)', 2147483647, 342 );
	INSERT INTO #GlobalServerSettings VALUES ( 'max text repl size (B)', 65536, 343 );
	INSERT INTO #GlobalServerSettings VALUES ( 'max worker threads', 0, 344 );
	INSERT INTO #GlobalServerSettings VALUES ( 'media retention', 0, 345 );
	INSERT INTO #GlobalServerSettings VALUES ( 'min memory per query (KB)', 1024, 346 );
	INSERT INTO #GlobalServerSettings VALUES ( 'min server memory (MB)', 0, 347 );
	INSERT INTO #GlobalServerSettings VALUES ( 'nested triggers', 1, 348 );
	INSERT INTO #GlobalServerSettings VALUES ( 'network packet size (B)', 4096, 349 );
	INSERT INTO #GlobalServerSettings VALUES ( 'Ole Automation Procedures', 0, 350 );
	INSERT INTO #GlobalServerSettings VALUES ( 'open objects', 0, 351 );
	INSERT INTO #GlobalServerSettings VALUES ( 'optimize for ad hoc workloads', 0, 352 );
	INSERT INTO #GlobalServerSettings VALUES ( 'PH timeout (s)', 60, 353 );
	INSERT INTO #GlobalServerSettings VALUES ( 'polybase network encryption', 1, 354 );			-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'precompute rank', 0, 355 );
	INSERT INTO #GlobalServerSettings VALUES ( 'priority boost', 0, 358 );
	INSERT INTO #GlobalServerSettings VALUES ( 'query governor cost limit', 0, 359 );
	INSERT INTO #GlobalServerSettings VALUES ( 'query wait (s)', -1, 360 );
	INSERT INTO #GlobalServerSettings VALUES ( 'recovery interval (min)', 0, 361 );
	INSERT INTO #GlobalServerSettings VALUES ( 'remote access', 1, 362 );
	INSERT INTO #GlobalServerSettings VALUES ( 'remote admin connections', 0, 363 );
	INSERT INTO #GlobalServerSettings VALUES ( 'remote data archive', 0, 364 );					-- not in 2008
	INSERT INTO #GlobalServerSettings VALUES ( 'remote login timeout (s)', 10, 365 );
	INSERT INTO #GlobalServerSettings VALUES ( 'remote proc trans', 0, 366 );
	INSERT INTO #GlobalServerSettings VALUES ( 'remote query timeout (s)', 600, 367 );
	INSERT INTO #GlobalServerSettings VALUES ( 'Replication XPs', 0, 368 );
	INSERT INTO #GlobalServerSettings VALUES ( 'scan for startup procs', 0, 369 );
	INSERT INTO #GlobalServerSettings VALUES ( 'server trigger recursion', 1, 370 );
	INSERT INTO #GlobalServerSettings VALUES ( 'set working set size', 0, 371 );
	INSERT INTO #GlobalServerSettings VALUES ( 'show advanced options', 0, 372 );
	INSERT INTO #GlobalServerSettings VALUES ( 'SMO and DMO XPs', 1, 373 );
	INSERT INTO #GlobalServerSettings VALUES ( 'transform noise words', 0, 374 );
	INSERT INTO #GlobalServerSettings VALUES ( 'two digit year cutoff', 2049, 345 );
	INSERT INTO #GlobalServerSettings VALUES ( 'user connections', 0, 376 );
	INSERT INTO #GlobalServerSettings VALUES ( 'user options', 0, 377 );
	INSERT INTO #GlobalServerSettings VALUES ( 'xp_cmdshell', 0, 378 );

	IF OBJECT_ID('tempdb..#DBCCLogInfo2012') IS NOT NULL
		DROP TABLE #DBCCLogInfo2012;
	CREATE TABLE #DBCCLogInfo2012 (
		  [recoveryunitid] INT
		, [FileID] SMALLINT
		, [FileSize] BIGINT
		, [StartOffset] BIGINT
		, [FSeqNo] BIGINT
		, [Status] TINYINT
		, [Parity] TINYINT
		, [CreateLSN] NUMERIC(38)
		);
	IF OBJECT_ID('tempdb..#DBCCLogInfo') IS NOT NULL
		DROP TABLE #DBCCLogInfo;
	CREATE TABLE #DBCCLogInfo (
		  [FileID] SMALLINT
		, [FileSize] BIGINT
		, [StartOffset] BIGINT
		, [FSeqNo] BIGINT
		, [Status] TINYINT
		, [Parity] TINYINT
		, [CreateLSN] NUMERIC(38)
		);
	IF OBJECT_ID('tempdb..#LastFullBackup') IS NOT NULL
		DROP TABLE #LastFullBackup;
	CREATE TABLE #LastFullBackup (
		  [DatabaseName] VARCHAR(50)
		, [LastFullBackup] DATETIME
		, [NoBackupSinceHours] INT
		);
	INSERT INTO #LastFullBackup
	SELECT
		  msdb.dbo.backupset.database_name AS [DatabaseName]
		, MAX(msdb.dbo.backupset.backup_finish_date) AS [LastFullBackup]
		, DATEDIFF(hh, MAX(msdb.dbo.backupset.backup_finish_date), GETDATE()) AS [NoBackupSinceHours]
	FROM msdb.dbo.backupset 
	WHERE msdb.dbo.backupset.type = 'D'  
	GROUP BY msdb.dbo.backupset.database_name 
	HAVING (MAX(msdb.dbo.backupset.backup_finish_date) < DATEADD(hh, -24, GETDATE()))

	--------------------------------------------------------------------------------
	--| It is very useful to know what global trace flags are currently enabled 
	--| as part of the diagnostic process
	--------------------------------------------------------------------------------
	IF OBJECT_ID('tempdb..#TraceFlagsGlobalStatus') IS NOT NULL
		DROP TABLE #TraceFlagsGlobalStatus;
	CREATE TABLE #TraceFlagsGlobalStatus (
		  [TraceFlag] VARCHAR(5)
		, [Status] BIT
		, [Global] BIT
		, [Session] BIT
		);
	IF OBJECT_ID('tempdb..#TraceFlagsIn') IS NOT NULL
		DROP TABLE #TraceFlagsIn;
	CREATE TABLE #TraceFlagsIn (
		  [TraceFlag] VARCHAR(5)
		);
	IF @@VERSION LIKE '%Microsoft SQL Server 2019%'
	BEGIN
		INSERT INTO #TraceFlagsIn VALUES ( '7745' );	--| Prevents Query Store data from being written to disk in case of a failover or shutdown command
		--INSERT INTO #TraceFlagsIn VALUES ( '6534' );	--| Enables use of native code to improve performance with spatial data
		INSERT INTO #TraceFlagsIn VALUES ( '3226' );	--| Supresses logging of successful database backup messages to the SQL Server Error Log
	END
	IF @@VERSION LIKE '%Microsoft SQL Server 2017%' OR @@VERSION LIKE '%Microsoft SQL Server 2016%'
	BEGIN
		INSERT INTO #TraceFlagsIn VALUES ( '7752' );	--| Enables asynchronous load of Query Store
		INSERT INTO #TraceFlagsIn VALUES ( '7745' );	--| Prevents Query Store data from being written to disk in case of a failover or shutdown command
		--INSERT INTO #TraceFlagsIn VALUES ( '6534' );	--| Enables use of native code to improve performance with spatial data
		INSERT INTO #TraceFlagsIn VALUES ( '3226' );	--| Supresses logging of successful database backup messages to the SQL Server Error Log
		INSERT INTO #TraceFlagsIn VALUES ( '460' );		--| Improvement: Optional replacement for "String or binary data would be truncated" message with extended information in SQL Server 2017
	END
	IF @@VERSION LIKE '%Microsoft SQL Server 2014%' OR @@VERSION LIKE '%Microsoft SQL Server 2012%'
	BEGIN
		INSERT INTO #TraceFlagsIn VALUES ( '8079' );	--| Enables automatic soft-NUMA on systems with eight or more physical cores per NUMA node (with SQL Server 2014 SP2)
		INSERT INTO #TraceFlagsIn VALUES ( '6534' );	--| Enables use of native code to improve performance with spatial data
		INSERT INTO #TraceFlagsIn VALUES ( '6533' );	--| Spatial performance improvements in SQL Server 2012 and 2014
		INSERT INTO #TraceFlagsIn VALUES ( '3449' );	--| Enables use of dirty page manager (SQL Server 2014 SP1 CU7 and later)
		INSERT INTO #TraceFlagsIn VALUES ( '3226' );	--| Supresses logging of successful database backup messages to the SQL Server Error Log
		INSERT INTO #TraceFlagsIn VALUES ( '2371' );	--| Lowers auto update statistics threshold for large tables (on tables with more than 25,000 rows)
		INSERT INTO #TraceFlagsIn VALUES ( '1118' );	--| Recommendations to reduce allocation contention in SQL Server tempdb database
		INSERT INTO #TraceFlagsIn VALUES ( '1117' );	--| When growing a data file, grow all files at the same time so they remain the same size, reducing allocation contention points
	END
	ELSE IF @@VERSION LIKE '%Microsoft SQL Server 2012%'
	BEGIN
		INSERT INTO #TraceFlagsIn VALUES ( '3023' );	--| Enables backup checksum default
	END
	ELSE
	IF @@VERSION LIKE '%Microsoft SQL Server 2008%'
	BEGIN
		INSERT INTO #TraceFlagsIn VALUES ( '3226' );	--| Supresses logging of successful database backup messages to the SQL Server Error Log
		INSERT INTO #TraceFlagsIn VALUES ( '2371' );	--| Lowers auto update statistics threshold for large tables (on tables with more than 25,000 rows)
		INSERT INTO #TraceFlagsIn VALUES ( '1118' );	--| Recommendations to reduce allocation contention in SQL Server tempdb database
		INSERT INTO #TraceFlagsIn VALUES ( '1117' );	--| When growing a data file, grow all files at the same time so they remain the same size, reducing allocation contention points
	END

	IF OBJECT_ID('tempdb..#TraceFlagToSet') IS NOT NULL
		DROP TABLE #TraceFlagToSet;
	CREATE TABLE #TraceFlagToSet (
		  [TraceFlag] VARCHAR(5)
		);

	IF OBJECT_ID('tempdb..#TemporaryDatabaseResults') IS NOT NULL
		DROP TABLE #TemporaryDatabaseResults;
	CREATE TABLE #TemporaryDatabaseResults (
		  [DatabaseName] NVARCHAR(128)
		, [Finding] NVARCHAR(128)
		);

	--------------------------------------------------------------------------------
	--| Log definition                                                     
	--------------------------------------------------------------------------------
	SET @StartTime = GETDATE()
	SET @StartTimeSec = CONVERT(DATETIME, CONVERT(NVARCHAR, @StartTime,120), 120)
	SET @StartMessage = 'Hardening Solution, Version: 20.01'
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	SET @StartMessage = 'Date and time: ' + CONVERT(NVARCHAR, @StartTimeSec, 120)
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	SET @StepNameConfigOption = 'Ensure latest SQL Server service packs and hotfixes are installed'
	SET @CountUp = 1		
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	--------------------------------------------------------------------------------
	--| End Log definition                                                     
	--------------------------------------------------------------------------------
	BEGIN
		DECLARE @iDate VARCHAR(MAX) = ( SELECT CAST(CONVERT(DATETIME, create_date, 102) AS VARCHAR) FROM sys.server_principals WHERE sid = 0x010100000000000512000000 )
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '-1', 0
			, 'Instance name: ''' + ISNULL(CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(100)), '(default instance)') + ''''
			, '-' , '-', '-', 'Instance were installed on ' + @iDate + 
			CASE WHEN CAST(SERVERPROPERTY('IsClustered') AS VARCHAR(100)) = 1 THEN 
				CASE WHEN CAST(COALESCE(SERVERPROPERTY('IsHadrEnabled'), 0) AS VARCHAR(100)) = 1 THEN ', AlwaysOn is enabled' ELSE ', is clustered' END 
				ELSE '' END + ', last startup ' + ( SELECT CAST(create_date AS VARCHAR(100)) FROM sys.databases WHERE database_id = 2 ) + '. Script executed by ' + QUOTENAME(SUSER_SNAME()) + ' on ' + CAST(CONVERT(DATETIME, GETDATE(), 102) AS VARCHAR(100)) + '.'
	END;

	/*	
		| 10 (1.1) Ensure Latest SQL Server Service Packs and Hotfixes are Installed (Not Scored)
		|	Conclusion: will be covered with Lifecycle process
		|   Starting with SQL Server 2017, no Service Packs will be released.
	*/
	IF OBJECT_ID('tempdb..#Versions') IS NOT NULL
		DROP TABLE #Versions;
	CREATE TABLE #Versions (
		  [Name] NVARCHAR(28)
		, [Service Pack] NVARCHAR(8)
	)
	BEGIN
		INSERT INTO #Versions (
			  [Name]
			, [Service Pack]
			)
		SELECT
			CASE																									
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '10.0%' THEN 'SQL Server 2008'
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '10.5%' THEN 'SQL Server 2008 R2'
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '11.0%' THEN 'SQL Server 2012'
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '12.0%' THEN 'SQL Server 2014'
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '13.0%' THEN 'SQL Server 2016'
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '14.0%' THEN 'SQL Server 2017'
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '15.0%' THEN 'SQL Server 2019'
				ELSE 'unknown'
			END
			, CASE 																						-- | Obsolete versions – out of support
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '10.0%' THEN 'SP4'	-- | (10.0.6000.29,	7/9/2019)
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '10.5%' THEN 'SP3'	-- | (10.50.6000.34,	09/07/2019)
																										-- | Extended Support End Dates
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '11.0%' THEN 'SP4'	-- | (11.0.7001.0,	7/12/2022)
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '12.0%' THEN 'SP3'	-- | (12.0.6024.0,	7/9/2024)
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '13.0%' THEN 'SP2'	-- | (13.0.5026.0,	7/14/2026)
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '14.0%' THEN 'CU20'	-- | (14.0.3294.2)
				WHEN CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) LIKE '15.0%' THEN 'CU4'	-- | (15.0.4033.1)
				ELSE 'unknown'
			END;
	END;
	IF @@VERSION LIKE '%Microsoft SQL Server 2017%'
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '10', 0 AS [Severity], 'Version: ' + [Name] AS [Name], CONVERT(VARCHAR(128), SERVERPROPERTY('ProductUpdateLevel')) AS [Current Setting], CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(100)) AS [Target Setting]
			, CASE WHEN CAST(SERVERPROPERTY('ProductUpdateLevel') AS NVARCHAR(100)) = [Service Pack] THEN 'Yes' ELSE 'No' END AS [Target Achieved]
			, CASE WHEN CAST(SERVERPROPERTY('ProductUpdateLevel') AS NVARCHAR(100)) = [Service Pack] THEN 'No problem was found (' + CAST(SERVERPROPERTY('ProductUpdateReference') AS VARCHAR(20)) + ').'
				ELSE 'We strongly recommend you install the latest Cumulative Update (' + [Service Pack] + ') and GDRs (security fixes).' END FROM #Versions;
	END
	ELSE
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '10', 0, 'Version: ' + [Name], CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(100)), CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(100))
			, CASE WHEN CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(100)) = [Service Pack] THEN 'Yes' ELSE 'No' END
			, CASE WHEN CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(100)) = [Service Pack] THEN 'No problem was found.'
				ELSE 'We strongly recommend you install the latest Service Pack (' + [Service Pack] + ').' END FROM #Versions AS [Details]
	END DROP TABLE #Versions;

	/*
		| 1.2 Ensure Single-Function Member Servers are Used (Not Scored)
	*/

	/*
		| 31 (5.2) Ensure 'default trace enabled' is set to '1' (Scored)
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 1, cr.name AS [Name], CONVERT(VARCHAR(100), cr.value_in_use) AS [Current Setting]
		, cd.DefaultValue AS [Target Setting]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END AS [Target Achieved]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'Enable system logging to include detailed information such as an event source, date, user, timestamp, source addresses, destination addresses, and other useful elements.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'default trace enabled';
	SET @StepNameConfigOption = 'Ensure ''default trace enabled''is set to ''1'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 300 SQL Server instance settings 'access check cache bucket count' is set to '0'
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. In some very rare cases, performance problems can result if these settings, which affect the size of the ''access check result cache'' are too low or too high.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'access check cache bucket count';
	SET @StepNameConfigOption = 'Ensure ''access check cache bucket count'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 301 SQL Server instance settings 'access check cache quota' is set to '0'
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. Microsoft recommends that you don''t change these values unless you have been told to do so by a Microsoft Customer Support Services.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'access check cache quota';
	SET @StepNameConfigOption = 'Ensure ''access check cache quota'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 302 (2.1) SQL Server instance settings 'Ad Hoc Distributed Queries' is set to '0'
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. Enabling ''' + cr.name + ''' allows users to query data and execute statements on external data sources.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'Ad Hoc Distributed Queries';
	SET @StepNameConfigOption = 'Ensure ''Ad Hoc Distributed Queries'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 303 SQL Server Instance Settings 'affinity I/O mask' is set to '0'
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. This option should not be changed unless you are an expert.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'affinity I/O mask';
	SET @StepNameConfigOption = 'Ensure ''affinity I/O mask'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 304 SQL Server Instance Settings 'affinity mask' is set to '0'
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. Selecting the correct settings can be complex, and incorrect settings can lead to poor performance.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'affinity mask';
	SET @StepNameConfigOption = 'Ensure ''affinity mask'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 305 SQL Server Instance Settings 'affinity64 I/O mask' is set to '0'
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. This option should not be changed unless you are an expert.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'affinity64 I/O mask';
	SET @StepNameConfigOption = 'Ensure ''affinity64 I/O mask'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 306 SQL server instance settings 'affinity64 mask' is set to '0'
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled. This option should not be changed unless you are an expert.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'affinity64 mask';
	SET @StepNameConfigOption = 'Ensure ''affinity64 mask'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 309 SQL Server Instance Settings 'allow updates' is set to '0'
		|	Obsolete. Do not use. Will cause an error during reconfigure.
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be disabled.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'allow updates';
	SET @StepNameConfigOption = 'Ensure ''allow updates'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 310 Server Configuration Option 'automatic soft-NUMA disabled' (should be 0 in most cases) 
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name AS [Name]
		, CONVERT(VARCHAR(100), cr.value_in_use) AS [Current Setting], cd.DefaultValue AS [Target Setting]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END AS [Target Achieved]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be set to 0 in most cases.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'automatic soft-NUMA disabled';
	SET @StepNameConfigOption = 'Ensure ''automatic soft-NUMA disabled'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 312 Server configuration option 'backup compression default' (should be enabled in most cases)
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 1, cr.name AS [Name]
		, CONVERT(VARCHAR(100), cr.value_in_use) AS [Current Setting], cd.DefaultValue AS [Target Setting]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END AS [Target Achieved]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'	-- Do not rely on this configuration setting. Using WITH COMPRESSION or WITH NO_COMPRESSION will always override the value for this configuration option.
			ELSE 'Instead of using this configuration setting, always specify the specific options you want, such as specifically adding WITH COMPRESSION or WITH NO_COMPRESSION to the BACKUP DATABASE or BACKUP LOG statements in backup solution.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'backup compression default';
	SET @StepNameConfigOption = 'Ensure ''backup compression default'' is set to ''1'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 314 Server configuration option 'c2 audit mode' (should be enabled in most cases)
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 1, cr.name AS [Name]
		, CONVERT(VARCHAR(100), cr.value_in_use) AS [Current Setting], cd.DefaultValue AS [Target Setting]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END AS [Target Achieved]
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option is very resource intensive and uses large amounts of disk space. It is recommended that this option not be used.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'c2 audit mode';
	SET @StepNameConfigOption = 'Ensure ''c2 audit mode'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 315 (2.2) Ensure 'clr enabled' is set to '0' (only enable if it is needed)
		|	If 'clr enabled' is turned on, then 'lightweight pooling' has to be turned off.
	*/	
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'Enabling use of ''CLR'' assemblies widens the attack surface of SQL Server and puts it at risk from both inadvertent and malicious assemblies.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'clr enabled';
	SET @StepNameConfigOption = 'Ensure ''clr enabled'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 316 Server configuration option 'clr strict security' since SQL Server 2017
		|	Advanced options, which should be changed only by an experienced database administrator or a certified SQL Server professional.
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name AS [Name], CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option is enabled by default. Disabling the CLR Strict Security configuration option is highly unrecommended by Microsoft.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'clr strict security';
	SET @StepNameConfigOption = 'Ensure ''clr strict security'' hat default setting'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 317 Server configuration option 'common criteria compliance enabled'
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name AS [Name], CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should only be turned on if required by law or regulation, as it can impose a performance penalty and use a lot of disk space.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'common criteria compliance enabled';
	SET @StepNameConfigOption = 'Ensure ''common criteria compliance enabled'' hat default setting'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 320 (2.3) Ensure option 'cross db ownership chaining' is set to '0' (Scored)
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'When enabled, this option allows a member of the ''db_owner'' role in a database to gain access to objects owned by a login in any other database, causing an unnecessary information disclosure. If only some of the databases on an instance need to participate in cross ownership chaining, then this feature should be turned on at the database level.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'cross db ownership chaining';
	SET @StepNameConfigOption = 'Ensure ''cross db ownership chaining'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 322 (2.4) Ensure option 'Database Mail XPs' is set to '0' (Scored)
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'Disabling the ''' + cr.name + ''' option reduces the SQL Server surface, eliminates a DOS attack vector and channel to exfiltrate data from the database server to a remote host. On the other hand, Database Mail is very useful, and you shouldn''t be afraid to turn it on.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'Database Mail XPs';
	SET @StepNameConfigOption = 'Ensure ''Database Mail XPs'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 323 Ensure server configuration option 'disallow results from triggers' is set to '0'
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should always be ''0'' for existing instances of SQL Server.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'disallow results from triggers';
	SET @StepNameConfigOption = 'Ensure ''disallow results from triggers'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 331-4 Ensure server configuration options
		|	'ft crawl bandwidth (max)', 'ft crawl bandwidth (min)', 'ft notify bandwidth (max)', 'ft notify bandwidth (min)' should not be used
	*/
	/*
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name
		, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should always be ''0'' for existing instances of SQL Server.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name LIKE 'ft%';
	SET @StepNameConfigOption = 'Ensure ''ft crawl bandwidth (max)'', ''ft crawl bandwidth (min)'', ''ft notify bandwidth (max)'', ''ft notify bandwidth (min)'' are not used'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	*/

	/*
		| 338 Server Configuration Option 'lightweight pooling' (should be set to '0')
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should be zero. If used incorrectly, it can hurt CPU performance.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'lightweight pooling';
	SET @StepNameConfigOption = 'Ensure ''lightweight pooling'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 350 (2.5) Ensure option 'Ole Automation Procedures' is set to '0' (Scored)
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'Enabling this option will increase the attack surface of SQL Server and allow users to execute functions in the security context of SQL Server. Leave this option to off, unless you have some legacy code that requires its use.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'Ole Automation Procedures';
	SET @StepNameConfigOption = 'Ensure ''Ole Automation Procedures'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 351 Ensure option 'open objects' is set to '0' (Scored)
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should always stay at its default value of ''0''.' END
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'open objects';
	SET @StepNameConfigOption = 'Ensure ''open objects'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 358 Server configuration option 'priority boost' (should be set to '0')
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option should never be used.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'priority boost';
	SET @StepNameConfigOption = 'Ensure ''priority boost'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 362 (2.6) Ensure server configuration option 'remote access' is set to '0' (Scored)
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'Do not use this feature. Used value for this option is default and strictly not recommended. Use ''sp_addlinkedserver'' instead. Set the option to ''0'' to prevent local stored procedures from being run from a remote server or remote stored procedures from being run on the local server.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'remote access';
	SET @StepNameConfigOption = 'Ensure ''remote access'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 363 (2.7) Ensure option 'remote admin connections' is set to '0'
		|		Disable it for standalone installations where not required.
		|		If it's a clustered installation, this option must be enabled as a clustered SQL Server cannot bind to localhost and DAC will be unavailable otherwise. 
		|		Enable it for clustered installations (set to '1').
	*/
	IF ( SELECT SERVERPROPERTY('IsClustered') ) = 0
		BEGIN					
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
				, CASE WHEN cr.value_in_use = 0 THEN 'Yes' ELSE 'No' END
				, CASE WHEN cr.value_in_use = 0 THEN 'No problem was found.'
					ELSE 'This setting should be disabled.' END
			FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
			WHERE cr.name = 'remote admin connections';
		END
		ELSE	--| Instance is clustered and/or if you're connecting over TCP/IP, you're out of luck unless this setting has been changed ('Remote Admin Connections').
		BEGIN					
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), 1
				, CASE WHEN cr.value_in_use = 1 THEN 'Yes' ELSE 'No' END
				, CASE WHEN cr.value_in_use = 1 THEN 'No problem was found.'
					ELSE 'This instance is clustered and current setting should be enabled. Ensure that only network ports, protocols, and services listening on a system with validated business needs, are running on each system.' END AS [Details]
			FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
			WHERE cr.name = 'remote admin connections';
		END;
	SET @StepNameConfigOption = 'Ensure ''remote admin connections'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 369 (2.8) Ensure 'scan for startup procs' is set to '0' (Scored)
	*/
	/* IF Replication = True */
	IF EXISTS ( SELECT name, is_published, is_subscribed, is_merge_published, is_distributor 
				FROM sys.databases WHERE is_published = 1 OR is_subscribed = 1 OR is_merge_published = 1 OR is_distributor = 1 )
		BEGIN
			/* and other procedures then 'sp_ssis_startup' are activated at start up */
			IF ( SELECT name FROM sys.objects WHERE type = 'P' AND OBJECTPROPERTY(object_id, 'ExecIsStartup') = 1 ) <> 'sp_ssis_startup'
			BEGIN					
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
				SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
					, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
					, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
						ELSE 'This option is enabled and may cause SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup. Replication requires this setting to be enabled.' END AS [Details]
				FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
				WHERE cr.name = 'scan for startup procs'
			END
			ELSE
			BEGIN
				INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
				SELECT cd.CheckID, 0
					, cr.name	/* Replication requires this setting to be enabled (Target Achieved = 1) */ 
					, CAST(value_in_use AS INT), 1, CASE WHEN 1 = cr.value_in_use THEN 'Yes' ELSE 'No' END
					, CASE WHEN 1 = cr.value_in_use THEN 'No problem was found.' 
						ELSE 'This option is enabled and may cause SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup. Replication requires this setting to be enabled (1).' END
				FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
				WHERE cr.name = 'scan for startup procs'
			END;
		END;
	IF ( SELECT name FROM sys.objects WHERE type = 'P' AND OBJECTPROPERTY(object_id, 'ExecIsStartup' ) = 1 ) <> 'sp_ssis_startup'
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT cd.CheckID, 0, cr.name
				, CAST(value_in_use AS INT), 1, CASE WHEN 1 = cr.value_in_use THEN 'Yes' ELSE 'No' END
				, CASE WHEN 1 = cr.value_in_use THEN 'No problem was found.' 
					ELSE 'This option is enabled and may cause SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup. Replication requires this setting to be enabled.' END
			FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
			WHERE cr.name = 'scan for startup procs'
		END
		ELSE
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT cd.CheckID, 0, cr.name, CAST( value_in_use AS INT ), cd.DefaultValue
				, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
				, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.' 
					ELSE 'This option is enabled and may cause SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup. Replication requires this setting to be enabled (1).' END
			FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
			WHERE cr.name = 'scan for startup procs'
		END;
	SET @StepNameConfigOption = 'Ensure ''scan for startup procs'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 378 (2.15) Ensure option 'xp_cmdshell' is set to '0' (Scored)
	*/			
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 0, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'No problem was found.'
			ELSE 'This option must be disabled. The ''xp_cmdshell'' procedure is commonly used by attackers to read or write data to/from the underlying Operating System of a database server.' END AS [Details]
	FROM sys.configurations cr INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'xp_cmdshell';
	SET @StepNameConfigOption = 'Ensure ''xp_cmdshell'' is set to ''0'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 20 (2.10) Ensure unnecessary SQL Server protocols are set to 'Disabled' (Not Scored)
	*/
	IF OBJECT_ID('tempdb..#USPNP') IS NOT NULL
		DROP TABLE #USPNP;
	CREATE TABLE #USPNP ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #USPNP ( [ValueInUse], [Target] )
		SELECT CASE WHEN ( SELECT value_data FROM sys.dm_server_registry 
		WHERE registry_key LIKE '%np' AND value_name = 'Enabled' ) = 1 THEN 1 ELSE 0 END, 0
	END
	IF OBJECT_ID('tempdb..#USPSM') IS NOT NULL
		DROP TABLE #USPSM;
	CREATE TABLE #USPSM ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #USPSM ( [ValueInUse], [Target] )
		SELECT CASE WHEN ( SELECT value_data FROM sys.dm_server_registry 
		WHERE registry_key LIKE '%sm' AND value_name = 'Enabled' ) = 1 THEN 1 ELSE 0 END, 1
	END
	IF OBJECT_ID('tempdb..#USPTCP') IS NOT NULL
		DROP TABLE #USPTCP;
	CREATE TABLE #USPTCP ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #USPTCP ( [ValueInUse], [Target] )
		SELECT CASE WHEN ( SELECT value_data FROM sys.dm_server_registry 
		WHERE registry_key LIKE '%tcp' AND value_name = 'Enabled' ) = 1 THEN 1 ELSE 0 END, 1
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		VALUES ( '20', 0, 'Unnecessary SQL Server Protocols'
			, CASE WHEN ( SELECT [ValueInUse] FROM #USPNP ) <> 0 OR ( SELECT [ValueInUse] FROM #USPSM) <> 1 OR ( SELECT [ValueInUse] FROM #USPTCP ) <> 1 THEN 1 ELSE 0 END, 0
			, CASE WHEN ( SELECT [ValueInUse] FROM #USPNP ) = 0 AND ( SELECT [ValueInUse] FROM #USPSM ) = 1 AND ( SELECT [ValueInUse] FROM #USPTCP ) = 1 THEN 'Yes' ELSE 'No' END
			, CASE WHEN ( SELECT [ValueInUse] FROM #USPNP ) = 0 AND ( SELECT [ValueInUse] FROM #USPSM ) = 1 AND ( SELECT [ValueInUse] FROM #USPTCP ) = 1 THEN 'No problem was found.' 
				ELSE 'Ensure that only required protocols are enabled. On failover clusters only TCP/IP and Named pipes will work. Clustered SQL Server installations require the TCP/IP protocol, because it is the only supported protocol for use with server clusters.' END ) END DROP TABLE #USPTCP; DROP TABLE #USPNP; DROP TABLE #USPSM;
	SET @StepNameConfigOption = 'Ensure unnecessary SQL Server protocols are set to ''Disabled'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 2.11 Ensure SQL Server is configured to use non-standard ports (Scored)
		| We will NOT follow the recommendation (see comment)
	*/

	/*
		| 21 (2.13) Ensure 'sa' Login Account is set to 'Disabled' (Scored)
		| Created as example. It must be already done in LEV
	*/
	IF OBJECT_ID('tempdb..#SALA') IS NOT NULL
		DROP TABLE #SALA;
	CREATE TABLE #SALA ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #SALA ( [ValueInUse], [Target] )
		VALUES (( SELECT is_disabled FROM sys.server_principals WHERE sid = 0x01 ), 1 )
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '21', 0, '''sa'' Login Account is set to ''Disabled'''
			, [ValueInUse], [Target]
			, CASE WHEN [Target] = [ValueInUse] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [Target] = [ValueInUse] THEN 'No problem was found.' 
				ELSE 'This account should remains disabled. Enforcing this control reduces the probability of an attacker executing brute force attacks against a well-known principal.' END FROM #SALA END DROP TABLE #SALA;
	SET @StepNameConfigOption = 'Ensure ''sa'' login account is set to ''Disabled'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 2.14 Ensure 'sa' Login Account has been renamed (Scored)
		| We will NOT follow the recommendation
	*/

	/*
		| 2.17 Ensure no login exists with the name 'sa' (Scored)
		|      We will not follow the recommendation
	*/

	/*
		| 3.1 Ensure 'Server Authentication' property is set to 'Windows Authentication Mode' (Scored)
		|     Is default in LEV. Some application still need SQL Authentication
	*/

	/*
		| 22 (3.2) Ensure CONNECT permissions on the 'guest' user is revoked within
		|	  all SQL Server databases excluding the master, msdb and tempdb (Scored)
	*/
	EXEC dbo.sp_MSforeachdb 'USE [?];
	IF OBJECT_ID(''tempdb..#CPGU'') IS NOT NULL
		DROP TABLE #CPGU;
	CREATE TABLE #CPGU ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #CPGU ( [ValueInUse], [Target] )
		VALUES ( CASE WHEN ( SELECT COUNT(DB_NAME()) FROM sys.database_permissions
			WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID(''guest'') 
				AND [state_desc] LIKE ''GRANT%'' AND [permission_name] = ''CONNECT'' 
				AND DB_NAME() NOT IN ( ''master'', ''tempdb'', ''msdb'' )) = 0 THEN 0 ELSE 1 END, 0 )
	END
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT ''22'', 0, ''''''CONNECT'''' Permissions for ''''guest'''' User''
			, ( SELECT [ValueInUse] FROM #CPGU ), ( SELECT [Target] FROM #CPGU )
			, CASE WHEN ( SELECT [Target] FROM #CPGU ) = ( SELECT [ValueInUse] FROM #CPGU ) THEN ''Yes'' ELSE ''No'' END
			, ''The ''''CONNECT'''' permission should be revoked for the ''''guest'''' user in ['' + DB_NAME() + ''] database on the SQL Server instance.''
		FROM [?].sys.database_permissions WHERE [grantee_principal_id] = DATABASE_PRINCIPAL_ID(''guest'') 
			AND [state_desc] LIKE ''GRANT%'' AND [permission_name] = ''CONNECT'' AND DB_NAME() NOT IN ( ''master'', ''tempdb'', ''msdb'' ) DROP TABLE #CPGU'
	SET @StepNameConfigOption = 'Prove ''Connect'' permissions on the ''guest'' user'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 23 (3.3) Ensure 'Orphaned Users' are dropped from SQL Server databases (Scored)
	*/
	IF @@VERSION NOT LIKE '%Microsoft SQL Server 2008%'
	BEGIN
		IF OBJECT_ID('tempdb..#OU') IS NOT NULL
			DROP TABLE #OU;
		CREATE TABLE #OU ( [ValueInUse] INT, [Target] INT )
		BEGIN
			INSERT INTO #OU ( [ValueInUse], [Target] )
			VALUES ( CASE WHEN ( SELECT COUNT(name) FROM sys.sysusers WHERE SID IS NOT NULL AND SID <> 0X0 AND ISLOGIN = 1 AND SID NOT IN ( SELECT SID FROM sys.syslogins )) IS NULL THEN 0 ELSE 1 END, 0 )
		END
		BEGIN
			EXEC sp_MSforeachdb 'USE [?];
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT DISTINCT ''23'', 0, ''Orphaned User in ['' + DB_NAME() + '']''
				, 1, ( SELECT [Target] FROM #OU )
				, CASE WHEN ( SELECT [Target] FROM #OU ) = ( SELECT [ValueInUse] FROM #OU ) THEN ''Yes'' ELSE ''No'' END
				, CASE WHEN ( SELECT [Target] FROM #OU ) = ( SELECT [ValueInUse] FROM #OU ) THEN ''No problem was found.'' 
					ELSE ''User '''''' + NAME + '''''' was detected as ''''Orphaned User'''' based on missing SQL Server authentication login (SID). Be cautious, there are multiple scenarios that can make things complex. If it is ''''Orphan User'''', it should be fixed or removed to avoid potential misuse of this broken user in any way.'' END
			FROM [?].sys.database_principals WHERE type = ''S'' AND name NOT IN (''dbo'', ''guest'', ''INFORMATION_SCHEMA'', ''sys'', ''MS_DataCollectorInternalUser'') AND authentication_type_desc = ''INSTANCE'' AND sid NOT IN ( SELECT sid FROM sys.sql_logins WHERE type = ''S'' )'
		SET @StepNameConfigOption = 'Ensure ''Orphaned Users'' are dropped from SQL Server databases'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
		END DROP TABLE #OU
	END;

	/*
		| 3.4 Ensure SQL Authentication is not used in contained databases (Scored)
		|     Currently contained DBs are not used in LEV
	*/

	/*
		| 3.5 Ensure the SQL Server Engine Service Account is Not an Administrator (Scored)
		|     This recommendation refers to WINDOWS administrators (not SQL Server sysadmins)
	*/

	/*
		| 3.6 Ensure the SQL Server Agent Service Account is Not an Administrator (Scored)
		|     This recommendation refers to WINDOWS administrators (not SQL Server sysadmins)
	*/

	/*
		| 3.7 Ensure the SQL Server Full-Text Service Account is Not an Administrator (Scored)
		|     This recommendation refers to WINDOWS administrators (not SQL Server sysadmins)
	*/

	/*
		| 24 (3.8) Ensure only the default permissions specified by Microsoft are granted to the 'public' server role (Scored)
	*/
	IF OBJECT_ID('tempdb..#PGPSR') IS NOT NULL
		DROP TABLE #PGPSR;
	CREATE TABLE #PGPSR ( [ValueInUse] INT, [Target] INT )
	IF NOT EXISTS( SELECT * FROM master.sys.server_permissions WHERE ( grantee_principal_id = SUSER_SID(N'public') AND state_desc LIKE 'GRANT%' )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'VIEW ANY DATABASE' AND class_desc = 'SERVER' )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 2 )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 3 )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 4 )
		AND NOT ( state_desc = 'GRANT' AND [permission_name] = 'CONNECT' AND class_desc = 'ENDPOINT' AND major_id = 5 )
		)
		BEGIN
			INSERT INTO #PGPSR ( [ValueInUse], [Target] ) VALUES (0, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #PGPSR ( [ValueInUse], [Target] ) VALUES (1, 0)
		END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '24', 0, 'Default permissions for ''public'' server role', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.'
				ELSE 'You should avoid modifying the public roles and instead create one or more additional roles.' END FROM #PGPSR
		SET @StepNameConfigOption = 'Ensure only the default permissions are granted to the public server role'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #PGPSR;

	/*
		| 25 (3.9) Ensure Windows BUILTIN groups are not SQL Logins (Scored)
	*/
	IF OBJECT_ID('tempdb..#WBI') IS NOT NULL
		DROP TABLE #WBI;
	CREATE TABLE #WBI ( [ValueInUse] INT, [Target] INT )
	IF EXISTS( SELECT pr.[name], pe.[permission_name], pe.[state_desc]
		FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name LIKE 'BUILTIN%' )
		BEGIN
			INSERT INTO #WBI ( [ValueInUse], [Target] ) VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #WBI ( [ValueInUse], [Target] ) VALUES (0, 0)
		END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '25', 0, 'Windows ''BUILTIN'' groups are not SQL logins', [ValueInUse] , [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'The BUILTIN groups (Administrators, Everyone, Authenticated Users, Guests, etc.) generally should not be used for any level of access into a SQL Server database engine instance.' END FROM #WBI
		SET @StepNameConfigOption = 'Ensure Windows BUILTIN groups are not SQL logins'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #WBI;

	/*
		| 26 (3.10) Ensure Windows local groups are not SQL Logins (Scored)
	*/
	IF OBJECT_ID('tempdb..#WLG') IS NOT NULL
		DROP TABLE #WLG;
	CREATE TABLE #WLG ( [ValueInUse] INT, [Target] INT )
	IF EXISTS( SELECT pr.[name], pe.[permission_name], pe.[state_desc]
		FROM sys.server_principals pr JOIN sys.server_permissions pe
			ON pr.[principal_id] = pe.[grantee_principal_id]
		WHERE pr.[type_desc] = 'WINDOWS_GROUP' AND pr.[name] LIKE CAST(SERVERPROPERTY('MachineName') AS NVARCHAR) + '%' )
		BEGIN
			INSERT INTO #WLG ( [ValueInUse], [Target] ) VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #WLG ( [ValueInUse], [Target] ) VALUES (0, 0)
		END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '26', 0, 'Windows local groups are SQL logins', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.'
				ELSE 'Local Windows groups should not be used as logins for SQL Server instances. Add the AD group or individual Windows accounts as a SQL Server login and grant it the permissions required.' END FROM #WLG
		SET @StepNameConfigOption = 'Ensure Windows local groups are not SQL logins'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #WLG;

	/*
		| 27 (3.11) Ensure the 'public' role in the msdb database is not granted access to SQL Agent proxies (Scored)
	*/
	IF OBJECT_ID('tempdb..#PRP') IS NOT NULL
		DROP TABLE #PRP;
	CREATE TABLE #PRP ( [ValueInUse] INT, [Target] INT )
	USE [msdb]
	IF EXISTS(
		SELECT sp.name AS proxyname FROM dbo.sysproxylogin spl JOIN sys.database_principals dp
			ON dp.sid = spl.sid JOIN sysproxies sp ON sp.proxy_id = spl.proxy_id
		WHERE principal_id = USER_ID('public') )
		BEGIN
			INSERT INTO #PRP ( [ValueInUse], [Target] ) VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #PRP ( [ValueInUse], [Target] ) VALUES (0, 0)
		END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '27', 0, 'The ''public'' Role in [msdb] database', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'Granting access to SQL Agent proxies for the public role would allow all users to utilize the proxy which may have high privileges. This would likely break the principle of least privileges.' END FROM #PRP
		SET @StepNameConfigOption = 'Ensure the public role in the msdb database is not granted access to SQL Agent proxies'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #PRP;

	/*
		| 4.1 Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins (Not Scored)
		|     Cannot be checked by CCS as this box is cleared after 1st PW change
		|     Can only be regulated via SOP
	*/
	/*
		| 28 (4.2)
		|	Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role (Scored)
	*/
	IF OBJECT_ID('tempdb..#CEO') IS NOT NULL
		DROP TABLE #CEO;
	CREATE TABLE #CEO ( [ValueInUse] INT, [Target] INT )
	IF EXISTS( SELECT l.[name], 'sysadmin membership' FROM sys.sql_logins AS l
		WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1 AND l.is_expiration_checked <> 1
		UNION ALL
		SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
		FROM sys.sql_logins AS l JOIN sys.server_permissions AS p
			ON l.principal_id = p.grantee_principal_id
		WHERE p.type = 'CL' AND p.state IN ( 'G', 'W' ) AND l.is_expiration_checked <> 1 )
		BEGIN
			INSERT INTO #CEO ( [ValueInUse], [Target] ) VALUES (1, 0)
		END
		ELSE
		BEGIN
			INSERT INTO #CEO ( [ValueInUse], [Target] ) VALUES (0, 0)
		END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '28', 0, '''CHECK_EXPIRATION'' Setting', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'This is a mitigating recommendation for systems which cannot follow the recommendation to use only Windows Authenticated logins. ''CONTROL SERVER'' is an equivalent permission to sysadmin and logins with that permission should also be required to have expiring passwords.' END FROM #CEO
		SET @StepNameConfigOption = 'Ensure ''CHECK_EXPIRATION'' option is set to ''ON'' for all SQL authenticated logins within the sysadmin role'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #CEO;

	/*
		| 29 (4.3)
		|	Ensure 'CHECK_POLICY' Option is set to 'ON' for all SQL authenticated logins (Scored)
	*/
	IF OBJECT_ID('tempdb..#CPO') IS NOT NULL
		DROP TABLE #CPO;
	CREATE TABLE #CPO ( [ValueInUse] INT, [Target] INT )
	IF EXISTS ( SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0 AND is_disabled != 1 )
	BEGIN
		INSERT INTO #CPO ( [ValueInUse], [Target] ) VALUES (1, 0)
	END
	ELSE
	BEGIN
		INSERT INTO #CPO ( [ValueInUse], [Target] ) VALUES (0, 0)
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '29', 0, '''CHECK_POLICY'' Setting', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'Weak passwords can lead to compromised systems. The setting is only enforced when the password is changed.' END FROM #CPO
		SET @StepNameConfigOption = 'Ensure ''CHECK_POLICY'' option is set to ''ON'' for all SQL authenticated logins'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #CPO;

	/*
		| 30 (5.1)
		|	Ensure 'Maximum number of error log files' corresponds to client policy (Scored)
	*/
	IF OBJECT_ID('tempdb..#MNEL') IS NOT NULL
		DROP TABLE #MNEL;
	CREATE TABLE #MNEL ( [ValueInUse] INT, [Target] INT )
	DECLARE @NumErrorLogs INT;
	EXEC master.sys.xp_instance_regread
		  N'HKEY_LOCAL_MACHINE'
		, N'Software\Microsoft\MSSQLServer\MSSQLServer'
		, N'NumErrorLogs'
		, @NumErrorLogs OUTPUT;

	IF( SELECT ISNULL( @NumErrorLogs, 6 )) = 6
	BEGIN
		INSERT INTO #MNEL ( [ValueInUse], [Target] )
		VALUES (( SELECT ISNULL( @NumErrorLogs, 6 )), 99 )
	END
	ELSE
	BEGIN
		INSERT INTO #MNEL ( [ValueInUse], [Target] )
		VALUES (( SELECT ISNULL( @NumErrorLogs, -1 )), 99 )
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '30', 0, 'Maximum Number of Error Log files'
			, CASE WHEN [ValueInUse] <> [Target] THEN 0 ELSE 1 END, CASE WHEN [Target] = 99 THEN 1 ELSE 0 END
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'Increase the Number of SQL Server error logs to ' + ( SELECT CONVERT(VARCHAR(2), [Target]) FROM #MNEL ) + '.' END FROM #MNEL
	SET @StepNameConfigOption = 'Ensure ''Maximum number of error log files'' corresponds to client policy'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #MNEL;

	/*
		| 32 (5.3) 
		|	Ensure 'Login auditing' is set to 'failed logins' (Scored)
		|	This setting will record failed authentication attempts for SQL Server logins to the SQL Server Errorlog
		|	0 - None | 1 - Successful logins only | 2 - Failed logins only | 3 - Both failed and successful logins
	*/
	IF OBJECT_ID('tempdb..#LAFL') IS NOT NULL
		DROP TABLE #LAFL;
	CREATE TABLE #LAFL (  [ValueInUse] INT, [Target] INT )
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
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '32', 0, 'Audit Level Setting', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'If the Audit object is not implemented with the appropriate setting, SQL Server will not capture successful logins, which might prove of use for forensics.' END FROM #LAFL
		SET @StepNameConfigOption = 'Ensure ''Login auditing'' is set to ''failed logins'''
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #LAFL;

	/*
		| 33 (5.4) 
		|	Ensure 'SQL Server audit' is set to capture both 'failed' and 'successful logins' (Scored)
	*/
	IF OBJECT_ID('tempdb..#AFSL') IS NOT NULL
		DROP TABLE #AFSL;
	CREATE TABLE #AFSL ( [ValueInUse] INT, [Target] INT )
	IF ( SELECT SAD.audit_action_name
		FROM sys.server_audit_specification_details AS SAD JOIN sys.server_audit_specifications AS SA
			ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid
		WHERE SAD.audit_action_id IN ( 'CNAU', 'LGFL', 'LGSD' ) ) NOT IN ( 'AUDIT_CHANGE_GROUP', 'FAILED_LOGIN_GROUP', CONVERT(INT,
			CASE WHEN ISNUMERIC( CONVERT(VARCHAR(28), 'SUCCESSFUL_LOGIN_GROUP' )) = 1 THEN CONVERT(VARCHAR(28), 'SUCCESSFUL_LOGIN_GROUP' ) END ) )
	BEGIN
		INSERT INTO #AFSL ( [ValueInUse], [Target] )
		VALUES (( SELECT COUNT(SAD.audit_action_name)
			FROM sys.server_audit_specification_details AS SAD JOIN sys.server_audit_specifications AS SA
				ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid
			WHERE SAD.audit_action_id IN ( 'CNAU', 'LGFL', 'LGSD' )), 1 )
	END
	ELSE
	BEGIN
		INSERT INTO #AFSL ( [ValueInUse], [Target] )
		VALUES (( SELECT COUNT(SAD.audit_action_name)
			FROM sys.server_audit_specification_details AS SAD JOIN sys.server_audit_specifications AS SA
				ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits AS S
				ON SA.audit_guid = S.audit_guid
			WHERE SAD.audit_action_id IN ( 'CNAU', 'LGFL', 'LGSD' )), 1 )
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '33', 0, 'SQL Server Audit Setting', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'Make sure that failed logins are captured in order to detect if an adversary is attempting to brute force passwords or otherwise attempting to access a SQL Server improperly.' END FROM #AFSL END DROP TABLE #AFSL;
	SET @StepNameConfigOption = 'Ensure ''SQL Server audit'' is set to capture both ''failed'' and ''successful logins'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 6.1 Ensure Sanitize Database and Application User Input is Sanitized (Not Scored)
		|     Must be controlled by the application owners
	*/
	/*
		| 34 (6.2) 
		|	Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for all CLR assemblies (Scored)
		|	Maintain documented, standard security configuration standards for all authorized operating systems and software.
	*/
	IF OBJECT_ID('tempdb..#CLRA') IS NOT NULL
		DROP TABLE #CLRA;
	CREATE TABLE #CLRA ( [ValueInUse] INT, [Target] INT )
	IF NOT EXISTS( SELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1 )	--AND permission_set_desc = 'SAFE_ACCESS' )
	BEGIN
		INSERT INTO #CLRA ( [ValueInUse], [Target] ) VALUES (0, 0)
	END
	ELSE
	BEGIN
		INSERT INTO #CLRA ( [ValueInUse], [Target] ) VALUES (0, 1)
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '34', 0, 'CLR Assembly Permission', [ValueInUse], [Target]
			, CASE WHEN [ValueInUse] = [Target] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [ValueInUse] = [Target] THEN 'No problem was found.' 
				ELSE 'Establish Secure Configurations. The remediation measure should first be tested within a test environment prior to production to ensure the assembly still functions as designed with SAFE permission setting. Make sure that disabling the CLR Strict Security configuration option is highly unrecommended by Microsoft' END FROM #CLRA
		SET @StepNameConfigOption = 'Ensure ''CLR Assembly Permission Set'' is set to ''SAFE_ACCESS'' for all CLR assemblies'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #CLRA;

	/*
		| 35 (7.1)
		|	Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases (Scored)
	*/
	IF OBJECT_ID('tempdb..#SKEA') IS NOT NULL
		DROP TABLE #SKEA;
	CREATE TABLE #SKEA ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #SKEA ( [ValueInUse], [Target] )
		VALUES ( CASE WHEN ( SELECT COUNT(name) FROM sys.symmetric_keys WHERE algorithm_desc IN ( 'AES_128','AES_192','AES_256' ) AND DB_ID() > 4 ) IS NULL THEN 0 ELSE 1 END, 0 )
	END;
	BEGIN
		EXEC sp_MSforeachdb 'USE [?];
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT DISTINCT ''35'', 0, ''Encryption algorithm for Symmetric Key  in ['' + DB_NAME() + '']''
			, ''['' + NAME + '']'', ( SELECT [Target] FROM #SKEA )
			, CASE WHEN ( SELECT [Target] FROM #SKEA ) = ( SELECT [ValueInUse] FROM #SKEA ) THEN ''Yes'' ELSE ''No'' END
			, CASE WHEN ( SELECT [Target] FROM #SKEA ) = ( SELECT [ValueInUse] FROM #SKEA ) THEN ''No problem was found.'' 
				ELSE ''The Microsoft Best Practices, only the SQL Server AES algorithm options, AES_128, AES_192, and AES_256, should be used for a symmetric key encryption algorithm. Eliminate use of weak and deprecated algorithms which may put a system at higher risk of an attacker breaking the key. If you use compression, you should compress data before encrypting it.'' END 
		FROM sys.symmetric_keys WHERE algorithm_desc IN ( ''AES_128'',''AES_192'',''AES_256'' ) AND DB_ID() > 4 AND name NOT LIKE ''%##%'''
		SET @StepNameConfigOption = 'Ensure ''Symmetric Key encryption algorithm'' is set to ''AES_128'' or higher in non-system databases'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END DROP TABLE #SKEA;

	/*
		| 36	Ensure Asymmetric Key size is set to 'greater than or equal to 2048' in non-system databases (Scored)
	*/
	IF OBJECT_ID('tempdb..#AKS') IS NOT NULL
		DROP TABLE #AKS;
	CREATE TABLE #AKS ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #AKS ( [ValueInUse], [Target] )
		VALUES ( CASE WHEN ( SELECT COUNT(name) FROM sys.symmetric_keys WHERE key_length < 2048 AND DB_ID() > 4 ) IS NULL THEN 0 ELSE 1 END, 0 )
	END;
	BEGIN
		EXEC sp_MSforeachdb 'USE [?];
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT ''36'', 0, ''Asymmetric Key size to low  in ['' + DB_NAME() + '']''
				, ''['' + NAME + '']'', ( SELECT [Target] FROM #AKS )
				, CASE WHEN ( SELECT [Target] FROM #AKS ) = ( SELECT [ValueInUse] FROM #AKS ) THEN ''Yes'' ELSE ''No'' END
				, CASE WHEN ( SELECT [Target] FROM #AKS ) = ( SELECT [ValueInUse] FROM #AKS ) THEN ''No problem was found.'' 
					ELSE ''Microsoft Best Practices recommend to use at least a 2048-bit encryption algorithm for asymmetric keys. The higher-bit level may result in slower performance, but reduces the likelihood of an attacker breaking the key.'' END 
			FROM sys.symmetric_keys WHERE key_length < 2048 AND DB_ID() > 4 AND name NOT LIKE ''%##%'' END'
		SET @StepNameConfigOption = 'Ensure Asymmetric Key size is set to ''greater than or equal to 2048'' in non-system databases'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	 END DROP TABLE #AKS;

	/*
		| Prove SQL Server settings to change
		| 37	Ensure current version of maintenance solution objects are in use
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	VALUES ( '37', 1, 'Maintenance Solution Objects', CASE WHEN ( 
		SELECT COUNT(objects.[name]) FROM sys.objects objects INNER JOIN sys.schemas schemas ON objects.[schema_id] = schemas.[schema_id] 
		WHERE objects.[type] = 'U' AND schemas.[name] = 'dbo' AND objects.[name] IN ( 'CommandLog', 'QueueDatabase', 'Queue' ) ) <= 3 AND ( 
		SELECT COUNT(objects.[name]) FROM sys.objects objects INNER JOIN sys.schemas schemas ON objects.[schema_id] = schemas.[schema_id] 
		WHERE objects.[type] = 'P' AND schemas.[name] = 'dbo' AND objects.[name] IN ( 'CommandExecute', 'DatabaseBackup', 'DatabaseIntegrityCheck', 'IndexOptimize' )) = 4 AND ( 
		SELECT COUNT(SPECIFIC_NAME) FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_DEFINITION LIKE '%2020-01-26 14:06:53%' AND ROUTINE_TYPE = 'PROCEDURE' ) = 4 THEN 0 ELSE 1 END, 0, CASE WHEN ( 
		SELECT COUNT(objects.[name]) FROM sys.objects objects INNER JOIN sys.schemas schemas ON objects.[schema_id] = schemas.[schema_id] 
		WHERE objects.[type] = 'U' AND schemas.[name] = 'dbo' AND objects.[name] IN ( 'CommandLog', 'QueueDatabase', 'Queue' ) ) <= 3 AND ( 
		SELECT COUNT(objects.[name]) FROM sys.objects objects INNER JOIN sys.schemas schemas ON objects.[schema_id] = schemas.[schema_id] 
		WHERE objects.[type] = 'P' AND schemas.[name] = 'dbo' AND objects.[name] IN ( 'CommandExecute', 'DatabaseBackup', 'DatabaseIntegrityCheck', 'IndexOptimize' )) = 4 AND ( 
		SELECT COUNT(SPECIFIC_NAME) FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_DEFINITION LIKE '%2020-01-26 14:06:53%' AND ROUTINE_TYPE = 'PROCEDURE' ) = 4 THEN 'Yes' ELSE 'No' END, CASE WHEN (
		SELECT COUNT(objects.[name]) FROM sys.objects objects 
			INNER JOIN sys.schemas schemas ON objects.[schema_id] = schemas.[schema_id] 
		WHERE objects.[type] = 'U' AND schemas.[name] = 'dbo' 
			AND objects.[name] IN ( 'CommandLog', 'QueueDatabase', 'Queue' )) BETWEEN 1 AND 3 
			AND (	SELECT COUNT(objects.[name]) FROM sys.objects objects 
						INNER JOIN sys.schemas schemas ON objects.[schema_id] = schemas.[schema_id] 
					WHERE objects.[type] = 'P' AND schemas.[name] = 'dbo' 
						AND objects.[name] IN ( 'CommandExecute'
							, 'DatabaseBackup'
							, 'DatabaseIntegrityCheck'
							, 'IndexOptimize' ) ) = 4 THEN CASE 
						WHEN ( SELECT COUNT(SPECIFIC_NAME) FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_DEFINITION LIKE '%2020-01-26 14:06:53%' 
							AND ROUTINE_TYPE = 'PROCEDURE' ) <> 4 THEN 'Installed objects are not up to date. We strongly recomend you reinstall the latest Maintenance Solution Version 2001' ELSE 'No problem was found.' END 
							ELSE 'We strongly recomend you to use Maintenance Solution Version 2001' 
							END )
	SET @StepNameConfigOption = 'Prove current version of Maintenance Solution'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 38	Ensure current 'max degree of parallelism' option is set up
	*/
	IF OBJECT_ID('tempdb..#MDOP') IS NOT NULL
		DROP TABLE #MDOP;
	CREATE TABLE #MDOP ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #MDOP ( [ValueInUse], [Target] )
		SELECT CAST ( sc.value AS VARCHAR(MAX) ), CONVERT( INT, CASE WHEN [MaxDop_RAW] > 10 THEN 10 ELSE [MaxDop_RAW] END )
		FROM (
			SELECT
				  [LogicalCPUs]
				, [hyperthread_ratio]
				, [PhysicalCPU]
				, [HTEnabled]
				, [LogicalCPUPerNuma]
				, [NoOfNUMA]
				, [Number of Cores]
				, [MaxDop_RAW] =
					CASE
						WHEN [NoOfNUMA] > 1 AND HTEnabled = 0 THEN LogicalCPUPerNuma
						WHEN [NoOfNUMA] > 1 AND HTEnabled = 1 THEN CONVERT(DECIMAL(9, 4), [NoOfNUMA] / CONVERT(DECIMAL(9, 4), Res_MAXDOP.PhysicalCPU) * CONVERT(DECIMAL(9, 4), 1))
						WHEN HTEnabled = 0 THEN Res_MAXDOP.LogicalCPUs
						WHEN HTEnabled = 1 THEN Res_MAXDOP.PhysicalCPU
					END
			FROM (
				SELECT
					  [LogicalCPUs] = osi.cpu_count
					, osi.hyperthread_ratio 
					, [PhysicalCPU] = osi.cpu_count/osi.hyperthread_ratio
					, [HTEnabled] = CASE WHEN osi.cpu_count > osi.hyperthread_ratio THEN 1 ELSE 0 END
					, [LogicalCPUPerNuma]
					, [NoOfNUMA]
					, [Number of Cores] 
				FROM (
					SELECT
						  [NoOfNUMA] = COUNT(res.parent_node_id)
						, [Number of Cores] = res.LogicalCPUPerNuma / COUNT(res.parent_node_id)
						, res.LogicalCPUPerNuma
					FROM (	SELECT s.parent_node_id, LogicalCPUPerNuma = COUNT(1)
							FROM [master].[sys].[dm_os_schedulers] s
							WHERE s.parent_node_id < 64 AND s.status = 'VISIBLE ONLINE'
							GROUP BY s.parent_node_id
						) res
					GROUP BY res.LogicalCPUPerNuma
					) Res_NUMA CROSS APPLY [master].[sys].[dm_os_sys_info] osi
				) Res_MAXDOP
			) Res_Final CROSS APPLY [master].[sys].[configurations] sc
		WHERE sc.name = 'max degree of parallelism'
		OPTION (RECOMPILE)
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT TOP 1 '38', 1, 'MaxDOP Setting', [ValueInUse]
			, CASE WHEN [Target] <> [ValueInUse] THEN 1 ELSE [Target] END
			, CASE 
				WHEN [ValueInUse] = 0 THEN 'No' 
				WHEN [ValueInUse] = 1 AND [Target] > 1 THEN 'Yes' 
				WHEN [Target] >= [ValueInUse] THEN 'Yes' ELSE 'No' END
			, CASE 	
				WHEN [ValueInUse] = 0 THEN 'A ''0'' for this value means that every processor will be used by parallel queries. We strongly recomend you to set this value to ' + CAST([Target] AS VARCHAR(2)) + '.' 
				WHEN [ValueInUse] = 1 AND [Target] > 1 THEN 'Current setting is just fine. But to truly optimize your resources we recomend you to set this value to ' + CAST([Target] AS VARCHAR(2)) + '.'
				WHEN [Target] > [ValueInUse] THEN 'To truly optimize your resources we strongly recomend you to set this value to ' + CAST([Target] AS VARCHAR(2) ) + '.' 
				WHEN [Target] = [ValueInUse] THEN 'No problem was found.' 
					ELSE 'This configuration option should be set to max. value ' + CAST([Target] AS VARCHAR(2)) + '. Current configuration can cause performance problems and limit concurrency.' END FROM #MDOP END DROP TABLE #MDOP;
	SET @StepNameConfigOption = 'Ensure ''max degree of parallelism'' option is set up'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 39	Ensure 'Cost Threshold for Parallelism' is configured
	*/				
	INSERT INTO #HardeningResults ( [FindingID] , [Severity] , [Name] , [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 1, cr.name
		, CASE WHEN cr.value_in_use >= cd.[DefaultValue] - 10 THEN 1 ELSE 0 END AS [Current Setting], 1
		, CASE WHEN cr.value_in_use >= cd.[DefaultValue] - 10 THEN 'Yes' ELSE 'No' END AS [Target Achieved]
		, CASE WHEN cr.value_in_use >= cd.[DefaultValue] - 10 THEN 'No problem was found.' 
			ELSE 'Currently configured value ' + CONVERT(VARCHAR(100), cr.value_in_use) + ' is too low. We recommend you increase the setting to at least ' 
			+ CONVERT(VARCHAR(100), cd.[DefaultValue]) + '. This is an arbitrary number, but it is significantly higher than the default.' END AS [Details]
	FROM sys.configurations cr
		INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
		LEFT OUTER JOIN #GlobalServerSettings cdUsed ON cdUsed.name = cr.name 
	WHERE cr.name = 'cost threshold for parallelism';
	SET @StepNameConfigOption = 'Ensure ''Cost Threshold for Parallelism'' is configured'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 41	Ensure Trace Flags enabled globally
	*/
	TRUNCATE TABLE #TemporaryDatabaseResults;
	EXEC dbo.sp_MSforeachdb 'USE [?]; 
	SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED; 
	IF EXISTS( SELECT * FROM sys.indexes WHERE type IN (5,6) ) 
	INSERT INTO #TemporaryDatabaseResults (DatabaseName, Finding) VALUES (DB_NAME(), ''Yes'') OPTION (RECOMPILE);';
	IF EXISTS ( SELECT * FROM #TemporaryDatabaseResults ) SET @ColumnStoreIndexesInUse = 1;
	BEGIN
		INSERT INTO #TraceFlagsGlobalStatus
		EXEC ( 'DBCC TRACESTATUS(-1) WITH NO_INFOMSGS' );

	INSERT INTO #TraceFlagToSet
		SELECT TF1.TraceFlag FROM #TraceFlagsIn TF1 
			LEFT JOIN #TraceFlagsGlobalStatus TF2 ON TF1.TraceFlag = TF2.TraceFlag 
		WHERE TF1.TraceFlag NOT IN ( SELECT TraceFlag FROM #TraceFlagsGlobalStatus )

	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT 41, 3, 'Trace flag missing', 1, 0, 'No', 'Trace flag ' + CASE 
			WHEN TraceFlag IS NOT NULL THEN TraceFlag + ' should be enabled in most cases. This trace flag is fully supported in a production environment.' ELSE '' END
			FROM #TraceFlagToSet

		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT 41, 3, 'Trace flags global setting', 1, 1, 'Yes', 'Trace flag ' + CASE
			WHEN [T].[TraceFlag] = '11024' AND @ProductVersion < '13.0.5026.0' AND @ProductVersion < '14.0.3015.40' THEN '11024 enabled globally. This TF applies only to SQL Server 2016 SP2, SQL Server 2017 CU3 and higher builds.'
			WHEN [T].[TraceFlag] = '9939' THEN '9939 enabled globally. TF 9939 is not needed if TF 4199 is also explicitly enabled.'
			WHEN [T].[TraceFlag] = '9481' AND @ProductVersion >= '13.0.4001.0' THEN '9481 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''FORCE_LEGACY_CARDINALITY_ESTIMATION'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '9476' AND @ProductVersion >= '13.0.4001.0' THEN '9476 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''ASSUME_JOIN_PREDICATE_DEPENDS_ON_FILTERS'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '9471' AND @ProductVersion >= '13.0.4001.0' THEN '9471 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''ASSUME_MIN_SELECTIVITY_FOR_FILTER_ESTIMATES'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '9259' THEN '9259 enabled globally. Please, don''t use TF 9259 that disables Project Normalization step in a real production system, besides it is undocumented and unsupported, it may hurt your performance.'
			WHEN [T].[TraceFlag] = '9024' AND @ProductVersion >= '11.00.2100.60' AND @ProductVersion >= '12.0.4100.1' THEN '9024 enabled globally. Beginning with SQL Server 2012 SP3 and SQL Server 2014 SP1 this behavior is controlled by the engine and TF 9024 has no effect.'
			WHEN [T].[TraceFlag] = '8649' THEN '8649 enabled globally. Using this TF drops cost threshold for parallelism down to 0. This flag is not something you want to enable and use it in a production environment. You can use DBCC TRACEON on a case-by-case basis, but it''s much nicer to use the QUERYTRACEON hint.'
			WHEN [T].[TraceFlag] = '8079' AND @ProductVersionMajor > '13' THEN '8079 enabled globally. Beginning with SQL Server 2016 this behavior is controlled by the engine and TF 8079 has no effect.'
			WHEN [T].[TraceFlag] = '8075' AND @ProductVersionMajor > '13' THEN '8075 enabled globally. Starting with SQL Server 2016 this behavior is controlled by the engine and TF 8075 has no effect.'
			WHEN [T].[TraceFlag] = '8048' AND @ProductVersion > '12.0.5000.0' AND @ProductVersionMajor > '13' THEN '8048 enabled globally. Beginning with SQL Server 2014 SP2 and SQL Server 2016 this behavior is controlled by the engine and TF 8048 has no effect.'
			WHEN [T].[TraceFlag] = '8032' THEN '8032 is enabled globally. WARNING: TF 8032 can cause poor performance if large caches make less memory available for other memory consumers, such as the buffer pool.'
			WHEN [T].[TraceFlag] = '8017' AND (CAST(SERVERPROPERTY('Edition') AS NVARCHAR(1000)) LIKE N'%Express%') THEN '8017 is enabled globally, which is the default for express edition. This (TF) controls whether SQL Server creates schedulers for all logical processors, including those that are not available for SQL Server to use (according to the affinity mask)'
			WHEN [T].[TraceFlag] = '8017' AND (CAST(SERVERPROPERTY('Edition') AS NVARCHAR(1000)) NOT LIKE N'%Express%') THEN '8017 is enabled globally. Using this TF disables creation schedulers for all logical processors.'
			WHEN [T].[TraceFlag] = '7752' AND @ProductVersionMajor >= '15'THEN '7752 enabled globally. Starting with SQL Server 2019 this behavior is controlled by the engine and TF 7752 has no effect.'
			WHEN [T].[TraceFlag] = '7745' AND @ProductVersionMajor >= '14'THEN '7412 enabled globally. Starting with SQL Server 2019 this TF has no effect because lightweight profiling is enabled by default.'
			WHEN [T].[TraceFlag] = '7412' AND @ProductVersionMajor >= '15'THEN '7412 enabled globally. Starting with SQL Server 2019 this TF has no effect because lightweight profiling is enabled by default.'
			WHEN [T].[TraceFlag] = '7412' AND @ProductVersion < '13.0.4001.0' THEN '7412 enabled globally. This TF applies only to SQL Server 2016 SP1 and higher builds.'
			WHEN [T].[TraceFlag] = '6533' AND @ProductVersionMajor >= '13' THEN '6533 enabled globally. Starting with SQL Server 2016 this behavior is controlled by the engine and TF 6533 has no effect.'
			WHEN [T].[TraceFlag] = '6532' AND @ProductVersionMajor >= '13' THEN '6532 enabled globally. Starting with SQL Server 2016 this behavior is controlled by the engine and TF 6532 has no effect.'
			WHEN [T].[TraceFlag] = '6498' AND @ProductVersion >= '12.0.5000.0' AND @ProductVersionMajor >= '13' THEN '6498 enabled globally. Beginning with SQL Server 2014 SP2 and SQL Server 2016 this behavior is controlled by the engine and TF 6498 has no effect.'
			WHEN [T].[TraceFlag] = '4199' AND @ProductVersion < '13.0.4001.0' THEN '4199 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '4199' AND @ProductVersionMajor >= '13' THEN '4199 enabled globally. It''s recommended only for customers who are seeing specific performance issues, customers are advised to remove TF 4199 after they migrate their databases to the latest compatibility level because this TF 4199 will be reused for future fixes that may not apply to your application and could cause unexpected plan performance changes on a production system.'
			WHEN [T].[TraceFlag] = '4139' AND @ProductVersion >= '13.0.4001.0' THEN '4139 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''ENABLE_HIST_AMENDMENT_FOR_ASC_KEYS'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '4138' AND @ProductVersion >= '13.0.4001.0' THEN '4138 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''DISABLE_OPTIMIZER_ROWGOAL'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '4137' AND @ProductVersion >= '13.0.4001.0' THEN '4137 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''ASSUME_MIN_SELECTIVITY_FOR_FILTER_ESTIMATES'' query hint instead of using this TF'
			WHEN [T].[TraceFlag] = '4136' AND @ProductVersion >= '13.0.4001.0' THEN '4136 enabled globally. Starting with SQL Server 2016 SP1, a second option to accomplish this at the query level is to add the USE HINT ''DISABLE_PARAMETER_SNIFFING'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '3656' THEN '3656 enabled globally. WARNING: This is a debugging TF and not meant for production environment use.'
			WHEN [T].[TraceFlag] = '3656' AND @ProductVersionMajor >= '15' THEN '3656 enabled globally. Starting with SQL Server 2019, TF 2592 must be enabled in conjunction with TF 3656 to enable symbol resolution.'
			WHEN [T].[TraceFlag] = '3608' THEN '3608 enabled globally. Some features, such as snapshot isolation and read committed snapshot, might not work. Do not use during normal operation.'
			WHEN [T].[TraceFlag] = '3505' THEN '3505 enabled globally. Using this TF disables Checkpoints. It may increase recovery time and can prevent log space reuse until the next checkpoint is issued. For high availability systems, such as clusters, Microsoft recommends that you do not change the recovery interval because it may affect data safety and availability.'
			WHEN [T].[TraceFlag] = '3468' AND @ProductVersion < '13.0.4451.0' AND @ProductVersion < '14.0.3006.16' THEN '3468 enabled globally. This TF applies only to SQL Server 2016 SP1 CU5, SQL Server 2017 CU1 and higher builds.'
			WHEN [T].[TraceFlag] = '3459' AND @ProductVersionMajor < '13' THEN '3459 enabled globally. This TF applies to SQL Server 2016 and higher builds, has no effect on current instance. Remove it.'
			WHEN [T].[TraceFlag] = '3449' AND @ProductVersion < '11.0.6537.0' AND @ProductVersion < '12.0.4459.0' THEN '3449 enabled globally. This TF applies only to SQL Server 2012 SP3 CU3 or later or SQL Server 2014 SP1 CU7 and higher builds. This TF has no effect. Remove it.'
			WHEN [T].[TraceFlag] = '3427' AND @ProductVersion >= '13.0.5216.0' AND @ProductVersionMajor >= '14' THEN '3427 enabled globally. Starting with SQL Server 2016 SP2 CU3 and SQL Server 2017, this TF has no effect. Remove it.'
			WHEN [T].[TraceFlag] = '3023' AND @ProductVersionMajor >= '12' THEN '3023 enabled globally. Starting with SQL Server 2014 this behavior is controlled by setting the backup checksum default configuration option.'
			WHEN [T].[TraceFlag] = '2422' AND @ProductVersion < '13.0.5026.0' AND @ProductVersion < '14.0.3015.40' THEN '2422 enabled globally. This TF applies only to SQL Server 2016 SP2, SQL Server 2017 CU3, and higher builds. This TF has no effect. Remove it.'
			WHEN [T].[TraceFlag] = '2371' AND @ProductVersionMajor >= '13' THEN '2371 enabled globally. Beginning with SQL Server 2016 TF 2371 has no affect. Remove it.'
			WHEN [T].[TraceFlag] = '2340' AND @ProductVersion >= '13.0.4001.0' THEN '2340 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '2330' THEN '2330 enabled globally. Disables collection of index usage/missing index requests. It''s bad idea for 99.9% of people.'
			WHEN [T].[TraceFlag] = '2312' AND @ProductVersion >= '13.0.4001.0' THEN '2312 enabled globally. Starting with SQL Server 2016 SP1, to accomplish this at the query level, add the USE HINT ''FORCE_DEFAULT_CARDINALITY_ESTIMATION'' query hint instead of using this TF.'
			WHEN [T].[TraceFlag] = '1806' THEN '1806 enabled globally. Using this TF disables Instant File Initialization. Disabling IFI means the data will be overwritten with zeroes, which will increase the allocation time.'
			WHEN [T].[TraceFlag] = '1237' AND @ProductVersionMajor >= '14' THEN '1237 enabled globally. Starting with SQL Server 2017 this TF 1236 has no effect. Remove it.'
			WHEN [T].[TraceFlag] = '1236' AND @ProductVersion >= '12.0.4100.1' THEN '1236 enabled globally. Beginning with SQL Server 2012 SP3 and SQL Server 2014 SP1 this TF 1236 has no effect. Remove it.'
			WHEN [T].[TraceFlag] = '1224' THEN '1224 enabled globally. Using this TF disables lock escalation based on the number of locks being taken. If both TFs 1211 and 1224 are set, 1211 takes precedence over 1224. Because TF 1211 prevents escalation in every case, even under memory pressure, we recommend that you use TF 1224. '
			WHEN [T].[TraceFlag] = '1211' THEN '1211 enabled globally. Using this TF disables lock escalation when you least expect it.'
			WHEN [T].[TraceFlag] = '1118' AND @ProductVersionMajor >= '13' THEN '1118 enabled globally. Beginning with SQL Server 2016 Trace Flag 1118 has no affect and can be removed.'
			WHEN [T].[TraceFlag] = '1117' AND @ProductVersionMajor >= '13' THEN '1117 enabled globally. Beginning with SQL Server 2016 Trace Flag 1117 has no affect and can be removed.'
			WHEN [T].[TraceFlag] = '876' AND @ProductVersionMajor < '15' THEN '876 enabled globally. This TF applies only to SQL Server 2019 and higher builds. Remove it.'
			WHEN [T].[TraceFlag] = '834' AND @ColumnStoreIndexesInUse = 1 AND @ProductVersionMajor < '15' THEN '834 enabled globally. If you are using the Columnstore Index feature of SQL Server 2012 through SQL Server 2019, we do not recommend turning on TF 834. To resolve this issue, remove TF 834 from SQL Server startup parameters.'
			WHEN [T].[TraceFlag] = '834' AND @ColumnStoreIndexesInUse = 1 AND @ProductVersionMajor >= '15' THEN '834 enabled globally. If using SQL Server 2019 and Columnstore, see TF 876 instead. Remove TF 834 from startup parameters.'
			WHEN [T].[TraceFlag] = '692' AND @ProductVersionMajor >= '13' THEN '692 enabled globally. This TF applies only to SQL Server 2016 RTM and higher builds.'
			WHEN [T].[TraceFlag] = '661' THEN '661 enabled globally. Using this TF disables ghost record removal. Turn it off.'
			WHEN [T].[TraceFlag] = '652' THEN '652 enabled globally. Using this TF disables pre-fetching during index scans. Turn that off. If you turn it on, SQL Server no longer brings database pages into the buffer pool before these database pages are consumed by the scans.'
			ELSE [T].[TraceFlag] + ' enabled globally' END
			FROM #TraceFlagsGlobalStatus T;
		END;
	END;
	SET @StepNameConfigOption = 'Ensure trace flags enabled globally.'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 42	Detect logins without permissions
	*/
	IF OBJECT_ID('tempdb..#AEGU') IS NOT NULL
		DROP TABLE #AEGU;
	CREATE TABLE #AEGU ( [DB] VARCHAR(70), sid VARBINARY(85), stat VARCHAR(50) )
	EXEC master.sys.sp_MSforeachdb '
		INSERT INTO #AEGU
		SELECT ''?'', CONVERT(VARBINARY(85), SID), CASE WHEN r.role_principal_id IS NULL AND p.major_id IS NULL THEN ''no permissions'' ELSE ''db_user'' END
		FROM [?].sys.database_principals u LEFT JOIN [?].sys.database_permissions p ON u.principal_id = p.grantee_principal_id AND p.permission_name <> ''CONNECT'' LEFT JOIN [?].sys.database_role_members r ON u.principal_id = r.member_principal_id
		WHERE u.SID IS NOT NULL AND u.type_desc <> ''DATABASE_ROLE'''
	IF EXISTS (
		SELECT DISTINCT l.name FROM sys.server_principals l LEFT JOIN sys.server_permissions p ON l.principal_id = p.grantee_principal_id 
			AND p.permission_name <> 'CONNECT SQL' 
				LEFT JOIN sys.server_role_members r ON l.principal_id = r.member_principal_id 
				LEFT JOIN #AEGU u ON l.sid = u.sid
		WHERE l.name NOT IN ( 'NT SERVICE\ClusSvc' ) 
			AND r.role_principal_id IS NULL 
			AND l.type_desc <> 'SERVER_ROLE' 
			AND p.major_id IS NULL )
		BEGIN
			IF OBJECT_ID('tempdb..#TTLN') IS NOT NULL DROP TABLE #TTLN;
			CREATE TABLE #TTLN ( LoginName VARCHAR(MAX) ) INSERT INTO #TTLN ( [LoginName] )
			SELECT l.name FROM sys.server_principals l 
				LEFT JOIN sys.server_permissions p ON l.principal_id = p.grantee_principal_id 
				AND p.permission_name <> 'CONNECT SQL' 
				LEFT JOIN sys.server_role_members r ON l.principal_id = r.member_principal_id 
				LEFT JOIN #AEGU u ON l.sid = u.sid
			WHERE l.name NOT IN ( 'NT SERVICE\ClusSvc' ) AND l.type_desc <> 'SERVER_ROLE' 
				AND (
					( u.DB IS NULL AND p.major_id IS NULL AND r.role_principal_id IS NULL ) 
					OR ( u.stat = 'no_db_permissions' AND p.major_id IS NULL AND r.role_principal_id IS NULL )
					) ORDER BY 1
		END
		SET @MsgLoginUsers = 'We have found some user accounts without permissions. These logins should be reviewed and most likely some of them have to be disabled or deleted (' + @ListLoginName + ')'
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		VALUES ( '42', 0, 'Logins without permissions'
			, CASE WHEN ( SELECT DISTINCT COUNT(LoginName) FROM #TTLN ) > 0 THEN 1 ELSE 0 END
			, 0, CASE WHEN ( SELECT DISTINCT COUNT(LoginName) FROM #TTLN ) = 0 THEN 'Yes' ELSE 'No' END
			, CASE WHEN ( SELECT COUNT(LoginName) FROM #TTLN ) > 0 THEN @MsgLoginUsers ELSE 'No problem was found.' END ) DROP TABLE #TTLN DROP TABLE #AEGU;
	SET @StepNameConfigOption = 'Detect logins without permissions'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 43 (20.7) Service Account Isolation
	*/
	IF OBJECT_ID('tempdb..#ISSA') IS NOT NULL
		DROP TABLE #ISSA;
	CREATE TABLE #ISSA ( [servicename] VARCHAR(50), [service_account] VARCHAR(50) )
	BEGIN
		INSERT INTO #ISSA ( [servicename], [service_account] )
		SELECT service_account, COUNT(*) 'CountDown' FROM sys.dm_server_services GROUP BY service_account HAVING COUNT(*) > 1
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		VALUES ( '43', 0, 'Service Account Isolation'
			, ( SELECT CASE WHEN ( SELECT [service_account] FROM #ISSA ) <> 1 THEN 0 ELSE 1 END )
			, 1, CASE WHEN ( SELECT [service_account] FROM #ISSA ) <> 1 THEN 'No' ELSE 'Yes' END
			, CASE WHEN ( SELECT [service_account] FROM #ISSA ) <> 1 THEN 'We have found ' + ( SELECT [service_account] FROM #ISSA ) 
				+ ' SQL components associated with service account ''' + ( SELECT [servicename] FROM #ISSA ) 
				+ '''. If this service account is compromised, all components associated with the service account will be breached. For isolation purposes, a separate account should be created for each SQL Server instance and component being installed.' ELSE 'No problem was found.' END ) DROP TABLE #ISSA;
	END;
	SET @StepNameConfigOption = 'Prove Service Account Isolation'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 44 (20.08) Failed Jobs
	*/
	IF EXISTS (
		SELECT step_name FROM [msdb].[dbo].[sysjobsteps]
		WHERE last_run_outcome = 0 AND last_run_date <> 0 AND step_name LIKE ('ST%'))
		BEGIN
			DECLARE @sJobName NVARCHAR(50), @sJobStepID NVARCHAR(2), @sJobStepName NVARCHAR(50), @sRunDuration NVARCHAR(20), @sLastRun NVARCHAR(20), @sMessage NVARCHAR(2048)
			DECLARE cErrorMessage
			CURSOR STATIC READ_ONLY FOR
			SELECT [sJob].[name]
				, [sJStp].[step_id]
				, [sJStp].[step_name]
				, STUFF(
					STUFF(RIGHT('000000' + CAST([sJStp].[last_run_duration] AS VARCHAR(6)),  6)
							, 3, 0, ':')
						, 6, 0, ':')
				, CASE [sJStp].[last_run_date]
					WHEN 0 THEN NULL
					ELSE
					CAST(
						CAST([sJStp].[last_run_date] AS CHAR(8))
					+ ' '
					+ STUFF(
						STUFF(RIGHT('000000' + CAST([sJStp].[last_run_time] AS VARCHAR(6)),  6)
							, 3, 0, ':')
						, 6, 0, ':')
					AS DATETIME)
				END
			FROM [msdb].[dbo].[sysjobsteps] AS [sJStp]
				INNER JOIN [msdb].[dbo].[sysjobs] AS [sJob] ON [sJStp].[job_id] = [sJob].[job_id]
			WHERE sJStp.last_run_outcome = 0 AND sJStp.step_name LIKE ('ST0%') AND sJStp.step_name NOT LIKE ('%CHECK_STEPS_ERRORS%') AND sJob.name LIKE '%MAINTENANCE_ALL_DATABASES'
			OPEN cErrorMessage
			FETCH NEXT FROM cErrorMessage INTO @sJobName, @sJobStepID, @sJobStepName, @sRunDuration, @sLastRun
			WHILE @@FETCH_STATUS = 0
				BEGIN
					SELECT @sMessage = 'The Step "' + @sJobStepName + '" (ID:' + @sJobStepID + ')'
						+ ' is part of Job "' + @sJobName + '" failed on ' + @sLastRun + ' after ' + @sRunDuration + ' min./sec. of execution.'
					INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
					SELECT '44', 1, 'Failed Job', 1, 0, 'No', @sMessage				
					FETCH NEXT FROM cErrorMessage INTO @sJobName, @sJobStepID, @sJobStepName, @sRunDuration, @sLastRun
				END
			CLOSE cErrorMessage
			DEALLOCATE cErrorMessage
		END
		ELSE
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT '44', 1, 'Failed Job', 0, 0, 'Yes', 'No problem was found.'
		END;
	SET @StepNameConfigOption = 'Prove failed jobs'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 45 (20.09) Check for DBCC errors
		|	  Monitoring error messages in the SQL Server error log after execution a DBCC command in SQL Server (last 7 days)
	*/
	IF OBJECT_ID('tempdb..#DBCC') IS NOT NULL
		DROP TABLE #DBCC;
	CREATE TABLE #DBCC ( [DatabaseName] [SYSNAME], [EndTime] [DATETIME], [ErrorNumber] [INT], [ErrorMessage] [NVARCHAR](MAX) )
	IF NOT EXISTS ( SELECT * FROM sysobjects WHERE name = 'CommandLog' AND xtype = 'U' )
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			VALUES	( '45', 2, 'Check for DBCC errors', 0, 1, 'No' , 'We have found that not all objects from Maintenance Solution are currently installed. Check all objects existence and if needed reinstall it again.' );
		END
		ELSE
		BEGIN
			INSERT INTO #DBCC ( [DatabaseName], [EndTime], [ErrorNumber], [ErrorMessage] )
			SELECT [DatabaseName], [EndTime] , [ErrorNumber], CASE
				WHEN [ErrorNumber] IN ( '1823', '3313', '5128', '7928', '8921' ) THEN 'These error(s) show up when the drive that your databases reside on doesn''t have enough room for the snapshot that DBCC CHECKDB takes and uses to be created. Right now, we don''t have any control over that. This option might be covered in next releases of Maintenance Solution.'
				WHEN [ErrorNumber] IN ( '8928', '8944' ) THEN 'Please don''t run repair first. Best possible solution here is to restore from valid backup. The error could also be the result of hardware problems.'
				WHEN [ErrorNumber] IN ( '8946', '8998' ) THEN 'One or more of the database allocation pages are damaged. CHECKDB will not repair damage to the allocation pages, as it is extremely difficult to work out, without those pages, what extents are allocated and which are not. Dropping the allocation page is not an option.'
				WHEN [ErrorNumber] IN ( '8941', '8942' ) THEN 'The corruption can be completely repaired by dropping the damaged nonclustered indexes and recreating them. If there is insufficient time available to rebuild the affected index and there is a clean backup with an unbroken log chain, the damaged pages can be restored from backup.'
				WHEN [ErrorNumber] IN ( '7985' ) THEN 'CHECKDB depends on a few of the critical system tables to get a view of what should be in the database. If those tables themselves are damaged, then CHECKDB cannot know what the database should look like, and won''t even be able to analyze it, let alone repair.'
				WHEN [ErrorNumber] IN ( '665', '1450' ) THEN 'Solution well documented with a few recommended fixes in http://support.microsoft.com/kb/2002606 Disk Space is one reason why writes to the internal database snapshot may fail.'
				WHEN [ErrorNumber] = '17053' THEN 'When you run a DBCC command, the DBCC command first tries to create an internal snapshot. When the snapshot is created, database recovery is performed against this snapshot to bring the snapshot into a consistent state. The error messages reflect this activity. This behavior is by design.'
				WHEN [ErrorNumber] = '2508' THEN 'This is not a serious problem and it''s trivial to fix. Run DBCC UPDATEUSAGE on the database in question and the warnings will disappear.'
				WHEN [ErrorNumber] = '8964' THEN 'Corruption in the LOB pages. If these are the only errors that CHECKDB returns, then running repair with the ALLOW_DDATA_LOSS will simply deallocate these pages. Since the data rows that the LOB data belongs to does not exist, this will not result in further data loss.'
				WHEN [ErrorNumber] = '2570' THEN 'The fix for this is fairly easy, but manual. The bad values have to annually updated to something meaningful. The main challenge is finding the bad rows.'
				WHEN [ErrorNumber] = '8976' THEN 'If there is a clean backup, restoring from the backup is usually the recommended method of fixing these errors. If the database is in full recovery and there is an unbroken log chain since the clean database backup, then it is possible backup the tail of the transaction log and to restore, either the entire database or just the damaged pages, with no data loss at all.'
				WHEN [ErrorNumber] = '3853' THEN 'Fixing these is not trivial. CHECKDB will not repair them, as the only fix is to delete records from the system tables, which may cause major data loss.'
				WHEN [ErrorNumber] = '1222' THEN 'If this error occurs frequently change the lock time-out period or modify the offending transactions so that they hold the lock in less time.'
				ELSE 'There are a lot of reasons that CHECKDB can fail that don''t indicate corruption. Don''t panic. At first, turn off your backup-delete jobs: you''re gonna need''em. Any decisions made or actions taken should be carefully thought through and made after careful consideration with all factors taken into account. It''s very easy to make the situation worse with ill-thought through decisions.'
				END FROM msdb.dbo.CommandLog WHERE [ErrorNumber] <> 0 AND EndTime BETWEEN DATEADD(DAY, -7, GETDATE()) AND GETDATE() GROUP BY [EndTime], [ErrorNumber],[DatabaseName] HAVING [EndTime] > DATEADD(DAY, -30, GETDATE())
		END;

	IF ( SELECT COUNT(*) FROM #DBCC WHERE [ErrorNumber] <> 0 ) <> 0
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			VALUES	( '45', 2, 'Check for DBCC errors', ( SELECT COUNT(*) FROM #DBCC ), 0
				, CASE WHEN ( SELECT COUNT(*) FROM #DBCC ) = 0 THEN 'Yes' ELSE 'No' END, CASE WHEN ( SELECT COUNT(*) ) = 0 THEN 'No problem was found.' 
					ELSE 'We have found an error: ' + ( SELECT TOP 1 CAST([ErrorNumber] AS VARCHAR(10)) + ' in database [' + ( SELECT TOP 1 [DatabaseName] FROM #DBCC ) FROM #DBCC ) + '] occurred '
					+ ( SELECT CONVERT(VARCHAR(10), COUNT(*)) FROM #DBCC ) + ' time(s) on ' + ( SELECT TOP 1 CAST([EndTime] AS NVARCHAR(20)) FROM #DBCC ) + '. ' + ( SELECT TOP 1 [ErrorMessage] FROM #DBCC ) END );
			SET @StepNameConfigOption = 'Check for DBCC errors'
			SET @CountUp = @CountUp + 1
			SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
			RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
		END;

	/*
		| 46 (20.15) Filestream Setting
		|		There are two settings governing Filestream option, one in the registry (OS level) and one in SQL Server configuration. 
		|		There is a separation of security concerns between the Windows and database administrators, 
		|		and the same access level set for the Windows service needs to be set for the SQL Server instance.
		|		The result will return a "No" and aceptable, if the use of Filestream is documented and authorized.
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT cd.CheckID, 2, cr.name, CONVERT(VARCHAR(100), cr.value_in_use), cd.DefaultValue
		, CASE WHEN cd.[DefaultValue] = cr.value_in_use THEN 'Yes' ELSE 'No' END
		, CASE WHEN cd.[DefaultValue] <> cr.value_in_use THEN 
			CASE 
				WHEN cr.value_in_use = 1 THEN 'This setting means only T-SQL access to FILESTREAM data is allowed. Review the system documentation to see if FILESTREAM is officially in use.'
				WHEN cr.value_in_use = 2 THEN 'This setting means T-SQL access and local streaming access are allowed. Review the system documentation to see if FileStream is officially in use.'
				WHEN cr.value_in_use = 3 THEN 'This setting means T-SQL access, local and remote streaming access are allowed. Review the system documentation to see if FILESTREAM is officially in use.' END
			ELSE 'No problem was found.' END AS [Details] -- 0 = FILESTREAM disabled
	FROM sys.configurations cr
		INNER JOIN #GlobalServerSettings cd ON cd.name = cr.name
	WHERE cr.name = 'filestream access level';
	SET @StepNameConfigOption = 'Prove ''Filestream'' setting'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 47	Prove full backups within past 24 hours
	*/
	IF (( SELECT TOP 1 [NoBackupSinceHours] FROM #LastFullBackup ) > 24 )
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT DISTINCT '47', 1, 'Full Backup missing within past 24 hours'
			, 0, 1, 'No', 'Last full backup for database [' + CAST([DatabaseName] AS VARCHAR(50)) 
					+ '] was created on ' + CAST([LastFullBackup] AS VARCHAR(30)) 
					+ '. Important points to consider are what type of data is contained in the database and how busy the database is, '
					+ 'which can be thought of as the number of transactions per hour/ day? We recomend you at least one full backup every 24 hours.'
		FROM #LastFullBackup
	SET @StepNameConfigOption = 'Prove full backup''s within past 24 hours'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT DROP TABLE #LastFullBackup
	END;

	/*
		| 48	Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances (Scored)
		|		We will NOT follow the recommendation (see comment)
	*/
	DECLARE @HideInstance INT; 
	EXEC master..xp_instance_regread       
		  @rootkey = N'HKEY_LOCAL_MACHINE'
		, @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib'
		, @value_name = N'HideInstance'
		, @value = @HideInstance OUTPUT; 
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		VALUES ( '48', 0, 'Hidden Instance State', @HideInstance, 1
			, CASE WHEN @HideInstance <> 1 THEN 'No' ELSE 'Yes' END
			, CASE WHEN @HideInstance <> 1 THEN 'We recommend you to configure SQL Server instance within production environments as hidden. If it''s not implemented this can present a large security threat to organizations because sensitive production data can be compromised. This is typically a best practice for mission-critical production database servers that host sensitive data because there is no need to broadcast this information.' ELSE 'No problem was found.' END )
		SET @StepNameConfigOption = 'Ensure ''Hide Instance'' option is set to ''Yes'' for Production SQL Server instances'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 49	Determine failed logins
	*/
	WHILE @ErrorLogType < 3
	BEGIN

		IF OBJECT_ID(N'tempdb..#KeepExclusions', N'U') IS NOT NULL
			DROP TABLE #KeepExclusions;
		CREATE TABLE #KeepExclusions (
			  LogTextToExclude VARCHAR(MAX) COLLATE Latin1_General_CI_AS NOT NULL
			, LogType TINYINT NOT NULL
			);

		INSERT INTO #KeepExclusions (LogTextToExclude, LogType)
		VALUES ('%Using ''dbghelp.dll'' version ''4.0.5''%', 1)
			, ('%informational message%no user action is required%', 1)
			, ('Log was backed up%', 1)
			, ('Database backed up%', 1)
			, ('BACKUP DATABASE %', 1)
			, ('DBCC %', 1)
			, ('Setting database option RECOVERY to %', 1)
			, ('This instance of SQL Server has been using a process ID of %', 1)
			, ('Starting up database%', 1)
			, ('Software Usage Metrics is enabled.', 1)
			, ('Authentication mode is MIXED.', 1)
			, ('All rights reserved.', 1)
			, ('(c) Microsoft Corporation.', 1)
			, ('Server process ID is%', 1)
			, ('System Manufacturer:%', 1)
			, ('%has been reinitialized%', 1)
			, ('Logging SQL Server messages in file%', 1)		
			, ('|[184|] Job completion for % is being logged to sysjobhistory%', 2)
			, ('|[177|] Job % has been requested to run by Schedule %', 2)
			, ('%[177] Die Ausführung von Auftrag % wurde von Zeitplan %', 2)	-- %[177]%' OR el.Text NOT LIKE '%[184]%'
			, ('%[184] Der Auftragsabschluss für % wird in %', 2)
			-- [177] Die Ausführung von Auftrag ''JB_PRO_CYCLE_ERRORLOG'' wurde von Zeitplan 18 (Daily) angefordert.
			-- [184] Der Auftragsabschluss für ''JB_PRO_CYCLE_ERRORLOG'' wird in ''sysjobhistory'' protokolliert.

			, ('|[248|] Saving NextRunDate/Times for all updated job schedules...%', 2)
			, ('|[249|] % job schedule|(s|) saved%', 2)
			, ('|[182|] Job completion for % is being logged to the eventlog%', 2)
			, ('|[171|] There are % alert|(s|) in the alert cache%', 2)
			, ('|[168|] There are 21 job(s) |[0 disabled|] in the job cache%', 2)
			, ('|[170|] Populating alert cache...%', 2)
			, ('|[473|] Database Mail profile DBA refreshed.%', 2)
			, ('|[353|] Mail session started%', 2)
			, ('|[273|] Mail dispatcher started%', 2)
			, ('|[174|] Job scheduler engine started |(maximum user worker threads: 200, maximum system worker threads: 100|)%', 2)
			, ('|[193|] Alert engine started |(using Eventlog Events|)%', 2)
			, ('|[146|] Request servicer engine started%', 2)
			, ('|[167|] Populating job cache...%', 2)
			, ('|[133|] Support engine started%', 2)
			, ('|[271|] Idle processor poller started%', 2)

		IF OBJECT_ID(N'tempdb..#TempErrorLog', N'U') IS NOT NULL
			DROP TABLE #TempErrorLog;
		CREATE TABLE #TempErrorLog (
			  RowNum int PRIMARY KEY CLUSTERED IDENTITY(1, 1)
			, ErrorLogFileNum INT NULL
			, LogDate DATETIME
			, ProcessInfo VARCHAR(255)
			, [Text] VARCHAR(4000)
			);

		DECLARE @ErrorLogEnum TABLE (
			  [Archive #] VARCHAR(3) NOT NULL
			, [Date] VARCHAR(30) NOT NULL
			, [Log File Size (Byte)] INT NOT NULL
			);

		INSERT INTO @ErrorLogEnum ([Archive #], [Date], [Log File Size (Byte)])
		EXEC sys.sp_enumerrorlogs;

		SET @ErrorLogCount = COALESCE((
			SELECT COUNT(1)
			FROM @ErrorLogEnum eln
			WHERE eln.[Log File Size (Byte)] > 0
			), 0);

		IF @ErrorLogType = 1 
		BEGIN
			SET @ErrorLogCount = 2
			SET @HardeningResultsName = 'SQL Server Error Log'
			SET @StepNameConfigOption = 'Prove errors in SQL Error Log'	--'Determine failed logins'
		END
		ELSE
		BEGIN
			SET @ErrorLogCount = 3
			SET @HardeningResultsName = 'SQL Server Agent Error Log'
			SET @StepNameConfigOption = 'Prove errors in SQL Agent Error Log'
		END;

		DECLARE @FileNum INT = 0;

		WHILE @FileNum < @ErrorLogCount
		BEGIN
			IF @ErrorLogType = 1
			BEGIN
				INSERT INTO #TempErrorLog (LogDate, ProcessInfo, Text)
				EXEC sys.xp_readerrorlog @FileNum, @ErrorLogType;
			END
			IF @ErrorLogType = 2
			BEGIN
				INSERT INTO #TempErrorLog (LogDate, ProcessInfo, Text)
				EXEC sys.xp_readerrorlog @FileNum, @ErrorLogType, N'Error';
				INSERT INTO #TempErrorLog (LogDate, ProcessInfo, Text)
				EXEC sys.xp_readerrorlog @FileNum, @ErrorLogType, N'failed';
			END

			UPDATE #TempErrorLog
			SET ErrorLogFileNum = @FileNum
			WHERE ErrorLogFileNum IS NULL;
			SET @FileNum = @FileNum + 1;
		END

		IF @ErrorLogType = 1 AND EXISTS (
			SELECT *
			FROM #TempErrorLog el
			WHERE el.Text LIKE '%Login failed%'
				AND el.Text NOT IN ( SELECT LogTextToExclude FROM #KeepExclusions )
			)

		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT '49', 0, @HardeningResultsName, 0, 1, 'No'
				, 'We have found on ' + CONVERT(NVARCHAR(19), [LogDate]) + ' - ' + el.Text
			FROM #TempErrorLog el WHERE el.Text LIKE '%Login failed%'
		END
		ELSE

	/*
		| 50	Determine failed logins
	*/

		IF @ErrorLogType = 2 AND EXISTS (
			SELECT 1
			FROM #TempErrorLog el
			WHERE el.Text NOT LIKE '%[177]%' AND el.Text NOT LIKE '%[184]%' 
			)

		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT '50', 0, @HardeningResultsName, 0, 1, 'No'
				, 'We have found on ' + CONVERT(NVARCHAR(11), [LogDate]) + ' - ' + el.Text
			FROM #TempErrorLog el
			WHERE el.Text NOT IN ( SELECT LogTextToExclude FROM #KeepExclusions )
		END
		ELSE
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			VALUES ( '50', 0, @HardeningResultsName, 0, 0, 'Yes', 'No problem was found.' )
		END;

		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

		SET @ErrorLogType = @ErrorLogType + 1;
	END;

	/*
		| 51	Detect HA endpoint account the same as the SQL Server Service Account
	*/
	IF ( SELECT SERVERPROPERTY ('ProductVersion')) >= '10.0%'
	BEGIN
		IF SERVERPROPERTY('IsHadrEnabled') = 1
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT 51, 0, 'Endpoint account security', 0, 1, 'No'
				, ( 'Endpoint ' + ep.[name] + ' is owned by ' + SUSER_NAME(ep.principal_id) + '. If the endpoint owner login is disabled or not available due to Active Directory problems, the high availability will stop working.' ) AS [Details]
			FROM sys.database_mirroring_endpoints ep LEFT OUTER JOIN sys.dm_server_services s ON SUSER_NAME(ep.principal_id) = s.service_account
			WHERE s.service_account IS NULL AND ep.principal_id <> 1;
		END;
		SET @StepNameConfigOption = 'Detect HA endpoint account the same as the SQL Server service account'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END;

	/*
		| 52	32-bit SQL Server Installed
	*/
	IF SERVERPROPERTY('EngineEdition') <> 8
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT 52, 1, '32-bit SQL Server Installed' AS [Name], 1, 0, 'No'
			, 'Installation of SQL Server is supported on x64 processors only. It is no longer supported on x86 processors. This server uses the 32-bit x86 binaries for SQL Server instead of the 64-bit x64 binaries. The amount of memory available for query workspace and execution plans is heavily limited.'
		WHERE CAST(SERVERPROPERTY('Edition') AS VARCHAR(100)) NOT LIKE '%64%';
	END;
	SET @StepNameConfigOption = 'Ensure 64-bit SQL Server installed'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 53	Determine harmful startup options
	*/
	IF EXISTS ( SELECT 1 FROM sys.all_objects WHERE name = 'dm_server_registry' )
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT DISTINCT 53, 1, 'Harmful startup option', 1, 0, 'No'
			, 'Warning: You have -x as a startup parameter. When the -x startup option is in use, the information that is available to diagnose performance and functional problems with SQL Server is greatly reduced.'
		FROM [sys].[dm_server_registry] AS [dsr]
		WHERE [dsr].[registry_key] LIKE N'%MSSQLServer\Parameters' AND [dsr].[value_data] = '-x';
	END;
	SET @StepNameConfigOption = 'Ensure no harmful startup options configured'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 54	Determin installed Evaluation Edition
	*/
	IF ( SELECT CAST(SERVERPROPERTY('Edition') AS NVARCHAR(4000)) ) LIKE '%Evaluation%'
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT 54, 1, 'Evaluation Edition', 1, 0, 'No'
				, 'This server will stop working on: ' + CAST(CONVERT(DATETIME, DATEADD(DD, 180, create_date), 102) AS VARCHAR(100)) FROM sys.server_principals WHERE sid = 0x010100000000000512000000; 						
		END;
	SET @StepNameConfigOption = 'Prove installed Server Edition'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 55	Ensure instance memory is specifyed to a max limit on server
	*/
	DECLARE @GetInstances TABLE ( Value NVARCHAR(50), InstanceNames NVARCHAR(50), Data NVARCHAR(50) )
	DECLARE @InstanceNumber INT
	INSERT INTO @GetInstances
	EXEC xp_regread
		  @rootkey = 'HKEY_LOCAL_MACHINE'
		, @key = 'SOFTWARE\Microsoft\Microsoft SQL Server'
		, @value_name = 'InstalledInstances'
	SET @InstanceNumber = ( SELECT COUNT(InstanceNames) FROM @GetInstances )
	--DECLARE @TotalPhysicalMemory INT = ( SELECT [total_physical_memory_kb] / 1024 FROM [master].[sys].[dm_os_sys_memory] )
	DECLARE @InstanceMaxMemory INT = ( SELECT CAST( [value] AS VARCHAR(20) ) FROM [master].[sys].[configurations] WHERE name IN ('max server memory (MB)') )
	--DECLARE @AvalableMemory INT = @TotalPhysicalMemory - 4096
	--DECLARE @SetInstanceMaxMemory INT = @AvalableMemory / @InstanceNumber /* count memory for multiple instances */
	--DECLARE @MSGMML NVARCHAR(MAX) = ( SELECT 'Current setting is ' + CAST(c.value_in_use AS VARCHAR(20)) + ' megabytes, but the server only has '
	--			+ CAST(( CAST(m.total_physical_memory_kb AS BIGINT ) / 1024 ) AS VARCHAR(20) ) + ' megabytes. Leave at least 4096 MB of total memory free for OS, or adjust this as needed. Misunderstanding this can lead to the SQL Server not allocating enough memory to properly start up.'
	--		FROM sys.dm_os_sys_memory m INNER JOIN sys.configurations c ON c.name = 'max server memory (MB)'
	--		WHERE CAST(m.total_physical_memory_kb AS BIGINT) < ( CAST(c.value_in_use AS BIGINT) * 1024 ) )

	IF OBJECT_ID('tempdb..#SMML') IS NOT NULL
		DROP TABLE #SMML;
	CREATE TABLE #SMML ( [ServerPhysicalMemory] INT, [Total Instances] INT, [Available Memory] INT, [Target] INT, [ValueInUse] INT )
	BEGIN
		INSERT INTO #SMML ( [ServerPhysicalMemory], [Total Instances], [Available Memory], [Target], [ValueInUse] ) 
		SELECT CAST(m.total_physical_memory_kb AS BIGINT) / 1024
			, @InstanceNumber
			, ( m.total_physical_memory_kb / 1024 ) - 4096
			, (( m.total_physical_memory_kb / 1024 ) - 4096 ) / @InstanceNumber
			, CAST(@InstanceMaxMemory AS INT)
		FROM sys.dm_os_sys_memory m INNER JOIN sys.configurations c ON c.name = 'max server memory (MB)' --))
	END
	IF (( SELECT [ValueInUse] FROM #SMML ) > ( SELECT [Target] FROM #SMML) AND @InstanceNumber = 1 )
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '55', 1, 'Maximum Memory Limit'
			, 0, 1, 'No', 'Avoid this configuration. This server has ' + CAST(ServerPhysicalMemory AS VARCHAR(10)) 
					+ ' MB total of memory and ' + CAST(ValueInUse AS VARCHAR) + ' MB assigned to this instance. Leave at least 4096 MB of total memory free for OS, or adjust this as needed. Misunderstanding this can lead to the SQL Server not allocating enough memory to properly start up.'
		FROM #SMML
	END
	ELSE
	IF (( SELECT [ValueInUse] FROM #SMML ) > ( SELECT [Target] FROM #SMML) AND @InstanceNumber > 1 )
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '55', 1, 'Maximum Memory Limit'
			, 0, 1, 'No', 'This instance currently assigned ' + CAST(ValueInUse AS VARCHAR) + ' MB of memory. Because of ' + CAST(@InstanceNumber AS VARCHAR(2)) 
				+ ' instances are existing on this server you may apply only max. ' + CAST([Target] AS VARCHAR(10)) 
				+ ' MB of memory for this instance.'
		FROM #SMML
	END
	ELSE
	BEGIN
		IF @InstanceNumber > 1
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT '55', 1, 'Maximum Memory Limit', 1, 1, 'Yes', 'No problem was found. This server has ' + CAST(ServerPhysicalMemory AS VARCHAR(10)) 
				+ ' MB total of memory and ' + CAST(ValueInUse AS VARCHAR) + ' MB assigned to this instance. Because of ' + CAST(@InstanceNumber AS VARCHAR(2)) 
				+ ' instances are existing on this server you may extend to max. ' + CAST([Target] AS VARCHAR(10)) 
				+ ' MB of memory for current instance.'				
			FROM #SMML
		END
		ELSE
		BEGIN
			INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT '55', 1, 'Maximum Memory Limit', 1, 1, 'Yes', 'No problem was found.'				
			FROM #SMML
		END;
	END;
	SET @StepNameConfigOption = 'Ensure instance memory is specifyed'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 56	Prove external memory conditions
	*/
	IF ( SELECT system_memory_state_desc 
		FROM sys.dm_os_sys_memory WITH (NOLOCK) ) <> 'Available physical memory is high'
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		VALUES ( 56, 1, 'External memory conditions', 0, 1, 'No', 'Current system state indicates that you are under external memory pressure. This may result in a performance degradation or a time-out occurs for applications that connect to SQL Server.' )
		SET @StepNameConfigOption = 'Prove external memory conditions'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END

	/*
		| 71	Ensure 'Trustworthy' database property is set to 'Off' (Scored)
	*/
	IF OBJECT_ID('tempdb..#TDBP') IS NOT NULL
		DROP TABLE #TDBP;
	CREATE TABLE #TDBP ( [ValueInUse] INT, [Target] INT )
	BEGIN
		INSERT INTO #TDBP ( [ValueInUse], [Target] )
		SELECT CASE WHEN ( SELECT COUNT(name) FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb' ) > 0 THEN 1 ELSE 0 END, 0
	END
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '71', 0, 'The Trustworthy database setting', [ValueInUse], [Target]
			, CASE WHEN [Target] = [ValueInUse] THEN 'Yes' ELSE 'No' END
			, CASE WHEN [Target] = [ValueInUse] THEN 'No problem was found.' 
				ELSE 'This database option must be set to ''Off''. It''s allows database objects to access objects in other databases under certain circumstances.' END FROM #TDBP END DROP TABLE #TDBP;
	SET @StepNameConfigOption = 'Ensure ''Trustworthy'' database property is turned ''Off'''
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 72	Ensure 'AUTO_CLOSE OFF' is set on contained databases (Scored)
		|	Beginning with SQL Server 2012 and beyond
	*/
	DECLARE @vAutoCloseOff VARCHAR(128) = ( SELECT name FROM sys.all_columns WHERE name = 'containment' AND object_id = OBJECT_ID('sys.databases' ) 
		AND EXISTS ( SELECT name FROM sys.databases WHERE is_auto_close_on = 1 ))
	IF @vAutoCloseOff IS NOT NULL
	BEGIN 
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '72', 0, '''Auto Close'' setting on [' + name + ']', 1, 0, CASE WHEN name IS NULL THEN 'Yes' ELSE 'No' END
			, CASE WHEN name IS NULL THEN 'No problem was found.' 
				ELSE 'Do not configure contained databases to auto close. The frequent opening/closing of the database consumes additional server resources and may contribute to a denial of service.' END 
		FROM sys.databases WHERE is_auto_close_on = 1
	END 
	ELSE
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT '72', 1, '''Auto Close'' setting on [' + name + ']', 0, 0, CASE WHEN name IS NOT NULL THEN 'Yes' ELSE 'No' END
			, CASE WHEN name IS NOT NULL THEN 'No problem was found.' END FROM sys.databases
	END;
	SET @StepNameConfigOption = 'Ensure ''AUTO_CLOSE OFF'' is set on contained databases'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 73	Check auto growth setting
	*/
	EXEC sp_MSforeachdb 'INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT DISTINCT ''73'', 1, ''File growth setting on [?]'', 0, 1, ''No''
			, ''Avoid this configuration. The [?] database is using percent filegrowth settings. This can lead to out of control filegrowth.''
		FROM [?].sys.database_files WHERE is_percent_growth = 1';
	SET @StepNameConfigOption = 'Prove ''AUTO_GROWTH'' setting'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 74	Only one tempdb data file
	*/
	IF ( SELECT COUNT(*) FROM tempdb.sys.database_files WHERE type_desc = 'ROWS' ) = 1
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		VALUES ( '74', 1, 'Only one tempdb data file', 0, 1, 'No'
			, 'Current state is default and this can slow down the system in some cases.' )
	END;
	SET @StepNameConfigOption = 'Prove tempdb file configuration'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 75	Multiple log files on the same drive
	*/
	EXEC dbo.sp_MSforeachdb 'INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] ) 
		SELECT ''75'', 1, ''Multiple log files on the same drive'', 1, 0, ''No''
			, (''The [?] database has multiple log files on the '' + LEFT(physical_name, 1) + '' drive. If database has two transaction logs on one drive, remove one of them. Be careful, you can''''t remove it if it''''s in active use.'') 
		FROM [?].sys.database_files WHERE type_desc = ''LOG'' AND ''?'' <> ''[tempdb]'' GROUP BY LEFT(physical_name, 1) HAVING COUNT(*) > 1';
	SET @StepNameConfigOption = 'Prove log files configuration'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 76	Uneven file growth settings in one filegroup
	*/
	EXEC dbo.sp_MSforeachdb 'INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )  
		SELECT DISTINCT ''76'', 1, ''Uneven file growth settings in one filegroup'', 1, 0, ''No''
			, (''The [?] database has multiple data files in one filegroup, but they are not all set up to grow in identical amounts. Size the data files equally.'')
		FROM [?].sys.database_files WHERE type_desc = ''ROWS'' GROUP BY data_space_id HAVING COUNT(DISTINCT growth) > 1 OR COUNT(DISTINCT is_percent_growth) > 1';
	SET @StepNameConfigOption = 'Prove uneven file growth settings'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 77	Database files configuration
	*/
	EXEC sp_MSforeachdb 'USE [?];
		SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
        SELECT DISTINCT 77, 1, ''File configuration in [?]'', 0, 1, ''No''
			, ''The ['' + DB_NAME() + ''] database file '' + f.physical_name + '' is using 1MB filegrowth settings, but it has grown to '' + CAST((f.size * 8 / 1000000) AS NVARCHAR(10)) + '' GB. This must be changed to at least 64MB.''
		FROM [?].sys.database_files f WHERE is_percent_growth = 0 AND growth = 128 AND size >= 8192 OPTION (RECOMPILE);';
	SET @StepNameConfigOption = 'Prove database files setting'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 78	Prove databases for corruption
	*/
	IF EXISTS ( SELECT * FROM msdb.sys.all_objects WHERE name = 'suspect_pages' )
		AND @@VERSION NOT LIKE '%Microsoft SQL Server 2008%'
	BEGIN
		EXEC sp_MSforeachdb 'INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT DISTINCT ''78'', 1, ''Database corruption detected'', 0, 1, ''No''
				, ''Database mirroring has automatically repaired at least one corrupt page in the last 10 days.''
			FROM ( SELECT rp2.database_id, rp2.modification_time
				FROM sys.dm_db_mirroring_auto_page_repair rp2
				WHERE rp2.[database_id] NOT IN (
					SELECT db2.[database_id]
					FROM sys.databases AS db2
					WHERE db2.[state] = 1
					)
				) AS rp
			INNER JOIN master.sys.databases db ON rp.database_id = db.database_id
			WHERE rp.modification_time >= DATEADD(dd, -10, GETDATE()) OPTION (RECOMPILE);';	
	SET @StepNameConfigOption = 'Prove databases for corruption (Availability Groups: Database Mirroring)'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END;
	ELSE
	BEGIN
		EXEC sp_MSforeachdb 'INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
			SELECT DISTINCT ''78'', 1, ''Database corruption detected'', 0, 1, ''No''
				, ''This is dangerous. SQL Server has detected at least one corrupt page in the last 10 days. Prove point ''''Check for DBCC errors'''' and/or to check the entire database or all of the databases on that server, run DBCC CHECKDB once again.''
			FROM msdb.dbo.suspect_pages sp INNER JOIN master.sys.databases db ON sp.database_id = db.database_id WHERE sp.last_update_date >= DATEADD(dd, -10, GETDATE()) OPTION (RECOMPILE);';
	SET @StepNameConfigOption = 'Prove databases for corruption'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END;

	/*
		| 79	Prove file configuration for system databases
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT DISTINCT 79, 1, 'System database on C Drive'
		, 1, 0, 'No', ( 'The [' + DB_NAME(database_id)
			+ '] database has a file on the C drive. Putting system databases on the C drive runs the risk of crashing the server when it runs out of space.' )
	FROM sys.master_files
	WHERE UPPER(LEFT(physical_name, 1)) = 'C' AND DB_NAME(database_id) IN ( 'master', 'model', 'msdb' );
	SET @StepNameConfigOption = 'Prove file configuration for system database'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 80	Prove file configuration for user databases
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT DISTINCT 80, 1, 'User Databases on C Drive'
		, 1, 0, 'No', ( 'The [' + DB_NAME(database_id)
			+ '] database has a file on the C drive. Putting databases on the C drive runs the risk of crashing the server when it runs out of space.' )
	FROM sys.master_files
	WHERE UPPER(LEFT(physical_name, 1)) = 'C' AND DB_NAME(database_id) NOT IN ( 'master', 'model', 'msdb', 'tempdb' )
	SET @StepNameConfigOption = 'Prove file configuration for user databases'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 81	Prove file configuration for tempdb
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT TOP 1 81, 1, 'TempDB on C Drive'
		, 1, 0, 'No', CASE WHEN growth > 0
			THEN ( 'The tempdb database has files on the C drive. TempDB frequently grows unpredictably, putting your server at risk of running out of C drive space and crashing hard. C is also often much slower than other drives, so performance may be suffering.' )
			ELSE ( 'The tempdb database has files on the C drive. TempDB is not set to Autogrow, hopefully it is big enough. C is also often much slower than other drives, so performance may be suffering.' ) END
	FROM sys.master_files
	WHERE UPPER(LEFT(physical_name, 1)) = 'C' AND DB_NAME(database_id) = 'tempdb';
	SET @StepNameConfigOption = 'Prove file configuration for [tempdb] database'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	
	/*
		| 82	Count virtual log files
	*/
	IF CONVERT(VARCHAR(128), SERVERPROPERTY ('ProductVersion')) >= '11'
	BEGIN
		EXEC sp_MSforeachdb N'USE [?];
		SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
		INSERT INTO #DBCCLogInfo2012
		EXEC sp_executesql N''DBCC LOGINFO() WITH NO_INFOMSGS'';
		IF @@ROWCOUNT > 999
			BEGIN
				INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
				SELECT 82, 3, ''High VLF Count'', 1, 0, ''No''
					, ''The ['' + DB_NAME() + ''] database has '' +  CAST(COUNT(*) AS VARCHAR(20)) + '' virtual log files (VLFs). This may be slowing down startup, restores, and even inserts/updates/deletes.''
					+ '' Try to keep VLF counts under 200 in most cases (depending on log file size)''
				FROM #DBCCLogInfo2012
				WHERE EXISTS (SELECT name FROM master.sys.databases WHERE source_database_id IS NULL) OPTION (RECOMPILE);
			END
			TRUNCATE TABLE #DBCCLogInfo2012;';
			DROP TABLE #DBCCLogInfo2012;
	END
	ELSE
	BEGIN
		EXEC sp_MSforeachdb N'USE [?];
		SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
		INSERT INTO #DBCCLogInfo
		EXEC sp_executesql N''DBCC LOGINFO() WITH NO_INFOMSGS'';
		IF @@ROWCOUNT > 999
			BEGIN
				INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
				SELECT 82, 3, ''High VLF Count'', 1, 0, ''No''
					,''The ['' + DB_NAME() + ''] database has '' +  CAST(COUNT(*) AS VARCHAR(20)) + '' virtual log files (VLFs). This may be slowing down startup, restores, and even inserts/updates/deletes.''
					+ '' Try to keep VLF counts under 200 in most cases (depending on log file size)''
				FROM #DBCCLogInfo
				WHERE EXISTS (SELECT name FROM master.sys.databases WHERE source_database_id IS NULL) OPTION (RECOMPILE);
			END
			TRUNCATE TABLE #DBCCLogInfo;';
			DROP TABLE #DBCCLogInfo;
	END;
	SET @StepNameConfigOption = 'Count virtual log files'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
	IF EXISTS ( SELECT [name] AS [Database Name], [VLFCount]
		FROM sys.databases AS db WITH (NOLOCK)
		CROSS APPLY (SELECT file_id, COUNT(*) AS [VLFCount]
					FROM sys.dm_db_log_info(db.database_id)
					GROUP BY file_id
					) AS li
		WHERE [VLFCount] > 200 )
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT 82, 1, 'High Virtual Log File counts', 1, 0, 'No'
			, ( 'The [' + DB_NAME(database_id)
				+ '] database has a ' + CAST([VLFCount] AS VARCHAR(10)) + ' VLF''s. High counts can affect startup, restores, and even inserts/updates/deletes. Try to keep VLF counts under 200 in most cases (depending on log file size)' )
		FROM sys.databases AS db WITH (NOLOCK)
			CROSS APPLY (
				SELECT file_id, COUNT(*) AS [VLFCount]
				FROM sys.dm_db_log_info(db.database_id)
				GROUP BY file_id
				) AS li
		WHERE [VLFCount] > 200;
		SET @StepNameConfigOption = 'Prove file configuration for system database'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END
	*/

	/*
		| 83	Ensure no user defined tables in the [master] database
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT 83, 1, 'Tables in the [master] Database'
		, 1, 0, 'No', ( 'The ''' + name
			+ ''' table in the [master] database was created by end users on '
			+ CAST(create_date AS VARCHAR(20))
			+ '. Tables in the [master] database may not be restored in the event of a disaster.' )
	FROM master.sys.tables
	WHERE is_ms_shipped = 0 AND name NOT IN ('CommandLog');
	SET @StepNameConfigOption = 'Ensure no tables in the [master] database'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 84	Ensure no user defined tables in the [msdb] database
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT 84, 1, 'Tables in the [msdb] Database'
		, 1, 0, 'No', ( 'The ''' + name
			+ ''' table in the [msdb] database was created by end users on '
			+ CAST(create_date AS VARCHAR(20))
			+ '. Tables in the [msdb] database may not be restored in the event of a disaster.' )
	FROM msdb.sys.tables
	WHERE is_ms_shipped = 0 AND name NOT IN ('CommandLog', 'Queue', 'QueueDatabase'); --AND name NOT LIKE '%DTA_%';
	SET @StepNameConfigOption = 'Ensure no tables in the [msdb] database'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 85	Ensure no user defined tables in the [model] database
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT 85, 1, 'Tables in the [model] Database'
		, 1, 0, 'No', ( 'The ''' + name
			+ ''' table in the [model] database was created by end users on '
			+ CAST(create_date AS VARCHAR(20))
			+ '. Tables in the [model] database are automatically copied into all new databases.' )
	FROM model.sys.tables
	WHERE is_ms_shipped = 0;
	SET @StepNameConfigOption = 'Ensure no tables in the [model] database'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 86	Prove for slow storage reads
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT 86, 1, 'Slow storage reads on drive ' + UPPER(LEFT(mf.physical_name, 1))
		, 1, 0, 'No', 'Reads are averaging longer than 200ms for at least one database on this drive.' AS Details
	FROM sys.dm_io_virtual_file_stats(NULL, NULL) AS fs
		INNER JOIN sys.master_files AS mf ON fs.database_id = mf.database_id AND fs.[file_id] = mf.[file_id]
	WHERE ( io_stall_read_ms / ( 1.0 + num_of_reads ) ) > 200
	AND num_of_reads > 100000;
	SET @StepNameConfigOption = 'Prove for slow storage reads'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 87	Prove for slow storage writes
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT 87, 1, 'Slow storage writes on drive ' + UPPER(LEFT(mf.physical_name, 1))
		, 1, 0, 'No', 'Writes are averaging longer than 100ms for at least one database on this drive.'
	FROM sys.dm_io_virtual_file_stats(NULL, NULL) AS fs
		INNER JOIN sys.master_files AS mf ON fs.database_id = mf.database_id AND fs.[file_id] = mf.[file_id]
	WHERE ( io_stall_write_ms / ( 1.0 + num_of_writes ) ) > 100 AND num_of_writes > 100000;
	SET @StepNameConfigOption = 'Prove for slow storage writes'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 88	Ensure linked server provides a security
	*/
	INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
	SELECT DISTINCT 88, 0, 'Securing linked servers', CASE 
		WHEN l.remote_name = 'sa' THEN 0 ELSE 1 END, 0, CASE 
		WHEN l.remote_name = 'sa' THEN 'Yes' ELSE 'No' END,  
		CASE WHEN l.remote_name = 'sa'
			THEN '[' + name + ']'
			+ ' is configured as a linked server. Check its security configuration as it is connecting with ''sa'', because any user who queries it will get admin-level permissions.'
			ELSE '[' + name + ']'
			+ ' is configured as a linked server. The current login isn''t ''sa''. You have to investigate each linked server to check and fix its security configuration. We can''t easily tell from SQL whether we''re using a login that''s a sysadmin (or just an overly powerful login) on another server. You don''t have to let everyone through the linked server!' END
	FROM sys.servers s INNER JOIN sys.linked_logins l ON s.server_id = l.server_id WHERE s.is_linked = 1 GROUP BY s.name, l.remote_name;
	SET @StepNameConfigOption = 'Provide linked server security'
	SET @CountUp = @CountUp + 1
	SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
	RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT

	/*
		| 90	Ensure statistics is up to date
	*/
	IF NOT EXISTS (
		SELECT SCHEMA_NAME(o.Schema_ID) + N'.' + o.[NAME]
			, i.[name] AS [Index Name]
			, STATS_DATE(i.[object_id], i.index_id)
			, st.row_count
			, st.used_page_count
		FROM sys.objects AS o WITH (NOLOCK)
		INNER JOIN sys.indexes AS i WITH (NOLOCK) ON o.[object_id] = i.[object_id]
		INNER JOIN sys.stats AS s WITH (NOLOCK) ON i.[object_id] = s.[object_id] AND i.index_id = s.stats_id
		INNER JOIN sys.dm_db_partition_stats AS st WITH (NOLOCK) ON o.[object_id] = st.[object_id] AND i.[index_id] = st.[index_id]
		WHERE o.[type] IN ('U', 'V') AND st.row_count > 0 AND STATS_DATE(i.[object_id], i.index_id) >= DATEADD(DAY, -10, GETDATE())
		)
	BEGIN
		INSERT INTO #HardeningResults ( [FindingID], [Severity], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details] )
		SELECT TOP 5 90, 1, 'Statistics out of date', 1, 0, 'No'
			, ( 'Index ''' + i.[name] + ''' in table ''' + o.[NAME] + ''' were last updated on ' + CAST(STATS_DATE(i.[object_id], i.index_id) AS VARCHAR(20)) + ' which is over 10 days. There is problems with out-of-date index statistics. '
				+ 'For the large databases, it might take unnecessary longer time and system resources as well because it performs a check on each statistic on the object.' )
		FROM sys.objects AS o WITH (NOLOCK)
		INNER JOIN sys.indexes AS i WITH (NOLOCK) ON o.[object_id] = i.[object_id]
		INNER JOIN sys.stats AS s WITH (NOLOCK) ON i.[object_id] = s.[object_id] AND i.index_id = s.stats_id
		INNER JOIN sys.dm_db_partition_stats AS st WITH (NOLOCK) ON o.[object_id] = st.[object_id]  AND i.[index_id] = st.[index_id]
		WHERE o.[type] IN ('U', 'V') AND st.row_count > 0 AND STATS_DATE(i.[object_id], i.index_id) >= DATEADD(DAY, -10, GETDATE())
		SET @StepNameConfigOption = 'Ensure statistics not out of date'
		SET @CountUp = @CountUp + 1
		SET @StartMessage = 'Step ' + CAST(@CountUp AS VARCHAR(2)) + ': ' + @StepNameConfigOption
		RAISERROR('%s', 10, 1, @StartMessage) WITH NOWAIT
	END

	--------------------------------------------------------------------------------
	--| Completing log definition
	--------------------------------------------------------------------------------
	SET @EndTime = GETDATE()
	SET @EndTimeSec = CONVERT(DATETIME, CONVERT(VARCHAR, @EndTime, 120), 120)
	
	RAISERROR(@EmptyLine, 10, 1) WITH NOWAIT

	SET @EndMessage = 'Duration: ' + CASE WHEN DATEDIFF(ss, @StartTimeSec, @EndTimeSec) / (24 * 3600) > 0 THEN CAST(DATEDIFF(ss, @StartTimeSec, @EndTimeSec) / (24 * 3600) AS nvarchar) + '.' ELSE '' END + CONVERT(nvarchar,@EndTimeSec - @StartTimeSec,108)
	RAISERROR('%s', 10, 1, @EndMessage) WITH NOWAIT

	SET @EndMessage = 'End date and time: ' + CONVERT(NVARCHAR, @EndTimeSec, 120)
	RAISERROR('%s', 10, 1, @EndMessage) WITH NOWAIT
	--------------------------------------------------------------------------------
	--| End completing log                                                    
	--------------------------------------------------------------------------------
SELECT [FindingID], [Name], [Current Setting], [Target Setting], [Target Achieved], [Details]	--, [Severity]
FROM #HardeningResults
WHERE --[Target Achieved] = 'No'	--  
	Details NOT IN ( 'No problem was found.' )
	--Details NOT LIKE ( 'No problem was found.%' )
ORDER BY [FindingID]	--, [Severity]	--, [Target Achieved], [Name] ASC
DROP TABLE #HardeningResults
