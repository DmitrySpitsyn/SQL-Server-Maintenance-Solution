--SET NOCOUNT ON;
/*
For Test purpose:

	EXEC sp_configure 'Database Mail XPs', 0
	EXEC sp_configure 'Agent XPs', 0
	RECONFIGURE WITH OVERRIDE

*/
DECLARE @SetupDatabaseMail BIT = 0

/*	Declare parameters to create new Database Mail account and profile.
	You may also manualy view, change, or delete existing Database Mail account(s) and profile(s).
	A Database Mail profile is a collection of Database Mail accounts.
*/

DECLARE @SetProfileName NVARCHAR(MAX)		= 'profile.name'				/*	the name of the profile: @ProfileName	*/
DECLARE @SetAccountName SYSNAME				= 'account.name'				/*	the name of the account: @AccountName		*/
DECLARE @SetEmailAddress NVARCHAR(128)		= 'smtp.mail.name@domain.name'	/*	SMTP accounts	*/
DECLARE @SetReplyToAddress NVARCHAR(128)	= 'support@domain.name'			/*	Mail account for reply	*/
DECLARE @SetMailServerName NVARCHAR(MAX)	= 'mail.domain.name'			/*	SMTP mail server	*/
DECLARE @SetDisplayName NVARCHAR(128)		= @@SERVERNAME + ' - Central SQL Report'	/*	Display name	*/
DECLARE @SMTPUserName NVARCHAR(128)			= 'dbmailtosmtp'				/*	The user name that Database Mail uses to sign in to the SMTP server. The user name is required if the SMTP server requires basic authentication.	*/
DECLARE @SMTPPwd NVARCHAR(128)				= 'getpassword'					/*	Change the password that Database Mail uses to sign in to the SMTP server. The password is required if the SMTP server requires basic authentication.	*/


IF @SetupDatabaseMail = 1	/*	Set this value to 1 to create a new Database Mail account holding information about an SMTP account.	*/

BEGIN

	/*	In order to setup Database Mail and SQL Agent mail, it will need to turn on two Global Configuration Settings.	*/
	IF EXISTS (
		SELECT 1 FROM sys.configurations 
		WHERE NAME = 'Database Mail XPs' AND VALUE = 0 OR (
			NAME = 'Agent XPs' AND VALUE = 0
			)
		)
	BEGIN
		EXEC sp_configure 'show advanced options', 1
		EXEC sp_configure 'Database Mail XPs', 1
		EXEC sp_configure 'Agent XPs', 1
		RECONFIGURE WITH OVERRIDE
	END

	/*
		| Configure a Database Mail profile with user defined name
		| added by Dmitry Spitsyn 14.06.2019
	*/

	IF NOT EXISTS( SELECT * FROM msdb.dbo.sysmail_profile WHERE  name = @SetProfileName )
		BEGIN 
			EXEC msdb.dbo.sysmail_add_profile_sp  
				  @profile_name = @SetProfileName
				, @description = 'Profile created for sending outgoing notifications.'
			PRINT 'Profile name ' + @SetProfileName + ' successfully created.'
		END
	ELSE
		BEGIN
			RAISERROR (N'Profile name already exists.', 16, 1)
			RETURN
		END

	/*
		| Create a new Database Mail account holding information about an SMTP account
	*/
	IF NOT EXISTS( SELECT * FROM msdb.dbo.sysmail_account WHERE  name = @SetAccountName )
		BEGIN 
			EXEC msdb.dbo.sysmail_add_account_sp
				  @account_name = @SetAccountName			-- The name of the account to add
				, @description = 'Account for operational post'	-- Description for the account
				, @email_address = @SetEmailAddress			-- The e-mail address to send the message from
				, @display_name = @SetDisplayName			-- The display name to use on e-mail messages from this account
				, @replyto_address = @SetReplyToAddress		-- The address that responses to messages from this account are sent to
				, @mailserver_name = @SetMailServerName		-- The name or IP address of the SMTP mail server to use for this account
				, @port = 25								-- The port number for the e-mail server. | User defined port :: 465
				, @enable_ssl = 1							-- A bit column indicating whether the connection to the SMTP mail server is made using Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL). | 0 - not enabled / 1 - enabled
				, @username = @SMTPUserName					-- Update the user name that Database Mail uses to sign in to the SMTP server. The user name is required if the SMTP server requires basic authentication
				, @password = @SMTPPwd						-- Change the password that Database Mail uses to sign in to the SMTP server. The password is required if the SMTP server requires basic authentication
		END
	ELSE
		BEGIN
			RAISERROR (N'Database Mail Account name already exists.', 16, 1)
			RETURN
		END

	/*
		| Grant permission for a database user or role to use this Database Mail profile 
	*/  
	EXEC msdb.dbo.sysmail_add_principalprofile_sp
		  @profile_name = @SetProfileName
		, @principal_name = 'public'
		, @is_default = 1	/*	0 - not default | 1 - default	*/
		/*
		When @is_default is 1 and the user is already associated with one or more profiles, the specified profile becomes the default profile for the user.
		When @is_default is 0 and no other association exists, the stored procedure returns an error.
		*/

	/*
		| Add the Database Mail account to the Database Mail profile 
	*/  
	EXEC msdb.dbo.sysmail_add_profileaccount_sp  
		  @profile_name = @SetProfileName
		, @account_name = @SetAccountName
		, @sequence_number = 1

	IF EXISTS (
		SELECT [sysmail_server].[account_id]
			, [sysmail_account].[name] AS [Account Name]
			, [servertype]
			, [servername] AS [SMTP Server Address]
			, [Port]
		FROM [msdb].[dbo].[sysmail_server]
			INNER JOIN [msdb].[dbo].[sysmail_account] ON [sysmail_server].[account_id] = [sysmail_account].[account_id]
		WHERE [sysmail_account].[name] = @SetAccountName
		)
	PRINT 'Database Mail with account ''' + @SetAccountName + ''' and SMTP Server ''' + @SetMailServerName + ''' successfully configured.'
	RAISERROR('Use the Send Test E-Mail dialog box to test the ability to send mail using a specific profile.', 16, 1) WITH NOWAIT	

END

	/*
		| Task to prove Database Mail configuration
	*/

	/*
	EXEC msdb.dbo.sp_send_dbmail
			@profile_name = @SetProfileName	--'ProfileName_Notifications'
		, @recipients = @SetAccountName		--'Use a valid e-mail address'
		, @body = 'The database mail configuration was completed successfully.'
		, @subject = 'Automated Success Message';
	GO
	*/
