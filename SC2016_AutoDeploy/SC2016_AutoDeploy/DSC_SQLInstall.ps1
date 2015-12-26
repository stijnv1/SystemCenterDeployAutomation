#
# DSC_SQL.ps1
#
#
# DSC_SQLInstall.ps1
#
param 
(
	[Parameter(Mandatory=$true)]
	[string]$SQLServerName,

	[Parameter(Mandatory=$true)]
	[PSCredential]$SQLServiceAccountCreds,

	[Parameter(Mandatory=$true)]
	[PSCredential]$SACreds,

	[Parameter(Mandatory=$true)]
	[PSCredential]$InstallCreds,

	[Parameter(Mandatory=$true)]
	[string]$SourceRootDir
)

$ConfigData = @{
	AllNodes = @(
		@{
			NodeName = $SQLServerName
			PSDscAllowPlainTextPassword = $true
			PSDscAllowDomainUser = $true
		}
	)
}

Configuration DSC_SQLInstall
{
	Import-DscResource -ModuleName xSqlServer
	Import-DscResource -ModuleName PSDesiredStateConfiguration

	Node $AllNodes.NodeName
	{
		WindowsFeature installDotNet35
		{
			Ensure = "Present"
			Name = "Net-Framework-Core"
			Source = "$SourceRootDir\WindowsServer\sources\sxs"
		}

		xSQLServerSetup DefaultInstanceInstallation
		{
			SourcePath = "$SourceRootDir"
			SourceFolder = "SQL"
			SetupCredential = $InstallCreds
			Features = "SQLENGINE,SSMS,ADV_SSMS,IS,FullText"
			UpdateEnabled = "false"
			UpdateSource = "MU"
			SQMReporting = "false"
			ErrorReporting = "false"
			InstanceName = "MSSQLSERVER"
			InstallSharedDir = "C:\Program Files\Microsoft SQL Server"
			InstallSharedWOWDir = "C:\Program Files x86\Microsoft SQL Server"
			InstanceDir = "C:\Program Files\Microsoft SQL Server"
			SQLSvcAccount = $SQLServiceAccountCreds
			AgtSvcAccount = $SQLServiceAccountCreds
			SecurityMode = "SQL"
			SAPwd = $SACreds
			InstallSQLDataDir = "D:\SQLDATA\"
			SQLUserDBDir = "D:\SQLDATA\"
			SQLUserDBLogDir = "D:\SQLLOG\"
			SQLTempDBDir = "D:\SQLTEMPDB"
			SQLTempDBLogDir = "D:\SQLTEMPDBLOG"
			SQLBackupDir = "D:\SQLDATA\"
			FTSvcAccount = $SQLServiceAccountCreds
			ISSvcAccount = $SQLServiceAccountCreds
			SQLSysAdminAccounts = @("$($InstallCreds.Username)")
		}

		xSQLServerFirewall EnableRemoteSQLAccess
		{
			Ensure = "Present"
			SourcePath = "$SourceRootDir\SQL\"
			Features = "SQLENGINE,IS"
			InstanceName = "MSSQLSERVER"
		}
	}
}

DSC_SQLInstall -ConfigurationData $ConfigData
$sqlInstallJob = Start-DscConfiguration -Path .\DSC_SQLInstall -Verbose -Force

$jobRunning = $true
do 
{
	$runningJob = Get-Job -Name $sqlInstallJob.Name
	if ($runningJob.State -eq "Running")
	{
		Write-Host "SQL Installation DSC job is still running. Start sleep..." -ForegroundColor Green
		Start-Sleep -Seconds 10
	}
	elseif ($runningJob.State -eq "NotStarted")
	{
		Write-Host "SQL Installation DSC job is not started yet. Start sleep for 1 minute ..." -ForegroundColor Green
		Start-Sleep -Seconds 60
	}
	elseif ($runningJob.State -eq "Failed")
	{
		Write-Host "SQL Installation DSC Job installed SQL, but ended with an error" -ForegroundColor Red
		$jobRunning = $false
	}
	else
	{
		Write-Host "State of DSC job is $($runningJob.State)" -ForegroundColor Yellow
		$jobRunning = $false
	}

} while ($jobRunning)
