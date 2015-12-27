#
# DSC_SCVMMInstall.ps1
#
param 
(
	[Parameter(Mandatory=$true)]
	[string]$SCVMMServerName,

	[Parameter(Mandatory=$true)]
	[PSCredential]$SCVMMServiceAccountCreds,

	[Parameter(Mandatory=$true)]
	[PSCredential]$InstallCreds,

	[Parameter(Mandatory=$true)]
	[string]$SourceRootDir,

	[Parameter(Mandatory=$true)]
	[string]$SQLServerName,

	[Parameter(Mandatory=$true)]
	[string]$SQLInstanceName,

	[Parameter(Mandatory=$true)]
	[string]$SCVMMLibPath,

	[Parameter(Mandatory=$true)]
	[string]$SCVMMLibShare
)

$ConfigData = @{
	AllNodes = @(
		@{
			NodeName = $SCVMMServerName
			PSDscAllowPlainTextPassword = $true
			PSDscAllowDomainUser = $true
		}
	)
}

Configuration DSC_VMM
{
	Import-DscResource -Module xSCVMM
	Import-DscResource -Module xSmbShare
	Import-DscResource –ModuleName PSDesiredStateConfiguration
	Import-DscResource -Module xPendingReboot

	Node $AllNodes.NodeName
	{
		# Set LCM to reboot if needed
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

		xPendingReboot RebootCheckInstallVMM
		{
			Name = "RebootCheckInstallVMM"
		}

		# Install prerequisites on Management Servers
		Package "SQLServer2012NativeClient"
		{
			Ensure = "Present"
			Name = "Microsoft SQL Server 2012 Native Client "
			ProductId = ""
			Path = "$SourceRootDir\SCVMM\Prerequisites\SQLPrereqs\sqlncli.msi"
			Arguments = "IACCEPTSQLNCLILICENSETERMS=YES ALLUSERS=2"
			Credential = $InstallCreds
		}

		Package "SQLServer2012CommandLineUtilities"
		{
			Ensure = "Present"
			Name = "Microsoft SQL Server 2012 Command Line Utilities "
			ProductId = ""
			Path = "$SourceRootDir\SCVMM\Prerequisites\SQLPrereqs\SqlCmdLnUtils.msi"
			Arguments = "ALLUSERS=2"
			Credential = $InstallCreds
		}

		Package "WindowsADK"
		{
			Ensure = "Present"
			Name = "Windows Deployment Tools"
			ProductId = ""
			Path = "$SourceRootDir\ADK\adksetup.exe"
			Arguments = "/quiet /features OptionId.DeploymentTools OptionId.WindowsPreinstallationEnvironment"
			Credential = $InstallCreds
		}

		Group "Administrators"
		{
			GroupName = "Administrators"
			MembersToInclude = @(
				$SCVMMServiceAccountCreds.UserName
			)
			Credential = $InstallCreds
		}

		File SCVMMLib
		{
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = $SCVMMLibPath
		}

		xSmbShare SCVMMLibShare
		{
			Ensure = "Present"
			Path = $SCVMMLibPath
			FullAccess = "Everyone"
			Name = $SCVMMLibShare
		}

		# Create DependsOn for first Management Server
		$DependsOn = @(
			"[Package]SQLServer2012NativeClient",
			"[Package]SQLServer2012CommandLineUtilities",
			"[Package]WindowsADK",
			"[Group]Administrators"
			#"[File]SCVMMLib"
		)

		xSCVMMManagementServerSetup "VMMMS"
		{
			DependsOn = $DependsOn
			Ensure = "Present"
			SourcePath = $SourceRootDir
			SourceFolder = "SCVMM"
			SetupCredential = $InstallCreds
			vmmService = $SCVMMServiceAccountCreds
			SqlMachineName = $SQLServerName
			SqlInstanceName = $SQLInstanceName
			CreateNewLibraryShare = 0
			LibraryShareName = $SCVMMLibShare
			LibrarySharePath = $SCVMMLibPath
			SQMOptIn = 0
			MUOptIn = 0
		}
	}
}

DSC_VMM -ConfigurationData $ConfigData
$scvmmInstallJob = Start-DscConfiguration -Path .\DSC_VMM -Verbose -Force

$jobRunning = $true

do
{
	$runningJob = Get-Job -Name $scvmmInstallJob.Name
	if ($runningJob.State -eq "Running")
	{
		Write-Host "SCVMM Installation DSC job is still running. Start sleep..." -ForegroundColor Green
		Start-Sleep -Seconds 10
	}
	elseif ($runningJob.State -eq "NotStarted")
	{
		Write-Host "SCVMM Installation DSC job is not started yet. Start sleep for 1 minute ..." -ForegroundColor Green
		Start-Sleep -Seconds 60
	}
	elseif ($runningJob.State -eq "Failed")
	{
		Write-Host "SCVMM Installation DSC Job installed SCVMM, but ended with an error" -ForegroundColor Red
		$jobRunning = $false
	}
	else
	{
		Write-Host "State of DSC job is $($runningJob.State)" -ForegroundColor Yellow
		$jobRunning = $false
	}
} while ($jobRunning)

