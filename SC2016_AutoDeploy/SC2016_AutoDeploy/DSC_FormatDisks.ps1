#
# DSC_FormatDisks.ps1
#
#this script uses the different SQL DSC resources to automatically install SQL server
param
(
	[Parameter(Mandatory=$true)]
	[string]$ServerName
)

Configuration DSC_FormatDisks
{
	param
	(
		$MachineName
	)
	Import-DscResource -ModuleName xStorage

	Node $MachineName
	{
		LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

		if ($MachineName -like "*SQL*")
		{
			xDisk DVolume
			{
				DiskNumber = 1
				DriveLetter = "D"
				FSLabel = "SQLDATA"
				AllocationUnitSize = 64kb
			}
		}

		if ($MachineName -like "*VMM*")
		{
			xDisk DVolume
			{
				DiskNumber = 1
				DriveLetter = "D"
				FSLabel = "SCVMMLib"
			}
		}
	}
}

#check if server is online
$VMOnline = $false
do
{
	if (Resolve-DnsName -Name $ServerName -ErrorAction SilentlyContinue)
	{
		Write-Host "DNS lookup succeeded..." -ForegroundColor Green
		if (Test-NetConnection -ComputerName $ServerName -CommonTCPPort WINRM -InformationLevel Quiet -ErrorAction SilentlyContinue)
		{
			Write-Host "$ServerName is online. DSC configuration can be pushed" -ForegroundColor Yellow
			$VMOnline = $true
		}
		else
		{
			Write-Host "$ServerName is not online yet. Start sleeping for 30 seconds..." -ForegroundColor Green
			Start-Sleep -Seconds 30
		}
	}
	else
	{
		Write-Host "DNS lookup failed. Start sleeping for 30 seconds..." -ForegroundColor Red
		Start-Sleep -Seconds 30
	}
} While (!$VMOnline)

Write-Host "DSC configuration is being pushed" -ForegroundColor Yellow

#compile DSC for disk formats
DSC_FormatDisks -MachineName $ServerName
$diskJob = Start-DscConfiguration -Path .\DSC_FormatDisks -Verbose -Force

$jobRunning = $true

do 
{
	$runningJob = Get-Job -Name $diskJob.Name
	if ($runningJob.State -eq "Running")
	{
		Write-Host "Format Disk DSC job is still running. Start sleep..." -ForegroundColor Green
		Start-Sleep -Seconds 10
	}
	elseif ($runningJob.State -eq "NotStarted")
	{
		Write-Host "Format Disk DSC job is not started yet. Start sleep..." -ForegroundColor Green
		Start-Sleep -Seconds 10
	}
	else
	{
		Write-Host "State of DSC job is $($runningJob.State)" -ForegroundColor Yellow
		$jobRunning = $false
	}

} while ($jobRunning)