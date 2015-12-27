#
# WF_DeployVMs.ps1
#
#workflows which deploys VMs in parallel
#this version only supports standalone deployments, no HA VM deployments yet
param
(
	[Parameter(Mandatory=$true)]
	[string[]]$VMNames,

	[Parameter(Mandatory=$true)]
	[string]$VMRootPath,

	[Parameter(Mandatory=$true)]
	[string]$VMTemplatePath,

	[Parameter(Mandatory=$true)]
	[int]$VMMinMemory,

	[Parameter(Mandatory=$true)]
	[int]$VMMaxMemory,

	[Parameter(Mandatory=$true)]
	[int]$VMStartupMemory,

	[Parameter(Mandatory=$true)]
	[int]$VMprocessorCount,

	[Parameter(Mandatory=$false)]
    [int]$VLANId,

	[string]$SQLServiceAccountUsername,
	[string]$SQLServiceAccountPassword,
	[string]$SCVMMServiceAccountUsername,
	[string]$SCVMMServiceAccountPassword,
	[string]$DomainFQDN,
	[string]$DomainNETBIOS,
	[string]$ServiceAccountOU,
	[string]$ServerOU,
    [string]$ADJoinUsername,
    [string]$ADJoinPassword,
	[string]$VMInfoCSVPath,
	[string]$InstallUserName,
	[string]$InstallPassword,
	[string]$SourceRootDir
)

Function CreateADObjects
{
	param
	(
		[string]$SQLServiceAccountUsername,
		[string]$SQLServiceAccountPassword,
		[string]$SCVMMServiceAccountUsername,
		[string]$SCVMMServiceAccountPassword,
		[string]$DomainFQDN,
		[string]$DomainNETBIOS,
		[string]$ServiceAccountOU,
		[string]$ServerOU,
		[string[]]$VMNames
	)

	$SQLsvcSecPassword = ConvertTo-SecureString -AsPlainText -String $SQLServiceAccountPassword -Force
	$SCVMMsvcSecPassword = ConvertTo-SecureString -AsPlainText -String $SCVMMServiceAccountPassword -Force

	Write-Output "Creating SQL Service Account with username $SQLServiceAccountUsername" 
	$sqlsvcAccount = New-ADUser -Name "SQL Service Account" -PasswordNeverExpires $true -SamAccountName $SQLServiceAccountUsername -AccountPassword $SQLsvcSecPassword -Path "$ServiceAccountOU" -UserPrincipalName "$SQLServiceAccountUsername@$DomainFQDN" -Enabled $true -PasswordNotRequired $true -PassThru 
	$scvmmsvcAccount = New-ADUser -Name "SCVMM Service Account" -PasswordNeverExpires $true -SamAccountName $SCVMMServiceAccountUsername -AccountPassword $SCVMMsvcSecPassword -Path "$ServiceAccountOU" -UserPrincipalName "$SCVMMServiceAccountUsername@$DomainFQDN" -Enabled $true -PasswordNotRequired $true -PassThru 

	#set read-write service principal name permissions on created service account for SQL
	$sqlsvcLDAP = "LDAP://$($sqlsvcAccount.DistinguishedName)" 
	$sqlsvcIdentity = [security.principal.ntaccount]"$DomainNETBIOS\$($sqlsvcAccount.SamAccountName)" 
	Write-Host "Give Read-Write Service Principal Name permissions to SQL service account" 
	Set-SpnPermission -TargetObject $sqlsvcLDAP -Identity $sqlsvcIdentity -Write -Read  
	#set trust for delegation flag for SQL service account 
	$sqlsvcAccount | Set-ADUser -TrustedForDelegation $true 

	#set read-write service principal name permissions on created service account for SCVMM
	$scvmmsvcLDAP = "LDAP://$($scvmmsvcAccount.DistinguishedName)" 
	$scvmmsvcIdentity = [security.principal.ntaccount]"$DomainNETBIOS\$($scvmmsvcAccount.SamAccountName)" 
	Write-Host "Give Read-Write Service Principal Name permissions to SCVMM service account" 
	Set-SpnPermission -TargetObject $scvmmsvcLDAP -Identity $scvmmsvcIdentity -Write -Read  
	#set trust for delegation flag for SQL service account 
	$scvmmsvcAccount | Set-ADUser -TrustedForDelegation $true

	#create server objects
	foreach ($VMName in $VMNames)
	{
		New-ADComputer -Path "$ServerOU" -Name $VMName -DisplayName $VMName
	}
}

Function Set-SpnPermission  
{ 
	param 
	( 
		[adsi]$TargetObject, 
		[Security.Principal.IdentityReference]$Identity, 
		[switch]$Write, 
		[switch]$Read 
	) 
 
	if(!$write -and !$read) 
	{ 
		throw "Missing either -read or -write" 
	} 
	$rootDSE = [adsi]"LDAP://RootDSE" 
	$schemaDN = $rootDSE.psbase.properties["schemaNamingContext"][0] 
	$spnDN = "LDAP://CN=Service-Principal-Name,$schemaDN" 
	$spnEntry = [adsi]$spnDN 
	$guidArg=@("") 
	$guidArg[0]=$spnEntry.psbase.Properties["schemaIDGUID"][0] 
	$spnSecGuid = new-object GUID $guidArg 
 
	if($read ){$adRight=[DirectoryServices.ActiveDirectoryRights]"ReadProperty" } 
	if($write){$adRight=[DirectoryServices.ActiveDirectoryRights]"WriteProperty"} 
	if($write -and $read){$adRight=[DirectoryServices.ActiveDirectoryRights]"readproperty,writeproperty"} 
	$accessRuleArgs = $identity,$adRight,"Allow",$spnSecGuid,"None" 
	$spnAce = new-object DirectoryServices.ActiveDirectoryAccessRule $accessRuleArgs 
	$TargetObject.psbase.ObjectSecurity.AddAccessRule($spnAce) 
	$TargetObject.psbase.CommitChanges() | Out-Null
	#return $spnAce 
} 

Workflow WF_DeployVMs
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string[]]$VMNames,

		[Parameter(Mandatory=$true)]
		[string]$VMRootPath,

		[Parameter(Mandatory=$true)]
		[string]$VMTemplatePath,

		[Parameter(Mandatory=$true)]
		[int]$VMMinMemory,

		[Parameter(Mandatory=$true)]
		[int]$VMMaxMemory,

		[Parameter(Mandatory=$true)]
		[int]$VMStartupMemory,

		[Parameter(Mandatory=$true)]
		[int]$VMprocessorCount,

		[Parameter(Mandatory=$false)]
		[int]$VLANId
	)

	function Copy-File 
	{
		param( [string]$from, [string]$to)
		$ffile = [io.file]::OpenRead($from)
		$tofile = [io.file]::OpenWrite($to)
		Write-Progress `
			-Activity "Copying file" `
			-status ($from.Split("\")|select -last 1) `
			-PercentComplete 0
		try 
		{
			$sw = [System.Diagnostics.Stopwatch]::StartNew();
			[byte[]]$buff = new-object byte[] (4096*1024)
			[long]$total = [long]$count = 0
			do 
			{
				$count = $ffile.Read($buff, 0, $buff.Length)
				$tofile.Write($buff, 0, $count)
				$total += $count
				[int]$pctcomp = ([int]($total/$ffile.Length* 100));
				[int]$secselapsed = [int]($sw.elapsedmilliseconds.ToString())/1000;
				if ( $secselapsed -ne 0 ) 
				{
					[single]$xferrate = (($total/$secselapsed)/1mb);
				} 
				else 
				{
					[single]$xferrate = 0.0
				}

				if ($total % 1mb -eq 0) 
				{
					if ($pctcomp -gt 0)
					{
						[int]$secsleft = ((($secselapsed/$pctcomp)* 100)-$secselapsed)
					} else 
					{
						[int]$secsleft = 0
					}

					Write-Progress `
						-Activity ($pctcomp.ToString() + "% Copying file @ " + "{0:n2}" -f $xferrate + " MB/s")`
						-status ($from.Split("\")|select -last 1) `
						-PercentComplete $pctcomp `
						-SecondsRemaining $secsleft;
				}
			} while ($count -gt 0)
			$sw.Stop();
			$sw.Reset();
		}

		finally 
		{
			write-output (($from.Split("\")|select -last 1) + `
				" copied in " + $secselapsed + " seconds at " + `
				"{0:n2}" -f [int](($ffile.length/$secselapsed)/1mb) + " MB/s.");

			$ffile.Dispose()
			$tofile.Dispose()
		}
	}

	#get vSwitch Name
	$SwitchName = Get-VMSwitch | Select-Object Name

	#start parallel copy action
	foreach ($VMName in $VMNames)
	{
		#create VM directories
		New-Item -ItemType directory "$VMRootPath\$VMName"

		#copy VHDX file
		$vhdxName = "$($VMName)_C.vhdx"
		Write-Output "Start Copy template VHDX file"
		Copy-File "$VMTemplatePath" -to "$VMRootPath\$VMName\$vhdxName"

		#create a standalone VM
		#$vhdxName = "$($VMName)_C.vhdx"
		Write-Output "Creating Standalone VM $VMName"
		$minMemory = $VMMinMemory * 1024 * 1024
		$maxMemory = $VMMaxMemory * 1024 * 1024
		$startMemory = $VMStartupMemory * 1024 * 1024
		New-VM -Name $VMName -SwitchName $SwitchName.Name -VHDPath "$VMRootPath\$VMName\$vhdxName" -Path "$VMRootPath\$VMName\" -Generation 2 -BootDevice VHD
		#$createdVM = Get-VM -Name $VMName

		#if VLANs are in use
		if ($VLANId)
		{
			Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapterVlan -Access -VlanId $VMVlanID
		}
    
		Set-VM -Name $VMName -ProcessorCount $VMprocessorCount -AutomaticStopAction ShutDown
		Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes $minMemory -MaximumBytes $maxMemory -StartupBytes $startMemory -Buffer 20
		if ($VMName -like "*SQL*")
		{
			New-VHD -Path "$VMRootPath\$VMName\$($VMName)_D.vhdx" -SizeBytes 20GB -Dynamic
			Add-VMHardDiskDrive -VMName $VMName -ControllerType SCSI -Path "$VMRootPath\$VMName\$($VMName)_D.vhdx"
		}
		elseif ($VMName -like "*VMM*")
		{
			New-VHD -Path "$VMRootPath\$VMName\$($VMName)_D.vhdx" -SizeBytes 100GB -Dynamic
			Add-VMHardDiskDrive -VMName $VMName -ControllerType SCSI -Path "$VMRootPath\$VMName\$($VMName)_D.vhdx"
		}
		Start-VM -Name $VMName
	}
}

#start workflow
WF_DeployVMs -VMNames $VMNames -VMRootPath $VMRootPath -VMTemplatePath $VMTemplatePath -VMMinMemory $VMMinMemory -VMMaxMemory $VMMaxMemory -VMStartupMemory $VMStartupMemory -VMprocessorCount $VMprocessorCount
CreateADObjects -SQLServiceAccountUsername $SQLServiceAccountUsername -SQLServiceAccountPassword $SQLServiceAccountPassword -SCVMMServiceAccountUsername $SCVMMServiceAccountUsername -SCVMMServiceAccountPassword $SCVMMServiceAccountPassword -DomainFQDN $DomainFQDN -DomainNETBIOS $DomainNETBIOS -ServiceAccountOU $ServiceAccountOU -ServerOU $ServerOU -VMNames $VMNames | Out-Null

#read CSV with VM info
$VMInfoCSV = Import-Csv $VMInfoCSVPath

#region wait for VMs to come online
$boolOnline = $false
Write-Host "Start tests to see whether VMs are online and reachable over the network ..." -ForegroundColor Yellow
foreach ($VMName in $VMNames)
{
	do
	{
		#get assigned IP address
		$assignedIP = (Get-VMNetworkAdapter -VMName $VMName).IPAddresses[0]

		if ($assignedIP)
		{
			Write-Host "$VMName has an IP assigned = $assignedIP" -ForegroundColor Yellow
			Write-Host "Start testing connectivity for VM $VMName with IP address $assignedIP ..." -ForegroundColor Yellow
			$boolOnline = $true
			$boolReachable = $false
			do
			{
				#start extra sleep of 30 seconds to make sure sysprepped image is completely deployed
				start-sleep -Seconds 30
				if (Test-NetConnection -ComputerName $assignedIP -CommonTCPPort RDP -InformationLevel Quiet -ErrorAction SilentlyContinue)
				{
					Write-Host "$VMName is reachable, continueing script ..." -ForegroundColor Yellow
					$boolReachable = $true
				}
				else
				{
					Write-Host "$VMName not reachable, start sleep of 5 seconds ..." -ForegroundColor Green
					Start-Sleep -Seconds 5
				}
			} while (!$boolReachable)
		}
		else
		{
			Write-Host "No IP address assigned yet, start sleep of 20 seconds ..." -ForegroundColor Green
			Start-Sleep -Seconds 20
		}
	} while(!$boolOnline)
}
#endregion 

#region all VMs are online, guest services can be started
foreach ($VM in $VMNames)
{
	Write-Host "Enabling guest services for powershell direct access for VM $VM"
	Get-VMIntegrationService -VMName $VM -Name "Guest Service Interface" | Enable-VMIntegrationService
}
#endregion

#region start powershell direct script to join VM in domain
$ADJoinScriptBlock = {
    param
    (
        $JoinUsername,
        $JoinPassword,
        $domain,
		$VMIPAddress,
		$VMSubnet,
		$VMDefaultGateway,
		$VMPrimDNS
    )

	#change network ip address, assumption: only one network adapter is attached to the VM
	Get-NetAdapter | New-NetIPAddress -IPAddress $VMIPAddress -PrefixLength $VMSubnet -DefaultGateway $VMDefaultGateway -AddressFamily IPv4
	Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $VMPrimDNS

	#start sleep for 5 seconds
	Start-Sleep -Seconds 5

	#join to domain
    $JoinPasswordSec = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
    $ADJoinCreds = New-Object System.Management.Automation.PSCredential ($JoinUsername,$JoinPasswordSec)

    Add-Computer -DomainName $domain -Credential $ADJoinCreds -Restart -Force
}

$localPassword = ConvertTo-SecureString "F5rr1nt9" -AsPlainText -Force
$localVMCred = New-Object System.Management.Automation.PSCredential "Administrator", $localPassword

#generate Install Credentials
$installPasswordSec = ConvertTo-SecureString $InstallPassword -AsPlainText -Force
$installCreds = New-Object System.Management.Automation.PSCredential ("$DomainNETBIOS\$InstallUserName",$installPasswordSec)

#SQL Name variable
$SQLServerNameVariable = ""

Foreach ($VMName in $VMNames)
{
	#check if VM is online
	$boolReachable = $false

	Write-Host "Start sleep of 1 minute before checking connectivity for VM $VMName"
	Start-Sleep -Seconds 60

	do
	{
		if (Test-NetConnection -ComputerName $assignedIP -CommonTCPPort WINRM -InformationLevel Quiet -ErrorAction SilentlyContinue)
		{
			Write-Host "Test network connection succeeded for VM $VMName, start powershell direct session ..." -ForegroundColor Green
			$boolReachable = $true
			$VMIPAddress = ($VMInfoCSV | ? {$_.VMName -eq $VMName}).IPAddress
			$VMSubnet = ($VMInfoCSV | ? {$_.VMName -eq $VMName}).Subnet
			$VMDefaultGateway = ($VMInfoCSV | ? {$_.VMName -eq $VMName}).DefaultGateway
			$VMPrimDNS = ($VMInfoCSV | ? {$_.VMName -eq $VMName}).PrimaryDNS
			Invoke-Command -VMName $VMName -Credential $localVMCred -ScriptBlock $ADJoinScriptBlock -ArgumentList $ADJoinUsername,$ADJoinPassword,$DomainFQDN,$VMIPAddress,$VMSubnet,$VMDefaultGateway,$VMPrimDNS
		}
		else
		{
			Write-Host "VM $VMName not reachable, start sleep for 5 seconds ..." -ForegroundColor Green
			Start-Sleep -Seconds 5
		}
	} while (!$boolReachable)

	if (($VMInfoCSV | ? {$_.VMName -eq $VMName}).InstallSQL -eq "1")
	{
		Write-Host "Start installing SQL 2014 ..." -ForegroundColor Yellow
		$SQLServerNameVariable = $VMName
		#start sleep because domain join is still in progress
		Start-Sleep -Seconds 10
		.\DSC_FormatDisks.ps1 -ServerName $VMName
		
		#generate SQL service account credentials
		$SQLServiceAccountPasswordSec = ConvertTo-SecureString $SQLServiceAccountPassword -AsPlainText -Force
		$SQLServiceAccountCreds = New-Object System.Management.Automation.PSCredential ("$DomainNETBIOS\$SQLServiceAccountUsername",$SQLServiceAccountPasswordSec) 

		#generate SA credentials
		$SACreds = New-Object System.Management.Automation.PSCredential ("sa",$SQLServiceAccountPasswordSec)

		.\DSC_SQLInstall -SQLServerName $VMName -SQLServiceAccountCreds $SQLServiceAccountCreds -SACreds $SACreds -InstallCreds $installCreds -SourceRootDir $SourceRootDir
	}
	elseif (($VMInfoCSV | ? {$_.VMName -eq $VMName}).InstallSCVMM -eq "1")
	{
		Write-Host "Start installing SCVMM 2016 ..." -ForegroundColor Yellow
		#start sleep because domain join is still in progress
		Start-Sleep -Seconds 10
		.\DSC_FormatDisks.ps1 -ServerName $VMName

		#generate SCVMM service account credentials
		$SCVMMServiceAccountPasswordSec = ConvertTo-SecureString $SCVMMServiceAccountPassword -AsPlainText -Force
		$SCVMMServiceAccountCreds = New-Object System.Management.Automation.PSCredential ("$DomainNETBIOS\$SCVMMServiceAccountUsername",$SCVMMServiceAccountPasswordSec) 

		$SCVMMLibPath = ($VMInfoCSV | ? {$_.VMName -eq $VMName}).SCVMMLibPath
		$SCVMMLibShare = ($VMInfoCSV | ? {$_.VMName -eq $VMName}).SCVMMLibShare
		Write-Host "SCVMM Library Path = $SCVMMLibPath" -ForegroundColor DarkMagenta
		Write-Host "SCVMM Library Share = $SCVMMLibShare" -ForegroundColor DarkMagenta

		.\DSC_SCVMMInstall.ps1 -SCVMMServerName $VMName -SCVMMServiceAccountCreds $SCVMMServiceAccountCreds -InstallCreds $installCreds -SourceRootDir $SourceRootDir -SQLServerName $SQLServerNameVariable -SQLInstanceName "MSSQLServer" -SCVMMLibPath $SCVMMLibPath -SCVMMLibShare $SCVMMLibShare
	}
}
#endregion