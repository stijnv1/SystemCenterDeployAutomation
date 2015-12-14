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
    [string]$ADJoinPassword
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
	Write-Host "Give Read-Write Service Principal Name permissions ot SQL service account" 
	Set-SpnPermission -TargetObject $sqlsvcLDAP -Identity $sqlsvcIdentity -Write -Read  
	#set trust for delegation flag for SQL service account 
	$sqlsvcAccount | Set-ADUser -TrustedForDelegation $true 

	#set read-write service principal name permissions on created service account for SCVMM
	$scvmmsvcLDAP = "LDAP://$($scvmmsvcAccount.DistinguishedName)" 
	$scvmmsvcIdentity = [security.principal.ntaccount]"$DomainNETBIOS\$($scvmmsvcAccount.SamAccountName)" 
	Write-Host "Give Read-Write Service Principal Name permissions ot SCVMM service account" 
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
	$TargetObject.psbase.CommitChanges()     
	return $spnAce 
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
			$ffile.Dispose()
			$tofile.Dispose()
			write-output (($from.Split("\")|select -last 1) + `
				" copied in " + $secselapsed + " seconds at " + `
				"{0:n2}" -f [int](($ffile.length/$secselapsed)/1mb) + " MB/s.");
		}
	}

    #local administrator password of deployed VMs is set via unattend.xml sysprep. Hardcoded in script
    $locAdminPassword = ConvertTo-SecureString "F5rr1nt9" -AsPlainText -Force

	#get vSwitch Name
	$SwitchName = Get-VMSwitch | Select-Object Name

	foreach ($VMName in $VMNames)
	{
		#create VM directories
		New-Item -ItemType directory "$VMRootPath\$VMName"
	}

	#start parallel copy action
	foreach ($VMName in $VMNames)
	{
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
		Start-VM -Name $VMName
	}
}

#start workflow
WF_DeployVMs -VMNames $VMNames -VMRootPath $VMRootPath -VMTemplatePath $VMTemplatePath -VMMinMemory $VMMinMemory -VMMaxMemory $VMMaxMemory -VMStartupMemory $VMStartupMemory -VMprocessorCount $VMprocessorCount

$localPassword = ConvertTo-SecureString "F5rr1nt9" -AsPlainText -Force
$localVMCred = New-Object System.Management.Automation.PSCredential ("Administrator", $localPassword)

#& ((Split-Path $MyInvocation.InvocationName) + "\CreateADObject.ps1 -SQLServiceAccountUsername $SQLServiceAccountUsername -SQLServiceAccountPassword $SQLServiceAccountPassword -SCVMMServiceAccountUsername $SCVMMServiceAccountUsername -SCVMMServiceAccountPassword $SCVMMServiceAccountPassword -DomainFQDN $DomainFQDN -DomainNETBIOS $DomainNETBIOS -ServiceAccountOU $ServiceAccountOU -ServerOU $ServerOU -VMNames $VMNames")
CreateADObjects -SQLServiceAccountUsername $SQLServiceAccountUsername -SQLServiceAccountPassword $SQLServiceAccountPassword -SCVMMServiceAccountUsername $SCVMMServiceAccountUsername -SCVMMServiceAccountPassword $SCVMMServiceAccountPassword -DomainFQDN $DomainFQDN -DomainNETBIOS $DomainNETBIOS -ServiceAccountOU $ServiceAccountOU -ServerOU $ServerOU -VMNames $VMNames



#region wait for VMs to come online
$boolOnline = $false
Write-Host "Start tests to see whether VMs are online and reachable of the network ..." -ForegroundColor Yellow
foreach ($VMName in $VMNames)
{
	do
	{
		#get assigned IP address
		$assignedIP = (Get-VMNetworkAdapter -VMName $VMName).IPAddresses[0]

		if ($assignedIP)
		{
			Write-Host "$VMName has an IP assigned = $assignedIP" -ForegroundColor Yellow
			Write-Host "Start testing connectivity for VM $VMName ..." -ForegroundColor Yellow
			$boolOnline = $true
			$boolReachable = $false
			do
			{
				if (Test-NetConnection -ComputerName $assignedIP -CommonTCPPort RDP)
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
        $domain
    )

    $JoinPasswordSec = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
    $ADJoinCreds = New-Object System.Management.Automation.PSCredential ($JoinUsername, $JoinPassword)

    Add-Computer -DomainName $domain -Credential $ADJoinCreds -Force
}
Foreach ($VMName in $VMNames)
{
    Invoke-Command -VMName $VMName -Credential $localVMCred -ScriptBlock $ADJoinScriptBlock -ArgumentList $ADJoinUsername,$ADJoinPassword,$DomainFQDN
}
#endregion
