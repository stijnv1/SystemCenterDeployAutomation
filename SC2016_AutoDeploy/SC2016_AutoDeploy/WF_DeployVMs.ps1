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
    [int]$VLANId
)

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

foreach ($VM in $VMNames)
{
	Write-Host "Enabling guest services for powershell direct access for VM $VM"
	Get-VMIntegrationService -VMName $VM -Name "Guest Service Interface" | Enable-VMIntegrationService
}

$ScriptBlock = {
param($computerName)
	Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
	Enable-NetFirewallRule -DisplayName "Remote Desktop - Shadow (TCP-In)"
	Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)"
	Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"
	Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
	Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Name-In)"
	Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Datagram-In)"
	Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Session-In)"

	Rename-Computer -NewName $computerName -Restart
}

$localPassword = ConvertTo-SecureString "F5rr1nt9" -AsPlainText -Force
$localVMCred = New-Object System.Management.Automation.PSCredential ("Administrator", $localPassword)

foreach ($VM in $VMNames)
{

	Invoke-Command -VMName $VM -ScriptBlock $ScriptBlock -Credential $localVMCred -ArgumentList $VM
}


