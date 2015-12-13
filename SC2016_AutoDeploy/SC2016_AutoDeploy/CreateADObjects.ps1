#
# CreateADObjects.ps1
#
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

#function used to give service accounts read-write serviceprincipal name permissions 
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

$SQLsvcSecPassword = ConvertTo-SecureString -AsPlainText -String $SQLServiceAccountPassword -Force
$SCVMMsvcSecPassword = ConvertTo-SecureString -AsPlainText -String $SCVMMServiceAccountPassword -Force

Write-Output "Creating SQL Service Account with username $SQLServiceAccountUsername" 
$sqlsvcAccount = New-ADUser -Name "SQL Service Account" -PasswordNeverExpires $true -SamAccountName $SQLServiceAccountUsername -AccountPassword $SQLsvcSecPassword -Path "$ServiceAccountOU" -UserPrincipalName "$SQLServiceAccountUsername@$DomainFQDN" -Enabled $true -PasswordNotRequired $true -PassThru 
$scvmmsvcAccount = New-ADUser -Name "SCVMM Service Account" -PasswordNeverExpires $true -SamAccountName $SCVMMServiceAccountUsername -AccountPassword $SCVMMsvcSecPassword -Path "$ServiceAccountOU" -UserPrincipalName "$SCVMMServiceAccountUsername@$DomainFQDN" -Enabled $true -PasswordNotRequired $true -PassThru 

#set read-write service principal name permissions on created service account for SQL
$sqlsvcLDAP = "LDAP://$($sqlsvcAccount.DistinguishedName)" 
$sqlsvcIdentity = [security.principal.ntaccount]"customer\$($sqlsvcAccount.SamAccountName)" 
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

