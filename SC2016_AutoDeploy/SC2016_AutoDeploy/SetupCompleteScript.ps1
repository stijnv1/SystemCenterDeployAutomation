Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
Enable-NetFirewallRule -DisplayName "Remote Desktop - Shadow (TCP-In)"
Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Name-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Datagram-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Session-In)"

# Get the virtual machine name from the parent partition
 $vmName = (Get-ItemProperty –path “HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters”).VirtualMachineName
 # Replace any non-alphanumeric characters with an underscore
 $vmName = [Regex]::Replace($vmName,"\W","-")
 # Trim names that are longer than 15 characters
 $vmName = $vmName.Substring(0,[System.Math]::Min(15, $vmName.Length))
 
 #reset TCP/IP stack
 netsh int ip reset resettcpip.txt

 # Check the trimmed and cleaned VM name against the guest OS name
 # If it is different, change the guest OS name and reboot
 if ($env:computername -ne $vmName) {(gwmi win32_computersystem).Rename($vmName); shutdown -r -t 0}
