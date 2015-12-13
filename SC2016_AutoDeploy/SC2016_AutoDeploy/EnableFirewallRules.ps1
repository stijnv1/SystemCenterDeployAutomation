#
# EnableFirewallRules.ps1
#
Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
Enable-NetFirewallRule -DisplayName "Remote Desktop - Shadow (TCP-In)"
Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Name-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Datagram-In)"
Enable-NetFirewallRule -DisplayName "File and Printer Sharing (NB-Session-In)"