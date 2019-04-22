       
Configuration SecurityBaselineConfigurationWS2008R2SP1
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node localhost
	{
	 	Registry "CCE-10637-7: Devices: Allowed to format and eject removable media"
	 	{
	 	 	ValueName = 'AllocateDASD'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '2'

	 	}

	 	Registry "CCE-10940-5: Network access: Restrict anonymous access to Named Pipes and Shares"
	 	{
	 	 	ValueName = 'restrictnullsessaccess'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10027-1: Network access: Do not allow anonymous enumeration of SAM accounts"
	 	{
	 	 	ValueName = 'RestrictAnonymousSAM'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11049-4: Shutdown: Clear virtual memory pagefile"
	 	{
	 	 	ValueName = 'ClearPageFileAtShutdown'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10772-2: MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)"
	 	{
	 	 	ValueName = 'SafeDllSearchMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10557-7: Network access: Do not allow anonymous enumeration of SAM accounts and shares"
	 	{
	 	 	ValueName = 'RestrictAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10370-5: Recovery console: Allow automatic administrative logon"
	 	{
	 	 	ValueName = 'securitylevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10986-8: System objects: Require case insensitivity for non-Windows subsystems"
	 	{
	 	 	ValueName = 'ObCaseInsensitive'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10643-5: Recovery console: Allow floppy copy and access to all drives and all folders"
	 	{
	 	 	ValueName = 'setcommand'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10810-0: Interactive logon: Do not require CTRL+ALT+DEL"
	 	{
	 	 	ValueName = 'DisableCAD'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10883-7: Devices: Allow undock without having to log on"
	 	{
	 	 	ValueName = 'undockwithoutlogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10900-9: System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies"
	 	{
	 	 	ValueName = 'AuthenticodeEnabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10825-8: Network access: Sharing and security model for local accounts"
	 	{
	 	 	ValueName = 'ForceGuest'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10745-8: MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)"
	 	{
	 	 	ValueName = 'AutoAdminLogon'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-10419-0: Shutdown: Allow system to be shut down without having to log on"
	 	{
	 	 	ValueName = 'ShutdownWithoutLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10983-5: Microsoft network server: Disconnect clients when logon hours expire"
	 	{
	 	 	ValueName = 'enableforcedlogoff'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10019-8: MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)"
	 	{
	 	 	ValueName = 'ScreenSaverGracePeriod'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-10573-4: Interactive logon: Smart card removal behavior"
	 	{
	 	 	ValueName = 'scremoveoption'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '1'

	 	}

	 	Registry "CCE-10788-8: Interactive logon: Do not display last user name"
	 	{
	 	 	ValueName = 'DontDisplayLastUserName'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10035-4: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
	 	{
	 	 	ValueName = 'NTLMMinClientSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-10992-6: Microsoft network server: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'requiresecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10040-4: Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"
	 	{
	 	 	ValueName = 'NTLMMinServerSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-10009-9: Domain member: Digitally sign secure channel data (when possible)"
	 	{
	 	 	ValueName = 'signsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10970-2: Microsoft network client: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'RequireSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10871-2: Domain member: Digitally encrypt or sign secure channel data (always)"
	 	{
	 	 	ValueName = 'requiresignorseal'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10978-5: Microsoft network server: Digitally sign communications (if client agrees)"
	 	{
	 	 	ValueName = 'enablesecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10875-3: Domain member: Digitally encrypt secure channel data (when possible)"
	 	{
	 	 	ValueName = 'sealsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10838-1: Microsoft network client: Send unencrypted password to third-party SMB servers"
	 	{
	 	 	ValueName = 'EnablePlainTextPassword'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "NOT_ASSIGNED: Disable SMB v1 client"
	 	{
	 	 	ValueName = 'DependsOnService'
	 	 	ValueType = 'MultiString'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation'
	 	 	ValueData = 'Bowser","MRxSmb20","NSI'

	 	}

	 	Registry "NOT_ASSIGNED: Disable SMB v1 server"
	 	{
	 	 	ValueName = 'SMB1'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "NOT_ASSIGNED: Set SMB v1 client (MRxSMB10) to disabled'"
	 	{
	 	 	ValueName = 'Start'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
	 	 	ValueData = 4

	 	}

	 	Registry "CCE-10974-4: Microsoft network client: Digitally sign communications (if server agrees)"
	 	{
	 	 	ValueName = 'EnableSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10789-6: System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"
	 	{
	 	 	ValueName = 'Enabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10541-1: Domain member: Require strong (Windows 2000 or later) session key"
	 	{
	 	 	ValueName = 'requirestrongkey'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11010-6: System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)"
	 	{
	 	 	ValueName = 'ProtectionMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10930-6: Interactive logon: Prompt user to change password before expiration"
	 	{
	 	 	ValueName = 'passwordexpirywarning'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 14

	 	}

	 	Registry "CCE-10830-8: Network security: Do not store LAN Manager hash value on next password change"
	 	{
	 	 	ValueName = 'NoLMHash'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-9992-9: Accounts: Limit local account use of blank passwords to console logon only"
	 	{
	 	 	ValueName = 'LimitBlankPasswordUse'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10775-5: Domain member: Disable machine account password changes"
	 	{
	 	 	ValueName = 'disablepasswordchange'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-11041-1: Windows Firewall: Domain: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10732-6: MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-10123-8: Windows Firewall: Private: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10127-9: Windows Firewall: Private: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10481-0: Windows Firewall: Public: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10888-6: MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-11019-7: Windows Firewall: Domain: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10482-8: Windows Firewall: Domain: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10188-1: Windows Firewall: Public: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10113-9: Windows Firewall: Domain: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10798-7: Windows Firewall: Domain: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10631-0: Windows Firewall: Private: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10921-5: Windows Firewall: Private: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11050-2: Windows Firewall: Public: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11120-3: Windows Firewall: Public: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10131-1: Windows Firewall: Private: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10873-8: Windows Firewall: Public: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10529-6: Windows Firewall: Public: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11103-9: Windows Firewall: Private: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11036-1: Windows Firewall: Domain: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10112-1: Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
	 	{
	 	 	ValueName = 'scenoapplylegacyauditpolicy'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10918-1: Retain old events"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-11011-4: MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"
	 	{
	 	 	ValueName = 'WarningLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
	 	 	ValueData = 90

	 	}

	 	Registry "CCE-11055-1: Retain old events"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-10742-5: Audit: Shut down system immediately if unable to log security audits"
	 	{
	 	 	ValueName = 'crashonauditfail'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10663-3: Retain old events"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-10297-0: Network access: Let Everyone permissions apply to anonymous users"
	 	{
	 	 	ValueName = 'EveryoneIncludesAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10926-4: Interactive logon: Number of previous logons to cache (in case domain controller is not available)"
	 	{
	 	 	ValueName = 'cachedlogonscount'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-10705-2: Interactive logon: Require Domain Controller authentication to unlock workstation"
	 	{
	 	 	ValueName = 'ForceUnlockLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10984-3: Network security: LAN Manager authentication level"
	 	{
	 	 	ValueName = 'LmCompatibilityLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 5

	 	}

	 	Registry "CCE-10614-6: Network security: LDAP client signing requirements"
	 	{
	 	 	ValueName = 'LDAPClientIntegrity'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LDAP'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-9999-4: Devices: Prevent users from installing printer drivers"
	 	{
	 	 	ValueName = 'AddPrinterDrivers'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10794-6: User Account Control: Detect application installations and prompt for elevation"
	 	{
	 	 	ValueName = 'EnableInstallerDetection'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10570-0: User Account Control: Only elevate UIAccess applications that are installed in secure locations"
	 	{
	 	 	ValueName = 'EnableSecureUIAPaths'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10534-6: User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop"
	 	{
	 	 	ValueName = 'EnableUIADesktopToggle'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10865-4: User Account Control: Virtualize file and registry write failures to per-user locations"
	 	{
	 	 	ValueName = 'EnableVirtualization'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10922-3: User Account Control: Only elevate executables that are signed and validated"
	 	{
	 	 	ValueName = 'ValidateAdminCodeSignatures'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-10807-6: User Account Control: Behavior of the elevation prompt for standard users"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorUser'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 3

	 	}

	 	Registry "CCE-11028-8: User Account Control: Admin Approval Mode for the Built-in Administrator account"
	 	{
	 	 	ValueName = 'FilterAdministratorToken'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10684-9: User Account Control: Run all administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'EnableLUA'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-10109-7: User Account Control: Switch to the secure desktop when prompting for elevation"
	 	{
	 	 	ValueName = 'PromptOnSecureDesktop'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-11023-9: User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorAdmin'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 5

	 	}

	 	AuditPolicySubCategory "CCE-11001-5: Audit Policy: Account Management: Other Account Management Events (Success)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-11001-5: Audit Policy: Account Management: Other Account Management Events (Failure)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-11007-2: Audit Policy: System: Security State Change (Success)"
	 	{
	 	 	Name = 'Security State Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-11007-2: Audit Policy: System: Security State Change (Failure)"
	 	{
	 	 	Name = 'Security State Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-11160-9: Audit Policy: Policy Change: Authentication Policy Change"
	 	{
	 	 	Name = 'Authentication Policy Change'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubcategory "CCE-10514-8: Audit Policy: Detailed Tracking: Process Creation"
	 	{
	 	 	Name = 'Process Creation'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-11034-6: Audit Policy: System: System Integrity (Success)"
	 	{
	 	 	Name = 'System Integrity'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-11034-6: Audit Policy: System: System Integrity (Failure)"
	 	{
	 	 	Name = 'System Integrity'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-11107-0: Audit Policy: Logon-Logoff: Logon (Success)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-11107-0: Audit Policy: Logon-Logoff: Logon (Failure)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-10737-5: Audit Policy: Logon-Logoff: Special Logon"
	 	{
	 	 	Name = 'Special Logon'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-10203-8: Audit Policy: Account Management: User Account Management (Success)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-10203-8: Audit Policy: Account Management: User Account Management (Failure)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-11029-6: Audit Policy: System: Security System Extension (Success)"
	 	{
	 	 	Name = 'Security System Extension'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-11029-6: Audit Policy: System: Security System Extension (Failure)"
	 	{
	 	 	Name = 'Security System Extension'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-11003-1: Audit Policy: Privilege Use: Sensitive Privilege Use (Success)"
	 	{
	 	 	Name = 'Sensitive Privilege Use'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-11003-1: Audit Policy: Privilege Use: Sensitive Privilege Use (Failure)"
	 	{
	 	 	Name = 'Sensitive Privilege Use'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-10385-3: Audit Policy: Policy Change: Audit Policy Change (Success)"
	 	{
	 	 	Name = 'Audit Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-10385-3: Audit Policy: Policy Change: Audit Policy Change (Failure)"
	 	{
	 	 	Name = 'Audit Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-10860-5: Audit Policy: Account Management: Computer Account Management"
	 	{
	 	 	Name = 'Computer Account Management'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubcategory "CCE-11102-1: Audit Policy: Logon-Logoff: Logoff"
	 	{
	 	 	Name = 'Logoff'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-10741-7: Audit Policy: Account Management: Security Group Management (Success)"
	 	{
	 	 	Name = 'Security Group Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-10741-7: Audit Policy: Account Management: Security Group Management (Failure)"
	 	{
	 	 	Name = 'Security Group Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-10390-3: Audit Policy: System: IPsec Driver (Success)"
	 	{
	 	 	Name = 'IPsec Driver'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-10390-3: Audit Policy: System: IPsec Driver (Failure)"
	 	{
	 	 	Name = 'IPsec Driver'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-10192-3: Audit Policy: Account Logon: Credential Validation (Success)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-10192-3: Audit Policy: Account Logon: Credential Validation (Failure)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	UserRightsAssignment "CCE-10726-8: Manage auditing and security log"
	 	{
	 	 	Policy = 'Manage_auditing_and_security_log'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10548-6: Increase a process working set"
	 	{
	 	 	Policy = 'Increase_a_process_working_set'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10915-7: Debug programs"
	 	{
	 	 	Policy = 'Debug_programs'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10750-8: Deny log on locally"
	 	{
	 	 	Policy = 'Deny_log_on_locally'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-9961-4: Increase scheduling priority"
	 	{
	 	 	Policy = 'Increase_scheduling_priority'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10618-7: Enable computer and user accounts to be trusted for delegation"
	 	{
	 	 	Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-9972-1: Access Credential Manager as a trusted caller"
	 	{
	 	 	Policy = 'Access_Credential_Manager_as_a_trusted_caller'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-10439-8: Shut down the system"
	 	{
	 	 	Policy = 'Shut_down_the_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10955-3: Lock pages in memory"
	 	{
	 	 	Policy = 'Lock_pages_in_memory'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-10853-0: Allow log on locally"
	 	{
	 	 	Policy = 'Allow_log_on_locally'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10274-9: Generate security audits"
	 	{
	 	 	Policy = 'Generate_security_audits'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10849-8: Adjust memory quotas for a process"
	 	{
	 	 	Policy = 'Adjust_memory_quotas_for_a_process'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10733-4: Deny access to this computer from the network"
	 	{
	 	 	Policy = 'Deny_access_to_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10969-4: Remove computer from docking station"
	 	{
	 	 	Policy = 'Remove_computer_from_docking_station'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10785-4: Force shutdown from a remote system"
	 	{
	 	 	Policy = 'Force_shutdown_from_a_remote_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10858-9: Allow log on through Remote Desktop Services"
	 	{
	 	 	Policy = 'Allow_log_on_through_Remote_Desktop_Services'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10596-5: Deny log on as a batch job"
	 	{
	 	 	Policy = 'Deny_log_on_as_a_batch_job'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10954-6: Take ownership of files or other objects"
	 	{
	 	 	Policy = 'Take_ownership_of_files_or_other_objects'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-9946-5: Impersonate a client after authentication"
	 	{
	 	 	Policy = 'Impersonate_a_client_after_authentication'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10792-0: Create global objects"
	 	{
	 	 	Policy = 'Create_global_objects'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10086-7: Access this computer from the network"
	 	{
	 	 	Policy = 'Access_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-9937-4: Create a pagefile"
	 	{
	 	 	Policy = 'Create_a_pagefile'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10369-7: Bypass traverse checking"
	 	{
	 	 	Policy = 'Bypass_traverse_checking'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS', 'BUILTIN\Backup Operators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-10232-7: Act as part of the operating system"
	 	{
	 	 	Policy = 'Act_as_part_of_the_operating_system'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	}
}