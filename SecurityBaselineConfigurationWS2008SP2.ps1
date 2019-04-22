       
Configuration SecurityBaselineConfigurationWS2008SP2
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node localhost
	{
	 	Registry "CCE-1868-9: Domain member: Digitally encrypt secure channel data (when possible)"
	 	{
	 	 	ValueName = 'sealsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-1767-3: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
	 	{
	 	 	ValueName = 'NTLMMinClientSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-2410-9: Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"
	 	{
	 	 	ValueName = 'NTLMMinServerSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-2272-3: Microsoft network client: Send unencrypted password to third-party SMB servers"
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

	 	Registry "CCE-2203-8: Domain member: Digitally encrypt or sign secure channel data (always)"
	 	{
	 	 	ValueName = 'requiresignorseal'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2261-6: System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"
	 	{
	 	 	ValueName = 'Enabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2362-2: Domain member: Digitally sign secure channel data (when possible)"
	 	{
	 	 	ValueName = 'signsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-1802-8: Domain member: Require strong (Windows 2000 or later) session key"
	 	{
	 	 	ValueName = 'requirestrongkey'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2381-2: Microsoft network server: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'requiresecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2378-8: Microsoft network client: Digitally sign communications (if server agrees)"
	 	{
	 	 	ValueName = 'EnableSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2356-4: Microsoft network client: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'RequireSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2263-2: Microsoft network server: Digitally sign communications (if client agrees)"
	 	{
	 	 	ValueName = 'enablesecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2315-0: Audit: Shut down system immediately if unable to log security audits"
	 	{
	 	 	ValueName = 'crashonauditfail'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-12163-2: Retain old events"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-12284-6: Retain old events"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-13594-7: Retain old events"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-2442-2: MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"
	 	{
	 	 	ValueName = 'WarningLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
	 	 	ValueData = 90

	 	}

	 	Registry "CCE-2302-8: User Account Control: Admin Approval Mode for the Built-in Administrator account"
	 	{
	 	 	ValueName = 'FilterAdministratorToken'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2434-9: User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop"
	 	{
	 	 	ValueName = 'EnableUIADesktopToggle'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2266-5: User Account Control: Virtualize file and registry write failures to per-user locations"
	 	{
	 	 	ValueName = 'EnableVirtualization'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2451-3: System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)"
	 	{
	 	 	ValueName = 'ProtectionMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2473-7: User Account Control: Only elevate UIAccess applications that are installed in secure locations"
	 	{
	 	 	ValueName = 'EnableSecureUIAPaths'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2487-7: User Account Control: Detect application installations and prompt for elevation"
	 	{
	 	 	ValueName = 'EnableInstallerDetection'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2331-7: Interactive logon: Do not require CTRL+ALT+DEL"
	 	{
	 	 	ValueName = 'DisableCAD'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2474-5: User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorAdmin'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2478-6: User Account Control: Run all administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'EnableLUA'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2509-8: User Account Control: Only elevate executables that are signed and validated"
	 	{
	 	 	ValueName = 'ValidateAdminCodeSignatures'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2500-7: User Account Control: Switch to the secure desktop when prompting for elevation"
	 	{
	 	 	ValueName = 'PromptOnSecureDesktop'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2304-4: Network security: Do not store LAN Manager hash value on next password change"
	 	{
	 	 	ValueName = 'NoLMHash'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2364-8: Accounts: Limit local account use of blank passwords to console logon only"
	 	{
	 	 	ValueName = 'LimitBlankPasswordUse'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2256-6: Domain member: Disable machine account password changes"
	 	{
	 	 	ValueName = 'disablepasswordchange'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2324-2: Interactive logon: Prompt user to change password before expiration"
	 	{
	 	 	ValueName = 'passwordexpirywarning'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 14

	 	}

	 	Registry "CCE-2297-0: Interactive logon: Number of previous logons to cache (in case domain controller is not available)"
	 	{
	 	 	ValueName = 'cachedlogonscount'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-2346-5: Interactive logon: Require Domain Controller authentication to unlock workstation"
	 	{
	 	 	ValueName = 'ForceUnlockLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-1448-0: Interactive logon: Smart card removal behavior"
	 	{
	 	 	ValueName = 'scremoveoption'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '1'

	 	}

	 	Registry "CCE-1824-2: Network access: Let Everyone permissions apply to anonymous users"
	 	{
	 	 	ValueName = 'EveryoneIncludesAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2454-7: Network security: LAN Manager authentication level"
	 	{
	 	 	ValueName = 'LmCompatibilityLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 5

	 	}

	 	Registry "CCE-2152-7: Devices: Prevent users from installing printer drivers"
	 	{
	 	 	ValueName = 'AddPrinterDrivers'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-12706-8: Windows Firewall: Public: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-12504-7: Windows Firewall: Domain: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2404-2: MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic."
	 	{
	 	 	ValueName = 'NoDefaultExempt'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\IPSEC'
	 	 	ValueData = 3

	 	}

	 	Registry "CCE-14139-0: Windows Firewall: Public: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-1826-7: MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-11888-5: Windows Firewall: Domain: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-13615-0: Windows Firewall: Private: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-12640-9: Windows Firewall: Private: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-14271-1: Windows Firewall: Public: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2320-0: MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers"
	 	{
	 	 	ValueName = 'NoNameReleaseOnDemand'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-12973-4: Windows Firewall: Domain: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-12739-9: Windows Firewall: Private: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-5229-0: MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-13197-9: Windows Firewall: Domain: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-1470-4: MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes"
	 	{
	 	 	ValueName = 'EnableICMPRedirect'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-1800-2: MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)"
	 	{
	 	 	ValueName = 'PerformRouterDiscovery'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-12456-0: Windows Firewall: Public: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-13230-8: Windows Firewall: Private: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-13049-2: Windows Firewall: Public: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2399-4: MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds"
	 	{
	 	 	ValueName = 'KeepAliveTime'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 300000

	 	}

	 	Registry "CCE-13454-4: Windows Firewall: Private: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-5263-9: MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)"
	 	{
	 	 	ValueName = 'TcpMaxDataRetransmissions'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
	 	 	ValueData = 3

	 	}

	 	Registry "CCE-12473-5: Windows Firewall: Domain: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-13823-0: Windows Firewall: Domain: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-12990-8: Windows Firewall: Public: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-12562-5: Windows Firewall: Private: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2424-0: MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)"
	 	{
	 	 	ValueName = 'TcpMaxDataRetransmissions'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 3

	 	}

	 	Registry "CCE-2276-4: Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
	 	{
	 	 	ValueName = 'scenoapplylegacyauditpolicy'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2309-3: Recovery console: Allow automatic administrative logon"
	 	{
	 	 	ValueName = 'securitylevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2421-6: System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies"
	 	{
	 	 	ValueName = 'AuthenticodeEnabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2307-7: MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)"
	 	{
	 	 	ValueName = 'AutoAdminLogon'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-2340-8: Network access: Do not allow anonymous enumeration of SAM accounts and shares"
	 	{
	 	 	ValueName = 'RestrictAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2406-7: Network access: Sharing and security model for local accounts"
	 	{
	 	 	ValueName = 'ForceGuest'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-1553-7: Recovery console: Allow floppy copy and access to all drives and all folders"
	 	{
	 	 	ValueName = 'setcommand'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2416-6: Shutdown: Clear virtual memory pagefile"
	 	{
	 	 	ValueName = 'ClearPageFileAtShutdown'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2403-4: Shutdown: Allow system to be shut down without having to log on"
	 	{
	 	 	ValueName = 'ShutdownWithoutLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2447-1: MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)"
	 	{
	 	 	ValueName = 'SafeDllSearchMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-1962-0: Network access: Do not allow anonymous enumeration of SAM accounts"
	 	{
	 	 	ValueName = 'RestrictAnonymousSAM'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2249-1: Devices: Allow undock without having to log on"
	 	{
	 	 	ValueName = 'undockwithoutlogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-2377-0: Devices: Allowed to format and eject removable media"
	 	{
	 	 	ValueName = 'AllocateDASD'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-2429-9: System objects: Require case insensitivity for non-Windows subsystems"
	 	{
	 	 	ValueName = 'ObCaseInsensitive'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2089-1: Network access: Named Pipes that can be accessed anonymously"
	 	{
	 	 	ValueName = 'NullSessionPipes'
	 	 	ValueType = 'MultiString'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 'browser'

	 	}

	 	Registry "CCE-2361-4: Network access: Restrict anonymous access to Named Pipes and Shares"
	 	{
	 	 	ValueName = 'restrictnullsessaccess'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2199-8: Interactive logon: Do not display last user name"
	 	{
	 	 	ValueName = 'DontDisplayLastUserName'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2029-7: Microsoft network server: Disconnect clients when logon hours expire"
	 	{
	 	 	ValueName = 'enableforcedlogoff'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-2183-2: MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)"
	 	{
	 	 	ValueName = 'ScreenSaverGracePeriod'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-2327-5: Network security: LDAP client signing requirements"
	 	{
	 	 	ValueName = 'LDAPClientIntegrity'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LDAP'
	 	 	ValueData = 1

	 	}

	 	UserRightsAssignment "CCE-1834-1: Deny log on as a batch job"
	 	{
	 	 	Policy = 'Deny_log_on_as_a_batch_job'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-1843-2: Manage auditing and security log"
	 	{
	 	 	Policy = 'Manage_auditing_and_security_log'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2285-5: Bypass traverse checking"
	 	{
	 	 	Policy = 'Bypass_traverse_checking'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS', 'BUILTIN\Backup Operators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2294-7: Restore files and directories"
	 	{
	 	 	Policy = 'Restore_files_and_directories'
	 	 	Identity = @('BUILTIN\Administrators', 'BUILTIN\Backup Operators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2257-4: Modify firmware environment values"
	 	{
	 	 	Policy = 'Modify_firmware_environment_values'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2079-2: Act as part of the operating system"
	 	{
	 	 	Policy = 'Act_as_part_of_the_operating_system'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-2102-2: Deny log on through Terminal Services"
	 	{
	 	 	Policy = 'Deny_log_on_through_Remote_Desktop_Services'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2286-3: Allow log on locally"
	 	{
	 	 	Policy = 'Allow_log_on_locally'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2113-9: Profile system performance"
	 	{
	 	 	Policy = 'Profile_system_performance'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2506-4: Take ownership of files or other objects"
	 	{
	 	 	Policy = 'Take_ownership_of_files_or_other_objects'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2310-1: Debug programs"
	 	{
	 	 	Policy = 'Debug_programs'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2314-3: Deny access to this computer from the network"
	 	{
	 	 	Policy = 'Deny_access_to_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2360-6: Profile single process"
	 	{
	 	 	Policy = 'Profile_single_process'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-1527-1: Replace a process level token"
	 	{
	 	 	Policy = 'Replace_a_process_level_token'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-1944-8: Deny log on as a service"
	 	{
	 	 	Policy = 'Deny_log_on_as_a_service'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-2308-5: Allow log on through Terminal Services"
	 	{
	 	 	Policy = 'Allow_log_on_through_Remote_Desktop_Services'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2004-0: Adjust memory quotas for a process"
	 	{
	 	 	Policy = 'Adjust_memory_quotas_for_a_process'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2296-2: Deny log on locally"
	 	{
	 	 	Policy = 'Deny_log_on_locally'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-1750-9: Force shutdown from a remote system"
	 	{
	 	 	Policy = 'Force_shutdown_from_a_remote_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2290-5: Change the system time"
	 	{
	 	 	Policy = 'Change_the_system_time'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2026-3: Access Credential Manager as a trusted caller"
	 	{
	 	 	Policy = 'Access_Credential_Manager_as_a_trusted_caller'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-2075-0: Access this computer from the network"
	 	{
	 	 	Policy = 'Access_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2171-7: Change the time zone"
	 	{
	 	 	Policy = 'Change_the_time_zone'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-1328-4: Create a pagefile"
	 	{
	 	 	Policy = 'Create_a_pagefile'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2382-0: Remove computer from docking station"
	 	{
	 	 	Policy = 'Remove_computer_from_docking_station'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2129-5: Generate security audits"
	 	{
	 	 	Policy = 'Generate_security_audits'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-2078-4: Shut down the system"
	 	{
	 	 	Policy = 'Shut_down_the_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	}
}
