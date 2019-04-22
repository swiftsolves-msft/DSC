       
Configuration SecurityBaselineConfigurationWS2012R2
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node localhost
	{
	 	Registry "CCE-36173-3: Network security: LAN Manager authentication level"
	 	{
	 	 	ValueName = 'LmCompatibilityLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 5

	 	}

	 	Registry "CCE-37035-3: Network security: Allow LocalSystem NULL session fallback"
	 	{
	 	 	ValueName = 'allownullsessionfallback'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37863-8: Microsoft network client: Send unencrypted password to third-party SMB servers"
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

	 	Registry "CCE-38341-4: Network security: Allow Local System to use computer identity for NTLM"
	 	{
	 	 	ValueName = 'UseMachineId'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36326-7: Network security: Do not store LAN Manager hash value on next password change"
	 	{
	 	 	ValueName = 'NoLMHash'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37835-6: Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"
	 	{
	 	 	ValueName = 'NTLMMinServerSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-38333-1: Interactive logon: Smart card removal behavior"
	 	{
	 	 	ValueName = 'scremoveoption'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '1'

	 	}

	 	Registry "CCE-37553-5: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
	 	{
	 	 	ValueName = 'NTLMMinClientSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-37439-7: Interactive logon: Number of previous logons to cache (in case domain controller is not available)"
	 	{
	 	 	ValueName = 'cachedlogonscount'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '4'

	 	}

	 	Registry "CCE-36148-5: Network access: Let Everyone permissions apply to anonymous users"
	 	{
	 	 	ValueName = 'EveryoneIncludesAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-36077-6: Network access: Do not allow anonymous enumeration of SAM accounts and shares"
	 	{
	 	 	ValueName = 'RestrictAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36316-8: Network access: Do not allow anonymous enumeration of SAM accounts"
	 	{
	 	 	ValueName = 'RestrictAnonymousSAM'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-38335-6: Shutdown: Clear virtual memory pagefile"
	 	{
	 	 	ValueName = 'ClearPageFileAtShutdown'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-36788-8: Shutdown: Allow system to be shut down without having to log on"
	 	{
	 	 	ValueName = 'ShutdownWithoutLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37885-1: System objects: Require case insensitivity for non-Windows subsystems"
	 	{
	 	 	ValueName = 'ObCaseInsensitive'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37623-6: Network access: Sharing and security model for local accounts"
	 	{
	 	 	ValueName = 'ForceGuest'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37637-6: Interactive logon: Do not require CTRL+ALT+DEL"
	 	{
	 	 	ValueName = 'DisableCAD'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37701-0: Devices: Allowed to format and eject removable media"
	 	{
	 	 	ValueName = 'AllocateDASD'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-37172-4: System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies"
	 	{
	 	 	ValueName = 'AuthenticodeEnabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37067-6: MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)"
	 	{
	 	 	ValueName = 'AutoAdminLogon'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-36351-5: MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)"
	 	{
	 	 	ValueName = 'SafeDllSearchMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37624-4: Recovery console: Allow automatic administrative logon"
	 	{
	 	 	ValueName = 'securitylevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-36021-4: Network access: Restrict anonymous access to Named Pipes and Shares"
	 	{
	 	 	ValueName = 'restrictnullsessaccess'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37307-6: Recovery console: Allow floppy copy and access to all drives and all folders"
	 	{
	 	 	ValueName = 'setcommand'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37850-5: Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
	 	{
	 	 	ValueName = 'scenoapplylegacyauditpolicy'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37993-3: MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)"
	 	{
	 	 	ValueName = 'ScreenSaverGracePeriod'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '5'

	 	}

	 	Registry "CCE-38235-8: Interactive logon: Machine inactivity limit"
	 	{
	 	 	ValueName = 'InactivityTimeoutSecs'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 900

	 	}

	 	Registry "CCE-37972-7: Microsoft network server: Disconnect clients when logon hours expire"
	 	{
	 	 	ValueName = 'enableforcedlogoff'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36056-0: Interactive logon: Do not display last user name"
	 	{
	 	 	ValueName = 'DontDisplayLastUserName'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36264-0: Interactive logon: Machine account lockout threshold"
	 	{
	 	 	ValueName = 'MaxDevicePasswordFailedAttempts'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 10

	 	}

	 	Registry "CCE-37942-0: Devices: Prevent users from installing printer drivers"
	 	{
	 	 	ValueName = 'AddPrinterDrivers'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37614-5: Domain member: Require strong (Windows 2000 or later) session key"
	 	{
	 	 	ValueName = 'requirestrongkey'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37859-6: Windows Firewall: Domain: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37860-4: Windows Firewall: Domain: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-38239-0: Windows Firewall: Private: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36871-2: MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-36063-6: Windows Firewall: Private: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37134-4: Windows Firewall: Private: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37861-2: Windows Firewall: Public: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36268-1: Windows Firewall: Public: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37862-0: Windows Firewall: Public: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-38332-3: Windows Firewall: Private: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-36146-9: Windows Firewall: Domain: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-36062-8: Windows Firewall: Domain: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36324-2: Windows Firewall: Public: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-38040-2: Windows Firewall: Domain: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37621-0: Windows Firewall: Private: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-36535-3: MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-38041-0: Windows Firewall: Domain: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-38043-6: Windows Firewall: Public: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37434-8: Windows Firewall: Public: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37438-9: Windows Firewall: Private: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36494-3: User Account Control: Admin Approval Mode for the Built-in Administrator account"
	 	{
	 	 	ValueName = 'FilterAdministratorToken'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37057-7: User Account Control: Only elevate UIAccess applications that are installed in secure locations"
	 	{
	 	 	ValueName = 'EnableSecureUIAPaths'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37029-6: User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorAdmin'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-36863-9: User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop"
	 	{
	 	 	ValueName = 'EnableUIADesktopToggle'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37064-3: User Account Control: Virtualize file and registry write failures to per-user locations"
	 	{
	 	 	ValueName = 'EnableVirtualization'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36866-2: User Account Control: Switch to the secure desktop when prompting for elevation"
	 	{
	 	 	ValueName = 'PromptOnSecureDesktop'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36869-6: User Account Control: Run all administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'EnableLUA'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36864-7: User Account Control: Behavior of the elevation prompt for standard users"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorUser'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37644-2: System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)"
	 	{
	 	 	ValueName = 'ProtectionMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36533-8: User Account Control: Detect application installations and prompt for elevation"
	 	{
	 	 	ValueName = 'EnableInstallerDetection'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36269-9: Microsoft network client: Digitally sign communications (if server agrees)"
	 	{
	 	 	ValueName = 'EnableSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36858-9: Network security: LDAP client signing requirements"
	 	{
	 	 	ValueName = 'LDAPClientIntegrity'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LDAP'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36325-9: Microsoft network client: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'RequireSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37864-6: Microsoft network server: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'requiresecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37222-7: Domain member: Digitally sign secure channel data (when possible)"
	 	{
	 	 	ValueName = 'signsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36142-8: Domain member: Digitally encrypt or sign secure channel data (always)"
	 	{
	 	 	ValueName = 'requiresignorseal'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-35988-5: Microsoft network server: Digitally sign communications (if client agrees)"
	 	{
	 	 	ValueName = 'enablesecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37130-2: Domain member: Digitally encrypt secure channel data (when possible)"
	 	{
	 	 	ValueName = 'sealsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-36880-3: MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"
	 	{
	 	 	ValueName = 'WarningLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
	 	 	ValueData = 90

	 	}

	 	Registry "CCE-35907-5: Audit: Shut down system immediately if unable to log security audits"
	 	{
	 	 	ValueName = 'crashonauditfail'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37615-2: Accounts: Limit local account use of blank passwords to console logon only"
	 	{
	 	 	ValueName = 'LimitBlankPasswordUse'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-37508-9: Domain member: Disable machine account password changes"
	 	{
	 	 	ValueName = 'disablepasswordchange'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-37622-8: Interactive logon: Prompt user to change password before expiration"
	 	{
	 	 	ValueName = 'passwordexpirywarning'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 14

	 	}

	 	AuditPolicySubCategory "CCE-37853-9: Audit Policy: System: IPsec Driver (Success)"
	 	{
	 	 	Name = 'IPsec Driver'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-37853-9: Audit Policy: System: IPsec Driver (Failure)"
	 	{
	 	 	Name = 'IPsec Driver'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-36144-4: Audit Policy: System: Security System Extension (Success)"
	 	{
	 	 	Name = 'Security System Extension'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-36144-4: Audit Policy: System: Security System Extension (Failure)"
	 	{
	 	 	Name = 'Security System Extension'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-38034-5: Audit Policy: Account Management: Security Group Management (Success)"
	 	{
	 	 	Name = 'Security Group Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-38034-5: Audit Policy: Account Management: Security Group Management (Failure)"
	 	{
	 	 	Name = 'Security Group Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-37855-4: Audit Policy: Account Management: Other Account Management Events (Success)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-37855-4: Audit Policy: Account Management: Other Account Management Events (Failure)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-38114-5: Audit Policy: System: Security State Change (Success)"
	 	{
	 	 	Name = 'Security State Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-38114-5: Audit Policy: System: Security State Change (Failure)"
	 	{
	 	 	Name = 'Security State Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-36059-4: Audit Policy: Detailed Tracking: Process Creation"
	 	{
	 	 	Name = 'Process Creation'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-38030-3: Audit Policy: System: Other System Events (Success)"
	 	{
	 	 	Name = 'Other System Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-38030-3: Audit Policy: System: Other System Events (Failure)"
	 	{
	 	 	Name = 'Other System Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-37133-6: Audit Policy: Logon-Logoff: Account Lockout"
	 	{
	 	 	Name = 'Account Lockout'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-38028-7: Audit Policy: Policy Change: Audit Policy Change (Success)"
	 	{
	 	 	Name = 'Audit Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-38028-7: Audit Policy: Policy Change: Audit Policy Change (Failure)"
	 	{
	 	 	Name = 'Audit Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-36266-5: Audit Policy: Logon-Logoff: Special Logon"
	 	{
	 	 	Name = 'Special Logon'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-37856-2: Audit Policy: Account Management: User Account Management (Success)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-37856-2: Audit Policy: Account Management: User Account Management (Failure)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-37741-6: Audit Policy: Account Logon: Credential Validation (Success)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-37741-6: Audit Policy: Account Logon: Credential Validation (Failure)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-38036-0: Audit Policy: Logon-Logoff: Logon (Success)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-38036-0: Audit Policy: Logon-Logoff: Logon (Failure)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-38004-8: Audit Policy: Account Management: Computer Account Management"
	 	{
	 	 	Name = 'Computer Account Management'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-36267-3: Audit Policy: Privilege Use: Sensitive Privilege Use (Success)"
	 	{
	 	 	Name = 'Sensitive Privilege Use'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-36267-3: Audit Policy: Privilege Use: Sensitive Privilege Use (Failure)"
	 	{
	 	 	Name = 'Sensitive Privilege Use'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-38237-4: Audit Policy: Logon-Logoff: Logoff"
	 	{
	 	 	Name = 'Logoff'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubcategory "CCE-38327-3: Audit Policy: Policy Change: Authentication Policy Change"
	 	{
	 	 	Name = 'Authentication Policy Change'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-37132-8: Audit Policy: System: System Integrity (Success)"
	 	{
	 	 	Name = 'System Integrity'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-37132-8: Audit Policy: System: System Integrity (Failure)"
	 	{
	 	 	Name = 'System Integrity'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	UserRightsAssignment "CCE-37453-8: Create global objects"
	 	{
	 	 	Policy = 'Create_global_objects'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-35818-4: Access this computer from the network"
	 	{
	 	 	Policy = 'Access_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36054-5: Modify an object label"
	 	{
	 	 	Policy = 'Modify_an_object_label'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-37639-2: Generate security audits"
	 	{
	 	 	Policy = 'Generate_security_audits'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-38326-5: Increase scheduling priority"
	 	{
	 	 	Policy = 'Increase_scheduling_priority'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37877-8: Force shutdown from a remote system"
	 	{
	 	 	Policy = 'Force_shutdown_from_a_remote_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37072-6: Allow log on through Remote Desktop Services"
	 	{
	 	 	Policy = 'Allow_log_on_through_Remote_Desktop_Services'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37452-0: Change the system time"
	 	{
	 	 	Policy = 'Change_the_system_time'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-35821-8: Create a pagefile"
	 	{
	 	 	Policy = 'Create_a_pagefile'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37131-0: Profile single process"
	 	{
	 	 	Policy = 'Profile_single_process'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36923-1: Deny log on as a batch job"
	 	{
	 	 	Policy = 'Deny_log_on_as_a_batch_job'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36876-1: Act as part of the operating system"
	 	{
	 	 	Policy = 'Act_as_part_of_the_operating_system'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-37700-2: Change the time zone"
	 	{
	 	 	Policy = 'Change_the_time_zone'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36495-0: Lock pages in memory"
	 	{
	 	 	Policy = 'Lock_pages_in_memory'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-37056-9: Access Credential Manager as a trusted caller"
	 	{
	 	 	Policy = 'Access_Credential_Manager_as_a_trusted_caller'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-36861-3: Create a token object"
	 	{
	 	 	Policy = 'Create_a_token_object'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-37075-9: Debug programs"
	 	{
	 	 	Policy = 'Debug_programs'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36877-9: Deny log on as a service"
	 	{
	 	 	Policy = 'Deny_log_on_as_a_service'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37954-5: Deny access to this computer from the network"
	 	{
	 	 	Policy = 'Deny_access_to_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Guests', '[Local Account|Administrator]'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-35912-5: Back up files and directories"
	 	{
	 	 	Policy = 'Back_up_files_and_directories'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-38328-1: Shut down the system"
	 	{
	 	 	Policy = 'Shut_down_the_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37146-8: Deny log on locally"
	 	{
	 	 	Policy = 'Deny_log_on_locally'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37430-6: Replace a process level token"
	 	{
	 	 	Policy = 'Replace_a_process_level_token'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36867-0: Deny log on through Remote Desktop Services"
	 	{
	 	 	Policy = 'Deny_log_on_through_Remote_Desktop_Services'
	 	 	Identity = @('BUILTIN\Guests', '[Local Account]'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-38113-7: Modify firmware environment values"
	 	{
	 	 	Policy = 'Modify_firmware_environment_values'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37659-0: Allow log on locally"
	 	{
	 	 	Policy = 'Allow_log_on_locally'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37613-7: Restore files and directories"
	 	{
	 	 	Policy = 'Restore_files_and_directories'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36143-6: Perform volume maintenance tasks"
	 	{
	 	 	Policy = 'Perform_volume_maintenance_tasks'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-35906-7: Manage auditing and security log"
	 	{
	 	 	Policy = 'Manage_auditing_and_security_log'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36860-5: Enable computer and user accounts to be trusted for delegation"
	 	{
	 	 	Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-37106-2: Impersonate a client after authentication"
	 	{
	 	 	Policy = 'Impersonate_a_client_after_authentication'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36318-4: Load and unload device drivers"
	 	{
	 	 	Policy = 'Load_and_unload_device_drivers'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-38325-7: Take ownership of files or other objects"
	 	{
	 	 	Policy = 'Take_ownership_of_files_or_other_objects'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-37071-8: Adjust memory quotas for a process"
	 	{
	 	 	Policy = 'Adjust_memory_quotas_for_a_process'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-35823-4: Create symbolic links"
	 	{
	 	 	Policy = 'Create_symbolic_links'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-36532-0: Create permanent shared objects"
	 	{
	 	 	Policy = 'Create_permanent_shared_objects'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	}
}
