       
Configuration SecurityBaselineConfigurationWS2012
{

	Import-DSCResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
	Node localhost
	{
	 	Registry "CCE-22742-1: Network access: Sharing and security model for local accounts"
	 	{
	 	 	ValueName = 'ForceGuest'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24633-0: System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)"
	 	{
	 	 	ValueName = 'ProtectionMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24968-0: MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-24738-7: Windows Firewall: Private: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24907-8: Windows Firewall: Private: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-22773-6: Windows Firewall: Public: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23894-9: Windows Firewall: Public: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25350-0: Windows Firewall: Domain: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24663-7: Windows Firewall: Private: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24639-7: Windows Firewall: Domain: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24624-9: Windows Firewall: Private: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24810-4: Windows Firewall: Public: Apply local firewall rules"
	 	{
	 	 	ValueName = 'AllowLocalPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25111-6: Windows Firewall: Public: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25534-9: Windows Firewall: Domain: Apply local connection security rules"
	 	{
	 	 	ValueName = 'AllowLocalIPsecPolicyMerge'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25607-3: Windows Firewall: Private: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24936-7: Windows Firewall: Domain: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24452-5: MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)"
	 	{
	 	 	ValueName = 'DisableIPSourceRouting'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters'
	 	 	ValueData = 2

	 	}

	 	Registry "CCE-23892-3: Windows Firewall: Public: Outbound connections"
	 	{
	 	 	ValueName = 'DefaultOutboundAction'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-23615-8: Windows Firewall: Private: Firewall state"
	 	{
	 	 	ValueName = 'EnableFirewall'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25213-0: Windows Firewall: Domain: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-23900-4: Windows Firewall: Public: Display a notification"
	 	{
	 	 	ValueName = 'DisableNotifications'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-25359-1: Windows Firewall: Domain: Allow unicast response"
	 	{
	 	 	ValueName = 'DisableUnicastResponsesToMulticastBroadcast'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24252-9: Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
	 	{
	 	 	ValueName = 'scenoapplylegacyauditpolicy'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25198-3: Domain member: Require strong (Windows 2000 or later) session key"
	 	{
	 	 	ValueName = 'requirestrongkey'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24809-6: Interactive logon: Machine account lockout threshold"
	 	{
	 	 	ValueName = 'MaxDevicePasswordFailedAttempts'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 10

	 	}

	 	Registry "CCE-24154-7: Interactive logon: Smart card removal behavior"
	 	{
	 	 	ValueName = 'scremoveoption'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '1'

	 	}

	 	Registry "CCE-24993-8: MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)"
	 	{
	 	 	ValueName = 'ScreenSaverGracePeriod'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-24148-9: Microsoft network server: Disconnect clients when logon hours expire"
	 	{
	 	 	ValueName = 'enableforcedlogoff'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24748-6: Interactive logon: Do not display last user name"
	 	{
	 	 	ValueName = 'DontDisplayLastUserName'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23043-3: Interactive logon: Machine inactivity limit"
	 	{
	 	 	ValueName = 'InactivityTimeoutSecs'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 900

	 	}

	 	Registry "CCE-23716-4: Microsoft network server: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'requiresecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24969-8: Microsoft network client: Digitally sign communications (always)"
	 	{
	 	 	ValueName = 'RequireSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24812-0: Domain member: Digitally sign secure channel data (when possible)"
	 	{
	 	 	ValueName = 'signsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23921-0: System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"
	 	{
	 	 	ValueName = 'Enabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24465-7: Domain member: Digitally encrypt or sign secure channel data (always)"
	 	{
	 	 	ValueName = 'requiresignorseal'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25264-3: Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"
	 	{
	 	 	ValueName = 'NTLMMinServerSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-24740-3: Microsoft network client: Digitally sign communications (if server agrees)"
	 	{
	 	 	ValueName = 'EnableSecuritySignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24751-0: Microsoft network client: Send unencrypted password to third-party SMB servers"
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

	 	Registry "CCE-24414-5: Domain member: Digitally encrypt secure channel data (when possible)"
	 	{
	 	 	ValueName = 'sealsecurechannel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24783-3: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
	 	{
	 	 	ValueName = 'NTLMMinClientSec'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0'
	 	 	ValueData = 537395200

	 	}

	 	Registry "CCE-24354-3: Microsoft network server: Digitally sign communications (if client agrees)"
	 	{
	 	 	ValueName = 'enablesecuritysignature'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23462-5: MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)"
	 	{
	 	 	ValueName = 'SafeDllSearchMode'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25274-2: Recovery console: Allow floppy copy and access to all drives and all folders"
	 	{
	 	 	ValueName = 'setcommand'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24470-7: Recovery console: Allow automatic administrative logon"
	 	{
	 	 	ValueName = 'securitylevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-25217-1: Devices: Allowed to format and eject removable media"
	 	{
	 	 	ValueName = 'AllocateDASD'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-24927-6: MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)"
	 	{
	 	 	ValueName = 'AutoAdminLogon'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '0'

	 	}

	 	Registry "CCE-24939-1: System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies"
	 	{
	 	 	ValueName = 'AuthenticodeEnabled'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25100-9: Shutdown: Allow system to be shut down without having to log on"
	 	{
	 	 	ValueName = 'ShutdownWithoutLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-25120-7: Shutdown: Clear virtual memory pagefile"
	 	{
	 	 	ValueName = 'ClearPageFileAtShutdown'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24774-2: Network access: Do not allow anonymous enumeration of SAM accounts and shares"
	 	{
	 	 	ValueName = 'RestrictAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24870-8: System objects: Require case insensitivity for non-Windows subsystems"
	 	{
	 	 	ValueName = 'ObCaseInsensitive'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24564-7: Network access: Restrict anonymous access to Named Pipes and Shares"
	 	{
	 	 	ValueName = 'restrictnullsessaccess'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25803-8: Interactive logon: Do not require CTRL+ALT+DEL"
	 	{
	 	 	ValueName = 'DisableCAD'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-23082-1: Network access: Do not allow anonymous enumeration of SAM accounts"
	 	{
	 	 	ValueName = 'RestrictAnonymousSAM'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23807-1: Network access: Let Everyone permissions apply to anonymous users"
	 	{
	 	 	ValueName = 'EveryoneIncludesAnonymous'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24650-4: Network security: LAN Manager authentication level"
	 	{
	 	 	ValueName = 'LmCompatibilityLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 5

	 	}

	 	Registry "CCE-25245-2: Network security: LDAP client signing requirements"
	 	{
	 	 	ValueName = 'LDAPClientIntegrity'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\LDAP'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24150-5: Network security: Do not store LAN Manager hash value on next password change"
	 	{
	 	 	ValueName = 'NoLMHash'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25643-8: Interactive logon: Require Domain Controller authentication to unlock workstation"
	 	{
	 	 	ValueName = 'ForceUnlockLogon'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24264-4: Interactive logon: Number of previous logons to cache (in case domain controller is not available)"
	 	{
	 	 	ValueName = 'cachedlogonscount'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = '4'

	 	}

	 	Registry "CCE-23656-2: User Account Control: Switch to the secure desktop when prompting for elevation"
	 	{
	 	 	ValueName = 'PromptOnSecureDesktop'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25471-4: User Account Control: Only elevate UIAccess applications that are installed in secure locations"
	 	{
	 	 	ValueName = 'EnableSecureUIAPaths'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24519-1: User Account Control: Behavior of the elevation prompt for standard users"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorUser'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 3

	 	}

	 	Registry "CCE-23877-4: User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'ConsentPromptBehaviorAdmin'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 5

	 	}

	 	Registry "CCE-23295-9: User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop"
	 	{
	 	 	ValueName = 'EnableUIADesktopToggle'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-23880-8: User Account Control: Only elevate executables that are signed and validated"
	 	{
	 	 	ValueName = 'ValidateAdminCodeSignatures'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-24498-8: User Account Control: Detect application installations and prompt for elevation"
	 	{
	 	 	ValueName = 'EnableInstallerDetection'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23653-9: User Account Control: Run all administrators in Admin Approval Mode"
	 	{
	 	 	ValueName = 'EnableLUA'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24134-9: User Account Control: Admin Approval Mode for the Built-in Administrator account"
	 	{
	 	 	ValueName = 'FilterAdministratorToken'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24231-3: User Account Control: Virtualize file and registry write failures to per-user locations"
	 	{
	 	 	ValueName = 'EnableVirtualization'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-25176-9: Devices: Prevent users from installing printer drivers"
	 	{
	 	 	ValueName = 'AddPrinterDrivers'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-24243-8: Domain member: Disable machine account password changes"
	 	{
	 	 	ValueName = 'disablepasswordchange'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-23704-0: Interactive logon: Prompt user to change password before expiration"
	 	{
	 	 	ValueName = 'passwordexpirywarning'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
	 	 	ValueData = 14

	 	}

	 	Registry "CCE-25589-3: Accounts: Limit local account use of blank passwords to console logon only"
	 	{
	 	 	ValueName = 'LimitBlankPasswordUse'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 1

	 	}

	 	Registry "CCE-23782-6: Control Event Log behavior when the log file reaches its maximum size"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\System'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-23646-3: Control Event Log behavior when the log file reaches its maximum size"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application'
	 	 	ValueData = 'Disabled'

	 	}

	 	Registry "CCE-23988-9: Audit: Shut down system immediately if unable to log security audits"
	 	{
	 	 	ValueName = 'crashonauditfail'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\System\CurrentControlSet\Control\Lsa'
	 	 	ValueData = 0

	 	}

	 	Registry "CCE-25110-8: MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"
	 	{
	 	 	ValueName = 'WarningLevel'
	 	 	ValueType = 'DWORD'
	 	 	Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
	 	 	ValueData = 90

	 	}

	 	Registry "CCE-24583-7: Control Event Log behavior when the log file reaches its maximum size"
	 	{
	 	 	ValueName = 'Retention'
	 	 	ValueType = 'String'
	 	 	Key = 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security'
	 	 	ValueData = 'Disabled'

	 	}

	 	AuditPolicySubCategory "CCE-23955-8: Audit Policy: Account Management: Security Group Management (Success)"
	 	{
	 	 	Name = 'Security Group Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-23955-8: Audit Policy: Account Management: Security Group Management (Failure)"
	 	{
	 	 	Name = 'Security Group Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-25178-5: Audit Policy: System: Security State Change (Success)"
	 	{
	 	 	Name = 'Security State Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25178-5: Audit Policy: System: Security State Change (Failure)"
	 	{
	 	 	Name = 'Security State Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-25674-3: Audit Policy: Policy Change: Authentication Policy Change"
	 	{
	 	 	Name = 'Authentication Policy Change'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubcategory "CCE-23482-3: Audit Policy: Account Management: Computer Account Management"
	 	{
	 	 	Name = 'Computer Account Management'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-25093-6: Audit Policy: System: System Integrity (Success)"
	 	{
	 	 	Name = 'System Integrity'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25093-6: Audit Policy: System: System Integrity (Failure)"
	 	{
	 	 	Name = 'System Integrity'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-23670-3: Audit Policy: Logon-Logoff: Logon (Success)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-23670-3: Audit Policy: Logon-Logoff: Logon (Failure)"
	 	{
	 	 	Name = 'Logon'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-25123-1: Audit Policy: Account Management: User Account Management (Success)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25123-1: Audit Policy: Account Management: User Account Management (Failure)"
	 	{
	 	 	Name = 'User Account Management'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-24187-7: Audit Policy: Logon-Logoff: Special Logon"
	 	{
	 	 	Name = 'Special Logon'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubCategory "CCE-25088-6: Audit Policy: Account Logon: Credential Validation (Success)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25088-6: Audit Policy: Account Logon: Credential Validation (Failure)"
	 	{
	 	 	Name = 'Credential Validation'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-24691-8: Audit Policy: Privilege Use: Sensitive Privilege Use (Success)"
	 	{
	 	 	Name = 'Sensitive Privilege Use'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-24691-8: Audit Policy: Privilege Use: Sensitive Privilege Use (Failure)"
	 	{
	 	 	Name = 'Sensitive Privilege Use'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-24588-6: Audit Policy: Account Management: Other Account Management Events (Success)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-24588-6: Audit Policy: Account Management: Other Account Management Events (Failure)"
	 	{
	 	 	Name = 'Other Account Management Events'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-25372-4: Audit Policy: System: IPsec Driver (Success)"
	 	{
	 	 	Name = 'IPsec Driver'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25372-4: Audit Policy: System: IPsec Driver (Failure)"
	 	{
	 	 	Name = 'IPsec Driver'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-25527-3: Audit Policy: System: Security System Extension (Success)"
	 	{
	 	 	Name = 'Security System Extension'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25527-3: Audit Policy: System: Security System Extension (Failure)"
	 	{
	 	 	Name = 'Security System Extension'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubCategory "CCE-25035-7: Audit Policy: Policy Change: Audit Policy Change (Success)"
	 	{
	 	 	Name = 'Audit Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Success'

	 	}

 	 	AuditPolicySubCategory "CCE-25035-7: Audit Policy: Policy Change: Audit Policy Change (Failure)"
	 	{
	 	 	Name = 'Audit Policy Change'
	 	 	Ensure = 'Present'
	 	 	AuditFlag = 'Failure'

	 	}

	 	AuditPolicySubcategory "CCE-25461-5: Audit Policy: Detailed Tracking: Process Creation"
	 	{
	 	 	Name = 'Process Creation'
	 	 	AuditFlag = 'Success'

	 	}

	 	AuditPolicySubcategory "CCE-24901-1: Audit Policy: Logon-Logoff: Logoff"
	 	{
	 	 	Name = 'Logoff'
	 	 	AuditFlag = 'Success'

	 	}

	 	UserRightsAssignment "CCE-23456-7: Manage auditing and security log"
	 	{
	 	 	Policy = 'Manage_auditing_and_security_log'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24162-0: Increase a process working set"
	 	{
	 	 	Policy = 'Increase_a_process_working_set'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24555-5: Replace a process level token"
	 	{
	 	 	Policy = 'Replace_a_process_level_token'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24682-7: Modify an object label"
	 	{
	 	 	Policy = 'Modify_an_object_label'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-23939-2: Create a token object"
	 	{
	 	 	Policy = 'Create_a_token_object'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-25683-4: Access Credential Manager as a trusted caller"
	 	{
	 	 	Policy = 'Access_Credential_Manager_as_a_trusted_caller'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-24406-1: Allow log on through Remote Desktop Services"
	 	{
	 	 	Policy = 'Allow_log_on_through_Remote_Desktop_Services'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-23972-3: Create a pagefile"
	 	{
	 	 	Policy = 'Create_a_pagefile'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24734-6: Force shutdown from a remote system"
	 	{
	 	 	Policy = 'Force_shutdown_from_a_remote_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24460-8: Deny log on locally"
	 	{
	 	 	Policy = 'Deny_log_on_locally'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24911-0: Increase scheduling priority"
	 	{
	 	 	Policy = 'Increase_scheduling_priority'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24779-1: Load and unload device drivers"
	 	{
	 	 	Policy = 'Load_and_unload_device_drivers'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25271-8: Bypass traverse checking"
	 	{
	 	 	Policy = 'Bypass_traverse_checking'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS', 'BUILTIN\Backup Operators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25518-2: Restore files and directories"
	 	{
	 	 	Policy = 'Restore_files_and_directories'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24185-1: Change the system time"
	 	{
	 	 	Policy = 'Change_the_system_time'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-23850-1: Create global objects"
	 	{
	 	 	Policy = 'Create_global_objects'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25070-4: Perform volume maintenance tasks"
	 	{
	 	 	Policy = 'Perform_volume_maintenance_tasks'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24550-6: Remove computer from docking station"
	 	{
	 	 	Policy = 'Remove_computer_from_docking_station'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25215-5: Deny log on as a batch job"
	 	{
	 	 	Policy = 'Deny_log_on_as_a_batch_job'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25228-8: Allow log on locally"
	 	{
	 	 	Policy = 'Allow_log_on_locally'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25270-0: Enable computer and user accounts to be trusted for delegation"
	 	{
	 	 	Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-23723-0: Create permanent shared objects"
	 	{
	 	 	Policy = 'Create_permanent_shared_objects'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-23648-9: Debug programs"
	 	{
	 	 	Policy = 'Debug_programs'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-23844-4: Profile single process"
	 	{
	 	 	Policy = 'Profile_single_process'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25380-7: Back up files and directories"
	 	{
	 	 	Policy = 'Back_up_files_and_directories'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24938-3: Access this computer from the network"
	 	{
	 	 	Policy = 'Access_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\AUTHENTICATED USERS'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25112-4: Adjust memory quotas for a process"
	 	{
	 	 	Policy = 'Adjust_memory_quotas_for_a_process'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-23500-2: Shut down the system"
	 	{
	 	 	Policy = 'Shut_down_the_system'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24549-8: Create symbolic links"
	 	{
	 	 	Policy = 'Create_symbolic_links'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24632-2: Change the time zone"
	 	{
	 	 	Policy = 'Change_the_time_zone'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24188-5: Deny access to this computer from the network"
	 	{
	 	 	Policy = 'Deny_access_to_this_computer_from_the_network'
	 	 	Identity = @('BUILTIN\Guests'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-24477-2: Impersonate a client after authentication"
	 	{
	 	 	Policy = 'Impersonate_a_client_after_authentication'
	 	 	Identity = @('BUILTIN\Administrators', 'NT AUTHORITY\SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25533-1: Modify firmware environment values"
	 	{
	 	 	Policy = 'Modify_firmware_environment_values'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-23829-5: Lock pages in memory"
	 	{
	 	 	Policy = 'Lock_pages_in_memory'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-25043-1: Act as part of the operating system"
	 	{
	 	 	Policy = 'Act_as_part_of_the_operating_system'
	 	 	Force = $True
	 	 	Identity = ''

	 	}

	 	UserRightsAssignment "CCE-24048-1: Generate security audits"
	 	{
	 	 	Policy = 'Generate_security_audits'
	 	 	Identity = @('NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE'
	 	 	)

	 	}

	 	UserRightsAssignment "CCE-25585-1: Take ownership of files or other objects"
	 	{
	 	 	Policy = 'Take_ownership_of_files_or_other_objects'
	 	 	Identity = @('BUILTIN\Administrators'
	 	 	)

	 	}

	}
}
