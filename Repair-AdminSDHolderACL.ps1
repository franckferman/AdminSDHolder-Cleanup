<#
.SYNOPSIS
    Removes unauthorized or suspicious ACL entries from the AdminSDHolder object.

.DESCRIPTION
    After running Get-AdminSDHolderACL.ps1 and identifying suspicious permissions
    (e.g., standard users with GenericAll, WriteDacl, or WriteOwner), this script
    removes those illegitimate ACL entries from the AdminSDHolder object, neutralizing
    any potential backdoor.
    
    Uses Well-Known SIDs to identify legitimate accounts. Works on any AD language.

.PARAMETER AuditOnly
    Default mode. Shows what WOULD be removed without modifying anything.

.PARAMETER Remediate
    Actively removes unauthorized ACL entries. Asks for confirmation.

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1 -AuditOnly

.EXAMPLE
    .\Repair-AdminSDHolderACL.ps1 -Remediate

.AUTHOR
    Frank Ferman
#>

param (
    [switch]$AuditOnly = $true,
    [switch]$Remediate
)

if ($Remediate) { $AuditOnly = $false }

Import-Module ActiveDirectory

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " AdminSDHolder ACL Repair Tool (Backdoor Neutralizer)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Build the list of LEGITIMATE SIDs that are allowed on AdminSDHolder
$Domain = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value
$AdminSDHolderDN = "CN=AdminSDHolder,CN=System,$($Domain.DistinguishedName)"

# Well-Known SIDs that are EXPECTED on AdminSDHolder by default
$LegitSIDs = @(
    "S-1-5-18",              # NT AUTHORITY\SYSTEM (LocalSystem)
    "S-1-5-10",              # NT AUTHORITY\SELF
    "S-1-5-11",              # NT AUTHORITY\Authenticated Users
    "S-1-1-0",               # Everyone (Tout le monde) - limited ExtendedRight only
    "S-1-5-32-544",          # BUILTIN\Administrators
    "S-1-5-32-554",          # BUILTIN\Pre-Windows 2000 Compatible Access
    "S-1-5-32-560",          # BUILTIN\Windows Authorization Access Group
    "S-1-5-32-561",          # BUILTIN\Terminal Server License Servers
    "$DomainSID-512",        # Domain Admins
    "$DomainSID-519",        # Enterprise Admins
    "$DomainSID-517"         # Cert Publishers (Éditeurs de certificats)
)

Write-Host "`n[*] Target: $AdminSDHolderDN" -ForegroundColor Yellow
Write-Host "[*] Legitimate SIDs loaded: $($LegitSIDs.Count)" -ForegroundColor Green

# 2. Retrieve the ACL
try {
    $ADObject = [ADSI]"LDAP://$AdminSDHolderDN"
    $ACL = $ADObject.ObjectSecurity
    $Rules = $ACL.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
} catch {
    Write-Host "[!] ERROR: Could not retrieve AdminSDHolder ACL: $($_.Exception.Message)" -ForegroundColor Red
    Exit
}

# 3. Identify unauthorized rules
$SuspiciousRules = @()
$LegitRules = @()

foreach ($Rule in $Rules) {
    $SID = $Rule.IdentityReference.Value
    
    if ($LegitSIDs -contains $SID) {
        $LegitRules += $Rule
    } else {
        # Resolve the SID to a human-readable name for display
        try {
            $Account = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $Account = $SID
        }
        
        $SuspiciousRules += [PSCustomObject]@{
            "Account"     = $Account
            "SID"         = $SID
            "Rights"      = $Rule.ActiveDirectoryRights.ToString()
            "Access"      = $Rule.AccessControlType.ToString()
            "RuleObject"  = $Rule
        }
    }
}

# 4. Display results
Write-Host "`n--- ACL ANALYSIS ---" -ForegroundColor Cyan
Write-Host "Legitimate ACL entries: $($LegitRules.Count)" -ForegroundColor Green
Write-Host "Suspicious ACL entries: $($SuspiciousRules.Count)" -ForegroundColor ($SuspiciousRules.Count -gt 0 ? 'Red' : 'Green')

if ($SuspiciousRules.Count -eq 0) {
    Write-Host "`n[+] AdminSDHolder ACL is CLEAN. No unauthorized entries found." -ForegroundColor Green
    Exit
}

Write-Host "`nThe following ACL entries are NOT in the default whitelist:" -ForegroundColor Red
$SuspiciousRules | Select-Object Account, SID, Rights, Access | Format-Table -AutoSize

# 5. Remediation
if ($AuditOnly) {
    Write-Host "[i] Script ran in -AuditOnly mode. No changes were made." -ForegroundColor Yellow
    Write-Host "[i] To remove these entries, run with -Remediate." -ForegroundColor Yellow
    Exit
}

if ($Remediate) {
    Write-Host "[!] WARNING: You are about to modify the AdminSDHolder Security Descriptor." -ForegroundColor Red
    Write-Host "[!] This is a CRITICAL Active Directory object. Proceed with caution." -ForegroundColor Red
    $Confirm = Read-Host "Remove $($SuspiciousRules.Count) unauthorized ACL entries? (Y/N)"
    
    if ($Confirm -match "^[Yy]$") {
        Write-Host "`n[*] Removing unauthorized ACL entries..." -ForegroundColor Cyan
        
        $SuccessCount = 0
        $FailCount = 0

        foreach ($Entry in $SuspiciousRules) {
            Write-Host "   -> Removing: $($Entry.Account) ($($Entry.Rights))... " -NoNewline
            try {
                $ACL.RemoveAccessRule($Entry.RuleObject) | Out-Null
                $SuccessCount++
                Write-Host "Removed." -ForegroundColor Green
            } catch {
                $FailCount++
                Write-Host "Failed! ($($_.Exception.Message))" -ForegroundColor Red
            }
        }

        # Commit changes
        try {
            $ADObject.CommitChanges()
            Write-Host "`n[+] Changes committed to Active Directory." -ForegroundColor Green
        } catch {
            Write-Host "`n[!] FAILED to commit changes: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        Write-Host "[*] Summary: $SuccessCount removed, $FailCount failed." -ForegroundColor ($FailCount -gt 0 ? 'Yellow' : 'Green')
    } else {
        Write-Host "`n[-] Remediation cancelled. No objects were modified." -ForegroundColor Yellow
    }
}
