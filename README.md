# 🛡️ AdminSDHolder Cleanup Tool

A robust, language-agnostic PowerShell script to audit and remediate orphaned `AdminCount=1` accounts in Active Directory.

This tool resolves the classic **AdminSDHolder** bug where Active Directory fails to clean up user permissions and the `AdminCount` attribute after removing them from a highly privileged group. This commonly leads to false positives in security audits like PingCastle or BloodHound and prevents Helpdesk teams from managing standard user accounts.

## ✨ Why this script is superior

Most existing AdminSDHolder cleanup scripts rely on hardcoded group names (e.g., "Domain Admins"). **This will fail** on non-English Active Directory environments (like "Admins du domaine" in French or "Admins. del dominio" in Spanish).

This script is **100% universal** and unbreakable:
- 🌍 **Language-Agnostic:** It dynamically queries the Domain SID and uses **Well-Known RIDs** (Relative Identifiers like `-512`, `-500`) to find privileged groups regardless of the OS language.
- 🛡️ **Failsafe Design:** Hardcoded SID protections for critical built-in accounts (`krbtgt`, `Administrator`).
- 🔍 **Audit First:** Runs in `-AuditOnly` mode by default to prevent accidental modifications to your Active Directory.

## 🚀 Usage

Download the `Invoke-AdminSDHolderCleanup.ps1` script and run it on a domain-joined machine with Active Directory PowerShell modules installed (RSAT).

### 1. Audit Mode (Default)
Run the script to identify legitimate administrators vs. orphaned "false positive" accounts. No changes will be made to the AD.

```powershell
.\Invoke-AdminSDHolderCleanup.ps1 -AuditOnly
```

### 2. Remediation Mode
Run the script to actively clean the orphaned accounts. It will clear the AdminCount attribute and restore standard ACL inheritance. It will ask for confirmation before modifying objects.

```powershell
.\Invoke-AdminSDHolderCleanup.ps1 -Remediate
```

### 🧠 How it works
When a user is added to a privileged AD group, the SDProp background process:

1. Sets the AdminCount attribute to 1.
2. Disables ACL inheritance on the user object, applying a highly restrictive Security Descriptor.
When the user is later removed from the privileged group, AD does not revert these changes.

This script fixes this by:

1. Dynamically resolving all Protected Groups via their SIDs.
2. Finding all users with AdminCount=1.
3. Checking if they currently belong to any protected group (Direct MemberOf or Primary Group).
4. For orphaned accounts, it resets AdminCount to $null (0) and uses SetAccessRuleProtection($false, $false) to restore ACL inheritance, giving Helpdesk their management rights back.

### 📝 Requirements
Active Directory PowerShell Module (RSAT)
Domain Admin or equivalent rights (for the -Remediate switch)
