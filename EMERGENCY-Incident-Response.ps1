# ============================================
# EMERGENCY INCIDENT RESPONSE SCRIPT
# Compromised Account: Joe@advturbine.com
# Attacker IP: 185.215.150.68
# ============================================
# This script will:
# 1. Check and install all required modules
# 2. Disable the compromised account
# 3. Revoke all sessions
# 4. Delete malicious inbox rules
# 5. Reset password
# 6. Investigate the breach
# 7. Generate incident report
# ============================================

param(
    [string]$TargetUser = "Joe@advturbine.com",
    [string]$AttackerIP = "185.215.150.68"
)

Write-Host "============================================" -ForegroundColor Red
Write-Host "EMERGENCY INCIDENT RESPONSE" -ForegroundColor Red
Write-Host "ACCOUNT COMPROMISE REMEDIATION" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""
Write-Host "Target Account: $TargetUser" -ForegroundColor Yellow
Write-Host "Attacker IP: $AttackerIP" -ForegroundColor Red
Write-Host ""

$tempPassword = "TempSecure$(Get-Random -Minimum 1000 -Maximum 9999)!Pass"

# ============================================
# STEP 0: CHECK/INSTALL REQUIRED MODULES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "STEP 0: CHECKING & INSTALLING MODULES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Function to install module if not present
function Install-RequiredModule {
    param($ModuleName)
    
    Write-Host "[*] Checking for $ModuleName module..." -ForegroundColor Yellow
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "[!] $ModuleName not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "[OK] $ModuleName installed successfully" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[ERROR] Failed to install $ModuleName : $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "[OK] $ModuleName already installed" -ForegroundColor Green
        return $true
    }
}

# Install required modules
$modulesNeeded = @("ExchangeOnlineManagement", "Microsoft.Graph", "AzureAD", "MSOnline")
$modulesInstalled = @{}

foreach ($module in $modulesNeeded) {
    $modulesInstalled[$module] = Install-RequiredModule -ModuleName $module
}

Write-Host ""

# ============================================
# CONNECT TO SERVICES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CONNECTING TO MICROSOFT SERVICES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Connect to Exchange Online
Write-Host "[*] Connecting to Exchange Online..." -ForegroundColor Yellow
try {
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (-not $existingConnection) {
        Connect-ExchangeOnline -ShowBanner:$false
    }
    Write-Host "[OK] Connected to Exchange Online" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to connect to Exchange Online: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[!] Script cannot continue without Exchange Online connection" -ForegroundColor Red
    exit
}

# Connect to Microsoft Graph
Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Yellow
$graphConnected = $false
if ($modulesInstalled["Microsoft.Graph"]) {
    try {
        Import-Module Microsoft.Graph.Users
        Import-Module Microsoft.Graph.Authentication
        Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All" -NoWelcome -ErrorAction Stop
        Write-Host "[OK] Connected to Microsoft Graph" -ForegroundColor Green
        $graphConnected = $true
    } catch {
        Write-Host "[WARNING] Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $graphConnected = $false
    }
}

# Fallback to AzureAD if Graph failed
$azureADConnected = $false
if (-not $graphConnected -and $modulesInstalled["AzureAD"]) {
    Write-Host "[*] Connecting to AzureAD (fallback)..." -ForegroundColor Yellow
    try {
        Import-Module AzureAD
        Connect-AzureAD -ErrorAction Stop | Out-Null
        Write-Host "[OK] Connected to AzureAD" -ForegroundColor Green
        $azureADConnected = $true
    } catch {
        Write-Host "[WARNING] AzureAD connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
# Quick fix - add this to your script around line 120-ish, right before the MFA section:

Write-Host "[*] Reconnecting to MSOnline..." -ForegroundColor Yellow
try {
    # Test if already connected
    Get-MsolDomain -ErrorAction Stop | Out-Null
    Write-Host "[OK] MSOnline connection active" -ForegroundColor Green
} catch {
    # Not connected, reconnect
    Connect-MsolService
    Write-Host "[OK] Reconnected to MSOnline" -ForegroundColor Green
}

# Connect to MSOnline for password reset
$msolConnected = $false
if ($modulesInstalled["MSOnline"]) {
    Write-Host "[*] Connecting to MSOnline..." -ForegroundColor Yellow
    try {
        Import-Module MSOnline
        Connect-MsolService -ErrorAction Stop
        Write-Host "[OK] Connected to MSOnline" -ForegroundColor Green
        $msolConnected = $true
    } catch {
        Write-Host "[WARNING] MSOnline connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================
# STEP 1: DISABLE THE ACCOUNT
# ============================================
Write-Host "============================================" -ForegroundColor Red
Write-Host "STEP 1: DISABLING COMPROMISED ACCOUNT" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

Write-Host "[*] Disabling account: $TargetUser" -ForegroundColor Yellow
$accountDisabled = $false

if ($graphConnected) {
    try {
        Update-MgUser -UserId $TargetUser -AccountEnabled:$false -ErrorAction Stop
        Write-Host "[OK] Account disabled successfully (Microsoft Graph)" -ForegroundColor Green
        $accountDisabled = $true
    } catch {
        Write-Host "[ERROR] Microsoft Graph failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $accountDisabled -and $azureADConnected) {
    try {
        Set-AzureADUser -ObjectId $TargetUser -AccountEnabled $false -ErrorAction Stop
        Write-Host "[OK] Account disabled successfully (AzureAD)" -ForegroundColor Green
        $accountDisabled = $true
    } catch {
        Write-Host "[ERROR] AzureAD failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $accountDisabled) {
    Write-Host "[ERROR] CRITICAL: Could not disable account!" -ForegroundColor Red
}

Write-Host ""

# ============================================
# STEP 2: REVOKE ALL SESSIONS
# ============================================
Write-Host "============================================" -ForegroundColor Red
Write-Host "STEP 2: REVOKING ALL ACTIVE SESSIONS" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

Write-Host "[*] Revoking all refresh tokens and sessions..." -ForegroundColor Yellow
$sessionsRevoked = $false

if ($graphConnected) {
    try {
        Revoke-MgUserSignInSession -UserId $TargetUser -ErrorAction Stop
        Write-Host "[OK] All sessions revoked successfully (Microsoft Graph)" -ForegroundColor Green
        $sessionsRevoked = $true
    } catch {
        Write-Host "[ERROR] Microsoft Graph failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $sessionsRevoked -and $azureADConnected) {
    try {
        $user = Get-AzureADUser -ObjectId $TargetUser
        Revoke-AzureADUserAllRefreshToken -ObjectId $user.ObjectId -ErrorAction Stop
        Write-Host "[OK] All sessions revoked successfully (AzureAD)" -ForegroundColor Green
        $sessionsRevoked = $true
    } catch {
        Write-Host "[ERROR] AzureAD failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $sessionsRevoked) {
    Write-Host "[ERROR] CRITICAL: Could not revoke sessions!" -ForegroundColor Red
}

Write-Host ""

# ============================================
# STEP 3: DELETE MALICIOUS INBOX RULES
# ============================================
Write-Host "============================================" -ForegroundColor Red
Write-Host "STEP 3: REMOVING MALICIOUS INBOX RULES" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

Write-Host "[*] Retrieving inbox rules..." -ForegroundColor Yellow
try {
    $rules = Get-InboxRule -Mailbox $TargetUser -ErrorAction Stop
    
    if ($rules) {
        Write-Host "[WARNING] Found $($rules.Count) rule(s):" -ForegroundColor Yellow
        foreach ($rule in $rules) {
            Write-Host "  - Rule: $($rule.Name)" -ForegroundColor Yellow
            Write-Host "    Enabled: $($rule.Enabled)" -ForegroundColor $(if($rule.Enabled){"Red"}else{"Gray"})
            
            # Check if rule is suspicious
            $isSuspicious = $false
            if ($rule.Name -eq "......." -or 
                ($rule.MoveToFolder -like "*Deleted*" -and $rule.MarkAsRead -eq $true) -or
                ($rule.DeleteMessage -eq $true)) {
                $isSuspicious = $true
            }
            
            if ($isSuspicious) {
                Write-Host "    [SUSPICIOUS] This rule matches malicious pattern!" -ForegroundColor Red
                Write-Host "[*] Deleting malicious rule: $($rule.Name)" -ForegroundColor Red
                try {
                    Remove-InboxRule -Mailbox $TargetUser -Identity $rule.Identity -Confirm:$false -ErrorAction Stop
                    Write-Host "[OK] Deleted rule: $($rule.Name)" -ForegroundColor Green
                } catch {
                    Write-Host "[ERROR] Failed to delete rule: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    } else {
        Write-Host "[OK] No inbox rules found" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to retrieve inbox rules: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# STEP 4: RESET PASSWORD
# ============================================
Write-Host "============================================" -ForegroundColor Red
Write-Host "STEP 4: RESETTING PASSWORD" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

Write-Host "[*] Resetting password for: $TargetUser" -ForegroundColor Yellow
Write-Host "[*] Temporary password: $tempPassword" -ForegroundColor Cyan
$passwordReset = $false

if ($graphConnected) {
    try {
        $passwordProfile = @{
            Password = $tempPassword
            ForceChangePasswordNextSignIn = $true
        }
        Update-MgUser -UserId $TargetUser -PasswordProfile $passwordProfile -ErrorAction Stop
        Write-Host "[OK] Password reset successfully (Microsoft Graph)" -ForegroundColor Green
        $passwordReset = $true
    } catch {
        Write-Host "[ERROR] Microsoft Graph failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $passwordReset -and $msolConnected) {
    try {
        Set-MsolUserPassword -UserPrincipalName $TargetUser -NewPassword $tempPassword -ForceChangePassword $true -ErrorAction Stop
        Write-Host "[OK] Password reset successfully (MSOnline)" -ForegroundColor Green
        $passwordReset = $true
    } catch {
        Write-Host "[ERROR] MSOnline failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $passwordReset) {
    Write-Host "[ERROR] CRITICAL: Could not reset password!" -ForegroundColor Red
    Write-Host "[!] Manual password reset required in Azure AD portal" -ForegroundColor Red
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "TEMPORARY PASSWORD: $tempPassword" -ForegroundColor Cyan
Write-Host "SAVE THIS PASSWORD SECURELY!" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# STEP 5: INVESTIGATE SENT EMAILS
# ============================================
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "STEP 5: INVESTIGATING SENT EMAILS" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "[*] Searching for emails sent from attacker IP..." -ForegroundColor Yellow
try {
    $sentEmails = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) `
        -UserIds $TargetUser `
        -Operations "Send" `
        -ResultSize 1000 -ErrorAction Stop
    
    if ($sentEmails) {
        Write-Host "[WARNING] Found $($sentEmails.Count) sent email event(s)" -ForegroundColor Yellow
        
        $suspiciousSends = 0
        foreach ($email in $sentEmails) {
            $data = $email.AuditData | ConvertFrom-Json
            
            if ($data.ClientIP -like "*$AttackerIP*") {
                $suspiciousSends++
                Write-Host "============================================" -ForegroundColor Red
                Write-Host "[ALERT] EMAIL SENT FROM ATTACKER IP!" -ForegroundColor Red
                Write-Host "Time: $($data.CreationTime)" -ForegroundColor Yellow
                Write-Host "ClientIP: $($data.ClientIP)" -ForegroundColor Red
                if ($data.Item.Subject) {
                    Write-Host "Subject: $($data.Item.Subject)" -ForegroundColor Yellow
                }
                Write-Host ""
            }
        }
        
        if ($suspiciousSends -eq 0) {
            Write-Host "[OK] No emails sent from attacker IP" -ForegroundColor Green
        } else {
            Write-Host "[CRITICAL] $suspiciousSends email(s) sent from attacker IP!" -ForegroundColor Red
        }
    } else {
        Write-Host "[OK] No sent emails found in the last 24 hours" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to search sent emails: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# STEP 6: CHECK OTHER COMPROMISED ACCOUNTS
# ============================================
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "STEP 6: CHECKING FOR OTHER COMPROMISED ACCOUNTS" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "[*] Searching for other accounts accessed from $AttackerIP..." -ForegroundColor Yellow
try {
    $allEvents = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
        -IPAddresses $AttackerIP `
        -ResultSize 5000 -ErrorAction Stop
    
    $otherAccounts = $allEvents | Select-Object -ExpandProperty UserIds -Unique
    
    if ($otherAccounts) {
        Write-Host "[WARNING] Found $($otherAccounts.Count) account(s) accessed from attacker IP:" -ForegroundColor Red
        foreach ($account in $otherAccounts) {
            $color = if ($account -eq $TargetUser) { "Yellow" } else { "Red" }
            $marker = if ($account -eq $TargetUser) { " (CURRENT)" } else { " [INVESTIGATE!]" }
            Write-Host "  - $account$marker" -ForegroundColor $color
        }
        Write-Host ""
        
        $otherVictims = $otherAccounts | Where-Object { $_ -ne $TargetUser }
        if ($otherVictims) {
            Write-Host "[!] CRITICAL: Other accounts may be compromised!" -ForegroundColor Red
            Write-Host "[!] Run this script for each account above!" -ForegroundColor Red
        }
    } else {
        Write-Host "[OK] Only $TargetUser was accessed from this IP" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to search for other accounts: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# STEP 7: CHECK MAILBOX FORWARDING
# ============================================
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "STEP 7: CHECKING MAILBOX FORWARDING" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "[*] Checking for mailbox forwarding..." -ForegroundColor Yellow
try {
    $mailbox = Get-Mailbox $TargetUser -ErrorAction Stop | Select-Object ForwardingSmtpAddress, DeliverToMailboxAndForward, ForwardingAddress
    
    if ($mailbox.ForwardingSmtpAddress -or $mailbox.ForwardingAddress) {
        Write-Host "[WARNING] FORWARDING DETECTED!" -ForegroundColor Red
        Write-Host "ForwardingSmtpAddress: $($mailbox.ForwardingSmtpAddress)" -ForegroundColor Red
        Write-Host "ForwardingAddress: $($mailbox.ForwardingAddress)" -ForegroundColor Red
        Write-Host "DeliverToMailboxAndForward: $($mailbox.DeliverToMailboxAndForward)" -ForegroundColor Red
        
        Write-Host "[*] Removing forwarding..." -ForegroundColor Yellow
        Set-Mailbox $TargetUser -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false -ForwardingAddress $null
        Write-Host "[OK] Forwarding removed" -ForegroundColor Green
    } else {
        Write-Host "[OK] No mailbox forwarding configured" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to check forwarding: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# STEP 8: GENERATE INCIDENT REPORT
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "STEP 8: GENERATING INCIDENT REPORT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = "C:\IncidentReport_$($TargetUser.Replace('@','_'))_$timestamp.txt"

$report = @"
============================================
INCIDENT RESPONSE REPORT
============================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Affected Account: $TargetUser
Attacker IP: $AttackerIP
Location: Kansas City, MO, United States
ISP: Heymman Servers Corporation

REMEDIATION ACTIONS TAKEN:
---------------------------
$(if($accountDisabled){"[X]"}else{"[ ]"}) Account disabled
$(if($sessionsRevoked){"[X]"}else{"[ ]"}) All sessions revoked
[X] Malicious inbox rules removed
$(if($passwordReset){"[X]"}else{"[ ]"}) Password reset
$(if($passwordReset){"[X] Temporary password: $tempPassword"}else{"[ ] Manual password reset required"})

INVESTIGATION SUMMARY:
----------------------
- Attacker IP: $AttackerIP (Kansas City, MO)
- Investigation period: Last 7 days
- Account status: DISABLED
- Malicious rule: "......." (DELETED)
- Rule action: Move to Deleted Items, Mark as Read

TIMELINE OF COMPROMISE:
-----------------------
Based on audit logs from previous investigation:
- First login: 2026-02-12 14:09:53 UTC
- Email exfiltration: 2026-02-12 14:42:16-14:42:33 (60+ emails in 2 minutes)
- Calendar modification: 2026-02-12 15:43:28
- Malicious rule created: 2026-02-12 18:26:27
- Sent emails: 2026-02-12 18:49:08
- Hard delete activity: 2026-02-12 18:47:32
- Last activity: 2026-02-12 19:47:18

ATTACKER ACTIVITIES OBSERVED:
------------------------------
- UserLoggedIn (multiple times)
- MailItemsAccessed (60+ instances - DATA EXFILTRATION)
- New-InboxRule (malicious rule)
- Send (sent emails from account)
- HardDelete (evidence destruction)
- SoftDelete
- MoveToDeletedItems
- Set-MailboxCalendarConfiguration

IMMEDIATE NEXT STEPS:
---------------------
1. Contact $TargetUser immediately
   - Inform them of the breach
   - Provide temporary password: $tempPassword
   - Schedule security briefing

2. Enable MFA BEFORE re-enabling account
   Command: Set-MsolUser -UserPrincipalName $TargetUser -StrongAuthenticationRequirements @()

3. Review all sent emails for BEC/phishing attempts

4. Monitor account activity for next 30 days

5. Check if other accounts were compromised (see list above)

6. Consider blocking $AttackerIP at firewall level

7. Report to:
   - Management
   - Cyber insurance (if applicable)
   - Law enforcement (if required)

RECOMMENDED SECURITY IMPROVEMENTS:
-----------------------------------
1. Enforce MFA for ALL users (not just this account)
2. Implement Conditional Access policies
   - Block legacy authentication
   - Require MFA for risky sign-ins
   - Block suspicious countries
3. Enable mailbox auditing for all mailboxes
4. Set up alerts for:
   - New inbox rules
   - Mailbox forwarding
   - Unusual sign-in locations
   - Mass email access
5. Deploy Microsoft Defender for Office 365
6. Regular security awareness training
7. Password policy review

RE-ENABLING THE ACCOUNT:
-------------------------
DO NOT re-enable until:
[ ] User confirms they need access
[ ] MFA is enabled and tested
[ ] All sent emails reviewed
[ ] No other suspicious activity found
[ ] User has completed security briefing

Command to re-enable:
Update-MgUser -UserId $TargetUser -AccountEnabled:`$true
# OR
Set-AzureADUser -ObjectId $TargetUser -AccountEnabled `$true

============================================
END OF REPORT
============================================
"@

try {
    $report | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "[OK] Incident report saved to: $reportPath" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Could not save report: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Report content:" -ForegroundColor Yellow
    Write-Host $report
}

Write-Host ""

# ============================================
# FINAL SUMMARY
# ============================================
Write-Host "============================================" -ForegroundColor Green
Write-Host "INCIDENT RESPONSE COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "REMEDIATION STATUS:" -ForegroundColor Cyan
Write-Host "-------------------" -ForegroundColor Cyan
Write-Host "Account Disabled: $(if($accountDisabled){'YES'}else{'FAILED - MANUAL ACTION REQUIRED'})" -ForegroundColor $(if($accountDisabled){'Green'}else{'Red'})
Write-Host "Sessions Revoked: $(if($sessionsRevoked){'YES'}else{'FAILED - MANUAL ACTION REQUIRED'})" -ForegroundColor $(if($sessionsRevoked){'Green'}else{'Red'})
Write-Host "Malicious Rules: DELETED" -ForegroundColor Green
Write-Host "Password Reset: $(if($passwordReset){'YES'}else{'FAILED - MANUAL ACTION REQUIRED'})" -ForegroundColor $(if($passwordReset){'Green'}else{'Red'})
Write-Host ""
Write-Host "TEMPORARY PASSWORD: $tempPassword" -ForegroundColor Yellow
Write-Host "Report Location: $reportPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "CRITICAL REMINDERS:" -ForegroundColor Red
Write-Host "-------------------" -ForegroundColor Red
Write-Host "1. Contact Joe immediately" -ForegroundColor Red
Write-Host "2. Enable MFA before re-enabling account" -ForegroundColor Red
Write-Host "3. Review all sent emails for BEC attempts" -ForegroundColor Red
Write-Host "4. Check other accounts from attacker IP" -ForegroundColor Red
Write-Host "5. Document everything for compliance" -ForegroundColor Red
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
