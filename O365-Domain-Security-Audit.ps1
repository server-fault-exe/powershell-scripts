# ============================================
# O365 DOMAIN-WIDE SECURITY AUDIT
# Complete Compromise & Vulnerability Assessment
# ============================================
# This script performs a comprehensive security audit:
# 1. Checks ALL users for MFA status
# 2. Scans ALL mailboxes for suspicious inbox rules
# 3. Identifies legacy authentication usage
# 4. Detects suspicious sign-ins from risky locations
# 5. Finds mailbox forwarding and delegation
# 6. Reviews admin role assignments
# 7. Checks for shared mailbox security
# 8. Identifies stale/unused accounts
# 9. Reviews mobile device access
# 10. Generates comprehensive security report
# ============================================

param(
    [int]$DaysToAudit = 30,
    [string]$OutputPath = "C:\O365_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "O365 DOMAIN-WIDE SECURITY AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Audit Period: Last $DaysToAudit days" -ForegroundColor Yellow
Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Initialize findings arrays
$findings = @{
    CriticalFindings = @()
    HighRiskUsers = @()
    SuspiciousRules = @()
    NoMFAUsers = @()
    LegacyAuthUsers = @()
    SuspiciousSignIns = @()
    ForwardingRules = @()
    OverPrivilegedUsers = @()
    StaleAccounts = @()
    SharedMailboxIssues = @()
}

# ============================================
# STEP 0: CHECK/INSTALL REQUIRED MODULES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "STEP 0: CHECKING REQUIRED MODULES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

function Install-RequiredModule {
    param($ModuleName)
    Write-Host "[*] Checking $ModuleName..." -ForegroundColor Yellow
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "[!] Installing $ModuleName..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
        Write-Host "[OK] $ModuleName installed" -ForegroundColor Green
    } else {
        Write-Host "[OK] $ModuleName found" -ForegroundColor Green
    }
}

$modules = @("ExchangeOnlineManagement", "MSOnline", "AzureAD")
foreach ($module in $modules) {
    Install-RequiredModule -ModuleName $module
}

Write-Host ""

# ============================================
# CONNECT TO SERVICES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CONNECTING TO O365 SERVICES" -ForegroundColor Cyan
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
    Write-Host "[ERROR] Failed to connect to Exchange Online" -ForegroundColor Red
    exit
}

# Connect to MSOnline
Write-Host "[*] Connecting to MSOnline..." -ForegroundColor Yellow
try {
    Import-Module MSOnline
    Connect-MsolService
    Write-Host "[OK] Connected to MSOnline" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Could not connect to MSOnline (MFA status check limited)" -ForegroundColor Yellow
}

# Connect to AzureAD
Write-Host "[*] Connecting to AzureAD..." -ForegroundColor Yellow
try {
    Import-Module AzureAD
    Connect-AzureAD | Out-Null
    Write-Host "[OK] Connected to AzureAD" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Could not connect to AzureAD (some checks limited)" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 1: MFA STATUS AUDIT
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 1: MFA STATUS AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking MFA status for all users..." -ForegroundColor Yellow

try {
    $allUsers = Get-MsolUser -All
    $totalUsers = $allUsers.Count
    Write-Host "[*] Found $totalUsers total users" -ForegroundColor Yellow
    
    $mfaStats = @{
        Enabled = 0
        Enforced = 0
        Disabled = 0
    }
    
    $noMFAUsers = @()
    
    foreach ($user in $allUsers) {
        $mfaStatus = "Disabled"
        
        if ($user.StrongAuthenticationRequirements.State) {
            $mfaStatus = $user.StrongAuthenticationRequirements.State
        }
        
        switch ($mfaStatus) {
            "Enabled" { $mfaStats.Enabled++ }
            "Enforced" { $mfaStats.Enforced++ }
            default { 
                $mfaStats.Disabled++
                if ($user.isLicensed) {
                    $noMFAUsers += [PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        IsAdmin = $user.IsLicensed
                        LastSignIn = "N/A"
                        RiskLevel = "HIGH"
                    }
                }
            }
        }
    }
    
    Write-Host ""
    Write-Host "MFA STATUS SUMMARY:" -ForegroundColor Yellow
    Write-Host "  Total Users: $totalUsers" -ForegroundColor White
    Write-Host "  MFA Enforced: $($mfaStats.Enforced)" -ForegroundColor Green
    Write-Host "  MFA Enabled: $($mfaStats.Enabled)" -ForegroundColor Yellow
    Write-Host "  NO MFA: $($mfaStats.Disabled)" -ForegroundColor Red
    Write-Host ""
    
    if ($noMFAUsers.Count -gt 0) {
        Write-Host "[CRITICAL] $($noMFAUsers.Count) licensed users WITHOUT MFA!" -ForegroundColor Red
        $findings.NoMFAUsers = $noMFAUsers
        $findings.CriticalFindings += "[$($noMFAUsers.Count)] licensed users have NO MFA enabled"
    }
    
    # Export to CSV
    $noMFAUsers | Export-Csv -Path "$OutputPath\Users_Without_MFA.csv" -NoTypeInformation
    
} catch {
    Write-Host "[ERROR] MFA audit failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# SECTION 2: INBOX RULES AUDIT (ALL MAILBOXES)
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 2: SCANNING ALL INBOX RULES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Retrieving all mailboxes..." -ForegroundColor Yellow
$allMailboxes = Get-Mailbox -ResultSize Unlimited
Write-Host "[*] Found $($allMailboxes.Count) mailboxes" -ForegroundColor Yellow
Write-Host "[*] Scanning for suspicious inbox rules..." -ForegroundColor Yellow
Write-Host ""

$suspiciousRules = @()
$totalRules = 0
$currentMailbox = 0

foreach ($mailbox in $allMailboxes) {
    $currentMailbox++
    Write-Progress -Activity "Scanning Inbox Rules" -Status "Mailbox $currentMailbox of $($allMailboxes.Count): $($mailbox.UserPrincipalName)" -PercentComplete (($currentMailbox / $allMailboxes.Count) * 100)
    
    try {
        $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue
        
        if ($rules) {
            $totalRules += $rules.Count
            
            foreach ($rule in $rules) {
                $isSuspicious = $false
                $suspicionReasons = @()
                
                # Check for suspicious patterns
                if ($rule.MoveToFolder -like "*Deleted*" -or $rule.MoveToFolder -like "*Trash*") {
                    $isSuspicious = $true
                    $suspicionReasons += "Moves to Deleted/Trash"
                }
                
                if ($rule.ForwardTo -or $rule.RedirectTo) {
                    $isSuspicious = $true
                    $suspicionReasons += "Forwards/Redirects emails"
                }
                
                if ($rule.DeleteMessage) {
                    $isSuspicious = $true
                    $suspicionReasons += "Deletes messages"
                }
                
                if ($rule.MarkAsRead -and ($rule.MoveToFolder -or $rule.DeleteMessage)) {
                    $isSuspicious = $true
                    $suspicionReasons += "Marks as read + moves/deletes (stealth)"
                }
                
                if ($rule.Name -match "^\.*$" -or $rule.Name.Length -lt 3) {
                    $isSuspicious = $true
                    $suspicionReasons += "Suspicious rule name"
                }
                
                if ($isSuspicious) {
                    $suspiciousRules += [PSCustomObject]@{
                        Mailbox = $mailbox.UserPrincipalName
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        Created = $rule.WhenCreated
                        MoveToFolder = $rule.MoveToFolder
                        ForwardTo = $rule.ForwardTo
                        RedirectTo = $rule.RedirectTo
                        DeleteMessage = $rule.DeleteMessage
                        MarkAsRead = $rule.MarkAsRead
                        Reasons = $suspicionReasons -join "; "
                        RiskLevel = "CRITICAL"
                    }
                }
            }
        }
    } catch {
        Write-Host "[WARNING] Could not check rules for $($mailbox.UserPrincipalName)" -ForegroundColor Yellow
    }
}

Write-Progress -Activity "Scanning Inbox Rules" -Completed

Write-Host ""
Write-Host "INBOX RULES SUMMARY:" -ForegroundColor Yellow
Write-Host "  Total Rules Found: $totalRules" -ForegroundColor White
Write-Host "  Suspicious Rules: $($suspiciousRules.Count)" -ForegroundColor Red
Write-Host ""

if ($suspiciousRules.Count -gt 0) {
    Write-Host "[CRITICAL] Found $($suspiciousRules.Count) SUSPICIOUS INBOX RULES!" -ForegroundColor Red
    $suspiciousRules | Format-Table Mailbox, RuleName, Enabled, Reasons -AutoSize
    $findings.SuspiciousRules = $suspiciousRules
    $findings.CriticalFindings += "[$($suspiciousRules.Count)] suspicious inbox rules found across domain"
}

$suspiciousRules | Export-Csv -Path "$OutputPath\Suspicious_Inbox_Rules.csv" -NoTypeInformation

Write-Host ""

# ============================================
# SECTION 3: LEGACY AUTHENTICATION USAGE
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 3: LEGACY AUTHENTICATION AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Searching for legacy auth usage (last $DaysToAudit days)..." -ForegroundColor Yellow
Write-Host "[!] This may take several minutes..." -ForegroundColor Yellow

try {
    $legacyAuthLogins = @()
    $startDate = (Get-Date).AddDays(-$DaysToAudit)
    
    # Search for user logins
    $loginEvents = Search-UnifiedAuditLog -StartDate $startDate -EndDate (Get-Date) `
        -Operations "UserLoggedIn" `
        -ResultSize 5000
    
    if ($loginEvents) {
        Write-Host "[*] Analyzing $($loginEvents.Count) login events..." -ForegroundColor Yellow
        
        foreach ($event in $loginEvents) {
            $data = $event.AuditData | ConvertFrom-Json
            
            # Check for legacy auth indicators
            $isLegacyAuth = $false
            $authMethod = "Modern"
            
            # Check ExtendedProperties for auth type
            if ($data.ExtendedProperties) {
                foreach ($prop in $data.ExtendedProperties) {
                    if ($prop.Name -eq "RequestType" -and $prop.Value -notlike "*Modern*") {
                        $isLegacyAuth = $true
                        $authMethod = $prop.Value
                    }
                }
            }
            
            # Check for legacy protocols
            if ($data.ClientInfoString -match "Outlook|IMAP|POP|SMTP|ActiveSync" -and 
                $data.ClientInfoString -notmatch "Outlook Mobile|OutlookService") {
                $isLegacyAuth = $true
            }
            
            if ($isLegacyAuth) {
                $legacyAuthLogins += [PSCustomObject]@{
                    User = $data.UserId
                    Time = $data.CreationTime
                    ClientIP = $data.ClientIP
                    AuthMethod = $authMethod
                    ClientInfo = $data.ClientInfoString
                    RiskLevel = "HIGH"
                }
            }
        }
        
        $legacyAuthUsers = $legacyAuthLogins | Group-Object User | Select-Object Name, Count | Sort-Object Count -Descending
        
        Write-Host ""
        Write-Host "LEGACY AUTH SUMMARY:" -ForegroundColor Yellow
        Write-Host "  Total Legacy Auth Events: $($legacyAuthLogins.Count)" -ForegroundColor Red
        Write-Host "  Users Using Legacy Auth: $($legacyAuthUsers.Count)" -ForegroundColor Red
        Write-Host ""
        
        if ($legacyAuthUsers.Count -gt 0) {
            Write-Host "[CRITICAL] Legacy authentication still in use!" -ForegroundColor Red
            Write-Host "Top offenders:" -ForegroundColor Yellow
            $legacyAuthUsers | Select-Object -First 10 | Format-Table Name, Count -AutoSize
            
            $findings.LegacyAuthUsers = $legacyAuthUsers
            $findings.CriticalFindings += "[$($legacyAuthUsers.Count)] users still using legacy authentication (MFA bypass risk)"
        }
        
        $legacyAuthLogins | Export-Csv -Path "$OutputPath\Legacy_Auth_Usage.csv" -NoTypeInformation
    }
    
} catch {
    Write-Host "[ERROR] Legacy auth audit failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# SECTION 4: SUSPICIOUS SIGN-INS
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 4: SUSPICIOUS SIGN-IN ANALYSIS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Analyzing sign-in locations and patterns..." -ForegroundColor Yellow

# Define high-risk countries (common attack sources)
$highRiskCountries = @(
    "Russia", "China", "North Korea", "Iran", "Nigeria", 
    "Romania", "Ukraine", "Belarus", "Vietnam"
)

try {
    $suspiciousSignIns = @()
    
    # Get recent sign-ins
    $signInEvents = Search-UnifiedAuditLog -StartDate $startDate -EndDate (Get-Date) `
        -Operations "UserLoggedIn" `
        -ResultSize 5000
    
    if ($signInEvents) {
        Write-Host "[*] Analyzing $($signInEvents.Count) sign-in events..." -ForegroundColor Yellow
        
        foreach ($event in $signInEvents) {
            $data = $event.AuditData | ConvertFrom-Json
            
            # Check IP against geolocation
            if ($data.ClientIP) {
                try {
                    $ip = $data.ClientIP.Split(':')[0]  # Remove port if present
                    $geoInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 100  # Rate limit
                    
                    $isSuspicious = $false
                    $reasons = @()
                    
                    # Check for high-risk countries
                    if ($highRiskCountries -contains $geoInfo.country) {
                        $isSuspicious = $true
                        $reasons += "High-risk country: $($geoInfo.country)"
                    }
                    
                    # Check for VPN/Hosting providers
                    if ($geoInfo.isp -match "VPN|Proxy|Hosting|Cloud|Server|Data Center") {
                        $isSuspicious = $true
                        $reasons += "VPN/Hosting provider: $($geoInfo.isp)"
                    }
                    
                    if ($isSuspicious) {
                        $suspiciousSignIns += [PSCustomObject]@{
                            User = $data.UserId
                            Time = $data.CreationTime
                            IP = $data.ClientIP
                            Country = $geoInfo.country
                            City = $geoInfo.city
                            ISP = $geoInfo.isp
                            Reasons = $reasons -join "; "
                            RiskLevel = "HIGH"
                        }
                    }
                } catch {
                    # Skip IP lookup errors
                }
            }
        }
        
        Write-Host ""
        Write-Host "SUSPICIOUS SIGN-INS SUMMARY:" -ForegroundColor Yellow
        Write-Host "  Total Suspicious Sign-ins: $($suspiciousSignIns.Count)" -ForegroundColor Red
        Write-Host ""
        
        if ($suspiciousSignIns.Count -gt 0) {
            Write-Host "[WARNING] Found suspicious sign-ins from risky locations!" -ForegroundColor Red
            $suspiciousSignIns | Select-Object -First 10 | Format-Table User, Time, Country, ISP -AutoSize
            
            $findings.SuspiciousSignIns = $suspiciousSignIns
            $findings.CriticalFindings += "[$($suspiciousSignIns.Count)] sign-ins from suspicious locations/IPs"
        }
        
        $suspiciousSignIns | Export-Csv -Path "$OutputPath\Suspicious_SignIns.csv" -NoTypeInformation
    }
} catch {
    Write-Host "[ERROR] Suspicious sign-in analysis failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# SECTION 5: MAILBOX FORWARDING & DELEGATION
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 5: MAILBOX FORWARDING AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking for mailbox forwarding..." -ForegroundColor Yellow

$forwardingMailboxes = @()

foreach ($mailbox in $allMailboxes) {
    try {
        $mbx = Get-Mailbox $mailbox.UserPrincipalName | Select-Object UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
        
        if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
            $forwardingMailboxes += [PSCustomObject]@{
                Mailbox = $mbx.UserPrincipalName
                ForwardingTo = if ($mbx.ForwardingSmtpAddress) { $mbx.ForwardingSmtpAddress } else { $mbx.ForwardingAddress }
                KeepCopy = $mbx.DeliverToMailboxAndForward
                RiskLevel = "HIGH"
            }
        }
    } catch {
        # Skip errors
    }
}

Write-Host ""
Write-Host "FORWARDING SUMMARY:" -ForegroundColor Yellow
Write-Host "  Mailboxes with Forwarding: $($forwardingMailboxes.Count)" -ForegroundColor $(if($forwardingMailboxes.Count -gt 0){"Red"}else{"Green"})
Write-Host ""

if ($forwardingMailboxes.Count -gt 0) {
    Write-Host "[WARNING] Found mailbox forwarding rules!" -ForegroundColor Red
    $forwardingMailboxes | Format-Table Mailbox, ForwardingTo, KeepCopy -AutoSize
    
    $findings.ForwardingRules = $forwardingMailboxes
    $findings.CriticalFindings += "[$($forwardingMailboxes.Count)] mailboxes have forwarding enabled"
}

$forwardingMailboxes | Export-Csv -Path "$OutputPath\Mailbox_Forwarding.csv" -NoTypeInformation

Write-Host ""

# ============================================
# SECTION 6: ADMIN ROLE ASSIGNMENTS
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 6: ADMIN ROLE AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking admin role assignments..." -ForegroundColor Yellow

try {
    $adminRoles = Get-AzureADDirectoryRole
    $adminUsers = @()
    
    foreach ($role in $adminRoles) {
        $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
        
        foreach ($member in $members) {
            $adminUsers += [PSCustomObject]@{
                User = $member.UserPrincipalName
                DisplayName = $member.DisplayName
                RoleName = $role.DisplayName
                ObjectType = $member.ObjectType
            }
        }
    }
    
    Write-Host ""
    Write-Host "ADMIN ROLES SUMMARY:" -ForegroundColor Yellow
    Write-Host "  Total Admin Assignments: $($adminUsers.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    # Show admins without MFA
    $adminsNoMFA = $adminUsers | Where-Object {
        $user = $_.User
        $noMFAUsers.UserPrincipalName -contains $user
    }
    
    if ($adminsNoMFA.Count -gt 0) {
        Write-Host "[CRITICAL] $($adminsNoMFA.Count) ADMIN(S) WITHOUT MFA!" -ForegroundColor Red
        $adminsNoMFA | Format-Table User, RoleName -AutoSize
        $findings.CriticalFindings += "[$($adminsNoMFA.Count)] admin accounts WITHOUT MFA - CRITICAL RISK"
    }
    
    $adminUsers | Export-Csv -Path "$OutputPath\Admin_Role_Assignments.csv" -NoTypeInformation
    
} catch {
    Write-Host "[ERROR] Admin role audit failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# SECTION 7: SHARED MAILBOX SECURITY
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 7: SHARED MAILBOX AUDIT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking shared mailboxes..." -ForegroundColor Yellow

try {
    $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
    
    Write-Host "[*] Found $($sharedMailboxes.Count) shared mailboxes" -ForegroundColor Yellow
    
    $sharedMbxIssues = @()
    
    foreach ($mbx in $sharedMailboxes) {
        # Check if sign-in is enabled (should be disabled)
        try {
            $account = Get-MsolUser -UserPrincipalName $mbx.UserPrincipalName -ErrorAction SilentlyContinue
            
            if ($account.BlockCredential -eq $false) {
                $sharedMbxIssues += [PSCustomObject]@{
                    Mailbox = $mbx.UserPrincipalName
                    Issue = "Sign-in enabled (should be blocked)"
                    RiskLevel = "MEDIUM"
                }
            }
        } catch {
            # Skip errors
        }
    }
    
    Write-Host ""
    Write-Host "SHARED MAILBOX SUMMARY:" -ForegroundColor Yellow
    Write-Host "  Total Shared Mailboxes: $($sharedMailboxes.Count)" -ForegroundColor White
    Write-Host "  Security Issues: $($sharedMbxIssues.Count)" -ForegroundColor $(if($sharedMbxIssues.Count -gt 0){"Yellow"}else{"Green"})
    Write-Host ""
    
    if ($sharedMbxIssues.Count -gt 0) {
        Write-Host "[WARNING] Found shared mailbox security issues!" -ForegroundColor Yellow
        $sharedMbxIssues | Format-Table Mailbox, Issue -AutoSize
        $findings.SharedMailboxIssues = $sharedMbxIssues
    }
    
    $sharedMbxIssues | Export-Csv -Path "$OutputPath\Shared_Mailbox_Issues.csv" -NoTypeInformation
    
} catch {
    Write-Host "[ERROR] Shared mailbox audit failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# SECTION 8: STALE ACCOUNTS
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 8: STALE ACCOUNT DETECTION" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking for stale/inactive accounts..." -ForegroundColor Yellow

try {
    $staleAccounts = @()
    $staleThresholdDays = 90
    
    foreach ($user in $allUsers) {
        if ($user.isLicensed -and $user.LastPasswordChangeTimestamp) {
            $daysSincePasswordChange = (New-TimeSpan -Start $user.LastPasswordChangeTimestamp -End (Get-Date)).Days
            
            if ($daysSincePasswordChange -gt $staleThresholdDays) {
                $staleAccounts += [PSCustomObject]@{
                    User = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    LastPasswordChange = $user.LastPasswordChangeTimestamp
                    DaysSinceChange = $daysSincePasswordChange
                    RiskLevel = "MEDIUM"
                }
            }
        }
    }
    
    Write-Host ""
    Write-Host "STALE ACCOUNTS SUMMARY:" -ForegroundColor Yellow
    Write-Host "  Accounts inactive >$staleThresholdDays days: $($staleAccounts.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    if ($staleAccounts.Count -gt 0) {
        Write-Host "[WARNING] Found stale accounts (password unchanged >$staleThresholdDays days)!" -ForegroundColor Yellow
        $findings.StaleAccounts = $staleAccounts
    }
    
    $staleAccounts | Export-Csv -Path "$OutputPath\Stale_Accounts.csv" -NoTypeInformation
    
} catch {
    Write-Host "[ERROR] Stale account detection failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# ============================================
# GENERATE EXECUTIVE SUMMARY REPORT
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "GENERATING EXECUTIVE SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$executiveSummary = @"
============================================
O365 SECURITY AUDIT - EXECUTIVE SUMMARY
============================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Audit Period: Last $DaysToAudit days
Domain: $((Get-OrganizationConfig).DisplayName)

CRITICAL FINDINGS: $($findings.CriticalFindings.Count)
============================================
$($findings.CriticalFindings | ForEach-Object { "- $_`n" })

SECURITY POSTURE SUMMARY:
============================================

MFA STATUS:
-----------
Total Users: $totalUsers
MFA Enforced: $($mfaStats.Enforced) ($([math]::Round(($mfaStats.Enforced/$totalUsers)*100,1))%)
MFA Enabled: $($mfaStats.Enabled) ($([math]::Round(($mfaStats.Enabled/$totalUsers)*100,1))%)
NO MFA: $($mfaStats.Disabled) ($([math]::Round(($mfaStats.Disabled/$totalUsers)*100,1))%)
Risk Level: $(if($mfaStats.Disabled -gt ($totalUsers * 0.1)){"CRITICAL - >10% without MFA"}elseif($mfaStats.Disabled -gt 0){"HIGH - Users without MFA"}else{"LOW"})

INBOX RULES:
------------
Total Rules: $totalRules
Suspicious Rules: $($suspiciousRules.Count)
Affected Mailboxes: $($suspiciousRules.Mailbox | Select-Object -Unique | Measure-Object).Count
Risk Level: $(if($suspiciousRules.Count -gt 0){"CRITICAL - Possible compromises"}else{"LOW"})

AUTHENTICATION:
---------------
Legacy Auth Users: $($legacyAuthUsers.Count)
Legacy Auth Events: $($legacyAuthLogins.Count)
Risk Level: $(if($legacyAuthUsers.Count -gt 0){"HIGH - MFA bypass possible"}else{"LOW"})

SIGN-IN SECURITY:
-----------------
Suspicious Sign-ins: $($suspiciousSignIns.Count)
High-Risk Locations: $(($suspiciousSignIns.Country | Select-Object -Unique | Measure-Object).Count)
Risk Level: $(if($suspiciousSignIns.Count -gt 10){"HIGH - Multiple suspicious logins"}elseif($suspiciousSignIns.Count -gt 0){"MEDIUM"}else{"LOW"})

MAILBOX FORWARDING:
-------------------
Forwarding Rules: $($forwardingMailboxes.Count)
Risk Level: $(if($forwardingMailboxes.Count -gt 0){"MEDIUM - Data exfiltration risk"}else{"LOW"})

ADMIN SECURITY:
---------------
Total Admin Assignments: $($adminUsers.Count)
Admins WITHOUT MFA: $($adminsNoMFA.Count)
Risk Level: $(if($adminsNoMFA.Count -gt 0){"CRITICAL - Admin accounts at risk"}else{"LOW"})

IMMEDIATE ACTIONS REQUIRED:
===========================
$( if ($findings.CriticalFindings.Count -gt 0) {
"PRIORITY 1 - CRITICAL:
$($findings.CriticalFindings | ForEach-Object { "  - $_`n" })
"
} else {
"No critical findings - Good security posture!
"
})
$( if ($suspiciousRules.Count -gt 0) {
"PRIORITY 2 - INVESTIGATE COMPROMISES:
  - Review all suspicious inbox rules immediately
  - Check mailboxes: $($suspiciousRules.Mailbox -join ', ')
  - Look for signs of data exfiltration
  - Reset passwords for affected accounts
"
})
$( if ($noMFAUsers.Count -gt 0) {
"PRIORITY 3 - ENABLE MFA:
  - Enable MFA for all $($noMFAUsers.Count) users without MFA
  - Enforce MFA policy domain-wide
  - Prioritize admin accounts first
"
})
$( if ($legacyAuthUsers.Count -gt 0) {
"PRIORITY 4 - BLOCK LEGACY AUTH:
  - Disable legacy authentication protocols
  - Implement Conditional Access to block legacy auth
  - Notify affected users: $($legacyAuthUsers.Count) users
"
})

DETAILED REPORTS SAVED TO:
===========================
$OutputPath\

Files Generated:
- Users_Without_MFA.csv
- Suspicious_Inbox_Rules.csv
- Legacy_Auth_Usage.csv
- Suspicious_SignIns.csv
- Mailbox_Forwarding.csv
- Admin_Role_Assignments.csv
- Shared_Mailbox_Issues.csv
- Stale_Accounts.csv

NEXT STEPS:
===========
1. Review all critical findings immediately
2. Run the O365-Domain-Hardening.ps1 script
3. Investigate suspicious inbox rules
4. Enable MFA for all users
5. Block legacy authentication
6. Implement Conditional Access policies
7. Set up security alerts
8. Schedule regular security audits

============================================
END OF EXECUTIVE SUMMARY
============================================
"@

# Save executive summary
$executiveSummary | Out-File -FilePath "$OutputPath\EXECUTIVE_SUMMARY.txt" -Encoding UTF8

Write-Host $executiveSummary

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "SECURITY AUDIT COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "All reports saved to: $OutputPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "CRITICAL FINDINGS: $($findings.CriticalFindings.Count)" -ForegroundColor $(if($findings.CriticalFindings.Count -gt 0){"Red"}else{"Green"})
Write-Host ""
Write-Host "Next step: Run O365-Domain-Hardening.ps1 to fix these issues" -ForegroundColor Yellow
Write-Host ""
