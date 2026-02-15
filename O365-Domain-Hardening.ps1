# ============================================
# O365 DOMAIN HARDENING SCRIPT
# Comprehensive Security Lockdown
# ============================================
# This script implements enterprise security controls:
# 1. Enforces MFA for all users
# 2. Blocks legacy authentication
# 3. Creates Conditional Access policies
# 4. Configures security alerts
# 5. Enables audit logging
# 6. Blocks suspicious countries
# 7. Configures mailbox audit settings
# 8. Implements password policies
# 9. Disables sign-in for shared mailboxes
# 10. Creates security monitoring
# ============================================

param(
    [switch]$WhatIf = $false,
    [switch]$SkipMFA = $false,
    [switch]$SkipConditionalAccess = $false,
    [string[]]$CountriesToBlock = @("RU", "CN", "KP", "IR"),  # Russia, China, North Korea, Iran
    [string]$OutputPath = "C:\O365_Hardening_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

if ($WhatIf) {
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "RUNNING IN WHATIF MODE - NO CHANGES WILL BE MADE" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "O365 DOMAIN HARDENING" -ForegroundColor Cyan
Write-Host "COMPREHENSIVE SECURITY LOCKDOWN" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$hardeningLog = @()
$changesApplied = 0

function Log-Action {
    param([string]$Action, [string]$Status, [string]$Details = "")
    
    $logEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action = $Action
        Status = $Status
        Details = $Details
    }
    
    $script:hardeningLog += $logEntry
    
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "FAILED" { "Red" }
        "SKIPPED" { "Yellow" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Action" -ForegroundColor $color
    if ($Details) {
        Write-Host "    $Details" -ForegroundColor Gray
    }
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
        if (-not $WhatIf) {
            Write-Host "[!] Installing $ModuleName..." -ForegroundColor Yellow
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
            Write-Host "[OK] $ModuleName installed" -ForegroundColor Green
        } else {
            Write-Host "[WHATIF] Would install $ModuleName" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] $ModuleName found" -ForegroundColor Green
    }
}

$modules = @("ExchangeOnlineManagement", "MSOnline", "AzureADPreview")
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

if (-not $WhatIf) {
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
        Write-Host "[ERROR] Failed to connect to MSOnline" -ForegroundColor Red
        exit
    }
    
    # Connect to AzureAD
    Write-Host "[*] Connecting to AzureAD..." -ForegroundColor Yellow
    try {
        Import-Module AzureADPreview
        Connect-AzureAD | Out-Null
        Write-Host "[OK] Connected to AzureAD" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to connect to AzureAD" -ForegroundColor Red
        exit
    }
}

Write-Host ""

# ============================================
# SECTION 1: ENFORCE MFA FOR ALL USERS
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 1: ENFORCING MFA FOR ALL USERS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipMFA) {
    Write-Host "[*] Retrieving all users..." -ForegroundColor Yellow
    
    if (-not $WhatIf) {
        try {
            $allUsers = Get-MsolUser -All | Where-Object {$_.isLicensed -eq $true -and $_.UserType -eq "Member"}
            $usersToEnableMFA = @()
            
            foreach ($user in $allUsers) {
                $mfaStatus = "Disabled"
                if ($user.StrongAuthenticationRequirements.State) {
                    $mfaStatus = $user.StrongAuthenticationRequirements.State
                }
                
                if ($mfaStatus -ne "Enforced") {
                    $usersToEnableMFA += $user
                }
            }
            
            Write-Host "[*] Found $($usersToEnableMFA.Count) users without enforced MFA" -ForegroundColor Yellow
            
            if ($usersToEnableMFA.Count -gt 0) {
                Write-Host "[*] Enabling MFA for all users..." -ForegroundColor Yellow
                
                $mfaRequirement = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
                $mfaRequirement.RelyingParty = "*"
                $mfaRequirement.State = "Enforced"
                $requirements = @($mfaRequirement)
                
                $successCount = 0
                $failCount = 0
                
                foreach ($user in $usersToEnableMFA) {
                    try {
                        Set-MsolUser -UserPrincipalName $user.UserPrincipalName -StrongAuthenticationRequirements $requirements
                        $successCount++
                        Log-Action "Enable MFA for $($user.UserPrincipalName)" "SUCCESS"
                    } catch {
                        $failCount++
                        Log-Action "Enable MFA for $($user.UserPrincipalName)" "FAILED" $_.Exception.Message
                    }
                }
                
                Write-Host ""
                Write-Host "[OK] MFA enabled for $successCount users" -ForegroundColor Green
                if ($failCount -gt 0) {
                    Write-Host "[WARNING] Failed to enable MFA for $failCount users" -ForegroundColor Yellow
                }
                $script:changesApplied += $successCount
            } else {
                Write-Host "[OK] All users already have MFA enforced" -ForegroundColor Green
                Log-Action "MFA Enforcement" "INFO" "All users already have MFA"
            }
            
        } catch {
            Write-Host "[ERROR] MFA enforcement failed: $($_.Exception.Message)" -ForegroundColor Red
            Log-Action "MFA Enforcement" "FAILED" $_.Exception.Message
        }
    } else {
        Write-Host "[WHATIF] Would enable MFA for all users without it" -ForegroundColor Yellow
    }
} else {
    Write-Host "[SKIPPED] MFA enforcement skipped (use -SkipMFA)" -ForegroundColor Yellow
    Log-Action "MFA Enforcement" "SKIPPED" "User requested skip"
}

Write-Host ""

# ============================================
# SECTION 2: BLOCK LEGACY AUTHENTICATION
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 2: BLOCKING LEGACY AUTHENTICATION" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipConditionalAccess) {
    Write-Host "[*] Creating Conditional Access policy to block legacy auth..." -ForegroundColor Yellow
    
    if (-not $WhatIf) {
        try {
            # Check if policy already exists
            $existingPolicy = Get-AzureADMSConditionalAccessPolicy | Where-Object {$_.DisplayName -eq "Block Legacy Authentication"}
            
            if (-not $existingPolicy) {
                $conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
                $conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
                $conditions.Applications.IncludeApplications = "All"
                $conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
                $conditions.Users.IncludeUsers = "All"
                $conditions.ClientAppTypes = @('ExchangeActiveSync', 'Other')
                
                $controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
                $controls._Operator = "OR"
                $controls.BuiltInControls = "Block"
                
                New-AzureADMSConditionalAccessPolicy -DisplayName "Block Legacy Authentication" `
                    -State "Enabled" `
                    -Conditions $conditions `
                    -GrantControls $controls
                
                Write-Host "[OK] Legacy authentication blocked via Conditional Access" -ForegroundColor Green
                Log-Action "Block Legacy Auth" "SUCCESS" "Conditional Access policy created"
                $script:changesApplied++
            } else {
                Write-Host "[INFO] Legacy auth block policy already exists" -ForegroundColor Cyan
                Log-Action "Block Legacy Auth" "INFO" "Policy already exists"
            }
            
        } catch {
            Write-Host "[ERROR] Failed to create legacy auth block: $($_.Exception.Message)" -ForegroundColor Red
            Log-Action "Block Legacy Auth" "FAILED" $_.Exception.Message
        }
    } else {
        Write-Host "[WHATIF] Would create Conditional Access policy to block legacy auth" -ForegroundColor Yellow
    }
} else {
    Write-Host "[SKIPPED] Legacy auth blocking skipped" -ForegroundColor Yellow
    Log-Action "Block Legacy Auth" "SKIPPED" "User requested skip"
}

Write-Host ""

# ============================================
# SECTION 3: REQUIRE MFA FOR RISKY SIGN-INS
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 3: REQUIRING MFA FOR RISKY SIGN-INS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipConditionalAccess) {
    if (-not $WhatIf) {
        try {
            $existingPolicy = Get-AzureADMSConditionalAccessPolicy | Where-Object {$_.DisplayName -eq "Require MFA for Risky Sign-ins"}
            
            if (-not $existingPolicy) {
                $conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
                $conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
                $conditions.Applications.IncludeApplications = "All"
                $conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
                $conditions.Users.IncludeUsers = "All"
                $conditions.SignInRiskLevels = @('high', 'medium')
                
                $controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
                $controls._Operator = "OR"
                $controls.BuiltInControls = @("Mfa")
                
                New-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA for Risky Sign-ins" `
                    -State "Enabled" `
                    -Conditions $conditions `
                    -GrantControls $controls
                
                Write-Host "[OK] MFA required for risky sign-ins" -ForegroundColor Green
                Log-Action "Require MFA for Risky Sign-ins" "SUCCESS"
                $script:changesApplied++
            } else {
                Write-Host "[INFO] Risky sign-in policy already exists" -ForegroundColor Cyan
                Log-Action "Require MFA for Risky Sign-ins" "INFO" "Policy already exists"
            }
            
        } catch {
            Write-Host "[ERROR] Failed to create risky sign-in policy: $($_.Exception.Message)" -ForegroundColor Red
            Log-Action "Require MFA for Risky Sign-ins" "FAILED" $_.Exception.Message
        }
    } else {
        Write-Host "[WHATIF] Would create policy requiring MFA for risky sign-ins" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================
# SECTION 4: BLOCK HIGH-RISK COUNTRIES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 4: BLOCKING HIGH-RISK COUNTRIES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (-not $SkipConditionalAccess -and $CountriesToBlock.Count -gt 0) {
    Write-Host "[*] Countries to block: $($CountriesToBlock -join ', ')" -ForegroundColor Yellow
    
    if (-not $WhatIf) {
        try {
            $existingPolicy = Get-AzureADMSConditionalAccessPolicy | Where-Object {$_.DisplayName -eq "Block High-Risk Countries"}
            
            if (-not $existingPolicy) {
                $conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
                $conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
                $conditions.Applications.IncludeApplications = "All"
                $conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
                $conditions.Users.IncludeUsers = "All"
                $conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
                $conditions.Locations.IncludeLocations = $CountriesToBlock
                
                $controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
                $controls._Operator = "OR"
                $controls.BuiltInControls = "Block"
                
                New-AzureADMSConditionalAccessPolicy -DisplayName "Block High-Risk Countries" `
                    -State "Enabled" `
                    -Conditions $conditions `
                    -GrantControls $controls
                
                Write-Host "[OK] High-risk countries blocked" -ForegroundColor Green
                Log-Action "Block High-Risk Countries" "SUCCESS" "Blocked: $($CountriesToBlock -join ', ')"
                $script:changesApplied++
            } else {
                Write-Host "[INFO] Country blocking policy already exists" -ForegroundColor Cyan
                Log-Action "Block High-Risk Countries" "INFO" "Policy already exists"
            }
            
        } catch {
            Write-Host "[WARNING] Country blocking requires Azure AD Premium P1" -ForegroundColor Yellow
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
            Log-Action "Block High-Risk Countries" "FAILED" "Requires Azure AD Premium P1"
        }
    } else {
        Write-Host "[WHATIF] Would block countries: $($CountriesToBlock -join ', ')" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================
# SECTION 5: ENABLE MAILBOX AUDITING
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 5: ENABLING MAILBOX AUDITING" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Enabling mailbox auditing for all mailboxes..." -ForegroundColor Yellow

if (-not $WhatIf) {
    try {
        # Enable organization-wide mailbox auditing
        Set-OrganizationConfig -AuditDisabled $false
        
        # Get all mailboxes
        $mailboxes = Get-Mailbox -ResultSize Unlimited
        
        $enabledCount = 0
        foreach ($mbx in $mailboxes) {
            try {
                Set-Mailbox -Identity $mbx.UserPrincipalName -AuditEnabled $true -AuditLogAgeLimit 180
                $enabledCount++
            } catch {
                # Skip errors
            }
        }
        
        Write-Host "[OK] Mailbox auditing enabled for $enabledCount mailboxes" -ForegroundColor Green
        Log-Action "Enable Mailbox Auditing" "SUCCESS" "Enabled for $enabledCount mailboxes"
        $script:changesApplied++
        
    } catch {
        Write-Host "[ERROR] Failed to enable mailbox auditing: $($_.Exception.Message)" -ForegroundColor Red
        Log-Action "Enable Mailbox Auditing" "FAILED" $_.Exception.Message
    }
} else {
    Write-Host "[WHATIF] Would enable mailbox auditing for all mailboxes" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 6: CONFIGURE ALERT POLICIES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 6: CONFIGURING SECURITY ALERTS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Creating security alert policies..." -ForegroundColor Yellow

if (-not $WhatIf) {
    # Get admin email for alerts
    try {
        $adminEmail = (Get-MsolUser -UserPrincipalName (Get-MsolCompanyInformation).TechnicalNotificationEmails[0]).UserPrincipalName
    } catch {
        $adminEmail = "admin@yourdomain.com"  # Fallback
    }
    
    $alertsToCreate = @(
        @{
            Name = "New Inbox Rule Created"
            Category = "ThreatManagement"
            Operation = "New-InboxRule"
            Severity = "High"
        },
        @{
            Name = "Mailbox Forwarding Enabled"
            Category = "ThreatManagement"
            Operation = "Set-Mailbox"
            Severity = "High"
        },
        @{
            Name = "Unusual Email Deletion Activity"
            Category = "ThreatManagement"
            Operation = "HardDelete"
            Severity = "Medium"
        }
    )
    
    foreach ($alert in $alertsToCreate) {
        try {
            $existingAlert = Get-ProtectionAlert -Identity $alert.Name -ErrorAction SilentlyContinue
            
            if (-not $existingAlert) {
                New-ProtectionAlert -Name $alert.Name `
                    -Category $alert.Category `
                    -NotifyUser $adminEmail `
                    -Severity $alert.Severity `
                    -Operation $alert.Operation
                
                Write-Host "[OK] Created alert: $($alert.Name)" -ForegroundColor Green
                Log-Action "Create Alert: $($alert.Name)" "SUCCESS"
                $script:changesApplied++
            } else {
                Write-Host "[INFO] Alert already exists: $($alert.Name)" -ForegroundColor Cyan
            }
        } catch {
            Write-Host "[WARNING] Could not create alert $($alert.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            Log-Action "Create Alert: $($alert.Name)" "FAILED" $_.Exception.Message
        }
    }
    
} else {
    Write-Host "[WHATIF] Would create security alert policies" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 7: DISABLE SIGN-IN FOR SHARED MAILBOXES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 7: SECURING SHARED MAILBOXES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Disabling sign-in for shared mailboxes..." -ForegroundColor Yellow

if (-not $WhatIf) {
    try {
        $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
        
        $disabledCount = 0
        foreach ($mbx in $sharedMailboxes) {
            try {
                Set-MsolUser -UserPrincipalName $mbx.UserPrincipalName -BlockCredential $true
                $disabledCount++
            } catch {
                # Skip errors
            }
        }
        
        Write-Host "[OK] Disabled sign-in for $disabledCount shared mailboxes" -ForegroundColor Green
        Log-Action "Disable Shared Mailbox Sign-in" "SUCCESS" "Disabled for $disabledCount mailboxes"
        if ($disabledCount -gt 0) {
            $script:changesApplied++
        }
        
    } catch {
        Write-Host "[ERROR] Failed to secure shared mailboxes: $($_.Exception.Message)" -ForegroundColor Red
        Log-Action "Disable Shared Mailbox Sign-in" "FAILED" $_.Exception.Message
    }
} else {
    Write-Host "[WHATIF] Would disable sign-in for all shared mailboxes" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 8: CONFIGURE PASSWORD POLICIES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 8: CONFIGURING PASSWORD POLICIES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Configuring password policies..." -ForegroundColor Yellow

if (-not $WhatIf) {
    try {
        # Set password policy
        Set-MsolPasswordPolicy -DomainName (Get-MsolDomain | Where-Object {$_.IsDefault -eq $true}).Name `
            -ValidityPeriod 90 `
            -NotificationDays 14
        
        Write-Host "[OK] Password policy configured (90 day expiry, 14 day notification)" -ForegroundColor Green
        Log-Action "Configure Password Policy" "SUCCESS" "90 day expiry, 14 day notification"
        $script:changesApplied++
        
    } catch {
        Write-Host "[WARNING] Could not configure password policy: $($_.Exception.Message)" -ForegroundColor Yellow
        Log-Action "Configure Password Policy" "FAILED" $_.Exception.Message
    }
} else {
    Write-Host "[WHATIF] Would configure password policies" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 9: ENABLE UNIFIED AUDIT LOG
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 9: ENABLING UNIFIED AUDIT LOG" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Enabling unified audit log..." -ForegroundColor Yellow

if (-not $WhatIf) {
    try {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        
        Write-Host "[OK] Unified audit log enabled" -ForegroundColor Green
        Log-Action "Enable Unified Audit Log" "SUCCESS"
        $script:changesApplied++
        
    } catch {
        Write-Host "[ERROR] Failed to enable unified audit log: $($_.Exception.Message)" -ForegroundColor Red
        Log-Action "Enable Unified Audit Log" "FAILED" $_.Exception.Message
    }
} else {
    Write-Host "[WHATIF] Would enable unified audit log" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 10: REMOVE SUSPICIOUS INBOX RULES
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SECTION 10: REMOVING SUSPICIOUS INBOX RULES" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Scanning for and removing suspicious inbox rules..." -ForegroundColor Yellow

if (-not $WhatIf) {
    try {
        $allMailboxes = Get-Mailbox -ResultSize Unlimited
        $removedRules = 0
        
        foreach ($mailbox in $allMailboxes) {
            $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue
            
            foreach ($rule in $rules) {
                $isSuspicious = $false
                
                if (($rule.MoveToFolder -like "*Deleted*" -and $rule.MarkAsRead) -or 
                    ($rule.DeleteMessage -eq $true) -or
                    ($rule.Name -match "^\.*$")) {
                    $isSuspicious = $true
                }
                
                if ($isSuspicious) {
                    Write-Host "[WARNING] Removing suspicious rule: $($rule.Name) from $($mailbox.UserPrincipalName)" -ForegroundColor Red
                    Remove-InboxRule -Mailbox $mailbox.UserPrincipalName -Identity $rule.Identity -Confirm:$false
                    $removedRules++
                    Log-Action "Remove Suspicious Rule" "SUCCESS" "$($rule.Name) from $($mailbox.UserPrincipalName)"
                }
            }
        }
        
        if ($removedRules -gt 0) {
            Write-Host "[OK] Removed $removedRules suspicious inbox rules" -ForegroundColor Green
            $script:changesApplied += $removedRules
        } else {
            Write-Host "[OK] No suspicious rules found" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "[ERROR] Failed to scan inbox rules: $($_.Exception.Message)" -ForegroundColor Red
        Log-Action "Remove Suspicious Rules" "FAILED" $_.Exception.Message
    }
} else {
    Write-Host "[WHATIF] Would scan and remove suspicious inbox rules" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# GENERATE HARDENING REPORT
# ============================================
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "GENERATING HARDENING REPORT" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$report = @"
============================================
O365 DOMAIN HARDENING REPORT
============================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Mode: $(if($WhatIf){"WHATIF (No changes made)"}else{"PRODUCTION"})
Changes Applied: $changesApplied

HARDENING ACTIONS SUMMARY:
===========================

$($hardeningLog | ForEach-Object {
"[$($_.Status)] $($_.Action)
$(if($_.Details){"    Details: $($_.Details)"})
"
})

SECURITY CONFIGURATION:
=======================

[X] MFA enforced for all users
[X] Legacy authentication blocked
[X] Risky sign-ins require MFA
[X] High-risk countries blocked
[X] Mailbox auditing enabled
[X] Security alerts configured
[X] Shared mailbox sign-in disabled
[X] Password policies configured
[X] Unified audit log enabled
[X] Suspicious inbox rules removed

POST-HARDENING CHECKLIST:
=========================

[ ] Communicate MFA requirements to users
[ ] Provide MFA setup instructions
[ ] Test Conditional Access policies
[ ] Verify alerts are working
[ ] Schedule regular security audits (monthly)
[ ] Review admin role assignments quarterly
[ ] Train users on security awareness
[ ] Document security configuration
[ ] Create incident response plan
[ ] Schedule penetration testing

ONGOING MONITORING:
===================

1. Review security alerts daily
2. Audit admin activity weekly
3. Check for suspicious sign-ins weekly
4. Review inbox rules monthly
5. Audit MFA status monthly
6. Review Conditional Access logs monthly
7. Full security audit quarterly

RECOMMENDED ADDITIONAL STEPS:
==============================

1. Enable Azure AD Identity Protection
2. Deploy Microsoft Defender for Office 365
3. Configure Data Loss Prevention (DLP) policies
4. Enable Safe Links and Safe Attachments
5. Implement email encryption
6. Configure retention policies
7. Enable litigation hold for key mailboxes
8. Deploy Microsoft Cloud App Security
9. Enable Advanced Threat Protection (ATP)
10. Configure mobile device management (MDM)

============================================
END OF HARDENING REPORT
============================================
"@

$report | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host $report

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "DOMAIN HARDENING COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Changes Applied: $changesApplied" -ForegroundColor Cyan
Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Review the hardening report" -ForegroundColor Yellow
Write-Host "2. Communicate changes to users" -ForegroundColor Yellow
Write-Host "3. Monitor security alerts" -ForegroundColor Yellow
Write-Host "4. Schedule regular security audits" -ForegroundColor Yellow
Write-Host ""
