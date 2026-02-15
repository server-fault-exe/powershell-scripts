# ============================================
# O365 Inbox Rule Investigation Script
# Investigating suspicious rule for Joe@advturbine.com
# Suspicious IP: 185.215.150.68
# ============================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "O365 INBOX RULE BREACH INVESTIGATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Make sure you're connected to Exchange Online first
Write-Host "[*] Checking Exchange Online connection..." -ForegroundColor Yellow
try {
    Get-OrganizationConfig -ErrorAction Stop | Out-Null
    Write-Host "[OK] Connected to Exchange Online" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Not connected. Running connection..." -ForegroundColor Red
    Connect-ExchangeOnline
}

Write-Host ""

# ============================================
# SECTION 1: IP ADDRESS GEOLOCATION
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 1: IP GEOLOCATION LOOKUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$suspiciousIP = "185.215.150.68"

Write-Host "[*] Looking up IP: $suspiciousIP" -ForegroundColor Yellow
try {
    $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/$suspiciousIP"
    
    Write-Host ""
    Write-Host "IP Address: $($ipInfo.query)" -ForegroundColor Red
    Write-Host "Country: $($ipInfo.country)" -ForegroundColor Red
    Write-Host "Region: $($ipInfo.regionName)" -ForegroundColor Red
    Write-Host "City: $($ipInfo.city)" -ForegroundColor Red
    Write-Host "ISP: $($ipInfo.isp)" -ForegroundColor Red
    Write-Host "Organization: $($ipInfo.org)" -ForegroundColor Red
    Write-Host "Timezone: $($ipInfo.timezone)" -ForegroundColor Yellow
    Write-Host ""
} catch {
    Write-Host "[ERROR] Could not lookup IP address" -ForegroundColor Red
}

# ============================================
# SECTION 2: ALL ACTIVITY FROM SUSPICIOUS IP
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 2: ALL ACTIVITY FROM $suspiciousIP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Searching audit logs for activity from this IP (last 30 days)..." -ForegroundColor Yellow

$auditResults = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) `
    -IPAddresses $suspiciousIP `
    -ResultSize 5000

if ($auditResults) {
    Write-Host "[OK] Found $($auditResults.Count) events from this IP" -ForegroundColor Green
    Write-Host ""
    
    foreach ($result in $auditResults) {
        $data = $result.AuditData | ConvertFrom-Json
        
        Write-Host "============================================" -ForegroundColor DarkGray
        Write-Host "Time: $($data.CreationTime)" -ForegroundColor Yellow
        Write-Host "Operation: $($data.Operation)" -ForegroundColor Yellow
        Write-Host "User: $($data.UserId)" -ForegroundColor Yellow
        Write-Host "ClientIP: $($data.ClientIP)" -ForegroundColor Red
        Write-Host "Workload: $($data.Workload)" -ForegroundColor Yellow
        
        # Show parameters if it's a rule operation
        if ($data.Parameters) {
            Write-Host "Parameters:" -ForegroundColor Green
            $data.Parameters | Format-Table Name, Value -AutoSize
        }
        
        # Show important fields for specific operations
        if ($data.Operation -like "*InboxRule*") {
            Write-Host "[WARNING] INBOX RULE OPERATION DETECTED" -ForegroundColor Red
        }
        if ($data.Operation -like "*Forward*") {
            Write-Host "[WARNING] FORWARDING OPERATION DETECTED" -ForegroundColor Red
        }
        
        Write-Host ""
    }
} else {
    Write-Host "[ERROR] No audit results found for this IP" -ForegroundColor Red
}

Write-Host ""

# ============================================
# SECTION 3: ALL INBOX RULES FOR THE USER
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 3: ALL INBOX RULES" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$targetUser = "Joe@advturbine.com"

Write-Host "[*] Checking all inbox rules for $targetUser..." -ForegroundColor Yellow
$rules = Get-InboxRule -Mailbox $targetUser

if ($rules) {
    Write-Host "[OK] Found $($rules.Count) inbox rule(s)" -ForegroundColor Green
    Write-Host ""
    
    foreach ($rule in $rules) {
        Write-Host "============================================" -ForegroundColor DarkGray
        Write-Host "Rule Name: $($rule.Name)" -ForegroundColor Yellow
        Write-Host "Enabled: $($rule.Enabled)" -ForegroundColor $(if($rule.Enabled){"Red"}else{"Green"})
        Write-Host "Created: $($rule.WhenCreated)" -ForegroundColor Yellow
        
        if ($rule.MoveToFolder) {
            Write-Host "[WARNING] Moves to: $($rule.MoveToFolder)" -ForegroundColor Red
        }
        if ($rule.ForwardTo) {
            Write-Host "[WARNING] Forwards to: $($rule.ForwardTo)" -ForegroundColor Red
        }
        if ($rule.RedirectTo) {
            Write-Host "[WARNING] Redirects to: $($rule.RedirectTo)" -ForegroundColor Red
        }
        if ($rule.DeleteMessage) {
            Write-Host "[WARNING] DELETES MESSAGES" -ForegroundColor Red
        }
        if ($rule.MarkAsRead) {
            Write-Host "[WARNING] Marks as read (hides from user)" -ForegroundColor Red
        }
        
        Write-Host ""
    }
} else {
    Write-Host "[OK] No inbox rules found" -ForegroundColor Green
}

Write-Host ""

# ============================================
# SECTION 4: MAILBOX FORWARDING CHECK
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 4: MAILBOX FORWARDING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking for mailbox-level forwarding..." -ForegroundColor Yellow
$mailbox = Get-Mailbox $targetUser | Select-Object ForwardingSmtpAddress, DeliverToMailboxAndForward, ForwardingAddress

if ($mailbox.ForwardingSmtpAddress -or $mailbox.ForwardingAddress) {
    Write-Host "[WARNING] FORWARDING DETECTED!" -ForegroundColor Red
    Write-Host "ForwardingSmtpAddress: $($mailbox.ForwardingSmtpAddress)" -ForegroundColor Red
    Write-Host "ForwardingAddress: $($mailbox.ForwardingAddress)" -ForegroundColor Red
    Write-Host "DeliverToMailboxAndForward: $($mailbox.DeliverToMailboxAndForward)" -ForegroundColor Red
} else {
    Write-Host "[OK] No mailbox-level forwarding configured" -ForegroundColor Green
}

Write-Host ""

# ============================================
# SECTION 5: MAILBOX PERMISSIONS
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 5: MAILBOX PERMISSIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking for suspicious mailbox permissions..." -ForegroundColor Yellow
$permissions = Get-MailboxPermission -Identity $targetUser | Where-Object {$_.User -notlike "NT AUTHORITY\SELF" -and $_.User -notlike "S-1-5-*"}

if ($permissions) {
    Write-Host "[WARNING] Found $($permissions.Count) permission(s):" -ForegroundColor Yellow
    $permissions | Format-Table User, AccessRights, IsInherited -AutoSize
} else {
    Write-Host "[OK] No suspicious mailbox permissions" -ForegroundColor Green
}

Write-Host ""

# ============================================
# SECTION 6: RECENT SIGN-IN ACTIVITY
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 6: RECENT SIGN-IN ACTIVITY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Checking recent sign-ins for $targetUser..." -ForegroundColor Yellow
$signIns = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
    -UserIds $targetUser `
    -Operations "UserLoggedIn" `
    -ResultSize 100

if ($signIns) {
    Write-Host "[OK] Found $($signIns.Count) sign-in events (last 7 days)" -ForegroundColor Green
    Write-Host ""
    
    # Group by IP to find patterns
    $ipGroups = $signIns | ForEach-Object {
        $data = $_.AuditData | ConvertFrom-Json
        [PSCustomObject]@{
            Time = $data.CreationTime
            IP = $data.ClientIP
            UserAgent = $data.ExtendedProperties | Where-Object {$_.Name -eq "UserAgent"} | Select-Object -ExpandProperty Value
        }
    } | Group-Object IP
    
    Write-Host "Sign-ins grouped by IP address:" -ForegroundColor Yellow
    foreach ($group in $ipGroups | Sort-Object Count -Descending) {
        $color = if ($group.Name -eq $suspiciousIP) { "Red" } else { "White" }
        Write-Host "  $($group.Name): $($group.Count) sign-ins" -ForegroundColor $color
    }
} else {
    Write-Host "[ERROR] No sign-in events found" -ForegroundColor Yellow
}

Write-Host ""

# ============================================
# SECTION 7: RECOMMENDATIONS
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 7: IMMEDIATE ACTIONS REQUIRED" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. RESET PASSWORD for $targetUser immediately" -ForegroundColor Red
Write-Host "   Command: Set-MsolUserPassword -UserPrincipalName $targetUser -ForceChangePassword `$true" -ForegroundColor Gray
Write-Host ""

Write-Host "2. REVOKE ALL SESSIONS for $targetUser" -ForegroundColor Red
Write-Host "   Command: Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -ObjectId $targetUser).ObjectId" -ForegroundColor Gray
Write-Host ""

Write-Host "3. DELETE SUSPICIOUS INBOX RULE" -ForegroundColor Red
Write-Host "   Command: Remove-InboxRule -Mailbox $targetUser -Identity '......'" -ForegroundColor Gray
Write-Host ""

Write-Host "4. ENABLE MFA if not already enabled" -ForegroundColor Red
Write-Host ""

Write-Host "5. REVIEW mailbox for deleted/compromised emails" -ForegroundColor Yellow
Write-Host ""

Write-Host "6. CHECK for data exfiltration from this IP" -ForegroundColor Yellow
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "INVESTIGATION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
