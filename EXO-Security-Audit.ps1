# ============================================
# EXCHANGE ONLINE SECURITY AUDIT SCRIPT
# Organization: advturbine.onmicrosoft.com
# ============================================

# Ensure we're connected to Exchange Online
Write-Host "Checking Exchange Online connection..." -ForegroundColor Yellow
try {
    $org = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "✓ Connected to: $($org.Name)" -ForegroundColor Green
} catch {
    Write-Host "✗ Not connected to Exchange Online. Run: Connect-ExchangeOnline" -ForegroundColor Red
    exit
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   EXCHANGE ONLINE SECURITY AUDIT" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Create results object
$auditResults = @()

# ============================================
# 1. AUTHENTICATION POLICIES
# ============================================
Write-Host "[1/12] Authentication Policies & OAuth Configuration" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$authPolicies = Get-AuthenticationPolicy
if ($authPolicies) {
    $authPolicies | Format-Table Name, AllowBasicAuthSmtp, AllowBasicAuthImap, AllowBasicAuthPop, AllowBasicAuthMapi -AutoSize
} else {
    Write-Host "⚠ No authentication policies configured" -ForegroundColor Yellow
}

$orgConfig = Get-OrganizationConfig
Write-Host "Default Auth Policy: $($orgConfig.DefaultAuthenticationPolicy)" -ForegroundColor White
Write-Host "OAuth2 Enabled: $($orgConfig.OAuth2ClientProfileEnabled)" -ForegroundColor White
Write-Host ""

# ============================================
# 2. SMTP RELAY & CONNECTORS
# ============================================
Write-Host "[2/12] SMTP Relay & Connector Configuration" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

Write-Host "`nInbound Connectors:" -ForegroundColor Cyan
$inboundConnectors = Get-InboundConnector
if ($inboundConnectors) {
    foreach ($connector in $inboundConnectors) {
        Write-Host "  Name: $($connector.Name)" -ForegroundColor White
        Write-Host "    Enabled: $($connector.Enabled)" -ForegroundColor White
        Write-Host "    Type: $($connector.ConnectorType)" -ForegroundColor White
        Write-Host "    Sender IPs: $($connector.SenderIPAddresses -join ', ')" -ForegroundColor White
        Write-Host "    IP Restricted: $($connector.RestrictDomainsToIPAddresses)" -ForegroundColor White
        Write-Host "    Sender Domains: $($connector.SenderDomains -join ', ')" -ForegroundColor White
        
        # Security check
        if (-not $connector.RestrictDomainsToIPAddresses) {
            Write-Host "    ⚠ WARNING: Not restricted to specific IPs - potential open relay!" -ForegroundColor Red
        }
        Write-Host ""
    }
} else {
    Write-Host "  No inbound connectors configured" -ForegroundColor Yellow
}

Write-Host "SMTP Client Auth Disabled (Org): $($orgConfig.SmtpClientAuthenticationDisabled)" -ForegroundColor White
Write-Host ""

# ============================================
# 3. LEGACY PROTOCOL ACCESS
# ============================================
Write-Host "[3/12] Legacy Protocol Access (POP/IMAP/ActiveSync)" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

Write-Host "Scanning all mailboxes for protocol access..." -ForegroundColor Yellow
$allMailboxes = Get-Mailbox -ResultSize Unlimited
$casMailboxes = $allMailboxes | Get-CasMailbox

$popEnabled = ($casMailboxes | Where-Object {$_.PopEnabled -eq $true}).Count
$imapEnabled = ($casMailboxes | Where-Object {$_.ImapEnabled -eq $true}).Count
$activeSyncEnabled = ($casMailboxes | Where-Object {$_.ActiveSyncEnabled -eq $true}).Count

Write-Host "Total Mailboxes: $($allMailboxes.Count)" -ForegroundColor White
Write-Host "POP Enabled: $popEnabled" -ForegroundColor $(if ($popEnabled -gt 0) {'Yellow'} else {'Green'})
Write-Host "IMAP Enabled: $imapEnabled" -ForegroundColor $(if ($imapEnabled -gt 0) {'Yellow'} else {'Green'})
Write-Host "ActiveSync Enabled: $activeSyncEnabled" -ForegroundColor $(if ($activeSyncEnabled -gt 0) {'Yellow'} else {'Green'})

if ($popEnabled -gt 0 -or $imapEnabled -gt 0) {
    Write-Host "`n⚠ Mailboxes with legacy protocols enabled:" -ForegroundColor Yellow
    $casMailboxes | Where-Object {$_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true} | 
        Select-Object -First 10 DisplayName, PopEnabled, ImapEnabled, ActiveSyncEnabled | 
        Format-Table -AutoSize
    if (($casMailboxes | Where-Object {$_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true}).Count -gt 10) {
        Write-Host "  ... and $((($casMailboxes | Where-Object {$_.PopEnabled -eq $true -or $_.ImapEnabled -eq $true}).Count) - 10) more" -ForegroundColor Gray
    }
}
Write-Host ""

# ============================================
# 4. SHARED & EQUIPMENT MAILBOXES
# ============================================
Write-Host "[4/12] Shared & Equipment Mailbox Security" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox,EquipmentMailbox
Write-Host "Total Shared/Equipment Mailboxes: $($sharedMailboxes.Count)" -ForegroundColor White

if ($sharedMailboxes.Count -gt 0) {
    $sharedMailboxes | Get-CasMailbox | 
        Select-Object DisplayName, PopEnabled, ImapEnabled, ActiveSyncEnabled, SmtpClientAuthenticationDisabled | 
        Format-Table -AutoSize
}
Write-Host ""

# ============================================
# 5. AUDIT LOGGING
# ============================================
Write-Host "[5/12] Audit & Logging Configuration" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

Write-Host "Org Audit Disabled: $($orgConfig.AuditDisabled)" -ForegroundColor $(if ($orgConfig.AuditDisabled) {'Red'} else {'Green'})

$auditEnabledCount = ($allMailboxes | Where-Object {$_.AuditEnabled -eq $true}).Count
Write-Host "Mailboxes with Audit Enabled: $auditEnabledCount / $($allMailboxes.Count)" -ForegroundColor White

if ($auditEnabledCount -lt $allMailboxes.Count) {
    Write-Host "⚠ Some mailboxes do not have auditing enabled" -ForegroundColor Yellow
}
Write-Host ""

# ============================================
# 6. TRANSPORT RULES
# ============================================
Write-Host "[6/12] Mail Flow Transport Rules" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$transportRules = Get-TransportRule
Write-Host "Total Transport Rules: $($transportRules.Count)" -ForegroundColor White

if ($transportRules.Count -gt 0) {
    $transportRules | Select-Object Name, State, Priority, @{Name="Description";Expression={$_.Description.Substring(0, [Math]::Min(50, $_.Description.Length))}} | 
        Format-Table -AutoSize
}
Write-Host ""

# ============================================
# 7. ANTI-SPAM POLICIES
# ============================================
Write-Host "[7/12] Anti-Spam & Content Filter Policies" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$spamPolicies = Get-HostedContentFilterPolicy
Write-Host "Content Filter Policies: $($spamPolicies.Count)" -ForegroundColor White
$spamPolicies | Select-Object Name, IsDefault, EnableLanguageBlockList, EnableRegionBlockList, SpamAction | Format-Table -AutoSize
Write-Host ""

# ============================================
# 8. ANTI-MALWARE POLICIES
# ============================================
Write-Host "[8/12] Anti-Malware Policies" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$malwarePolicies = Get-MalwareFilterPolicy
Write-Host "Malware Filter Policies: $($malwarePolicies.Count)" -ForegroundColor White
$malwarePolicies | Select-Object Name, IsDefault, Action, EnableInternalSenderAdminNotifications | Format-Table -AutoSize
Write-Host ""

# ============================================
# 9. EXTERNAL FORWARDING
# ============================================
Write-Host "[9/12] External Email Forwarding" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$forwardingMailboxes = $allMailboxes | Where-Object {$_.ForwardingSmtpAddress -ne $null -or $_.ForwardingAddress -ne $null}
Write-Host "Mailboxes with External Forwarding: $($forwardingMailboxes.Count)" -ForegroundColor $(if ($forwardingMailboxes.Count -gt 0) {'Yellow'} else {'Green'})

if ($forwardingMailboxes.Count -gt 0) {
    Write-Host "`n⚠ External forwarding detected:" -ForegroundColor Yellow
    $forwardingMailboxes | Select-Object DisplayName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward | Format-Table -AutoSize
}
Write-Host ""

# ============================================
# 10. MAILBOX PERMISSIONS
# ============================================
Write-Host "[10/12] Delegated Mailbox Access" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

Write-Host "Scanning first 20 mailboxes for delegated permissions..." -ForegroundColor Yellow
$delegatedAccess = $allMailboxes | Select-Object -First 20 | Get-MailboxPermission | 
    Where-Object {$_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5*" -and $_.IsInherited -eq $false}

if ($delegatedAccess) {
    Write-Host "`nDelegated permissions found:" -ForegroundColor Yellow
    $delegatedAccess | Select-Object Identity, User, AccessRights | Format-Table -AutoSize
} else {
    Write-Host "No unusual delegated permissions found in sample" -ForegroundColor Green
}
Write-Host ""

# ============================================
# 11. RETENTION & COMPLIANCE
# ============================================
Write-Host "[11/12] Retention & Compliance Policies" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

$retentionPolicies = Get-RetentionPolicy
Write-Host "Retention Policies: $($retentionPolicies.Count)" -ForegroundColor White
if ($retentionPolicies) {
    $retentionPolicies | Select-Object Name, IsDefault, RetentionPolicyTagLinks | Format-Table -AutoSize
}

$litigationHolds = $allMailboxes | Where-Object {$_.LitigationHoldEnabled -eq $true}
Write-Host "Mailboxes on Litigation Hold: $($litigationHolds.Count)" -ForegroundColor White
Write-Host ""

# ============================================
# 12. MOBILE DEVICES
# ============================================
Write-Host "[12/12] Mobile Device Access" -ForegroundColor Green
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Gray

try {
    $mobileDevices = Get-MobileDevice -ResultSize 100
    Write-Host "Mobile Devices Registered: $($mobileDevices.Count)" -ForegroundColor White
    
    $recentDevices = $mobileDevices | Where-Object {$_.WhenChanged -gt (Get-Date).AddDays(-30)}
    Write-Host "Devices Active (Last 30 Days): $($recentDevices.Count)" -ForegroundColor White
} catch {
    Write-Host "Unable to enumerate mobile devices (may require additional permissions)" -ForegroundColor Yellow
}
Write-Host ""

# ============================================
# SECURITY SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   SECURITY SUMMARY" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

$findings = @()

# Check for issues
if (-not $orgConfig.DefaultAuthenticationPolicy) {
    $findings += "⚠ No default authentication policy set"
}

if ($inboundConnectors | Where-Object {-not $_.RestrictDomainsToIPAddresses}) {
    $findings += "⚠ SMTP relay not restricted to specific IPs - CRITICAL"
}

if ($popEnabled -gt 0 -or $imapEnabled -gt 0) {
    $findings += "⚠ Legacy protocols (POP/IMAP) enabled on $($popEnabled + $imapEnabled) mailboxes"
}

if ($forwardingMailboxes.Count -gt 0) {
    $findings += "⚠ External forwarding enabled on $($forwardingMailboxes.Count) mailboxes"
}

if ($orgConfig.AuditDisabled) {
    $findings += "⚠ Organization audit logging is DISABLED - CRITICAL"
}

if ($findings.Count -eq 0) {
    Write-Host "✓ No critical security issues found!" -ForegroundColor Green
} else {
    Write-Host "Security Findings:" -ForegroundColor Yellow
    foreach ($finding in $findings) {
        Write-Host "  $finding" -ForegroundColor Yellow
    }
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "   AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

# Export option
$export = Read-Host "Export detailed results to CSV? (y/n)"
if ($export -eq 'y') {
    $exportPath = "C:\Temp\EXO_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    # Create export directory if doesn't exist
    if (-not (Test-Path "C:\Temp")) {
        New-Item -ItemType Directory -Path "C:\Temp" | Out-Null
    }
    
    # Compile export data
    $exportData = [PSCustomObject]@{
        AuditDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Organization = $org.Name
        DefaultAuthPolicy = $orgConfig.DefaultAuthenticationPolicy
        OAuth2Enabled = $orgConfig.OAuth2ClientProfileEnabled
        SMTPAuthDisabled = $orgConfig.SmtpClientAuthenticationDisabled
        AuditDisabled = $orgConfig.AuditDisabled
        TotalMailboxes = $allMailboxes.Count
        POPEnabled = $popEnabled
        IMAPEnabled = $imapEnabled
        ActiveSyncEnabled = $activeSyncEnabled
        ExternalForwarding = $forwardingMailboxes.Count
        SharedMailboxes = $sharedMailboxes.Count
        TransportRules = $transportRules.Count
        MalwarePolicies = $malwarePolicies.Count
        SpamPolicies = $spamPolicies.Count
    }
    
    $exportData | Export-Csv -Path $exportPath -NoTypeInformation
    Write-Host "✓ Results exported to: $exportPath" -ForegroundColor Green
}
