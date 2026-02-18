# ========================================
# MAILBOX DECOMMISSIONING SCRIPT v12
# Back to basics - what actually worked + manual alias removal
# ========================================

# Prompt for variables
Write-Host "=== MAILBOX DECOMMISSIONING SCRIPT ===" -ForegroundColor Cyan
Write-Host ""

$UserEmail = Read-Host "Enter the email address to decommission (e.g., user@bfcmiami.com)"
$AdminEmail = Read-Host "Enter the admin email to receive the alias (e.g., admin@bfcmiami.com)"

# Auto-generate archived names
$UserName = $UserEmail.Split("@")[0]
$Domain = $UserEmail.Split("@")[1]
$NewUserEmail = "archived.$UserName@$Domain"
$NewDisplayName = "Archived.$UserName"

Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Yellow
Write-Host "Decommissioning: $UserEmail"
Write-Host "New mailbox name: $NewUserEmail"
Write-Host "New display name: $NewDisplayName"
Write-Host "Admin receiving alias: $AdminEmail"
Write-Host ""

$Confirm = Read-Host "Continue? (Y/N)"
if ($Confirm -ne "Y" -and $Confirm -ne "y") {
    Write-Host "Script cancelled." -ForegroundColor Red
    exit
}

# ========================================
# STEP 1: CHECK GROUP MEMBERSHIPS
# ========================================
Write-Host "`n=== STEP 1: Checking group memberships ===" -ForegroundColor Cyan

Write-Host "`nDistribution Groups:" -ForegroundColor Yellow
$DistGroups = Get-DistributionGroup | Where-Object {
    (Get-DistributionGroupMember $_.Identity | ForEach-Object {$_.PrimarySmtpAddress}) -contains $UserEmail
}
if ($DistGroups) {
    $DistGroups | Select-Object Name | Format-Table
} else {
    Write-Host "  (None found)" -ForegroundColor Gray
}

Write-Host "Microsoft 365 Groups:" -ForegroundColor Yellow
$M365Groups = Get-UnifiedGroup | Where-Object {
    (Get-UnifiedGroupLinks $_.Identity -LinkType Members | ForEach-Object {$_.PrimarySmtpAddress}) -contains $UserEmail
}
if ($M365Groups) {
    $M365Groups | Select-Object DisplayName | Format-Table
} else {
    Write-Host "  (None found)" -ForegroundColor Gray
}

Write-Host ""
Read-Host "Press Enter to continue with removal from groups"

# ========================================
# STEP 2: REMOVE FROM GROUPS
# ========================================
Write-Host "`n=== STEP 2: Removing from groups ===" -ForegroundColor Cyan

if ($DistGroups) {
    Write-Host "Removing from distribution groups..." -ForegroundColor Green
    foreach ($Group in $DistGroups) {
        try {
            Remove-DistributionGroupMember -Identity $Group.Identity -Member $UserEmail -Confirm:$false -ErrorAction Stop
            Write-Host "  ✓ Removed from: $($Group.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Error removing from $($Group.Name): $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No distribution groups to remove" -ForegroundColor Gray
}

if ($M365Groups) {
    Write-Host "Removing from Microsoft 365 groups..." -ForegroundColor Green
    foreach ($Group in $M365Groups) {
        try {
            Remove-UnifiedGroupLinks -Identity $Group.Identity -LinkType Members -Links $UserEmail -Confirm:$false -ErrorAction Stop
            Write-Host "  ✓ Removed from: $($Group.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Error removing from $($Group.DisplayName): $_" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No Microsoft 365 groups to remove" -ForegroundColor Gray
}

# ========================================
# STEP 3: GET MAILBOX INFO
# ========================================
Write-Host "`n=== STEP 3: Getting mailbox info ===" -ForegroundColor Cyan

$Mailbox = Get-Mailbox -Identity $UserEmail

Write-Host "Current mailbox:" -ForegroundColor Yellow
Write-Host "  Display Name: $($Mailbox.DisplayName)"
Write-Host "  Primary Email: $($Mailbox.PrimarySmtpAddress)"
Write-Host "  Type: $($Mailbox.RecipientTypeDetails)"

Write-Host "`nCurrent addresses:" -ForegroundColor Yellow
$Mailbox.EmailAddresses | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

# ========================================
# STEP 4: CHANGE PRIMARY EMAIL AND DISPLAY NAME
# ========================================
Write-Host "`n=== STEP 4: Changing primary email and display name ===" -ForegroundColor Cyan

try {
    Set-Mailbox -Identity $UserEmail `
        -WindowsEmailAddress $NewUserEmail `
        -DisplayName $NewDisplayName `
        -ErrorAction Stop
    
    Write-Host "  ✓ Changed primary email to $NewUserEmail" -ForegroundColor Green
    Write-Host "  ✓ Changed display name to $NewDisplayName" -ForegroundColor Green
    Start-Sleep -Seconds 5
} catch {
    Write-Host "  ✗ Error: $_" -ForegroundColor Red
}

# ========================================
# STEP 5: MANUAL ALIAS REMOVAL
# ========================================
Write-Host "`n" + ("=" * 70) -ForegroundColor Red
Write-Host "⚠️  MANUAL INTERVENTION REQUIRED ⚠️" -ForegroundColor Yellow
Write-Host ("=" * 70) -ForegroundColor Red
Write-Host ""
Write-Host "TIME TO BEAT MICROSOFT AT THEIR OWN BROKEN GAME!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Go to Exchange Admin Center and do the following:" -ForegroundColor Yellow
Write-Host "  1. Find the user: $NewUserEmail" -ForegroundColor White
Write-Host "  2. Go to 'Manage username and email'" -ForegroundColor White
Write-Host "  3. Remove the alias: $UserEmail" -ForegroundColor White
Write-Host "  4. Click Save (it will probably come back - Microsoft is stupid)" -ForegroundColor White
Write-Host "  5. Remove it AGAIN" -ForegroundColor White
Write-Host "  6. Remove it a THIRD time if needed" -ForegroundColor White
Write-Host "  7. Keep removing until it STAYS gone" -ForegroundColor White
Write-Host ""
Write-Host "Meanwhile, this script will be waiting for Microsoft's stupid-ass" -ForegroundColor Magenta
Write-Host "servers to propagate the changes through their janky infrastructure..." -ForegroundColor Magenta
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Red
Write-Host ""

# Animated waiting
Write-Host "Waiting for you to finish kicking Microsoft's ass" -NoNewline -ForegroundColor Yellow
for ($i = 0; $i -lt 10; $i++) {
    Start-Sleep -Seconds 1
    Write-Host "." -NoNewline -ForegroundColor Yellow
}
Write-Host ""
Write-Host ""

Read-Host "Press Enter when you've successfully removed the alias and it stayed gone"

Write-Host "`n  ✓ Nice! You beat Microsoft's bug!" -ForegroundColor Green
Write-Host "  Now waiting 10 more seconds for their servers to catch up..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# ========================================
# STEP 6: VERIFY ALIAS IS GONE
# ========================================
Write-Host "`n=== STEP 6: Verifying the alias is actually gone ===" -ForegroundColor Cyan

$VerifyMailbox = Get-Mailbox -Identity $NewUserEmail
$StillHasIt = $VerifyMailbox.EmailAddresses -contains "smtp:$UserEmail" -or $VerifyMailbox.EmailAddresses -contains "SMTP:$UserEmail"

if ($StillHasIt) {
    Write-Host "  ✗ WAIT! The alias is STILL THERE!" -ForegroundColor Red
    Write-Host "  Microsoft's servers haven't caught up yet..." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Go remove it one more time, then press Enter"
    Start-Sleep -Seconds 10
} else {
    Write-Host "  ✓ CONFIRMED: Alias is GONE! Fuck you Microsoft!" -ForegroundColor Green
}

# ========================================
# STEP 7: CONVERT TO SHARED MAILBOX
# ========================================
Write-Host "`n=== STEP 7: Converting to shared mailbox ===" -ForegroundColor Cyan

try {
    Set-Mailbox -Identity $NewUserEmail -Type Shared -ErrorAction Stop
    Write-Host "  ✓ Converted to shared mailbox (license will be auto-removed)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Error converting to shared: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 5

# ========================================
# STEP 8: ADD OLD EMAIL AS ALIAS TO ADMIN
# ========================================
Write-Host "`n=== STEP 8: Adding alias to admin mailbox ===" -ForegroundColor Cyan

$MaxRetries = 5
$RetryCount = 0
$Success = $false

while ($RetryCount -lt $MaxRetries -and -not $Success) {
    try {
        Set-Mailbox -Identity $AdminEmail -EmailAddresses @{Add="$UserEmail"} -ErrorAction Stop
        Write-Host "  ✓ SUCCESS: Added $UserEmail as alias to $AdminEmail" -ForegroundColor Green
        $Success = $true
    } catch {
        $RetryCount++
        if ($RetryCount -lt $MaxRetries) {
            Write-Host "  ✗ Attempt ${RetryCount} failed" -ForegroundColor Yellow
            Write-Host "  Waiting 15 seconds before retry $($RetryCount + 1)..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
        } else {
            Write-Host "  ✗ Failed after $MaxRetries attempts" -ForegroundColor Red
            Write-Host "`n  MANUAL STEP REQUIRED:" -ForegroundColor Red
            Write-Host "  Wait 10-15 minutes, then run:" -ForegroundColor Yellow
            Write-Host "  Set-Mailbox -Identity '$AdminEmail' -EmailAddresses @{Add='$UserEmail'}" -ForegroundColor Cyan
        }
    }
}

# ========================================
# STEP 9: GRANT ADMIN ACCESS TO SHARED MAILBOX
# ========================================
Write-Host "`n=== STEP 9: Granting admin access to shared mailbox ===" -ForegroundColor Cyan

Start-Sleep -Seconds 5

try {
    Add-MailboxPermission -Identity $NewUserEmail -User $AdminEmail -AccessRights FullAccess -InheritanceType All -ErrorAction Stop
    Write-Host "  ✓ Granted $AdminEmail full access to $NewUserEmail" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Error granting permissions: $_" -ForegroundColor Yellow
    Write-Host "  Run this later:" -ForegroundColor Yellow
    Write-Host "  Add-MailboxPermission -Identity '$NewUserEmail' -User '$AdminEmail' -AccessRights FullAccess -InheritanceType All" -ForegroundColor Cyan
}

# ========================================
# STEP 10: FINAL VERIFICATION
# ========================================
Write-Host "`n=== STEP 10: Final Verification ===" -ForegroundColor Cyan

Start-Sleep -Seconds 3

try {
    $ArchivedMailbox = Get-Mailbox -Identity $NewUserEmail -ErrorAction Stop
    Write-Host "`n✓ Archived mailbox found:" -ForegroundColor Green
    Write-Host "  Display Name: $($ArchivedMailbox.DisplayName)"
    Write-Host "  Type: $($ArchivedMailbox.RecipientTypeDetails)"
    Write-Host "  Primary Email: $($ArchivedMailbox.PrimarySmtpAddress)"
    Write-Host "`n  Email addresses:" -ForegroundColor Yellow
    $ArchivedMailbox.EmailAddresses | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    
    # Double check the old email is NOT on this mailbox
    $HasOldEmail = $ArchivedMailbox.EmailAddresses -contains "smtp:$UserEmail" -or $ArchivedMailbox.EmailAddresses -contains "SMTP:$UserEmail"
    
    if ($HasOldEmail) {
        Write-Host "`n  ✗ WARNING: Old email $UserEmail is STILL on this mailbox!" -ForegroundColor Red
    } else {
        Write-Host "`n  ✓ Confirmed: Old email $UserEmail is NOT on this mailbox" -ForegroundColor Green
    }
} catch {
    Write-Host "`n✗ Could not find mailbox at $NewUserEmail" -ForegroundColor Red
}

$AdminMailbox = Get-Mailbox -Identity $AdminEmail
$HasAlias = $AdminMailbox.EmailAddresses -contains "smtp:$UserEmail"

Write-Host "`nAdmin mailbox check:" -ForegroundColor Yellow
if ($HasAlias) {
    Write-Host "  ✓ $UserEmail is now an alias on $AdminEmail" -ForegroundColor Green
} else {
    Write-Host "  ✗ $UserEmail is NOT yet on $AdminEmail" -ForegroundColor Red
    Write-Host "  Run manually after waiting:" -ForegroundColor Yellow
    Write-Host "  Set-Mailbox -Identity '$AdminEmail' -EmailAddresses @{Add='$UserEmail'}" -ForegroundColor Cyan
}

# ========================================
# COMPLETION SUMMARY
# ========================================
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
if ($Success) {
    Write-Host "🎉 DECOMMISSIONING COMPLETE! 🎉" -ForegroundColor Green
    Write-Host "You beat Microsoft's broken alias system!" -ForegroundColor Green
} else {
    Write-Host "⚠️  DECOMMISSIONING PARTIALLY COMPLETE ⚠️" -ForegroundColor Yellow
}
Write-Host ("=" * 60) -ForegroundColor Cyan

Write-Host "`nSummary:" -ForegroundColor Yellow
Write-Host "  Original email: $UserEmail"
Write-Host "  New mailbox: $NewUserEmail (Shared)"
Write-Host "  Display name: $NewDisplayName"
if ($Success) {
    Write-Host "  Alias forwarding: ✓ $UserEmail → $AdminEmail" -ForegroundColor Green
} else {
    Write-Host "  Alias forwarding: ✗ Pending manual addition" -ForegroundColor Yellow
}
Write-Host ""