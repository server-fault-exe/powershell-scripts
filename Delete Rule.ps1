# Reconnect to Exchange Online
Connect-ExchangeOnline

# Set target user again
$TargetUser = "joe@advturbine.com"

# Now run the deletion script
Write-Host "============================================" -ForegroundColor Red
Write-Host "STEP 5: REMOVING MALICIOUS INBOX RULES" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Red
Write-Host ""
Write-Host "[*] Retrieving inbox rules..." -ForegroundColor Yellow
try {
    $rules = Get-InboxRule -Mailbox $TargetUser -ErrorAction Stop
    
    if ($rules) {
        Write-Host "[WARNING] Found $($rules.Count) rule(s):" -ForegroundColor Yellow
        $deletedCount = 0
        
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
                    Remove-InboxRule -Identity $rule.Identity -Confirm:$false -ErrorAction Stop
                    Write-Host "[OK] Deleted rule: $($rule.Name)" -ForegroundColor Green
                    $deletedCount++
                } catch {
                    Write-Host "[ERROR] Failed to delete rule: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
        
        Write-Host ""
        Write-Host "[SUMMARY] Deleted $deletedCount malicious rule(s)" -ForegroundColor $(if($deletedCount -gt 0){"Green"}else{"Gray"})
    } else {
        Write-Host "[OK] No inbox rules found" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to retrieve inbox rules: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Disconnect when done
Disconnect-ExchangeOnline -Confirm:$false
Write-Host "[OK] Disconnected from Exchange Online" -ForegroundColor Green