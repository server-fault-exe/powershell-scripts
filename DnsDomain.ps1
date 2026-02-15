function Get-AllDnsRecords {
    param(
        [string]$Domain,
        [switch]$ExportToCsv
    )
    
    # Ask for domain if not provided
    if (-not $Domain) {
        $Domain = Read-Host "Enter the domain to lookup (e.g., google.com)"
    }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "DNS RECORDS FOR: $Domain" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $AllRecords = @()
    $RecordTypes = @('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA')
    
    foreach ($Type in $RecordTypes) {
        Write-Host "`n[$Type Records]" -ForegroundColor Yellow
        
        try {
            $Records = Resolve-DnsName -Name $Domain -Type $Type -ErrorAction SilentlyContinue
            
            if ($Records) {
                foreach ($Record in $Records) {
                    $RecordData = switch ($Record.Type) {
                        'A' { $Record.IPAddress }
                        'AAAA' { $Record.IPAddress }
                        'MX' { "$($Record.Preference) $($Record.NameExchange)" }
                        'NS' { $Record.NameHost }
                        'TXT' { ($Record.Strings -join ' ') }
                        'CNAME' { $Record.NameHost }
                        'SOA' { "Primary: $($Record.PrimaryServer), Serial: $($Record.SerialNumber)" }
                        'SRV' { "Priority: $($Record.Priority), Weight: $($Record.Weight), Port: $($Record.Port), Target: $($Record.NameTarget)" }
                        'CAA' { "$($Record.Tag) $($Record.Value)" }
                        default { $Record | Out-String }
                    }
                    
                    $RecordObj = [PSCustomObject]@{
                        Domain = $Domain
                        Type = $Record.Type
                        Name = $Record.Name
                        TTL = $Record.TTL
                        Data = $RecordData
                    }
                    
                    $AllRecords += $RecordObj
                    
                    Write-Host "  $($Record.Name)" -NoNewline -ForegroundColor White
                    Write-Host " → " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$RecordData" -ForegroundColor Cyan
                    Write-Host "    TTL: $($Record.TTL) seconds" -ForegroundColor Gray
                }
            } else {
                Write-Host "  (None found)" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "Total records found: $($AllRecords.Count)" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    if ($ExportToCsv) {
        $OutputPath = "C:\DNS_Records_$Domain.csv"
        $AllRecords | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Host "`nExported to: $OutputPath" -ForegroundColor Yellow
    }
    
    return $AllRecords
}

# Just run it - it'll ask for the domain
Get-AllDnsRecords