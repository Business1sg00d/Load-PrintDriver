# References:
# https://www.blumira.com/blog/cve-2021-1675
# https://github.com/cube0x0/CVE-2021-1675

# Check if spooler is running.
Get-CimInstance -ClassName Win32_Service | ? {($_.Name -match "Spooler") -and ($_.State -match "Running")}
echo ""

# Who can munipulate the Printers registry configurations? Parse this manually. Look for "Write*" and "FullControl".
(ConvertFrom-SddlString -Sddl (Get-ACL -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint").sddl).DiscretionaryACL

# Get the raw SDDL for the spooler service
$sddl = (sc.exe sdshow spooler) -join "" -replace "\s",""

# Extract all ACEs from the SDDL (DACL section starts with 'D:')
$acePattern = '\(A;;([A-Z]+);;;([^)]+)\)'
$matches = [regex]::Matches($sddl, $acePattern)

# Define service start/stop rights
$targetRights = @('RP', 'WP')  # RP = start, WP = stop

$results = @()

foreach ($match in $matches) {
    $rights = $match.Groups[1].Value
    $sid = $match.Groups[2].Value

    # Check if the ACE contains either RP (start) or WP (stop)
    if ($targetRights | Where-Object { $rights -like "*$_*" }) {
        try {
            $account = try { (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]) } catch { $sid }
            $results += [PSCustomObject]@{
                Account = $account
                Start_Stop_Rights = $rights
            }
        } catch {
            Write-Warning "Failed to resolve SID: $sid"
        }
    }
}

# Output results
$results | Sort-Object Account | Format-Table -AutoSize



