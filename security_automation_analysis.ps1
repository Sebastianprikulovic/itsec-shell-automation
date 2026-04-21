param(
    [string]$UsersFile = ".\security_users_input.csv",
    [string]$EventsFile = ".\security_events_input.json"
)

Write-Host "Startar säkerhetsanalys..."

# Läs CSV
$users = Import-Csv $UsersFile

# Läs JSON
$events = Get-Content $EventsFile -Raw | ConvertFrom-Json

$results = @()

foreach ($user in $users) {

    $userEvents = $events | Where-Object {
        $_.username -eq $user.username
    }

    $score = 0
    $findings = @()

    # Regel 1 – nattlogin
    $nightLogin = $userEvents | Where-Object {
        $_.event_type -eq "login" -and
        (([datetime]$_.timestamp).Hour -ge 23 -or ([datetime]$_.timestamp).Hour -lt 5)
    }

    if ($nightLogin) {
        $score += 20
        $findings += "Nattlig inloggning"
    }

    # Regel 2 – många failed logins
    $failed = $userEvents | Where-Object {
        $_.status -eq "failed"
    }

    if ($failed.Count -ge 3) {
        $score += 25
        $findings += "Många misslyckade inloggningar"
    }

    # Regel 3 – stor filåtkomst
    $largeFile = $userEvents | Where-Object {
        $_.bytes_accessed -ge 1000000
    }

    if ($largeFile) {
        $score += 20
        $findings += "Stor filåtkomst"
    }

    # Kombinationsregel
    if ($nightLogin -and $failed.Count -ge 3) {
        $score += 30
        $findings += "Kombinationsregel: natt + brute force"
    }

    # Riskklass
    $risk = "LOW"

    if ($score -ge 80) {
        $risk = "CRITICAL"
    }
    elseif ($score -ge 50) {
        $risk = "HIGH"
    }
    elseif ($score -ge 25) {
        $risk = "MEDIUM"
    }

    $results += [PSCustomObject]@{
        Username = $user.username
        Score = $score
        Risk = $risk
        Findings = ($findings -join ", ")
    }
}

# Skapa rapport
$results | Export-Csv "risk_report.csv" -NoTypeInformation

Write-Host "Analys klar. Rapport skapad: risk_report.csv"