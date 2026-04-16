param(
    [string]$InputFile = ".\AI_UserSecurityData.csv",
    [string]$OutputFile = ".\AI_Risk_Report.csv"
)

function Get-RiskLevel {
    param(
        [int]$Score
    )

    if ($Score -ge 9) {
        return "CRITICAL"
    }
    elseif ($Score -ge 6) {
        return "HIGH"
    }
    elseif ($Score -ge 3) {
        return "MEDIUM"
    }
    else {
        return "LOW"
    }
}

function Test-RequiredFields {
    param(
        [psobject]$Row
    )

    $requiredFields = @(
        "username",
        "last_login_days",
        "status",
        "role",
        "failed_logins",
        "mfa_enabled",
        "country"
    )

    foreach ($field in $requiredFields) {
        if (-not ($Row.PSObject.Properties.Name -contains $field)) {
            throw "Missing field in data: $field"
        }
    }
}

function Convert-ToBoolean {
    param(
        [string]$Value
    )

    switch ($Value.ToString().ToLower()) {
        "true"  { return $true }
        "false" { return $false }
        default { throw "Invalid boolean value: $Value" }
    }
}

function Test-RowData {
    param(
        [psobject]$Row
    )

    Test-RequiredFields -Row $Row

    if ([string]::IsNullOrWhiteSpace($Row.username)) {
        throw "username cannot be empty"
    }

    if (-not ($Row.last_login_days.ToString() -match '^\d+$')) {
        throw "last_login_days must be a number"
    }

    if (-not ($Row.failed_logins.ToString() -match '^\d+$')) {
        throw "failed_logins must be a number"
    }

    if ($Row.status -notin @("active", "disabled")) {
        throw "status must be active or disabled"
    }

    if ($Row.role -notin @("user", "admin")) {
        throw "role must be user or admin"
    }

    [void](Convert-ToBoolean -Value $Row.mfa_enabled)
}

function Get-UserRiskAssessment {
    param(
        [psobject]$Row
    )

    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    $highRiskCountries = @("RU","KP","IR")

    $lastLoginDays = [int]$Row.last_login_days
    $failedLogins = [int]$Row.failed_logins
    $status = $Row.status.ToLower()
    $role = $Row.role.ToLower()
    $mfaEnabled = Convert-ToBoolean -Value $Row.mfa_enabled
    $country = $Row.country.ToUpper()

    if ($status -eq "active" -and $lastLoginDays -gt 90) {
        $score += 2
        $reasons.Add("Active account unused for over 90 days")
    }

    if ($role -eq "admin") {
        $score += 2
        $reasons.Add("Account has admin privileges")
    }

    if ($failedLogins -ge 5) {
        $score += 3
        $reasons.Add("Many failed login attempts")
    }

    if (-not $mfaEnabled) {
        $score += 2
        $reasons.Add("MFA not enabled")
    }

    if ($country -in $highRiskCountries) {
        $score += 2
        $reasons.Add("Activity from high-risk country")
    }

    if ($status -eq "active" -and $lastLoginDays -gt 365) {
        $score += 3
        $reasons.Add("Active account unused for over 365 days")
    }

    if ($role -eq "admin" -and -not $mfaEnabled) {
        $score += 3
        $reasons.Add("Combination risk: admin without MFA")
    }

    if ($failedLogins -ge 5 -and $country -in $highRiskCountries) {
        $score += 3
        $reasons.Add("Combination risk: failed logins from high-risk country")
    }

    $riskLevel = Get-RiskLevel -Score $score

    return [PSCustomObject]@{
        Username  = $Row.username
        Status    = $status
        Role      = $role
        Country   = $country
        RiskScore = $score
        RiskLevel = $riskLevel
        Reasons   = ($reasons -join "; ")
    }
}

try {

    if (-not (Test-Path $InputFile)) {
        throw "Input file not found: $InputFile"
    }

    $data = Import-Csv -Path $InputFile

    if (-not $data -or $data.Count -eq 0) {
        throw "CSV file is empty"
    }

    $results = @()

    foreach ($row in $data) {
        try {
            Test-RowData -Row $row
            $assessment = Get-UserRiskAssessment -Row $row
            $results += $assessment
        }
        catch {
            $results += [PSCustomObject]@{
                Username  = $row.username
                Status    = $row.status
                Role      = $row.role
                Country   = $row.country
                RiskScore = -1
                RiskLevel = "ERROR"
                Reasons   = $_.Exception.Message
            }
        }
    }

    $results | Sort-Object RiskScore -Descending | Format-Table -AutoSize

    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Report saved to: $OutputFile"

}
catch {
    Write-Error $_.Exception.Message
}