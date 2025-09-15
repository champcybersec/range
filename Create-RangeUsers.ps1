param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath = (Join-Path -Path $PSScriptRoot -ChildPath "range_users.csv"),
    [Parameter(Mandatory = $true)]
    [string]$DefaultPassword,
    [string]$UsersContainer = "OU=ChampSecGoobers",
    [string]$DomainAdminsGroup = "Domain Admins",
    [switch]$DryRun
)

# Requires: ActiveDirectory module (RSAT) and Domain Controller context
# Usage:
#   .\Create-RangeUsers.ps1 -DefaultPassword "P@ssw0rd!" [-CsvPath C:\path\range_users.csv] [-DryRun]
# Note: CSV has no headers. Column1 = samAccountName, Column2 = "admin" or "user"

function Ensure-ModuleLoaded {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT or run on a DC."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Get-UsersDefaultDN {
    param([string]$ContainerName)

    $domainDn = (Get-ADDomain).DistinguishedName
    if ($ContainerName -match "^\s*(OU|CN)=") {
        return "$ContainerName,$domainDn"
    }
    return "OU=ChampSecGoobers,$domainDn"
}

function Get-UserUpn {
    param([string]$SamAccountName)
    $dnsDomain = $env:USERDNSDOMAIN
    if ([string]::IsNullOrWhiteSpace($dnsDomain)) {
        $dnsDomain = (Get-ADDomain).DNSRoot
    }
    return "$SamAccountName@$dnsDomain"
}

function Ensure-UserExists {
    param(
        [string]$SamAccountName,
        [securestring]$SecurePassword,
        [string]$UsersDn,
        [switch]$WhatIfOnly
    )

    $existing = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[SKIP] User exists:" $SamAccountName
        return $existing
    }

    $upn = Get-UserUpn -SamAccountName $SamAccountName
    Write-Host "[CREATE]" $SamAccountName "UPN:" $upn "DN:" $UsersDn
    if ($WhatIfOnly) {
        return $null
    }

    New-ADUser `
        -Name $SamAccountName `
        -SamAccountName $SamAccountName `
        -UserPrincipalName $upn `
        -Path $UsersDn `
        -AccountPassword $SecurePassword `
        -Enabled $true `
        -ChangePasswordAtLogon $false `
        -PasswordNeverExpires $true `
        -PassThru
}

function Ensure-GroupMembership {
    param(
        [Microsoft.ActiveDirectory.Management.ADAccount]$User,
        [string]$GroupName,
        [switch]$WhatIfOnly
    )

    $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
    $isMember = $false
    if ($User) {
        try {
            $isMember = (Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.DistinguishedName -eq $User.DistinguishedName }) -ne $null
        } catch {
            $isMember = $false
        }
    }

    if ($isMember) {
        Write-Host "[OK] Membership exists:" $User.SamAccountName "->" $GroupName
        return
    }

    $displayName = "<new user>"
    if ($User) { $displayName = $User.SamAccountName }
    Write-Host "[ADD] Adding" $displayName "to" $GroupName
    if ($WhatIfOnly -or -not $User) { return }

    try {
        Add-ADGroupMember -Identity $group -Members $User -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -notmatch "is already a member") {
            throw
        }
    }
}

try {
    Ensure-ModuleLoaded

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "CSV path not found: $CsvPath"
    }

    $usersDn = Get-UsersDefaultDN -ContainerName $UsersContainer
    $secure = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

    # CSV has no headers; define them explicitly
    $rows = Import-Csv -LiteralPath $CsvPath -Header SamAccountName,Role

    foreach ($row in $rows) {
        $sam = ($row.SamAccountName).Trim()
        if ([string]::IsNullOrWhiteSpace($sam)) { continue }

        $role = ($row.Role).Trim().ToLowerInvariant()
        $isAdmin = $role -eq "admin"

        $createdOrExistingUser = Ensure-UserExists -SamAccountName $sam -SecurePassword $secure -UsersDn $usersDn -WhatIfOnly:$DryRun

        if ($isAdmin) {
            if ($DryRun) {
                Write-Host "[DRYRUN] Would add" $sam "to" $DomainAdminsGroup
            } else {
                $userObj = $createdOrExistingUser
                if (-not $userObj) {
                    $userObj = Get-ADUser -Filter "SamAccountName -eq '$sam'"
                }
                Ensure-GroupMembership -User $userObj -GroupName $DomainAdminsGroup -WhatIfOnly:$false
            }
        } else {
            Write-Host "[INFO]" $sam "is standard user"
        }
    }

    Write-Host "Done."
}
catch {
    Write-Error $_
    exit 1
}


