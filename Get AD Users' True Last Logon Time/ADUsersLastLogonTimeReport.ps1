<#
=============================================================================================

Name         : Get Users' True Last Logon in Active Directory Using PowerShell 
Version      : 1.0
Website      : o365reports.com

~~~~~~~~~~~~~~~~~~
Script Highlights:
~~~~~~~~~~~~~~~~~~
1. Finds the true last logon time by querying across all domain controllers in a domain.
2. Exports the last logon date and time for all Active Directory users.
3. Generates last logon reports for AD users in a specific OU.
4. Retrieves the last logon details of enabled Active Directory users.
5. Gets the last logon time for sign-in disabled users in Active Directory.
6. Automatically prompts to install the Active Directory PowerShell module if it is not available.
7. This script is scheduler friendly. 

For detailed script execution: https://o365reports.com/get-users-last-logon-in-active-directory-using-powershell/

============================================================================================
#>

[CmdletBinding()]
Param(
    [string]$OU,

    [Switch]$EnabledUsersOnly,

    [Switch]$DisabledUsersOnly,

    [Switch]$SuppressReportOpen
)

# Module check

Function Test-IsAdministrator {
    $CurrentPrincipal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    $OsCaption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

    # Home editions cannot install RSAT.
    if ($OsCaption -match 'Home') {
        Write-Host "The ActiveDirectory module (RSAT) is not supported on Windows Home edition."
        Write-Host "Run this script from Windows 10/11 Pro, Enterprise, or Education, or from a domain controller."
        return
    }

    # Install RSAT in server machines
    $InstallScript = if ($OsCaption -like '*Server*') {
        { Install-WindowsFeature -Name RSAT-AD-PowerShell }
    }
    #Install RSAT in client workstation
    else {
        { Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' }
    }
    $ManualInstallCommand = $InstallScript.ToString().Trim()

    # Installing RSAT requires elevation. Detect this before prompting Y/N
    if (-not (Test-IsAdministrator)) {
        Write-Host "The ActiveDirectory module is not installed."
        Write-Host "Installing it requires Administrator privileges (one-time per workstation; any user can use the module afterwards)." -ForegroundColor Yellow
        Write-Host "`nTo install the module manually, run the cmdlet: $ManualInstallCommand"
        return
    }

    $InstallConfirmation = Read-Host "The ActiveDirectory module is not installed. Install it now? (Y/N)"

    if ($InstallConfirmation -ne 'Y') {
        Write-Host "`nActiveDirectory module is required. Exiting."
        return
    }

    try {
        & $InstallScript | Out-Null
    }
    catch {
        Write-Host "Module installation failed: $_"
        Write-Host "To install manually, run the cmdlet: $ManualInstallCommand"
        return
    }
}

Import-Module ActiveDirectory

# LastLogon collection across DCs

Function Get-UserLastLogonAcrossDCs {
    [CmdletBinding()]
    param(
        [string]$Filter = '*',
        [string]$SearchBase
    )

    $LastLogonMap = @{}
    $DCs = @()

    try {
        $DCs = @((Get-ADDomainController -Filter * -ErrorAction Stop).HostName)
    } catch {
        Write-Warning "Could not enumerate domain controllers: $($_.Exception.Message)"
        Write-Warning "LastLogon values will reflect a single DC and may be inaccurate."
        return $LastLogonMap
    }

    Write-Host "Querying $($DCs.Count) domain controller(s) for accurate LastLogon..." -ForegroundColor Cyan

    $DcIndex = 0
    foreach ($DC in $DCs) {
        $DcIndex++
        Write-Progress -Activity "Reading LastLogon across DCs" `
            -Status "$DC ($DcIndex of $($DCs.Count))" `
            -PercentComplete (($DcIndex / $DCs.Count) * 100)

        $DcParams = @{
            Server         = $DC
            Filter         = $Filter
            Properties     = 'LastLogon'
            ResultPageSize = 1000
            ErrorAction    = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $DcParams['SearchBase'] = $SearchBase
        }

        try {
            Get-ADUser @DcParams |
                ForEach-Object {
                    $Sid = $_.SID.Value
                    $CurrentLastLogon = if ($_.LastLogon) { [int64]$_.LastLogon } else { 0 }
                    if (-not $LastLogonMap.ContainsKey($Sid) -or $LastLogonMap[$Sid] -lt $CurrentLastLogon) {
                        $LastLogonMap[$Sid] = $CurrentLastLogon
                    }
                }
        } catch {
            Write-Warning "Failed to query $DC : $($_.Exception.Message)"
        }
    }

    Write-Progress -Activity "Reading LastLogon across DCs" -Completed
    return $LastLogonMap
}

# User processing

Function Process-Users {
    $Name = $_.Name
    $SamAccountName = $_.SamAccountName
    $UserPrincipalName = $_.UserPrincipalName
    Write-Progress -Activity "Generating last logon report" `
        -Status "Processing $Name (user $script:Count)"

    # Look up the most recent LastLogon across all DCs.
    $Sid = $_.SID.Value
    $LastLogon = if ($script:LastLogonMap.ContainsKey($Sid)) { $script:LastLogonMap[$Sid] } else { 0 }
    $LastLogon_FriendlyFormat = if ($LastLogon -gt 0) {
        [DateTime]::FromFileTime($LastLogon).ToString("dd-MM-yyyy HH:mm:ss")
    }
    else { "-" }

    $AccountStatus = if ($_.Enabled) { "Enabled" } else { "Disabled" }
    $CreatedDate = if ($_.WhenCreated) { $_.WhenCreated.ToString("dd-MM-yyyy HH:mm:ss") } else { "-" }
    $Department = $_.Department
    if (-not $Department) { $Department = "-" }
    $JobTitle = $_.Title
    if (-not $JobTitle) { $JobTitle = "-" }
    $DN = $_.DistinguishedName
    $UserOU = $DN.Substring($DN.IndexOf(",") + 1)

    # Build a CSV row with quoted fields and escaped quotes.
    $Row = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}"' -f `
        ($Name -replace '"', '""'),
        ($SamAccountName -replace '"', '""'),
        ($UserPrincipalName -replace '"', '""'),
        $AccountStatus,
        $LastLogon_FriendlyFormat,
        ($UserOU -replace '"', '""'),
        ($Department -replace '"', '""'),
        ($JobTitle -replace '"', '""'),
        $CreatedDate
    if ($null -eq $script:Writer) {
        $script:Writer = New-Object System.IO.StreamWriter -ArgumentList $ExportCSV, $false, ([System.Text.Encoding]::UTF8)
        $script:Writer.AutoFlush = $true
        $script:Writer.WriteLine($script:CsvHeader)
    }
    $script:Writer.WriteLine($Row)
    $script:Count++
}

# Report setup

$Location=Get-Location
$ExportCSV="$Location\ADUsersLastLogonTimeReport_$((Get-Date -Format 'yyyy-MMM-dd-ddd_HH-mm-ss').ToString()).csv"
$script:Count=0
$script:Writer=$null
$script:CsvHeader='"Name","SAM Account Name","User Principal Name","Account Status","Last Logon Time","OU Path","Department","Job Title","Created Date"'
$RequiredProperties=@('WhenCreated','Department','Title','LastLogon')

# User selection

# Validate: -EnabledUsersOnly and -DisabledUsersOnly are mutually exclusive.
if ($EnabledUsersOnly -and $DisabledUsersOnly) {
    Write-Host "Cannot specify both -EnabledUsersOnly and -DisabledUsersOnly. Choose one." -ForegroundColor Red
    return
}

# Validate the OU exists before any AD query runs.
if (-not [string]::IsNullOrWhiteSpace($OU)) {
    try {
        Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host "The specified OU '$OU' was not found in the domain." -ForegroundColor Red
        return
    }
}

# Filter for enabled and disabled users.
$Filter = if ($EnabledUsersOnly) {
    'Enabled -eq $true'
} elseif ($DisabledUsersOnly) {
    'Enabled -eq $false'
} else {
    '*'
}

# LastLogon is per-DC; query every DC and keep the max.
$script:LastLogonMap = Get-UserLastLogonAcrossDCs -Filter $Filter -SearchBase $OU

$GetADUserParams = @{
    Filter         = $Filter
    Properties     = $RequiredProperties
    ResultPageSize = 1000
}
if (-not [string]::IsNullOrWhiteSpace($OU)) {
    $GetADUserParams['SearchBase'] = $OU
}

# Stream rows.
try {
    Get-ADUser @GetADUserParams | ForEach-Object { Process-Users }
}
finally {
    if ($null -ne $script:Writer) {
        $script:Writer.Close()
        $script:Writer.Dispose()
    }
}

# Output

Write-Host "`n~~ Script prepared by AdminDroid Community ~~`n" -ForegroundColor Green
Write-Host "~~ Check out " -NoNewline -ForegroundColor Green
Write-Host "admindroid.com" -NoNewline -ForegroundColor Yellow
Write-Host " to manage your AD environment effortlessly. Get access to 200+ AD reports in the free version ~~`n`n" -ForegroundColor Green

if (Test-Path -Path $ExportCSV) {
    Write-Host "The exported report contains $script:Count users."
    Write-Host "`nThe last logon time report available in: " -NoNewline -ForegroundColor Yellow
    Write-Host $ExportCSV
    if (-not $SuppressReportOpen) {
        $UserInput = Read-Host "`nDo you want to open the output file? (Y/N)"
        if ($UserInput -eq 'Y') {
            Invoke-Item $ExportCSV
        }
    }
}
else {
    Write-Host "No users found."
}
