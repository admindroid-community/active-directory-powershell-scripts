<#
=============================================================================================

Name         : Get Active Directory Users' Password Expiry Reports Using PowerShell
Description  : This script exports 5+ Active Directory user password reports to check users' last password change date, password expiry details, and more.
Version      : 1.0
Website      : o365reports.com

~~~~~~~~~~~~~~~~~~
Script Highlights:
~~~~~~~~~~~~~~~~~~
1. Allows you to generate 5+ password reports easily. 
2. Retrieves the last password change date for all Active Directory users. 
3. Lists the password expiry date for all Active Directory users. 
4. Allows you to get last password change and expiry details for enabled Active Directory users only. 
5. Allows you to filter password report for users within a specific Organizational Unit (OU). 
6. Helps to find all password-expired users in Active Directory. 
7. Gets Active Directory users whose passwords are set to never expire. 
8. Lists Active Directory users with soon-to-expire passwords. 
9. Exports output as a CSV file for further analysis and monitoring. 
10. Automatically installs the Active Directory (RSAT-AD) module, if it is not already present. 
11. This script is scheduler friendly. 

For detailed script execution: https://o365reports.com/get-active-directory-users-last-password-change-and-expiry-reports/

============================================================================================
#>

[CmdletBinding()]
Param(
    [string]$OU,
    [Switch]$EnabledUsersOnly,
    [Switch]$PasswordExpiredOnly,
    [Switch]$PasswordNeverExpiresOnly,
    [int]$SoonToExpirePasswordsInDays,
    [Switch]$Unattended
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

# User processing

Function Process-Users {
    $User = $_   # capture before any switch statement which can overwrite $_
    $script:ProcessedCount++
    $Name = $User.Name
    Write-Progress -Activity "Retrieving users" `
        -Status "Processing $Name (user $script:ProcessedCount)"

    # Resolve password expiry from msDS-UserPasswordExpiryTimeComputed.
    $ExpiryFileTime = $User.'msDS-UserPasswordExpiryTimeComputed'
    $PasswordNotRequired = [bool]$User.PasswordNotRequired
    $NeverExpires = ($ExpiryFileTime -eq [int64]::MaxValue) -or $User.PasswordNeverExpires
    $MustChangeAtNextLogon = ($ExpiryFileTime -eq 0)
    $NowFileTime = (Get-Date).ToFileTime()
    $IsExpired = (-not $NeverExpires) -and (-not $MustChangeAtNextLogon) -and ($null -ne $ExpiryFileTime) -and ($ExpiryFileTime -lt $NowFileTime)

    $DaysUntilExpiryNumeric = if ($NeverExpires -or $MustChangeAtNextLogon -or $null -eq $ExpiryFileTime) { $null }
    else { [int][math]::Floor((([DateTime]::FromFileTime($ExpiryFileTime)) - (Get-Date)).TotalDays) }

    # Apply password-expiry filters.
    if ($PasswordExpiredOnly -and -not $IsExpired) { return }
    if ($PasswordNeverExpiresOnly -and -not $NeverExpires) { return }
    if ($SoonToExpirePasswordsInDays -gt 0) {
        if ($null -eq $DaysUntilExpiryNumeric -or $DaysUntilExpiryNumeric -lt 0 -or $DaysUntilExpiryNumeric -gt $SoonToExpirePasswordsInDays) { return }
    }

    $SamAccountName = $User.SamAccountName
    $UserPrincipalName = $User.UserPrincipalName

    $PasswordLastSetDisplay = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString("dd-MM-yyyy HH:mm:ss") } else { "-" }
    $PasswordAge = if ($User.PasswordLastSet) { [int][math]::Floor(((Get-Date) - $User.PasswordLastSet).TotalDays) } else { "-" }
    $PasswordExpired = if ($IsExpired) { "Yes" } else { "No" }
    $PasswordNeverExpiresDisplay = if ($NeverExpires) { "Yes" } else { "No" }

    $PasswordExpiryDisplay = switch ($true) {
        ($null -eq $ExpiryFileTime)                        { "-"; break }
        $NeverExpires                                      { "Never expires"; break }
        ($PasswordNotRequired -and $ExpiryFileTime -eq 0)  { "Password not required"; break }
        $MustChangeAtNextLogon                             { "Must change at next logon"; break }
        default                                            { [DateTime]::FromFileTime($ExpiryFileTime).ToString("dd-MM-yyyy HH:mm:ss") }
    }
    $DaysUntilExpiryDisplay = if ($null -ne $DaysUntilExpiryNumeric) { $DaysUntilExpiryNumeric } else { "-" }

    $AccountStatus = if ($User.Enabled) { "Enabled" } else { "Disabled" }
    $CreatedDate = if ($User.WhenCreated) { $User.WhenCreated.ToString("dd-MM-yyyy HH:mm:ss") } else { "-" }
    $LastLogonDisplay = if ($User.LastLogonDate) { $User.LastLogonDate.ToString("dd-MM-yyyy HH:mm:ss") } else { "-" }
    $Department = $User.Department
    $JobTitle = $User.Title
    $DN = $User.DistinguishedName
    $UserOU = if ($DN -and $DN.Contains(",")) { $DN.Substring($DN.IndexOf(",") + 1) } else { "-" }

    # Build the CSV row.
    $Values = @(
        ($Name -replace '"', '""'),
        ($SamAccountName -replace '"', '""'),
        ($UserPrincipalName -replace '"', '""'),
        $AccountStatus,
        $PasswordLastSetDisplay,
        $PasswordAge,
        $PasswordExpiryDisplay,
        $DaysUntilExpiryDisplay,
        $PasswordExpired,
        $PasswordNeverExpiresDisplay,
        $LastLogonDisplay,
        ($UserOU -replace '"', '""'),
        ($Department -replace '"', '""'),
        ($JobTitle -replace '"', '""'),
        $CreatedDate
    )
    if ($null -eq $script:Writer) {
        $script:Writer = New-Object System.IO.StreamWriter -ArgumentList $ExportCSV, $false, ([System.Text.Encoding]::UTF8)
        $script:Writer.AutoFlush = $true
        $script:Writer.WriteLine($script:CsvHeader)
    }
    $script:Writer.WriteLine('"' + ($Values -join '","') + '"')
    $script:Count++
}

# Report setup

$Location=Get-Location
$ExportCSV="$Location\PasswordExpiryReport_$((Get-Date -Format 'yyyy-MMM-dd-ddd_HH-mm-ss').ToString()).csv"
$script:Count=0
$script:ProcessedCount=0
$script:Writer=$null
$script:CsvHeader='"Name","SAM Account Name","User Principal Name","Account Status","Password Last Set","Password Age (Days)","Password Expiry Date","Days Until Expiry","Password Expired","Password Never Expires","Last Logon Time","OU Path","Department","Job Title","Created Date"'
$RequiredProperties=@('WhenCreated','Department','Title','LastLogonDate','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired','msDS-UserPasswordExpiryTimeComputed')

# User selection

# At most one password-expiry filter is allowed.
$ExpiryFilterCount = @($PasswordExpiredOnly, $PasswordNeverExpiresOnly, ($SoonToExpirePasswordsInDays -gt 0)) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($ExpiryFilterCount -gt 1) {
    Write-Host "Specify at most one of -PasswordExpiredOnly, -PasswordNeverExpiresOnly, or -SoonToExpirePasswordsInDays." -ForegroundColor Red
    return
}

# Filter for enabled users (or all users).
$Filter = if ($EnabledUsersOnly) { 'Enabled -eq $true' } else { '*' }

$GetADUserParams = @{
    Filter         = $Filter
    Properties     = $RequiredProperties
    ResultPageSize = 1000
}
if (-not [string]::IsNullOrWhiteSpace($OU)) {
    $GetADUserParams['SearchBase'] = $OU
}

# Stream rows to the CSV file (writer is created lazily on the first matching user).
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
    Write-Host "`nThe password expiry report is available in: " -NoNewline -ForegroundColor Yellow
    Write-Host $ExportCSV
    if (-not $Unattended) {
        $UserInput = Read-Host "`nDo you want to open the output file? (Y/N)"
        if ($UserInput -eq 'Y') {
            Invoke-Item $ExportCSV
        }
    }
}
else {
    Write-Host "No users found."
}
