<#
=============================================================================================
Name:        Active Directory Break Glass Account Readiness Score PowerShell Script
Description: Runs 13 read-only survivability checks on break-glass accounts in Active Directory, generating a weighted score and CSV report, with unverifiable items flagged for manual review.
Version:     1.0
Website:     blog.admindroid.com

~~~~~~~~~~~~~~~~~~
Script Highlights:
~~~~~~~~~~~~~~~~~~
1. Runs 13 survivability checks on designated break-glass accounts to assess emergency readiness.
2. Generates a weighted score out of 100% for each break glass account to enable quick risk analysis.
3. Automatically installs the Active Directory PowerShell module via RSAT if it is not already available. 
4. Automatically exports an output CSV log after each execution for easy tracking and analysis.  
  
For detailed script execution: https://blog.admindroid.com/best-practices-for-break-glass-accounts-in-active-directory/  

=============================================================================================
#>

[CmdletBinding()]
param(
    [string[]]$Accounts,

    [string[]]$DomainControllers,

    [int]$TestWindowDays = 180,

    [int]$MaxPasswordAgeDays = 180
)

# --- Module check -------------------------------------------------------------

function Test-IsAdministrator {
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

    # Single source of truth: the install command lives in a script block.
    # Its text is shown to the user for manual install; the same block is
    # invoked when the script performs the install itself.
    $InstallScript = if ($OsCaption -like '*Server*') {
        { Install-WindowsFeature -Name RSAT-AD-PowerShell }
    }
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

# --- Resolve break-glass accounts --------------------------------------------

# Outer: -Accounts not passed at script invocation. Fall back to interactive prompt.
if (-not $Accounts) {
    $AccountsInput = Read-Host "Enter break-glass account SamAccountNames (comma-separated)"
    $Accounts = $AccountsInput -split ',' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }

    # Inner: prompt produced nothing usable (blank Enter, only commas, only whitespace).
    if (-not $Accounts) {
        Write-Host "`nNo account names provided. Exiting." -ForegroundColor Yellow
        return
    }
}

# --- Report setup -------------------------------------------------------------

$ReportPath = Join-Path -Path (Get-Location) -ChildPath "ActiveDirectory_BreakGlassAcc_Score_$((Get-Date -format yyyy-MMM-dd-ddd` hh-mm` tt).ToString()).csv"

# hash table to plan the Output
$CheckCatalog = @{
    ExcludedFromProtectedUsers  = @{
        Name   = 'Excluded from Protected Users group'
        Weight = 3
        Evidence = @{
            Pass = 'Not a member of Protected Users.'
            Fail = 'Member of Protected Users. 4-hour TGT cap and NTLM block break Kerberos-incident survivability.'
        }
    }
    NoSmartCardRequired         = @{
        Name   = 'Smart card logon not required'
        Weight = 3
        Evidence = @{
            Pass = 'Smart card requirement is not set.'
            Fail = 'SmartcardLogonRequired is set. PKI is a separate failure mode during emergencies.'
        }
    }
    DedicatedAccount            = @{
        Name   = 'Dedicated account (not built-in RID 500)'
        Weight = 2
        Evidence = @{
            Pass = "Dedicated account. Verify the name does not pattern-match wordlists like 'emergency', 'breakglass', 'recovery'."
            Fail = 'Built-in RID 500 Administrator. Well-known password-spray target. Migrate to a dedicated account, or verify compensating controls (audit policy, LogonWorkstations, passphrase length).'
        }
    }
    Tier0Placement              = @{
        Name   = 'Tier 0 placement with console logon exception'
        Weight = 2
        Evidence = @{
            Manual = 'Verify Tier 0 logon policy applies AND a GPO exception permits DC console logon during incidents.'
        }
    }
    RecentTest                  = @{ Name = "Tested within last $TestWindowDays days"; Weight = 2 }
    PasswordRotated             = @{ Name = 'Password rotated after last use';          Weight = 2 }
    PasswordNeverExpires        = @{
        Name   = 'Password never expires (availability flag set)'
        Weight = 1
        Evidence = @{
            Pass = 'PasswordNeverExpires is set. Password will not expire mid-incident.'
            Fail = 'PasswordNeverExpires is not set. Password will expire unexpectedly during an incident.'
        }
    }
    LogonWorkstationsRestricted = @{
        Name   = 'LogonWorkstations restricted to specific DCs'
        Weight = 2
        Evidence = @{
            Fail = "LogonWorkstations is empty. Account can log on from anywhere. Restrict via 'Log on to' in ADUC."
        }
    }
    PassphraseLong              = @{
        Name   = 'Passphrase length >= 25 characters'
        Weight = 2
        Evidence = @{
            Manual = 'Not readable from AD (password stored as hash). Verify against documented credential copies.'
        }
    }
    DsrmDistinct                = @{
        Name   = 'Break-glass distinct from DSRM'
        Weight = 3
        Evidence = @{
            Pass   = 'Dedicated domain break-glass account exists (separate from DSRM). Verify DSRM password rotation cadence manually - rotate per DC via ntdsutil.'
            Fail = 'No break-glass account retrieved from AD. Verify manually that a dedicated domain break-glass account exists and that DSRM passwords are rotated per DC via ntdsutil.'
        }
    }
    TwoOrMoreAccounts           = @{
        Name   = 'Two or more break-glass accounts'
        Weight = 3
        Evidence = @{
            Fail = 'Only 1 account provided. A single break-glass is a single point of failure.'
        }
    }
    CredentialsStoredBoth       = @{
        Name   = 'Credentials stored in both physical and digital locations'
        Weight = 3
        Evidence = @{
            Manual = 'Verify primary copy in sealed envelope in fireproof safe AND backup in hardware-isolated password vault with multi-person approval.'
        }
    }
    AuditPolicyLogsEvents       = @{
        Name   = 'Advanced audit policy logs break-glass events'
        Weight = 2
        Evidence = @{
            Manual = 'Verify via GPMC (Domain Controllers OU) that Advanced Audit Policy enables: Logon (Success+Failure), User Account Management (Success), Directory Service Access (Success). Confirm SIEM ingest from all DCs.'
        }
    }
}

function Add-AuditResult {
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$CheckpointKey,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Manual', 'Error')][string]$Result,
        [string]$Evidence
    )

    $Definition = $script:CheckCatalog[$CheckpointKey]
    if (-not $Definition) {
        throw "Unknown checkpoint key: $CheckpointKey"
    }

    # If caller did not pass -Evidence, look up the static text from the catalog.
    if (-not $Evidence) {
        $Evidence = $Definition.Evidence[$Result]
        if (-not $Evidence) {
            throw "No catalog Evidence for key '$CheckpointKey' result '$Result'. Pass -Evidence at the call site."
        }
    }

    [PSCustomObject]@{
        'Account'    = $Account
        'Checkpoint' = $Definition.Name
        'Weight'     = $Definition.Weight
        'Result'     = $Result
        'Evidence'   = $Evidence
    } | Export-Csv -Path $script:ReportPath -Append -NoTypeInformation
}

function Get-MostRecentLogonAcrossAllDcs {
    # Retrieve true last logon time from all the DCs
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][string[]]$DomainControllerHostNames
    )

    $DcCounter = 0
    $DcTotal   = $DomainControllerHostNames.Count

    $LogonTimestamps = foreach ($DcHostname in $DomainControllerHostNames) {
        $DcCounter++
        Write-Progress -Activity "Checking last logon for $AccountName" `
                       -Status "Querying $DcHostname ($DcCounter of $DcTotal)" `
                       -PercentComplete (($DcCounter / $DcTotal) * 100)

        try {
            $DcResult = Get-ADUser -Identity $AccountName -Properties lastLogon -Server $DcHostname
            if ($DcResult.lastLogon -and $DcResult.lastLogon -gt 0) {
                [DateTime]::FromFileTime($DcResult.lastLogon)
            }
        }
        catch {
            Write-Host "Could not query $DcHostname for $AccountName : $_"
        }
    }

    Write-Progress -Activity "Checking last logon for $AccountName" -Completed

    if ($LogonTimestamps) {
        ($LogonTimestamps | Measure-Object -Maximum).Maximum
    }
}

# --- Phase 1: Load account data ----------------------------------------------

Write-Host "`nRetrieving emergency account details..."

$AccountData = @{}
$AccountCounter = 0
$AccountTotal = $Accounts.Count

foreach ($AccountName in $Accounts) {
    $AccountCounter++
    Write-Progress -Activity "Retrieving emergency account details" `
                   -Status "Retrieving $AccountName ($AccountCounter of $AccountTotal)" `
                   -PercentComplete (($AccountCounter / $AccountTotal) * 100)

    try {
        $AccountData[$AccountName] = Get-ADUser -Identity $AccountName -Properties `
            SmartcardLogonRequired, PasswordNeverExpires, PasswordLastSet,
            LastLogonDate, LogonWorkstations, MemberOf, SID
    }
    catch {
        Write-Host "Could not retrieve $AccountName : $_" -foregroundcolor Red
        $AccountData[$AccountName] = $null
    }
}

Write-Progress -Activity "Loading account data" -Completed


$AllDomainControllers = @()
try {
    $AllDomainControllers = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
   # Write-Host "Found $($AllDomainControllers.Count) domain controller(s)."
}
catch {
    Write-Host "`nCould not enumerate domain controllers: $_"
    Write-Host "Last logon time will fall back to the replicated LastLogonDate attribute, which can lag up to 14 days."
}

# --- Phase 2: Run survivability checks ---------------------------------------

Write-Host "`nRunning Active Directory emergency account survivability checks..." -ForegroundColor Yellow

$TestThresholdDate = (Get-Date).AddDays(-$TestWindowDays)
$GlobalAccountLabel = 'Common Checks'

# --- Per-account checks ------------------------------------------------------

$ProtectedUsersMembers    = $null
$ProtectedUsersFetchError = $null
try {
    $ProtectedUsersMembers = Get-ADGroupMember -Identity 'Protected Users' |
        Select-Object -ExpandProperty SamAccountName
}
catch {
    $ProtectedUsersFetchError = $_
}

$AccountCheckCounter = 0

foreach ($AccountName in $Accounts) {
    $AccountCheckCounter++
    Write-Progress -Activity "Auditing accounts" `
                   -Status "Processing $AccountName ($AccountCheckCounter of $AccountTotal)" `
                   -PercentComplete (($AccountCheckCounter / $AccountTotal) * 100)

    $Account = $AccountData[$AccountName]
    if (-not $Account) {
     #   Write-Host "Skipping per-account checks for $AccountName (Account is not found)."
        continue
    }
#Check for proetected user group membership
    if ($null -ne $ProtectedUsersMembers) {
        if ($ProtectedUsersMembers -contains $AccountName) {
            Add-AuditResult -Account $AccountName -CheckpointKey 'ExcludedFromProtectedUsers' -Result Fail
        }
        else {
            Add-AuditResult -Account $AccountName -CheckpointKey 'ExcludedFromProtectedUsers' -Result Pass
        }
    }
    else {
        Add-AuditResult -Account $AccountName -CheckpointKey 'ExcludedFromProtectedUsers' `
            -Result Error `
            -Evidence "Could not query Protected Users group: $ProtectedUsersFetchError"
    }
#Check for smart card login capability
    if ($Account.SmartcardLogonRequired) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'NoSmartCardRequired' -Result Fail
    }
    else {
        Add-AuditResult -Account $AccountName -CheckpointKey 'NoSmartCardRequired' -Result Pass
    }
#Check emergency account is bult-in administrator account
    if ($Account.SID.Value.EndsWith('-500')) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'DedicatedAccount' -Result Fail
    }
    else {
        Add-AuditResult -Account $AccountName -CheckpointKey 'DedicatedAccount' -Result Pass
    }
#Check for tier implementation
    Add-AuditResult -Account $AccountName -CheckpointKey 'Tier0Placement' -Result Manual

#Cross-DC lastLogon avoids the lastLogonTimestamp replication lag (~14 days).
    $MostRecentLogon = $null
    $LogonSource     = ''

    if ($AllDomainControllers.Count -gt 0) {
        $MostRecentLogon = Get-MostRecentLogonAcrossAllDcs `
            -AccountName $AccountName `
            -DomainControllerHostNames $AllDomainControllers
        $LogonSource = "lastLogon across $($AllDomainControllers.Count) DCs"
    }
    else {
        $MostRecentLogon = $Account.LastLogonDate
        $LogonSource     = 'LastLogonDate (replicated, up to 14 days stale)'
    }

    if (-not $MostRecentLogon) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'RecentTest' `
            -Result Fail `
            -Evidence "No logon timestamp on any DC. Account may never have been tested. Source: $LogonSource."
    }
    elseif ($MostRecentLogon -ge $TestThresholdDate) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'RecentTest' `
            -Result Pass `
            -Evidence "Most recent logon: $MostRecentLogon. Source: $LogonSource."
    }
    else {
        $DaysSinceLogon = [int]((Get-Date) - $MostRecentLogon).TotalDays
        Add-AuditResult -Account $AccountName -CheckpointKey 'RecentTest' `
            -Result Fail `
            -Evidence "Most recent logon: $MostRecentLogon ($DaysSinceLogon days ago). Schedule a DC console test. Source: $LogonSource."
    }
#Check password is rotated and changed after last use/test run
    if (-not $Account.PasswordLastSet) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'PasswordRotated' `
            -Result Fail `
            -Evidence "No PasswordLastSet value recorded."
    }
    else {
        $PasswordAgeDays = [int]((Get-Date) - $Account.PasswordLastSet).TotalDays

        # Compare against the cross-DC $MostRecentLogon computed above, not
        # $Account.LastLogonDate (replicated lastLogonTimestamp, can be ~14 days stale).
        if ($MostRecentLogon -and $Account.PasswordLastSet -lt $MostRecentLogon) {
            Add-AuditResult -Account $AccountName -CheckpointKey 'PasswordRotated' `
                -Result Fail `
                -Evidence "PasswordLastSet $($Account.PasswordLastSet) is before last logon $MostRecentLogon. Documented copy may be stale."
        }
        elseif ($PasswordAgeDays -gt $MaxPasswordAgeDays) {
            Add-AuditResult -Account $AccountName -CheckpointKey 'PasswordRotated' `
                -Result Fail `
                -Evidence "Password age $PasswordAgeDays days, above max $MaxPasswordAgeDays."
        }
        else {
            Add-AuditResult -Account $AccountName -CheckpointKey 'PasswordRotated' `
                -Result Pass `
                -Evidence "PasswordLastSet $($Account.PasswordLastSet) ($PasswordAgeDays days ago)."
        }
    }
#Check password expiry is configured
    if ($Account.PasswordNeverExpires) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'PasswordNeverExpires' -Result Pass
    }
    else {
        Add-AuditResult -Account $AccountName -CheckpointKey 'PasswordNeverExpires' -Result Fail
    }
    # Check machine restriction configured or not
    $RestrictedWorkstations = $Account.LogonWorkstations

    if ([string]::IsNullOrWhiteSpace($RestrictedWorkstations)) {
        Add-AuditResult -Account $AccountName -CheckpointKey 'LogonWorkstationsRestricted' -Result Fail
    }
    else {
        $WorkstationList = $RestrictedWorkstations -split ','

        # Prefer explicit -DomainControllers; otherwise fall back to the auto-
        # discovered list of all DCs in the domain (already loaded for Item 9).
        $ExpectedDcList = if ($DomainControllers) { $DomainControllers } else { $AllDomainControllers }

        if ($ExpectedDcList -and $ExpectedDcList.Count -gt 0) {
            # Normalize hostnames before comparing so dc01 matches dc01.contoso.com.
            # Get-ADDomainController returns FQDN; LogonWorkstations stores short names.
            $NormalizedExpected = @($ExpectedDcList  | ForEach-Object { ($_ -split '\.', 2)[0].ToLower() })
            $NormalizedActual   = @($WorkstationList | ForEach-Object { ($_ -split '\.', 2)[0].ToLower() })

            $MissingDomainControllers = $NormalizedExpected | Where-Object { $NormalizedActual   -notcontains $_ }
            $UnexpectedWorkstations   = $NormalizedActual   | Where-Object { $NormalizedExpected -notcontains $_ }

            $MissingText    = if ($MissingDomainControllers) { $MissingDomainControllers -join ',' } else { 'none' }
            $UnexpectedText = if ($UnexpectedWorkstations)   { $UnexpectedWorkstations   -join ',' } else { 'none' }

            if (-not $MissingDomainControllers -and -not $UnexpectedWorkstations) {
                Add-AuditResult -Account $AccountName -CheckpointKey 'LogonWorkstationsRestricted' `
                    -Result Pass `
                    -Evidence "Restricted to: $RestrictedWorkstations. Matches expected DCs (compared by short name): $($NormalizedExpected -join ',')."
            }
            else {
                Add-AuditResult -Account $AccountName -CheckpointKey 'LogonWorkstationsRestricted' `
                    -Result Fail `
                    -Evidence "Restricted to: $RestrictedWorkstations. Expected DCs (compared by short name): $($NormalizedExpected -join ','). Missing DCs: $MissingText. Unexpected entries: $UnexpectedText."
            }
        }
        else {
            # DC enumeration failed and no -DomainControllers passed; the
            # account is restricted but we cannot validate to what.
            Add-AuditResult -Account $AccountName -CheckpointKey 'LogonWorkstationsRestricted' `
                -Result Pass `
                -Evidence "Restricted to: $RestrictedWorkstations. (Could not validate against domain controllers - DC enumeration failed.)"
        }
    }

    Add-AuditResult -Account $AccountName -CheckpointKey 'PassphraseLong' -Result Manual
}

Write-Progress -Activity "Auditing accounts" -Completed

# --- Common checks (do not vary per account) ---------------------------------

# A retrieved domain break-glass account is by definition distinct from DSRM
$LoadedAccountCount = @($AccountData.Values | Where-Object { $_ }).Count

if ($LoadedAccountCount -gt 0) {
    Add-AuditResult -Account $GlobalAccountLabel -CheckpointKey 'DsrmDistinct' -Result Pass
}
else {
    Add-AuditResult -Account $GlobalAccountLabel -CheckpointKey 'DsrmDistinct' -Result Manual
}
#Check atleast 2 emergency account is configured
if ($Accounts.Count -ge 2) {
    Add-AuditResult -Account $GlobalAccountLabel -CheckpointKey 'TwoOrMoreAccounts' `
        -Result Pass `
        -Evidence "$($Accounts.Count) accounts provided for audit."
}
else {
    Add-AuditResult -Account $GlobalAccountLabel -CheckpointKey 'TwoOrMoreAccounts' -Result Fail
}
#Check for secured storage for password
Add-AuditResult -Account $GlobalAccountLabel -CheckpointKey 'CredentialsStoredBoth' -Result Manual
#Check whether audit log configured for auditing
Add-AuditResult -Account $GlobalAccountLabel -CheckpointKey 'AuditPolicyLogsEvents' -Result Manual

# --- Phase 3: Summary --------------------------------------------------------

Write-Host "`nGenerating summary..." -Foregroundcolor Cyan

function Open-OutputFile {
    # Notify the user the report has been written and offer to open it.
    if (Test-Path -Path $ReportPath) {
        Write-Host "Report saved to: " -NoNewline -ForegroundColor Yellow
        Write-Host $ReportPath

        $Prompt = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup("Do you want to open the output file?", 0, "Open Output File", 4)
        if ($UserInput -eq 6) {
            Invoke-Item $ReportPath
        }
    }
}

function Get-ScoreSummary {
    param(
        [Parameter(Mandatory)][object[]]$Rows
    )

    $Pass   = @($Rows | Where-Object Result -eq 'Pass')
    $Fail   = @($Rows | Where-Object Result -eq 'Fail')
    $Manual = @($Rows | Where-Object Result -eq 'Manual')
    $ErrorRows = @($Rows | Where-Object Result -eq 'Error')

    $MaxAuto = ($Rows | Where-Object Result -in 'Pass', 'Fail' | Measure-Object Weight -Sum).Sum
    if ($null -eq $MaxAuto) { $MaxAuto = 0 }

    $Achieved = ($Pass | Measure-Object Weight -Sum).Sum
    if ($null -eq $Achieved) { $Achieved = 0 }

    $Percent = if ($MaxAuto -gt 0) { [math]::Round(($Achieved / $MaxAuto) * 100, 1) } else { 0 }

    [PSCustomObject]@{
        Passed       = $Pass.Count
        Failed       = $Fail.Count
        Manual       = $Manual.Count
        Errors       = $ErrorRows.Count
        Achieved     = $Achieved
        MaxAutomated = $MaxAuto
        Percent      = $Percent
    }
}

Write-Host ""
Write-Host "=== Per-Account Audit Score ==="

# Read the CSV we streamed to and coerce Weight back to int (CSV round-trip stringifies it).
$AuditResults = Import-Csv -Path $ReportPath | ForEach-Object {
    $_.Weight = [int]$_.Weight
    $_
}

foreach ($AccountName in $Accounts) {
    # Reset each iteration so a missing-account failure does not leak
    # the previous account's summary values into the Write-Host below.
    $AccountSummary = $null
    $AccountRows    = @($AuditResults | Where-Object Account -eq $AccountName)

    if ($AccountRows.Count -gt 0) {
        $AccountSummary = Get-ScoreSummary -Rows $AccountRows
    }

    if ($null -eq $AccountSummary) {
        Write-Host ("{0,-20} : Account not found in Active Directory" -f $AccountName)
        continue
    }

    Write-Host ("{0,-20} : Passed {1}, Failed {2}, Manual {3}, Errors {4}  |  Score {5} of {6} ({7} percent)" -f `
        $AccountName,
        $AccountSummary.Passed,
        $AccountSummary.Failed,
        $AccountSummary.Manual,
        $AccountSummary.Errors,
        $AccountSummary.Achieved,
        $AccountSummary.MaxAutomated,
        $AccountSummary.Percent)
}

Write-Host ""
Write-Host "=== Common Checks ==="

$GlobalRows    = $AuditResults | Where-Object Account -eq $GlobalAccountLabel
$GlobalSummary = Get-ScoreSummary -Rows $GlobalRows

Write-Host ("{0,-20} : Passed {1}, Failed {2}, Manual {3}, Errors {4}  |  Score {5} of {6} ({7} percent)" -f `
    $GlobalAccountLabel,
    $GlobalSummary.Passed,
    $GlobalSummary.Failed,
    $GlobalSummary.Manual,
    $GlobalSummary.Errors,
    $GlobalSummary.Achieved,
    $GlobalSummary.MaxAutomated,
    $GlobalSummary.Percent)

Write-Host ""
Write-Host "Manual items are not included in the automated score. Review each and verify manually."
Write-Host ""

# --- AdminDroid promo --------------------------------------------------------

Write-Host "~~ Script prepared by AdminDroid Community ~~" -ForegroundColor Green
Write-Host ""
Write-Host "~~ Check out " -NoNewline -ForegroundColor Green
Write-Host "admindroid.com" -NoNewline -ForegroundColor Yellow
Write-Host " to get access to 450+ Active Directory reports and 60+ management actions. ~~" -ForegroundColor Green
Write-Host ""

Open-OutputFile
