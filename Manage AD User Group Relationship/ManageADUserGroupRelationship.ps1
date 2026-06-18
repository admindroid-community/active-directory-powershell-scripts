<#

=============================================================================================
Name: Manage Active Directory User and Group Relationships Using PowerShell Script

Description: This script simplifies Active Directory user and group management by supporting 16 actions, including group membership updates, primary group assignment, and manager assignments for both single and bulk operations. 

Version: 1.0

Website: m365scripts.com
 
~~~~~~~~~~~~~~~~~~
Script Highlights:
~~~~~~~~~~~~~~~~~~
1. Performs 16 actions to manage Active Directory user-group relationships.
2. Enables you to run specific management actions directly.
3. Supports bulk user and group management using CSV input files.
4. Allows you to perform multiple actions in a single execution.
5. Automatically loads the Active Directory PowerShell module if it is not already available on the system.
6. Exports execution results to a CSV log file, including details such as the action performed, execution status, timestamp, and error information.

For detailed script execution:
https://m365scripts.com/security/manage-active-directory-user-group-membership-using-powershell/ 

=============================================================================================

#>

param (
    [string]$Action = "0",
    [switch]$MultiExecutionMode,
    [string]$Username,
    [string]$Password,
    [string]$DomainName
)
function Connect-AdModule {
    try {
        $os = (Get-CimInstance Win32_OperatingSystem).ProductType
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "`nActive Directory module is not available." -ForegroundColor Yellow
            $confirm = Read-Host "Are you sure you want to install the module? [Y] Yes [N] No"
            if ($confirm -match "[yY]") {
                Write-Host "Installing Active Directory Module..." -ForegroundColor Yellow

                if ($os -eq 1) {
                    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop | Out-Null
                }
                else {
                    Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
                }

                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Host "`nActive Directory module installed successfully." -ForegroundColor Cyan
            }
            else {
                Write-Host "`nActive Directory module is required to run this script." -ForegroundColor Red
                Exit 1
            }
        }
        else {
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        if (($script:CredentialBasedExecution -eq $false) -and ($os -eq 1)) {
            Write-Host "`nExiting. `nCredentials must be provided using the Username and Password parameters to perform Active Directory operations when running the script on a client OS" -ForegroundColor Red
            Exit 1
        }

        Write-Host "`nActive Directory module loaded successfully." -ForegroundColor Cyan
    }
    catch {
        Write-Host "`nFailed to load the Active Directory module: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
}

function Log-ScriptExecution {
    param (
        [string]$Identity,
        [string]$GroupName,
        [string]$Operation,
        [boolean]$Status,
        [string]$ErrorMessage
    )
    $Timestamp = (Get-Date).ToLocalTime()
    $CSVEntry = [PSCustomObject]@{
        "Event Time"    = $Timestamp
        "User"          = $Identity
        "Group"         = $GroupName
        "Operation"     = $Operation
        "Status"        = if ($Status) { "Success" } else { "Failed" }
        "Error Message" = if ([string]::IsNullOrEmpty($ErrorMessage)) { "-" } else { $ErrorMessage }
    }
            
    $CSVEntry | Export-Csv -Path $LogFilePath -NoTypeInformation -Append -Force
    
    if (-not $script:isBulkOperation) {
        $script:OperationStatus = $Status
        if ($Status) {
            $script:Message = "The $Operation operation for $Identity has been successful."
        }
        else {
            $script:Message = "The $Operation operation for $Identity failed. Error: $ErrorMessage"
        }
    }
}

function ValidateAndImportCsv {
    param (
        [string]$FilePath,
        [string[]]$RequiredColumns
    )
 
    if (-not (Test-Path $FilePath)) {
        Write-Host "CSV file not found at: $FilePath" -ForegroundColor Red
        Exit 1
    }
 
    $csvData = Import-Csv $FilePath
 
    if ($csvData.Count -eq 0) {
        Write-Host "CSV file is empty. Please check and update the csv file." -ForegroundColor Red
        Exit 1
    }
 
    $csvColumns = $csvData[0].PSObject.Properties.Name
    $missing = $RequiredColumns | Where-Object { $_ -notin $csvColumns }
 
    if ($missing.Count -gt 0) {
        Write-Host "`nCSV validation failed. Missing column(s): $($missing -join ', ')" -ForegroundColor Red
        Exit 1
    }
 
    return $csvData
}

function Validate-SingleInput {
    param(
        [string]$InputValue,
        [string]$Type
    )
    if ([string]::IsNullOrWhiteSpace($InputValue)) {
        throw "$($Type) identity cannot be empty."
    }
    if ($InputValue -match '\.csv$') {
        throw "Only single $($Type) identity is needed. Check the entered $($Type) identity"
    }
}

function Exit-Script {
    param([switch]$Exit)
    
    if ((Test-Path -Path $LogFilePath) -eq "True") {   
        Write-Host `n "The log file availble in: " -NoNewline -ForegroundColor Yellow; Write-Host "$LogFilePath" `n 
        $Prompt = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup("Do you want to open log file?", 0, "Open Log File", 4)
        if ($UserInput -eq 6) {
            Invoke-Item "$LogFilePath"
        }
    }
    Write-Host "`n~~ Script prepared by Admindroid Community ~~`n" -ForegroundColor Green
    Write-Host "~~ Check out " -NoNewline -ForegroundColor Green; Write-Host "admindroid.com" -ForegroundColor Yellow -NoNewline; Write-Host " to access 450+ insightful reports and 70+ management actions across your Active Directory environment. ~~" -ForegroundColor Green `n
    if ($Exit.IsPresent) { Exit }
}

function Add-UserToGroups {
    param (
        [string]$UserSam,
        [string]$GroupName,
        [string]$OperationName
    )
    try {
        $user = Get-ADUser -Identity $UserSam -ErrorAction Stop @credParams
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop @credParams
        Add-ADGroupMember -Identity $GroupName -Members $user -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $true
    }
    catch {
        Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Remove-UserFromGroup {
    param (
        [string]$UserSam,
        [string]$GroupName,
        [string]$OperationName
    )
    try {
        $group = Get-ADGroup -Identity $GroupName -Properties member -ErrorAction Stop @credParams
        if (!($group.member -contains $UserSam)) {
            throw "$($UserSam) is not a member of this group: $($GroupName)"
        }
        Remove-ADGroupMember -Identity $GroupName -Members $UserSam -Confirm:$false -ErrorAction Stop @credParams 
        Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $true
    }
    catch {
        Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Remove-UserFromAllGroups {
    param (
        [string]$UserSam,
        [string]$OperationName
    )
    try {
        $groupFound = $false
         Get-ADPrincipalGroupMembership -Identity $UserSam -ErrorAction Stop @credParams | Where-Object Name -ne "Domain Users" | ForEach-Object {
            $group = $_
            $groupFound = $true
            try {
                Remove-ADGroupMember -Identity $group -Members $UserSam -Confirm:$false -ErrorAction Stop @credParams
                Log-ScriptExecution -Identity $UserSam -GroupName $group.Name -Operation $OperationName -Status $true
            }
            catch {
                Log-ScriptExecution -Identity $UserSam -GroupName $group.Name -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
            }
        }

        if (-not $groupFound) {
            Log-ScriptExecution -Identity $UserSam -GroupName "-" -Operation $OperationName -Status $false -ErrorMessage "User is not a member of any removable groups."
        }
    }
    catch {
        Log-ScriptExecution -Identity $UserSam -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Invoke-SetPrimaryGroupForUser {
    param (
        [string]$UserSam,
        [string]$GroupName,
        [string]$OperationName
    )

    try {
        $user = Get-ADUser -Identity $UserSam -Properties primaryGroupID,MemberOf -ErrorAction Stop @credParams
        $group = Get-ADGroup -Identity $GroupName -Properties SID,GroupScope,GroupCategory,DistinguishedName -ErrorAction Stop @credParams

        # Validate supported group type
        if (($group.GroupCategory -ne 'Security') -or ($group.GroupScope -eq 'DomainLocal')) {
            throw "Only Global or Universal Security groups can be set as primary group."
        }
        $targetRID = $group.SID.Value.Split('-')[-1]
        if ($targetRID -eq $user.primaryGroupID) {
            Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $true -ErrorMessage "Group is already the primary group."
            return
        }
        if ($user.MemberOf -notcontains $group.DistinguishedName) {
            try {
                Add-UserToGroups -UserSam $UserSam -GroupName $GroupName -OperationName "Auto-add user before setting primary group"
            }
            catch {
                throw "User is not a member of $GroupName and could not be added automatically."
            }
        }
        Set-ADUser -Identity $UserSam -Replace @{ primaryGroupID = $targetRID } -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $true
    }
    catch {
        Log-ScriptExecution -Identity $UserSam -GroupName $GroupName -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Set-GroupManagedBy{
    param(
        [string]$Group,
        [string]$UserSam,
        [string]$OperationName
    )
    try{
        $user = Get-ADUser -Identity $UserSam -ErrorAction Stop @credParams
        Set-ADGroup -Identity $Group -ManagedBy $user -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $UserSam -GroupName $Group -Operation $OperationName -Status $true
    }
    catch{
        Log-ScriptExecution -Identity $UserSam -GroupName $Group -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Remove-GroupManagedBy{
    param(
        [string]$Group,
        [string]$OperationName
    )
    try{
        $Manager = (Get-ADGroup -Identity $Group -Properties ManagedBy -ErrorAction Stop @credParams).ManagedBy
        if([string]::IsNullOrWhiteSpace($Manager) ) {
            throw "manager doesn't exist in this group: $($Group)"
        }
        Set-ADGroup -Identity $Group -Clear ManagedBy -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $($Manager) -GroupName $Group -Operation $OperationName -Status $true
    }
    catch{
        Log-ScriptExecution -GroupName $Group -Operation $OperationName -Status $false -ErrorMessage $_.Exception.Message
    }
}

$credParams = @{ }
$script:CredentialBasedExecution = $false
if ($Username -and $Password) {
    $script:CredentialBasedExecution = $true
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $script:cred = [PSCredential]::new($Username, $SecurePassword)
    try {
        if ($DomainName) {
            $script:domainName = $DomainName
        }
        else {
            $script:domainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        }
    }
    catch {
        $script:domainName = Read-Host "Enter the Active Directory Domain Name"
    }
    $credParams = @{
        Credential = $script:cred
        Server     = $script:domainName
    }
}

Connect-AdModule
$script:OperationStatus = $null
$script:Message = ""
$script:isBulkOperation = $false
$Location = Get-Location
$LogFilePath = "$Location\AD_UsersGroups_Relationship_Management_Logs_$(Get-Date -Format 'yyyy-MMM-dd-ddd_hh-mm-ss_tt').csv"

do {
    if ($Action -eq 0) {
        Write-Host "`n ================================================="-ForegroundColor Cyan
        Write-Host "    AD Users and Groups Relationship Management"-ForegroundColor Green
        Write-Host " =================================================`n"-ForegroundColor Cyan        
        Write-Host @"
        1. Add a user to a group
        2. Add a user to bulk groups
        3. Add bulk users to a group
        4. Add bulk users to bulk groups
        5. Remove a user from a group
        6. Remove a user from bulk groups
        7. Remove bulk users from a group
        8. Remove bulk users from bulk groups
        9. Remove a user from all groups
       10. Remove bulk users from all groups
       11. Change the primary group for a user
       12. Change the primary group for bulk users
       13. Add managedBy to a group
       14. Add managedBy to bulk groups
       15. Remove managedBy from a group
       16. Remove managedBy from bulk groups
       17. Exit
"@ -ForegroundColor Yellow
         $Action = Read-Host "`nPlease choose the action to continue"
    }
    $script:isBulkOperation = $true
    switch ($Action) {
        "1" {
            $script:isBulkOperation = $false
            try{
                $UserSam = Read-Host "`nEnter the user identity"
                Validate-SingleInput -InputValue $UserSam -Type "User"
                $GroupName = Read-Host "Enter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                Add-UserToGroups -UserSam $UserSam -GroupName $GroupName -OperationName "Add a user to a group"
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "2" {
            try{
                $UserSam = Read-Host "`nEnter the user identity"
                Validate-SingleInput -InputValue $UserSam -Type "User"
                $GroupCsv = Read-Host "Enter the CSV file path containing group identities"
                ValidateAndImportCsv $GroupCsv -RequiredColumns "Group" | ForEach-Object {
                    Add-UserToGroups -UserSam $UserSam -GroupName $_.Group -OperationName "Add a user to bulk group"
                }
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "3" {
            try{
                $CsvPath = Read-Host "`nEnter the CSV file path containing users identities"
                $GroupName = Read-Host "Enter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                ValidateAndImportCsv $CsvPath -RequiredColumns "User" | ForEach-Object {
                    Add-UserToGroups -UserSam $_.User -GroupName $GroupName -OperationName "Add bulk users to a group"
                }
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "4" {
            $CsvPath = Read-Host "`nEnter the CSV file path containing users identities"
            $GroupCsv = Read-Host "Enter the CSV file path containing group identities"
            ValidateAndImportCsv $GroupCsv -RequiredColumns "Group" | ForEach-Object {
                $GroupName = $_.Group
                ValidateAndImportCsv $CsvPath -RequiredColumns "User" | ForEach-Object {
                    Add-UserToGroups -UserSam $_.User -GroupName $GroupName -OperationName "Add bulk users to bulk groups"
                }
            }
            break
        }

        "5" {
            $script:isBulkOperation = $false
            try{
                $UserSam = Read-Host "`nEnter the user identity"
                Validate-SingleInput -InputValue $UserSam -Type "User"
                $GroupName = Read-Host "Enter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                Remove-UserFromGroup -UserSam $UserSam -GroupName $GroupName -OperationName "Remove a user from a group"
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "6" {
            try{
                $UserSam = Read-Host "`nEnter the user identity"
                Validate-SingleInput -InputValue $UserSam -Type "User"
                $GroupCsv = Read-Host "Enter the CSV file path containing group identities"
                ValidateAndImportCsv $GroupCsv -RequiredColumns "Group" | ForEach-Object {
                    Remove-UserFromGroup -UserSam $UserSam -GroupName $_.Group -OperationName "Remove a user from bulk groups"
                }
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "7" {
            try{
                $CsvPath = Read-Host "`nEnter the CSV file path containing users identities"
                $GroupName = Read-Host "Enter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                ValidateAndImportCsv $CsvPath -RequiredColumns "User" | ForEach-Object {
                    Remove-UserFromGroup -UserSam $_.User -GroupName $GroupName -OperationName "Remove bulk users from a groups"
                }
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "8" {
           $CsvPath = Read-Host "`nEnter the CSV file path containing users identities"
            $GroupCsv = Read-Host "Enter the CSV file path containing group identities"
            ValidateAndImportCsv $GroupCsv -RequiredColumns "Group" | ForEach-Object {
                $GroupName = $_.Group
                ValidateAndImportCsv $CsvPath -RequiredColumns "User" | ForEach-Object {
                    Remove-UserFromGroup -UserSam $_.User -GroupName $GroupName -OperationName "Remove bulk users from bulk groups"
                }
            }
            break
        }

        "9" {
            $script:isBulkOperation = $false
            try{
                $UserSam = Read-Host "`nEnter the user identity"
                Validate-SingleInput -InputValue $UserSam -Type "User"
                Remove-UserFromAllGroups -UserSam $UserSam -OperationName "Remove a user from all groups"
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "10" {
            $CsvPath = Read-Host "`nEnter the CSV file path containing users identities"
            ValidateAndImportCsv $CsvPath -RequiredColumns "User" | ForEach-Object {
                Remove-UserFromAllGroups -UserSam $_.User -OperationName "Remove bulk users from all groups"
            }
            break
        }

        "11" {
            $script:isBulkOperation = $false
            try{
                $UserSam = Read-Host "`nEnter the user identity"
                Validate-SingleInput -InputValue $UserSam -Type "User"
                $GroupName = Read-Host "Enter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                Invoke-SetPrimaryGroupForUser -UserSam $UserSam -GroupName $GroupName -OperationName "Change primary group for a user"
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "12" {
            try {
                $CsvPath = Read-Host "`nEnter the CSV file path containing users identities"
                $GroupName = Read-Host "Enter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                ValidateAndImportCsv $CsvPath -RequiredColumns "User" | ForEach-Object {
                    Invoke-SetPrimaryGroupForUser -UserSam $_.User -GroupName $GroupName -OperationName "Change primary group for a user"
                }
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "13"{
            $script:isBulkOperation = $false
            try{
                $GroupName = Read-Host "`nEnter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                $UserSam = Read-Host "Enter the managedBy user identity"
                Validate-SingleInput -InputValue $UserSam -Type "managedBy user"
                Set-GroupManagedBy -UserSam $UserSam -Group $GroupName -OperationName "Add managedBy to a group"
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "14"{
            $CsvPath = Read-Host "`nEnter the CSV file path containing ManagedBy user identity and group identity"
            ValidateAndImportCsv $CsvPath -RequiredColumns @("User","Group") | ForEach-Object {
                Set-GroupManagedBy -UserSam $_.User -Group $_.Group -OperationName "Add managedBy to bulk group"
            }
            break
        }

        "15"{
            $script:isBulkOperation = $false
            try{
                $GroupName = Read-Host "`nEnter the group identity"
                Validate-SingleInput -InputValue $GroupName -Type "Group"
                Remove-GroupManagedBy -Group $GroupName -OperationName "Remove managedBy from a group"
            }
            catch {
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }

        "16"{
            $GroupCsv = Read-Host "Enter the CSV file path containing group identities"
            ValidateAndImportCsv $GroupCsv -RequiredColumns "Group" | ForEach-Object {
                Remove-GroupManagedBy -Group $_.Group -OperationName "Remove managedBy from bulk groups"
            }
            break
        }

        "17"{
            Exit-Script -Exit
        }

        default {
            Write-Host "`nInvalid choice. Please select a valid action." -ForegroundColor Red
        }
    }

    if ($null -ne $script:OperationStatus) {
        if ($script:OperationStatus) {
            Write-Host "`n$script:Message" -ForegroundColor Green
        }
        else {
            Write-Host "`n$script:Message" -ForegroundColor Red
        }
        $script:OperationStatus = $null
    }

    if ($MultiExecutionMode.IsPresent) { $Action = "0" }

} while ($MultiExecutionMode.IsPresent)

$credParams = @{ }
$script:cred = $null; $script:domainName = $null
$script:CredentialBasedExecution = $false
Exit-Script