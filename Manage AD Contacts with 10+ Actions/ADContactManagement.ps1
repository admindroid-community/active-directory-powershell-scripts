<#
=============================================================================================

Name         : Manage Active Directory Contacts Using PowerShell  
Description  : This PowerShell script helps you perform 12 Active Directory contact management actions, supporting both single and bulk operations.
Version      : 1.0
Website      : o365reports.com

~~~~~~~~~~~~~~~~~~
Script Highlights:
~~~~~~~~~~~~~~~~~~
1. Performs 12 actions to manage Active Directory contacts. 
2. Supports bulk contact management for all actions using CSV input files.
3. Allows you to perform multiple actions in a single execution. 
4. Enables you to run a specific contact management action directly. 
5. Automatically installs the Active Directory PowerShell module if it is not already installed.  
6. Exports the execution results to a CSV log file for easy tracking and review. 

For detailed script execution: https://o365reports.com/manage-active-directory-contacts-using-powershell/ 

============================================================================================
#>

param (
    [string]$Action = "0",
    [string]$InputCsvFilePath,
    [switch]$MultiExecutionMode,
    [string]$Username,
    [string]$Password,
    [string]$DomainName
)

function Connect-AdModule {
    try {
        $os = (Get-CimInstance Win32_OperatingSystem).ProductType
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Host "`nActive Directory module is not available."
            $confirm = (Read-Host "Are you sure you want to install the module? [Y] Yes [N] No").Trim()
            if ($confirm -match "[yY]") {
                Write-Host "Installing Active Directory Module..." -ForegroundColor Yellow
                # Check if running on a client or server OS
                if ($os -eq 1) {
                    # Client OS (Windows 10/11)
                    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop | Out-Null
                } else {
                    # Server OS
                    Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
                }
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Host "Active Directory module installed successfully." -ForegroundColor Yellow
            } else {
                Write-Host "`nActive Directory module is required to run this script." -ForegroundColor Red
                Exit 1
            }
        } else {
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        if (($script:CredentialBasedExecution -eq $false) -and ($os -eq 1)) {
            Write-Host "`nExiting. `nCredentials must be provided using the Username and Password parameters to perform Active Directroy operations when running the script on a client OS." -ForegroundColor Red
            Exit 1
        }

        Write-Host "`nActive Directory module loaded successfully." 
    } catch {
        Write-Host "`nFailed to load to Active Directory module: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
}

function Log-ScriptExecution {
    param (
        [string]$Identity,
        [string]$Operation,
        [boolean]$Status,
        [string]$ExecutionMessage,
        [string]$ErrorMessage
    )

    $EventTime = (Get-Date).ToLocalTime()
    $CSVEntry = [PSCustomObject]@{
        EventTime    = $EventTime
        Identity     = $Identity
        Operation    = $Operation.Substring(0,1).ToUpper() + $Operation.Substring(1)
        Status       = if ($Status) { "Success" } else { "Failed" }
        ErrorMessage = if ([string]::IsNullOrEmpty($ErrorMessage)) { "-" } else { $ErrorMessage }
    }

    $CSVEntry | Export-Csv -Path $LogFilePath -NoTypeInformation -Append -Force

    if (([string]::IsNullOrEmpty($InputCsvFilePath))) {
        $script:OperationStatus = $Status
        if ($Status) {
            $script:Message = $ExecutionMessage
        } else {
            $script:Message = "Attempt to $Operation is failed. Error: $ErrorMessage"
        }
    }
}

function ValidateAndImportCsv {
    param (
        [string]$FilePath,
        [string[]]$RequiredColumns
    )

    try {
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
    catch {
        Write-Host "`nCSV validation error: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
}

function Exit-Script {
    param([switch]$Exit)
    if((Test-Path -Path $LogFilePath) -eq "True")
    {   
        Write-Host `n "The log file is availble in: " -NoNewline -ForegroundColor Yellow; Write-Host "$LogFilePath"
        $Prompt = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup("Do you want to open log file?",` 0,"Open Log File",4)
        if ($UserInput -eq 6)
        {
            Invoke-Item "$LogFilePath"
        }
    }
        Write-Host `n~~ Script prepared by Admindroid Community ~~`n -ForegroundColor Green
        Write-Host "~~ Check out " -NoNewline -ForegroundColor Green; Write-Host "admindroid.com" -ForegroundColor Yellow -NoNewline; Write-Host " to access 450+ insightful reports and 70+ management actions across your Active Directory environment. ~~" -ForegroundColor Green `n
    if ($Exit.IsPresent) { Exit 0 }
}

function New-ADContactCustom {
    param (
        [string]$Name,
        [string]$Path
    )

    try {
        New-ADObject -Type contact -Name $Name -Path $Path -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $Name -Operation "create contact" -Status $true -ExecutionMessage "CN=$Name,$Path is created successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $Name -Operation "create contact" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Add-ContactToGroupCustom {
    param (
        [string]$ContactDN,
        [string]$GroupDN
    )

    try {
        Set-ADGroup -Identity $GroupDN -Add @{ member = $ContactDN } -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $ContactDN -Operation "add to group" -Status $true -ExecutionMessage "$ContactDN added to the group: $GroupDN successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "add to group" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Remove-ContactFromGroupCustom {
    param (
        [string]$ContactDN,
        [string]$GroupDN
    )

    try {
        $group = Get-ADGroup -Identity $GroupDN -Properties member -ErrorAction Stop @credParams
        if (!($group.member -contains $ContactDN)) {
            throw "$($ContactDN) is not a member of this group: $($GroupDN )"
        }
        Set-ADGroup -Identity $GroupDN -Remove @{ member = $ContactDN } -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $ContactDN -Operation "remove from group" -Status $true -ExecutionMessage "$ContactDN removed from the group: $GroupDN successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "remove from group" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Move-ContactToOUCustom {
    param (
        [string]$ContactDN,
        [string]$TargetOU,
        [string]$disable,
        [string]$enable
    )

    try {
        $obj = Get-ADObject -Identity $ContactDN -Properties ProtectedFromAccidentalDeletion,ObjectGUID -ErrorAction Stop @credParams
        $IsProtected = $obj.ProtectedFromAccidentalDeletion 
        if ($IsProtected) {
                if ([string]::IsNullOrWhiteSpace($disable)) 
                {
                    $disable=(Read-Host "Accidental deletion protection is enabled on this contact. Do you want to disable it and continue? [Y] Yes [N] No").Trim()
                }
                if ([string]::IsNullOrWhiteSpace($enable)) 
                {
                    $enable=(Read-Host "Do you want to enable accidental deletion protection after relocating this contact? [Y] Yes [N] No").Trim()
                } 
            if($disable -match "[yY]")
            {
                Update-AccidentalDeletionProtection -Identity $obj.ObjectGUID -Status $false
            }
            else
            {
                throw "$($ContactDN) is protected from accidental deletion and cannot be moved."
            }
        }
        Move-ADObject -Identity $ContactDN -TargetPath $TargetOU -ErrorAction Stop @credParams
        if($enable -match "[yY]")
        {
            Update-AccidentalDeletionProtection -Identity $obj.ObjectGUID -Status $true
        }      
    Log-ScriptExecution -Identity $ContactDN -Operation "move contact to $TargetOU" -Status $true -ExecutionMessage "$($obj.Name) is moved to $($TargetOU) successfully." -ErrorMessage ""
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "move contact to $TargetOU" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Remove-ADContactCustom {
    param (
        [string]$ContactDN,
        [string]$canRemove
    )

    try {
         $obj = Get-ADObject -Identity $ContactDN -Properties ProtectedFromAccidentalDeletion @credParams
         $IsProtected = $obj.ProtectedFromAccidentalDeletion 
                if ($IsProtected) {
                    if ([string]::IsNullOrWhiteSpace($canRemove)) 
                     {
                          $canRemove=(Read-Host "Accidental deletion protection is enabled on this contact. Do you want to disable it and continue? [Y] Yes [N] No").Trim()
                     }
                    if($canRemove -match "[yY]")
                    {
                        Update-AccidentalDeletionProtection -Identity $ContactDN -Status $false
                     }
                    else
                    {
                        throw "$($ContactDN) is protected from accidental deletion and cannot be deleted."
                    }
                }
        Remove-ADObject -Identity $ContactDN -Confirm:$false -ErrorAction Stop @credParams 
        Log-ScriptExecution -Identity $ContactDN -Operation "delete contact" -Status $true -ExecutionMessage "$ContactDN is deleted successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "delete contact" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Update-ContactManager {
    param (
        [string]$Manager,
        [string]$ContactDN,
        [string]$action       
    )

    try {
        if($action -eq "set")
        {
            Set-ADObject -Identity $ContactDN  -Replace @{ Manager = $Manager} -ErrorAction Stop @credParams            
        }
        else
        {
            Set-ADObject -Identity $ContactDN -Clear Manager -ErrorAction Stop @credParams         
        }
        Log-ScriptExecution -Identity $ContactDN -Operation "$action contact manager" -Status $true -ExecutionMessage "contact manager is $action successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "$action contact manager" -Status $false -ErrorMessage  $_.Exception.Message
    }
}

function Restore-ADContactCustom {
    param(
        [string]$ContactName
    )

    try {
        $RecycleBinEnable=(Get-ADOptionalFeature -Identity 'Recycle Bin Feature' @credParams ).EnabledScopes
        if( $RecycleBinEnable -ne $null)
        {
            $del = Get-ADObject -IncludeDeletedObjects -LDAPFilter "(&(objectClass=Contact)(isDeleted=TRUE)(msDS-LastKnownRDN=$ContactName))" -Properties lastKnownParent, whenChanged @credParams | Sort-Object whenChanged -Descending | Select-Object -First 1
        }
        else
        {
            $del=Get-ADObject -Filter "Name -like '$($ContactName)*' -and ObjectClass -eq 'contact' -and isDeleted -eq `$true" -IncludeDeletedObjects -Properties lastKnownParent, whenChanged @credParams| Sort-Object whenChanged -Descending | Where-Object { ($_.Name -split "`n")[0] -eq "$ContactName"} | Select-Object -First 1
        }
        if ($del) {
            if (-not $del.lastKnownParent) {
                throw "Cannot restore. lastKnownParent is missing."
            }
             if( $RecycleBinEnable -ne $null)
                {
                    Restore-ADObject -Identity $del.ObjectGUID -ErrorAction Stop @credParams
                }
                else
                {
                    Restore-ADObject -Identity $del.ObjectGUID -NewName "$ContactName" -ErrorAction Stop @credParams
                }
            $ContactDN=(Get-ADObject -Identity $del.ObjectGUID -Properties distinguishedName -ErrorAction Stop @credParams).distinguishedName
            Log-ScriptExecution -Identity $ContactDN -Operation "restore contact" -Status $true -ExecutionMessage "$ContactDN is restored successfully." -ErrorMessage "-"
        }
        else {
            throw "Not found in deleted objects."
        }
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactName -Operation "restore contact" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Update-ADContactProperties {
    param (
        [string]$ContactDN,
        [string]$PropertyToUpdate,
        [string]$OperationToPerform,
        [string]$Value
    )

    try {
        $setParams = @{ Identity = $ContactDN; ErrorAction = 'Stop' }

        switch ($OperationToPerform) {
            'Add' {
                $setParams['Add'] = @{ $PropertyToUpdate = $Value }
            }
            'Replace' {
                if ($PropertyToUpdate -eq 'ProtectedFromAccidentalDeletion') {
                    $setParams[$PropertyToUpdate] = [System.Convert]::ToBoolean($Value)
                    break
                }
                $setParams['Replace'] = @{ $PropertyToUpdate = $Value }
            }
            'Remove' {
                $setParams['Remove'] = @{ $PropertyToUpdate = $Value }
            }
            'Clear' {
                $setParams['Clear'] = @($PropertyToUpdate)
            }
            default {
                throw "Invalid operation: $OperationToPerform. Valid operations are Add, Replace, Remove, Clear."
            }
        }

        Set-ADObject @setParams @credParams
        Log-ScriptExecution -Identity $ContactDN -Operation "$OperationToPerform contact property ($PropertyToUpdate)" -Status $true -ExecutionMessage  "$($ContactDN) : $OperationToPerform operation On property $PropertyToUpdate is performed successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "$OperationToPerform contact property ($PropertyToUpdate)" -Status $false -ErrorMessage $_.Exception.Message
    }
}

function Rename-ADObjects {
    param (
        [string]$newName,
        [string]$ContactDN       
    )
    try {
        Rename-ADObject -Identity $ContactDN -NewName $newName @credParams
        Log-ScriptExecution -Identity $ContactDN -Operation "rename contact to '$($newName)'" -Status $true -ExecutionMessage "contact: $ContactDN is renamed successfully." -ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $ContactDN -Operation "rename contact to '$($newName)'" -Status $false -ErrorMessage  $_.Exception.Message
    }
}

function Update-AccidentalDeletionProtection {
    param (
        [string]$Identity,
        [bool]$Status
    )
    try {
        Set-ADObject -Identity $Identity -ProtectedFromAccidentalDeletion $Status -ErrorAction Stop @credParams
        Log-ScriptExecution -Identity $Identity -Operation "$(if ($Status) { 'Enable' } else { 'Disable' }) Accidental Deletion Protection of contact" -Status $true -ExecutionMessage  "Accidental deletion protection is $(if ($Status) { 'enable' } else { 'disable' })d for $($Identity) successfully"-ErrorMessage "-"
    }
    catch {
        $script:AllSuccess = $false
        Log-ScriptExecution -Identity $Identity -Operation "$(if ($Status) { 'Enable' } else { 'Disable' }) Accidental Deletion Protection of contact" -Status $false -ErrorMessage  $_.Exception.Message
    }
}

$credParams = @{}
$script:CredentialBasedExecution = $false
if ((!([string]::IsNullOrEmpty($Username))) -and (!([string]::IsNullOrEmpty($Password)))) {
    $script:CredentialBasedExecution = $true
    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $script:cred = [PSCredential]::new($Username, $SecurePassword)
    try {
        if ((!([string]::IsNullOrEmpty($DomainName)))) {
            $script:domainName = $DomainName
        } else {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $script:domainName = $domain.Name
        }
    }
    catch {
        $script:domainName = (Read-Host "Enter the Active Directory Domain name").Trim()
    }

    $credParams = @{ Credential = $script:cred; Server = $script:domainName }
}

Connect-AdModule
$script:OperationStatus = $null
$script:Message = ""
$script:AllSuccess = $true
$script:ActionName = ""
$script:RequireCSV = 0
$Location = Get-Location
$LogFilePath = "$Location\ADContact_Management_Log_$(Get-Date -Format 'yyyy-MMM-dd-ddd_hh-mm_tt').csv"

do {
    if ($Action -eq "0") {
        Write-Host "`n=======================================" -ForegroundColor cyan
        Write-Host "   Active Directory Contact Management   " -ForegroundColor Green
        Write-Host "=======================================`n" -ForegroundColor cyan
        Write-Host "You can also perform bulk operations by passing the -InputCsvFilePath parameter during script execution.`n" -ForegroundColor DarkYellow
        Write-Host @"
        1. Create contact(s)
        2. Add contact(s) to group(s)
        3. Set contact manager(s)
        4. Enable accidental deletion protection for contact(s)
        5. Move contact(s) from one OU to another OU
        6. Rename contact(s)
        7. Update contact property(s)
        8. Disable accidental deletion protection for contact(s)
        9. Remove contact manager(s)
       10. Remove contact(s) from group(s)
       11. Delete contact(s)
       12. Restore contact(s)
       13. Exit 
"@ -ForegroundColor Yellow

        $Action = (Read-Host "`nPlease choose the action to continue").Trim()
         if (($script:RequireCSV -gt 0) -and (!([string]::IsNullOrEmpty($InputCsvFilePath))) -and ($Action -ne @("13"))) {
                $InputCsvFilePath = (Read-Host "`nEnter input CSV file path to perform bulk operation, or press 'Enter' to run single operation").Trim()
        }
    }

    switch ($Action) {
        "1" {
            $script:ActionName = "Create contact(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $Name = (Read-Host -Prompt "`nEnter the Name of the Contact").Trim()
                $Path = (Read-Host -Prompt "Enter the Path to where you want to create the Contact").Trim()

                New-ADContactCustom -Name $Name -Path $Path
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "Name", "Path" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Currently Processing $($_.Name)" -PercentComplete 100
                    New-ADContactCustom -Name $_.Name -Path $_.Path
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

        "2" {
            $script:ActionName = "Add contact(s) to group(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                $GroupDN = (Read-Host -Prompt "Enter the Distinguished Name of the Group to add the contact").Trim()

                Add-ContactToGroupCustom -ContactDN $ContactDN -GroupDN $GroupDN
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN", "GroupDN" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Currently Processing $($_.ContactDN)" -PercentComplete 100
                    Add-ContactToGroupCustom -ContactDN $_.ContactDN -GroupDN $_.GroupDN
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

         "3" {
            $script:ActionName = "Set contact manager(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                $Manager = (Read-Host -Prompt "Enter the Distinguished Name of the manager").Trim()
                Update-ContactManager -ContactDN $ContactDN -Manager $Manager -action "set"
            } 
            else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN", "Manager" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Assigning $($_.Manager) as a manager for $($_.ContactDN)" -PercentComplete 100
                    Update-ContactManager -ContactDN $_.ContactDN -Manager $_.Manager -action "set"
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }
         "4" {
            $script:ActionName = "Enable accidental deletion protection for contact(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                Update-AccidentalDeletionProtection -Identity $ContactDN -Status $true
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Enabling accidental deletion protection for $($_.ContactDN)" -PercentComplete 100
                    Update-AccidentalDeletionProtection  -Identity $_.ContactDN -Status $true
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

        

        "5" {
            $script:ActionName = "Move contact(s) from one OU to another OU"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                $TargetOUPath  = (Read-Host -Prompt "Enter target OU path where you want to move the contact").Trim()

                Move-ContactToOUCustom -ContactDN $ContactDN -TargetOU $TargetOUPath
            } else {
                $disable=(Read-Host "If protection accidental deletion is enabled. Do you want to disable it and continue?[Y] Yes [N] No").Trim()
                $enable=(Read-Host "Do you want to enable protection accidental deletion after move ? [Y] Yes [N] No").Trim()
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN", "TargetOUPath" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Moving $($_.ContactDN) to $($_.TargetOUPath)" -PercentComplete 100
                    Move-ContactToOUCustom -ContactDN $_.ContactDN -TargetOU $_.TargetOUPath -disable $disable -enable $enable
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

      "6" {
          $script:ActionName = "Rename contact(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                $newName = (Read-Host -Prompt "Enter the New name for the contact").Trim()
                Rename-ADObjects -newName $newName -ContactDN $ContactDN 
            } 
            else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN", "newName" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Renaming $($_.ContactDN) to $($_.newName)" -PercentComplete 100
                    Rename-ADObjects -ContactDN $_.ContactDN -newName $_.newName
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }
       
      "7" {
          $script:ActionName = "Update contact property(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter contact distinguished Name").Trim()
                $OperationToPerform = (Read-Host -Prompt "Enter the Operation to Perform (Add/Remove/Replace/Clear)").Trim()
                $prop = (Read-Host -Prompt "Enter the property name to update").Trim()
                if($OperationToPerform -ne "Clear"){ $Value = Read-Host -Prompt "Enter the value" }
                Update-ADContactProperties -ContactDN $ContactDN -PropertyToUpdate $prop -Value $Value -OperationToPerform $OperationToPerform
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN", "PropertyToUpdate", "Value", "OperationToPerform" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Updating $($_.PropertyToUpdate) property of $($_.ContactDN)" -PercentComplete 100
                    Update-ADContactProperties -ContactDN $_.ContactDN -PropertyToUpdate $_.PropertyToUpdate -Value $_.Value -OperationToPerform $_.OperationToPerform
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }
       
       "8" {
           $script:ActionName = "Disable accidental deletion protection for contact(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                Update-AccidentalDeletionProtection -Identity $ContactDN -Status $false
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Disabling accidental deletion protection for $($_.ContactDN)" -PercentComplete 100
                    Update-AccidentalDeletionProtection -Identity $_.ContactDN -Status $false
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

       

        "9" {
            $script:ActionName = "Remove contact manager(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                Update-ContactManager -ContactDN $ContactDN -action "removed"
            } 
            else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Removing manager from $($_.ContactDN)" -PercentComplete 100
                    Update-ContactManager -ContactDN $_.ContactDN -action "removed"
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }
         
        "10" {
            $script:ActionName = "Remove contact(s) from group(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                $GroupDN = (Read-Host -Prompt "Enter the Distinguished Name of the Group to remove the contact from").Trim()

                Remove-ContactFromGroupCustom -ContactDN $ContactDN -GroupDN $GroupDN
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN", "GroupDN" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Removing $($_.ContactDN) from $($_.GroupDN)" -PercentComplete 100
                    Remove-ContactFromGroupCustom -ContactDN $_.ContactDN -GroupDN $_.GroupDN
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

        "11" {
            $script:ActionName = "Delete contact(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactDN = (Read-Host -Prompt "`nEnter the Distinguished Name (DN) of the contact").Trim()
                Remove-ADContactCustom -ContactDN $ContactDN
            } else {
                Write-Host " if contact accidental deletion is on, would you like me to off and execute the action?"
                $canRemove=(Read-Host "[Y] Yes [N] No").Trim()
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "ContactDN" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Deleting $($_.ContactDN)" -PercentComplete 100
                    Remove-ADContactCustom -ContactDN $_.ContactDN -canRemove $canRemove
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

        "12"{
            $script:ActionName = "Restore contact(s)"
            if ([string]::IsNullOrWhiteSpace($InputCsvFilePath)) {
                $ContactName = (Read-Host -Prompt "`nEnter the Name of the Contact you want to restore").Trim()
                Restore-ADContactCustom -ContactName $ContactName
            } else {
                ValidateAndImportCsv -FilePath $InputCsvFilePath -RequiredColumns "Name" | ForEach-Object {
                    Write-Progress -Activity "Processed contacts count: $($Count)" -Status "Restoring $($_.Name)" -PercentComplete 100
                    Restore-ADContactCustom -ContactName $_.Name
                    $Count++
                }
                Write-Progress -Activity "Completed" -Completed
            }
            break
        }

       "13" {
            Exit-Script -Exit
        }

        default {
            Write-Host "`nInvalid choice. Please select a valid action." -ForegroundColor Red
           Exit-Script -Exit
        }
    }

    if ($script:OperationStatus -ne $null) {
        if ($script:OperationStatus -eq $true) {
            Write-Host "`n$($script:Message)" -ForegroundColor Green
        } else {
            Write-Host "`n$($script:Message)" -ForegroundColor Red
        }
    }

    if ($MultiExecutionMode.IsPresent -and ![string]::IsNullOrWhiteSpace($InputCsvFilePath)) { 
        if ($script:AllSuccess) {
            Write-Host "`n$ActionName completed successfully for all given contacts." -ForegroundColor Green
        }
        else {
            Write-Host "`n$ActionName completed with some failures. Check the log file: " -NoNewline -ForegroundColor red; Write-Host "$LogFilePath"
        } 
        $script:AllSuccess = $true
        $script:ActionName = ""
    }

    if ($MultiExecutionMode.IsPresent) 
    { 
        $Action = "0"
        $script:RequireCSV=1
    }
   
} while ($MultiExecutionMode.IsPresent)

$credParams = @{}
$script:cred = $null; $script:domainName = $null
$script:CredentialBasedExecution = $false
$script:OperationStatus = $null; $script:Message = ""

Exit-Script