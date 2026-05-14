#REQUIRES -Version 5.0

<#
.SYNOPSIS
    A utility to setup an Entra ID Application, to be used with Adlumin's MDR service.
.DESCRIPTION
    A utility to setup an Entra ID Application.
    This script will create an application in Entra ID, assign the necessary permissions, and generate a client secret.
    The output of this script will be the necessary information to be entered into the Adlumin Azure Integration section for the tenant.
.NOTES
    File Name      : Azure_Adlumin_Setup_V3.0.ps1
    Author         : John Peterson
    Prerequisite   : PowerShell V5, an Entra ID account with the necessary permissions.
    Version        : 3.5
    Disclaimer     : Sample scripts are not supported under any N-able support program or service.
                     The sample scripts are provided AS IS without warranty of any kind.
                     N-able expressly disclaims all implied warranties including, warranties
                     of merchantability or of fitness for a particular purpose. 
                     In no event shall N-able or any other party be liable for damages arising
                     out of the use of or inability to use the sample scripts.
.EXAMPLE
    .\Azure_Adlumin_Setup_V3.0.ps1
#>

$workingDirectory = "C:\ProgramData\N-Able Technologies\N-hanced Services\Azure Adlumin Setup"
$logFile = "$workingDirectory\Azure_Adlumin_Setup.log"
$script:outputParams = [pscustomobject]@{}
$script:entraIDAppName = "N-able Technologies - Adlumin MDR Integration"

$script:entraIDResourceAppID = "00000003-0000-0000-c000-000000000000"
$script:o365ResourceAppID = "c5393580-f805-4401-95e8-94b7a6ef2fc2"
$script:ATPResourceAppID = "fc780465-2017-40d4-a0c5-307022471b92"
$script:IntuneResourceAppID = "c161e42e-d4df-4a3d-9b42-e7a3c31f59d4"

$script:entraIDPermissionIDs = @{
    "AuditLogReadAll"                                       = "b0afded3-3588-46d8-8b3d-9842eff778da"
    "DeviceManagementAppsReadAll"                           = "7a6ee1e7-141e-4cec-ae74-d9db155731ff"
    "DeviceManagementAppsReadWriteAll"                      = "78145de6-330d-4800-a6ce-494ff2d33d07"
    "DeviceManagementConfigurationReadAll"                  = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
    "DeviceManagementConfigurationReadWriteAll"             = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"
    "DeviceManagementManagedDevicesPrivilegedOperationsAll" = "5b07b0dd-2377-4e44-a38d-703f09a0dc3c"
    "DeviceManagementManagedDevicesReadAll"                 = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
    "DeviceManagementManagedDevicesReadWriteAll"            = "243333ab-4d21-40cb-a475-36241daa0842"
    "DeviceManagementRBACReadAll"                           = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
    "DeviceManagementRBACReadWriteAll"                      = "e330c4f0-4170-414e-a55a-2f022ec2b57b"
    "DeviceManagementServiceConfigReadAll"                  = "06a5fe6d-c49d-46a7-b082-56b1b14103c7"
    "DeviceManagementServiceConfigReadWriteAll"             = "5ac13192-7ace-4fcf-b828-1a26f28068ee"
    "DirectoryReadAll"                                      = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
    "IdentityRiskEventReadAll"                              = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
    "IdentityRiskyUserReadWriteAll"                         = "656f6061-f9fe-4807-9708-6a2e0934df76"
    "PolicyReadAll"                                         = "246dd0d5-5bd0-4def-940b-0421030a5b68"
    "PolicyReadWriteConditionalAccess"                      = "01c0a623-fc9b-48e9-b794-0756f8e8f067"
    "SecurityActionsReadAll"                                = "5e0edab9-c148-49d0-b423-ac253e121825"
    "SecurityActionsReadWriteAll"                           = "f2bf083f-0179-402a-bedb-b2784de8a49b"
    "SecurityAlertReadAll"                                  = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"
    "SecurityAlertReadWriteAll"                             = "ed4fca05-be46-441f-9803-1873825f8fdb"
    "SecurityAnalyzedMessageReadAll"                        = "b48f7ac2-044d-4281-b02f-75db744d6f5f"
    "SecurityAnalyzedMessageReadWriteAll"                   = "04c55753-2244-4c25-87fc-704ab82a4f69"
    "SecurityEventsReadAll"                                 = "bf394140-e372-4bf9-a898-299cfc7564e5"
    "SecurityEventsReadWriteAll"                            = "d903a879-88e0-4c09-b0c9-82f6a1333f84"
    "SecurityIncidentReadAll"                               = "45cc0394-e837-488b-a098-1918f48d186c"
    "SecurityIncidentReadWriteAll"                          = "34bf0e97-1971-4929-b999-9e2442d941d7"
    "UserManageIdentitiesAll"                               = "c529cfca-c91b-489c-af2b-d92990b66ce6"
    "UserReadAll"                                           = "df021288-bdef-4463-88db-98f22de89214"
    "UserReadWriteAll"                                      = "741f803b-c850-494e-b5df-cde7c675a1ca"
    "UserAuthenticationMethodReadAll"                       = "38d9df27-64da-44fd-b7c5-a6fbac20248f"
}


$script:o365PermissionIDs = @{
    "ServiceHealthRead"   = "e2cea78f-e743-4d8f-a16a-75b629a038ae"
    "ActivityFeedRead"    = "594c1fb6-4f81-4475-ae41-0c394909246c"
    "ActivityFeedReadDlp" = "4807a72c-ad38-4250-94c9-4eabfe26cd55"
}


$script:defenderATPPermissionIDs = @{
    "AdvancedQuery.Read.All"    = "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"
    "Alert.Read.All"            = "71fe6b80-7034-4028-9ed8-0f316df9c3ff"
    "Alert.ReadWrite.All"       = "0f7000ec-157b-497f-b70e-ef0b0584f140"
    "Ip.Read.All"               = "47bf842d-354b-49ef-b741-3a6dd815bc13"
    "Machine.CollectForensics"  = "15405ab2-2103-4a3c-ad80-e829841cedcc"
    "Machine.Isolate"           = "7e4e1300-e1b9-4102-88ba-f0cb6e6d5974"
    "Machine.LiveResponse"      = "1629b959-c0af-42a1-92f0-f6162060bdf1"
    "Machine.Read.All"          = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79"
    "Machine.ReadWrite.All"     = "aa027352-232b-4ed4-b963-a705fc4d6d2c"
    "Machine.RestrictExecution" = "96b6b35d-074d-4e2d-b167-8d68d9269648"
    "Machine.Scan"              = "a86d9824-b2b6-45f8-b042-16bc4922ed4e"
    "Machine.StopAndQuarantine" = "96e72b5e-7e68-4171-aad1-3937599e4751"
    "Software.Read.All"         = "37f71c98-d198-41ae-964d-2c49aab74926"
}


$script:intunePermissionIDs = @{
    "scep_challenge_provider"          = "39d724e8-6a34-4930-9a36-364082c35716"
    "pfx_cert_provider"                = "907d16c7-7591-49a4-b523-6fd42e5f2c7e"
    "send_data_usage"                  = "7828b294-fdcc-4ed6-a45a-854364afb21d"
    "update_device_health"             = "a5438881-186a-48f0-bc41-a93ae8a195fe"
    "get_device_compliance"            = "7ec88bad-30c7-4928-a005-4455362cfd98"
    "update_device_attributes"         = "7b3c62c0-bbe4-4ceb-971b-ecc50a191b3e"
    "get_data_warehouse"               = "3d9dc976-32fb-45a8-90bd-c9f8a850d098"
    "manage_partner_compliance_policy" = "3857e233-c379-404e-85e9-bdbf3a62b28f"
}

function Out-Logfile($state, $message, $foregroundColour = [System.Console]::ForegroundColor, $logToConsoleOnly = $false) {

    $script:timestamp = "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)

    switch -regex -Wildcard ($state) {
        "I" {
            $state = "INFO"
        }
        "E" {
            $state = "ERROR"
        }
        "W" {
            $state = "WARNING"
        }
        "F" {
            $state = "FAILURE"
        }
        "V" {
            $state = "VERBOSE"
        }
        "" {
            $state = "INFO"
        }
        Default {
            $state = "INFO"
        }
    }
    $string = "$($timestamp) - [$state]: $message"
    write-host "$($timestamp) - " -NoNewline #This outputs the timestamp and state in white
    write-host "[$state]: $message" -ForegroundColor $foregroundColour #This outputs the message in a specific colour on the same line as above
    if (!$logToConsoleOnly) {
        $string | Out-File $logFile -Append 
    }
}

# Function to initialize the log file if it does not exist
function New-LogFileAndWorkingDirectory ($workingDirectory, $logFile) {
    #Create the working directory
    if (!(test-path $workingDirectory)) {
        try {
            New-Item -ItemType Directory -Path $workingDirectory -ErrorAction Stop | Out-Null
            Write-Host "Working directory $workingDirectory has been created."
        }
        catch {
            $errorString = "We have failed to create the folder $workingDirectory which is the working directory of the script. Error message is: $($_.Exception)"
            Write-Host $errorString
            Exit-WithFailure
        }
    }
    else {
        Write-Host "Working directory $workingDirectory has been created."
    }

    #Create the logFile in the logFilePath
    try {
        New-Item -ItemType File -Path $logFile -ErrorAction Stop -Force | Out-Null
        Out-Logfile V "Log file $logFile has been created. Switched to logfile logging format."
    }
    catch {
        $errorString = "We have failed to create the file $logFile which is logfile the script logs to. Error message is: $($_.Exception)"
        Write-Host $errorString
        Exit-WithFailure
    }
}

function Exit-WithFailure {
    Out-Logfile E "Script has failed. Exiting." Red
    try {
        Get-MgContext
        Disconnect-Connections
    } catch {
        #This will error if the modules haven't been loaded.
    }
    Exit 1
}

function Exit-WithSuccess {
    Disconnect-Connections
    Exit 0
}

function Import-MicrosoftGraphModules () {
    $arrayOfModules = @("Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.Governance",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "ExchangeOnlineManagement")

    $missingModules = @()
    $graphModulesNotOnVersion2_26_1 = @()
    $exchangeOnlineManagementModuleOnVersion3_7_2 = $false
    $graphModulesAndTheirVersions = @{}
    Out-Logfile V "Checking if modules $($arrayOfModules -join ', ') are installed, if Microsoft Graph modules are installed with version 2.26.1, and if ExchangeOnlineManagement is on 3.7.2 or newer." Yellow
    foreach ($moduleName in $arrayOfModules) {
        $module = Get-Module -Name $moduleName -ListAvailable
        if ($null -eq $module) {
            $missingModules += $moduleName
        }
        else {
            if($moduleName.StartsWith("Microsoft.Graph")) {
                $doesModuleExistAs2_26_1 = $false
                
                foreach ($mod in $module) {
                    if($mod.Version.ToString() -eq "2.26.1") {
                        $doesModuleExistAs2_26_1 = $true
                        break
                    }
                }
                if(!$doesModuleExistAs2_26_1) {
                    $graphModulesNotOnVersion2_26_1 += $moduleName
                }
            }
            if($moduleName -eq "ExchangeOnlineManagement") {
                $doesModuleExistAs3_7_2 = $false
                foreach ($mod in $module) {
                    if($mod.Version.ToString() -ge "3.7.2") {
                        $doesModuleExistAs3_7_2 = $true
                        break
                    }
                }
                if($doesModuleExistAs3_7_2) {
                    $exchangeOnlineManagementModuleOnVersion3_7_2 = $true
                }
            }
        }
    }
    if ($missingModules.Count -gt 0 -or $graphModulesNotOnVersion2_26_1.Count -gt 0 -or !$exchangeOnlineManagementModuleOnVersion3_7_2) {
        if($missingModules.Count -gt 0) {
            Out-Logfile E "The following modules are missing: $($missingModules -join ', ')" Red
        }
        if($graphModulesNotOnVersion2_26_1.Count -gt 0) {
            Out-Logfile E "The following modules are not on version 2.26.1: $($graphModulesNotOnVersion2_26_1 -join ', ')" Red
        }
        if(!$exchangeOnlineManagementModuleOnVersion3_7_2) {
            Out-Logfile E "The ExchangeOnlineManagement module is on a version older than 3.7.2." Red
        }
        Out-Logfile I "Do you wish to install these modules? [Y/N]" Yellow
        $response = Read-Host
        if ($response.ToLower() -eq "y") {
            $jointArrays = $missingModules += $graphModulesNotOnVersion2_26_1
            if(!$exchangeOnlineManagementModuleOnVersion3_7_2) {
                $jointArrays += "ExchangeOnlineManagement"
            }
            foreach ($module in $jointArrays) {
                try {
                    if($module.StartsWith("Microsoft.Graph")) {
                        Out-Logfile I "Installing module $module with version 2.26.1." Yellow
                        Install-Module -Name $module -RequiredVersion 2.26.1 -Force -AllowClobber -ErrorAction Stop
                    }
                    else {
                        Out-Logfile I "Installing module $module." Yellow
                        Install-Module -Name $module -Force -AllowClobber -ErrorAction Stop
                    }
                }
                catch {
                    Out-Logfile E "Failed to install module $module. Error message is: $($_.Exception)" Red
                    Exit-WithFailure
                }
            }

        }
        else {
            Out-Logfile E "You have opted for the modules to not be installed via this script. Please install these modules manually using install-module. Make sure to install Microsoft Graph Modules on version 2.26.1." Red
            Exit-WithFailure
        }
    }
    
    Out-Logfile V "All required modules are present. Importing modules"
    foreach ($module in $arrayOfModules) {
        try {
            if($module.StartsWith("Microsoft.Graph")) {
                Import-Module -Name $module -requiredVersion 2.26.1 -ErrorAction Stop
            }
            else {
                Import-Module -Name $module -ErrorAction Stop
            }
        }
        catch {
            Out-Logfile E "Failed to import module $module. Error message is: $($_.Exception.Message)" Red
            if($_.Exception.Message -like "*Assembly with same name is already loaded*") {
                Out-Logfile E "This indicates that multiple Microsoft Graph modules are installed on your device, and an existing Microsoft Graph assembly of a different version to 2.26.1 has been loaded." Red
                Out-Logfile E "If you're running the script in VSCode, run this instead in Powershell or Windows Terminal. Alternatively, close all instances of PowerShell, remove all Microsoft Graph versions which are not 2.26.1, and run the script again." Red
            }
            Exit-WithFailure
        }
    }
}

function Connect-EntraIDTenant () {
    Out-Logfile I "Connecting to Graph."
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    try {
        Connect-MgGraph -Scopes "Application.Read.All", "Application.ReadWrite.All", "User.Read.All", "RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All", "Organization.Read.All", "AuditLog.Read.All", "AppRoleAssignment.ReadWrite.All" -ErrorAction Stop | Out-Null
    }
    catch {
        Out-Logfile E "Failed to connect to Graph. Error message is: $($_.Exception.Message)" Red
        Exit-WithFailure
    }
    
    $script:context = Get-MgContext
    if($null -eq $script:context) {
        Out-Logfile E "When we get the context of the connection, it is null. This indicates that Graph has not connected due to a timeout. Exiting script." Red
        Exit-WithFailure
    }
    $script:outputParams | Add-Member -NotePropertyName "TenantID" -NotePropertyValue $script:context.TenantId
    $script:outputParams | Add-Member -NotePropertyName "domainName" -NotePropertyValue (Get-MgDomain | Where-Object { $_.isDefault }).Id
}

function Get-TenantAuditLogs () {
    Disconnect-ExchangeOnline -Confirm:$false
    #Query audit logs using Exchange Online
    Out-Logfile I "Connecting to Exchange Online to determine if Purview auditing is enabled."
    $exchangeOnlineModule = Get-Module ExchangeOnlineManagement
    $msalPath = [System.IO.Path]::GetDirectoryName(($exchangeOnlineModule[0]).Path);
    Add-Type -Path "$msalPath\Microsoft.IdentityModel.Abstractions.dll";
    Add-Type -Path "$msalPath\Microsoft.Identity.Client.dll";
    [Microsoft.Identity.Client.IPublicClientApplication] $application = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create("fb78d390-0c51-40cd-8e17-fdbfab77341b").WithDefaultRedirectUri().Build();
    $task = $application.AcquireTokenInteractive([string[]]"https://outlook.office365.com/.default").ExecuteAsync()
    $timeout = 30
    
    if ($task.Wait($timeout * 1000)) {
        $result = $task.Result
    } else {
        Out-Logfile I "Timeout exceeded when attempting to connect to Exchange online. Authentication window was closed or not responded. Exiting script." Red
        Exit-WithFailure
    }
    
    try {
        Out-Logfile I "Connecting to ExchangeOnline with user $($result.Account.Username)." Yellow
        Connect-ExchangeOnline -AccessToken $result.AccessToken -UserPrincipalName $result.Account.Username -ShowBanner:$false -ErrorAction Stop
    }
    catch {
        Out-Logfile E "Failed to connect to Exchange Online. Error message is: $($_.Exception.Message)" Red
        Exit-WithFailure
    }

    if ((Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled) {
        Out-Logfile I "Unified Audit Log Ingestion is enabled. Purview logging is fully enabled." Green
        $script:outputParams | Add-Member -NotePropertyName "AuditLoggingEnabled" -NotePropertyValue $true
    }
    else {
        Out-Logfile W "Unified Audit Log Ingestion is disabled. Attempting to enable logging now." Yellow
        $previousErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        try {
            Enable-OrganizationCustomization
        }
        catch {
            if ($_.Exception.Message -like "*Organization is already enabled for customization*") {
                Out-Logfile I "The Organization is configured for customization." Green
            }
            else {
                Out-Logfile E "There was an exception when enabling customization in the organization. This is required before Unified Audit Log Ingestion can be enabled." Red
                Out-Logfile E "Exception is: $($_.Exception.Message)" Red
                $ErrorActionPreference = $previousErrorAction
                Exit-WithFailure
            }
        }
        try {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        }
        catch {
            Out-Logfile E "There was an exception when attempting to enable Unified Audit Log Ingestion. Exception is: $($_.Exception.Message)" Red
            Out-Logfile E "Please enable Audit Logging manually by following the steps found here: https://learn.microsoft.com/en-us/purview/audit-log-enable-disable" Red
        }
        $ErrorActionPreference = $previousErrorAction 
        $adminAuditLog = Get-AdminAuditLogConfig
        if($adminAuditLog.UnifiedAuditLogIngestionEnabled) {
            Out-Logfile I "Unified Audit Log Ingestion was successfully enabled. Purview logging is fully enabled." Green
            $script:outputParams | Add-Member -NotePropertyName "AuditLoggingEnabled" -NotePropertyValue $true
        }
        else {
            Out-Logfile E "Unified Audit Log Ingestion was not enabled." Red
            $script:outputParams | Add-Member -NotePropertyName "AuditLoggingEnabled" -NotePropertyValue $false
        }
    }
}

function Confirm-ExistingApp () {
    Out-Logfile I "Looking for an existing app with name $script:entraIDAppName."
    $alreadyexists = Get-MgApplication -ConsistencyLevel eventual -Search "DisplayName: $script:entraIDAppName"
    $appExists = $false
    if ($alreadyexists) {
        $script:entraIDAppName = $alreadyexists.DisplayName
        $appExists = $true
    } else {
        Out-Logfile I "App $script:entraIDAppName not found." Green
        Out-Logfile I "Do you have an existing Entra ID App registered for Adlumin? [Y/N]" Yellow
        $response = Read-Host
        if ($response.ToLower() -eq "y") {
            Out-Logfile I "Please enter the App ID of the existing app. This will be called Application (client) ID in the Entra ID portal." Yellow
            $tempAppId = Read-Host
            $alreadyexists = Get-MgApplication -ConsistencyLevel eventual -Search "AppId:$tempAppId"
            if($alreadyexists) {
                $appExists = $true
                $script:entraIDAppName = $alreadyexists.DisplayName
            } else {
                Out-Logfile W "We cannot find an app with ID $tempAppId. Do you want a new app to be created? If you say no, the script will end. [Y/N]" Yellow
                $response = Read-Host
                if($response.ToLower() -eq "y") {
                    Out-Logfile I "You have said yes. We will create a new Entra ID App." Green
                    return $appExists
                } else {
                    Out-Logfile I "You have said no. We will exit." Yellow
                    Exit-WithSuccess
                }
            }
        }
        else {
            Out-Logfile I "You have said no. We will create a new Entra ID App." Green
            return $appExists
        }
    }
    if ($appExists) {
        $script:AppId = $alreadyexists.AppId
        Out-Logfile I "*****************************************************************************************" Green
        Out-Logfile I "" Green
        Out-Logfile I "Enterprise App $script:entraIDAppName has been found in your tenant." Green
        Out-Logfile I "Would you like the script to update the existing app permissions? [Y/N]" Yellow
        $response = Read-Host
        if ($response.ToLower() -eq "y") {
            Out-Logfile I "You have said yes. Updating the existing app permissions." Green
            Out-Logfile I "*****************************************************************************************" Green
            Out-Logfile I ""
            $requiredResourceAccess = Build-RequiredResourceAccess -resourceAccessGrant $alreadyExists.RequiredResourceAccess -isNewApp $false
            $haveAppPermissionsChanged = $false
            foreach ($addedGrant in $requiredResourceAccess.addedGrants.keys) {
                if($requiredResourceAccess.addedGrants[$addedGrant]) {
                    $haveAppPermissionsChanged = $true
                    break
                } 
            }
            if ($haveAppPermissionsChanged) {
                Out-Logfile I "App permissions have changed. Updating app." Yellow
                try {
                    Update-MgApplication -ApplicationId $alreadyExists.Id -RequiredResourceAccess $requiredResourceAccess.resourceAccessGrant -ErrorAction Stop
                } catch {
                    Out-Logfile E "There was an exception when updating the app permissions. Exception is: $($_.Exception.Message)" Red
                    Exit-WithFailure
                }
                Grant-AdminConsentForResourceGrants -appId $alreadyExists.AppId -addedAccessGrants $requiredResourceAccess.addedGrants
            }
            else {
                Out-Logfile I "App permissions do not need updating." Green
            }
        }
        else {
            Out-Logfile I "You have said no." Green
        }

        $sp = Get-MgServicePrincipal -Filter "appId eq '$script:AppId'"
        Update-MgServicePrincipal -ServicePrincipalId $sp.Id -Tags @("HideApp", "WindowsAzureActiveDirectoryIntegratedApp")
        Out-Logfile I "Adjusted the Application to show under Enterprise Applications, and be invisible to users in MyApps." Green
        $roledefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq 'Privileged Authentication Administrator'"
        try {
            $response = Get-MgRoleManagementDirectoryRoleAssignment -Filter "PrincipalId eq '$($sp.Id)' and RoleDefinitionId eq '$($roledefinition.Id)'" -ErrorAction Stop
        } catch {
            Out-Logfile I "App hasn't been assined to Privileged Authentication Administrator role. Assigning now." Green
        }
        if($response) {
            if($response.DirectoryScopeId -eq "/") {
                Out-Logfile I "App is already assigned to Privileged Authentication Administrator role at Tenant wide scope." Green
                $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $true
            } else {
                Out-Logfile W "App is assigned to Privileged Authentication Administrator role, however it is at scope $($response.DirectoryScopeId), which is not Tenant scope. Adjusting this to be tenant scope." Yellow
                Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $response.Id -ErrorAction SilentlyContinue | Out-Null
                try {
                    New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -RoleDefinitionId $roledefinition.Id -PrincipalId $sp.Id -erroraction stop | Out-Null
                    Out-Logfile I "App has been successfully assigned to Privileged Authentication Administrator role." Green
                    $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $true
                } catch {
                    Out-Logfile E "There has been an error when assigning the app to the Privileged Authentication Administrator role. Exception is: $($_.Exception.Message)" Red
                    Out-Logfile E "Please assign the app to the Privileged Authentication Administrator role manually." Red
                    $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $false
                }
            }
        } else {
            try {
                New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -RoleDefinitionId $roledefinition.Id -PrincipalId $sp.Id -erroraction stop | Out-Null
                Out-Logfile I "App has been successfully assigned to Privileged Authentication Administrator role." Green
                $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $true
            } catch {
                Out-Logfile E "There has been an error when assigning the app to the Privileged Authentication Administrator role. Exception is: $($_.Exception.Message)" Red
                Out-Logfile E "Please assign the app to the Privileged Authentication Administrator role manually." Red
                $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $false
            }
        }
        
        

        Out-Logfile I "*****************************************************************************************" Green
        Out-Logfile I ""
        $script:outputParams | Add-Member -NotePropertyName "AppID" -NotePropertyValue $alreadyexists.AppId
        $script:outputParams | Add-Member -NotePropertyName "ClientSecret" -NotePropertyValue "The Client Secret has not been regenerated. If you do not remember your existing secret, please regenerate it manually."
    }
    return $appExists
}

function Register-EntraIDApp () {
    #Set Array For Required Permissions of for Ent App
    Out-Logfile I "Building Permissions Array For Basic Adlumin Permissions"

    $requiredGrants = Build-RequiredResourceAccess -isNewApp $true -resourceAccessGrant (New-Object -TypeName System.Collections.Generic.List[Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess])

    #Create App Registration
    Out-Logfile I "Creating App Registration"
    $App = New-MgApplication -DisplayName $script:entraIDAppName -SignInAudience "AzureADMultipleOrgs" -RequiredResourceAccess $requiredGrants.resourceAccessGrant -Web @{ RedirectUris = "https://portal.adlumin.com/" }
    $APPObjectID = $App.Id
    $script:AppId = $App.AppId
    $script:outputParams | Add-Member -NotePropertyName "AppID" -NotePropertyValue $App.AppId
    #Create App Service Principal
    Out-Logfile I "Creating Service Principal"
    $sp = New-MgServicePrincipal -AppId $App.AppId -Tags @("HideApp", "WindowsAzureActiveDirectoryIntegratedApp")
    Out-Logfile I "Adjusted the Application to show under Enterprise Applications, and be invisible to users in MyApps." Green

    #Add App To Privileged Authentication Administrator Role
    Start-Sleep -Seconds 5 # wating for Azure to catch up
    Out-Logfile I "Adding To Privileged Authentication Administrator Role"
    #$spappObjectid = (Get-MgServicePrincipal -Filter "DisplayName eq '$AppName'").Id
    $roledefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq 'Privileged Authentication Administrator'"
    try {
        New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId "/" -RoleDefinitionId $roledefinition.Id -PrincipalId $sp.Id -erroraction stop | Out-Null
        Out-Logfile I "App has been successfully assigned to Privileged Authentication Administrator role." Green
        $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $true
    } catch {
        Out-Logfile E "There has been an error when assigning the app to the Privileged Authentication Administrator role. Exception is: $($_.Exception.Message)" Red
        Out-Logfile E "Please assign the app to the Privileged Authentication Administrator role manually." Red
        $script:outputParams | Add-Member -NotePropertyName "DirectoryRoleAssignment" -NotePropertyValue $false
    }
    
    #Create Secret Key
    Out-Logfile I "Creating Secret Key Token"
    $passwordCred = @{
        "displayName" = "AdluminMDRSecret"
        "endDateTime" = (Get-Date).AddMonths(+24)
    }
    $ClientSecret2 = Add-MgApplicationPassword -ApplicationId $APPObjectID -PasswordCredential $passwordCred
    $script:outputParams | Add-Member -NotePropertyName "ClientSecret" -NotePropertyValue $ClientSecret2.SecretText

    Grant-AdminConsentForResourceGrants -appId $App.AppId -addedAccessGrants $requiredGrants.addedGrants
}

function Open-ConsentURL {
    param(
        [parameter(Mandatory = $true)]
        [string]$appId
    )

    #Grant Consent
    $script:adminConsentUrl = "https://login.microsoftonline.com/" + $script:context.TenantId + "/adminconsent?client_id=" + $appId
    Out-Logfile I "Waiting for 15 seconds while Microsoft Entra ID API catches up on the approval."
    for ($i = 1; $i -le 15; $i++) {
        Write-Progress -Activity "Waiting" -Status "Elapsed time: $i seconds" -PercentComplete (($i / 30) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity "Waiting" -Status "Completed" -Completed
    Start-Process $script:adminConsentUrl
    Out-Logfile I "The URL which has opened prompted you to authenticate the permissions of the Entra ID App. Have you successfully authenticated these permissions? [Y/N]" Yellow
    $response = Read-Host
    if ($response.ToLower() -eq "y") {
        Out-Logfile I "You have said you have successfully authenticated the permissions of the Entra ID App."
    }
    else {
        Out-Logfile E "You have said you have not successfully authenticated the permissions of the Entra ID App. Please authenticate these permissions manually in your Entra ID admin console." Red
    }
}

function Build-RequiredResourceAccess {
    param(
        [parameter(Mandatory = $true)]
        [bool]$isNewApp,
        [parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess]]$resourceAccessGrant
    )

    $addedPermissions = @{
        addedGraphPermissions = @()
        addedO365Permissions = @()
        addedATPPermissions = @()
        addedIntunePermissions = @()
    }

    # Adding Graph API permissions
    $existingGraphAPIResource = $resourceAccessGrant | Where-Object { $_.ResourceAppId -eq $script:entraIDResourceAppID }

    $script:graphServicePrincipal = get-mgserviceprincipal -filter "AppId eq '$script:entraIDResourceAppID'"

    if($null -eq $script:graphServicePrincipal) {
        Out-Logfile E "The Microsoft Graph API Service Principal (or Subscription) does not exist. This is a critical failure. Please contact Microsoft Support." Red
        Exit-WithFailure
    }

    if ($existingGraphAPIResource) {
        Out-Logfile I "We have found existing Microsoft Graph API application permissions on this app." Green
        foreach ($permission in $script:entraIDPermissionIDs.Keys) {
            $addedPermissions.addedGraphPermissions += $script:entraIDPermissionIDs[$permission]
            if ($script:entraIDPermissionIDs[$permission] -notin $existingGraphAPIResource.ResourceAccess.Id) {
                $existingGraphAPIResource.ResourceAccess += @{ Id = $script:entraIDPermissionIDs[$permission]; Type = "Role" }
                Out-Logfile V "Adding permission $permission to existing Microsoft Graph API application permissions."
            }
            else {
                Out-Logfile V "$permission was found in existing Microsoft Graph API application permissions."
            }
        }
    }
    else {
        if($isNewApp) {
            Out-Logfile I "Adding GraphAPI Permissions to app." Green
        } else {
            Out-Logfile I "We have not found existing Microsoft Graph API permissions on this app. Adding permissions now." Green
        }
        $requiredResourceAccess = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess
        $requiredResourceAccess.ResourceAppId = $script:entraIDResourceAppID ##Graph Permissions

        foreach ($permission in $script:entraIDPermissionIDs.Keys) {
            $requiredResourceAccess.ResourceAccess += @{ Id = $script:entraIDPermissionIDs[$permission]; Type = "Role" }
            Out-Logfile V "Adding permission $permission."
            $addedPermissions.addedGraphPermissions += $script:entraIDPermissionIDs[$permission]
        }
        $resourceAccessGrant.Add($requiredResourceAccess)
    }

    # Adding Office 365 Management API permissions
    $existingO365APIResource = $resourceAccessGrant | Where-Object { $_.ResourceAppId -eq $script:o365ResourceAppID }

    $script:o365ServicePrincipal = get-mgserviceprincipal -filter "AppId eq '$script:o365ResourceAppID'"

    if($null -eq $script:o365ServicePrincipal) {
        Out-Logfile W "An Office 365 Service Principal (or Subscription) does not exist in your tenant. We will not add any O365 permissions." Yellow
    } else {
        if ($existingO365APIResource) {
            Out-Logfile I "We have found existing Office 365 Management API application permissions on this app." Green
            foreach ($permission in $script:o365PermissionIDs.Keys) {
                $addedPermissions.addedO365Permissions += $script:o365PermissionIDs[$permission]
                if ($script:o365PermissionIDs[$permission] -notin $existingO365APIResource.ResourceAccess.Id) {
                    $existingO365APIResource.ResourceAccess += @{ Id = $script:o365PermissionIDs[$permission]; Type = "Role" }
                    Out-Logfile V "Adding permission $permission to existing Office 365 Management API application permissions."
                }
                else {
                    Out-Logfile V "$permission was found in existing Office 365 Management API application permissions."
                }
            }
        }
        else {
            if($isNewApp) {
                Out-Logfile I "Adding Office365 Permissions to app." Green
            } else {
                Out-Logfile I "We have not found existing Office365 Permissions on this app. Adding permissions now." Green
            }
            $requiredResourceAccess = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess
            $requiredResourceAccess.ResourceAppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2" # Office 365 Management APIs
    
            foreach ($permission in $script:o365PermissionIDs.Keys) {
                $requiredResourceAccess.ResourceAccess += @{ Id = $script:o365PermissionIDs[$permission]; Type = "Role" }
                Out-Logfile V "Adding permission $permission." Yellow
                $addedPermissions.addedO365Permissions += $script:o365PermissionIDs[$permission]
            }
            $resourceAccessGrant.Add($requiredResourceAccess)
        }
    }
    
    # Adding ATP API permissions
    $existingATPAPIResource = $resourceAccessGrant | Where-Object { $_.ResourceAppId -eq $script:ATPResourceAppID }

    $script:ATPServicePrincipal = get-mgserviceprincipal -filter "AppId eq '$script:ATPResourceAppID'"

    if($null -eq $script:ATPServicePrincipal) {
        Out-Logfile W "A Windows Defender ATP Service Principal (or Subscription) does not exist in your tenant. We will not add any ATP permissions." Yellow
    } else {
        if ($existingATPAPIResource) {
            Out-Logfile I "We have found existing Windows Defender ATP application permissions on this app." Green
            foreach ($permission in $script:defenderATPPermissionIDs.Keys) {
                $addedPermissions.addedATPPermissions += $script:defenderATPPermissionIDs[$permission]
                if ($script:defenderATPPermissionIDs[$permission] -notin $existingATPAPIResource.ResourceAccess.Id) {
                    $existingATPAPIResource.ResourceAccess += @{ Id = $script:defenderATPPermissionIDs[$permission]; Type = "Role" }
                    Out-Logfile V "Adding permission $permission to existing Windows Defender ATP application permissions."
                }
                else {
                    Out-Logfile V "$permission was found in existing Windows Defender ATP application permissions."
                }
            }
        }
        else {
            Out-Logfile I "We have found a Windows Defender ATP Service Principal (or Subscription) in your tenant. Adding permissions now." Green
            $requiredResourceAccess = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess
            $requiredResourceAccess.ResourceAppId = "fc780465-2017-40d4-a0c5-307022471b92" # Windows Defender ATP
    
            foreach ($permission in $script:defenderATPPermissionIDs.Keys) {
                $requiredResourceAccess.ResourceAccess += @{ Id = $script:defenderATPPermissionIDs[$permission]; Type = "Role" }
                Out-Logfile V "Adding permission $permission to existing Windows Defender ATP application permissions."
                $addedPermissions.addedATPPermissions += $script:defenderATPPermissionIDs[$permission]
            }
            $resourceAccessGrant.Add($requiredResourceAccess)
        }
    }

    # Adding Intune API Permissions

    $existingIntuneAPIResource = $resourceAccessGrant | Where-Object { $_.ResourceAppId -eq $script:IntuneResourceAppID }

    $script:IntuneServicePrincipal = get-mgserviceprincipal -filter "AppId eq '$script:IntuneResourceAppID'"

    if($null -eq $script:IntuneServicePrincipal) {
        Out-Logfile W "An Intune Service Principal (or Subscription) does not exist in your tenant. We will not add any Intune permissions." Yellow
    } else {
        if ($existingIntuneAPIResource) {
            Out-Logfile I "We have found existing Intune application permissions on this app." Green
            foreach ($permission in $script:intunePermissionIDs.Keys) {
                $addedPermissions.addedIntunePermissions += $script:intunePermissionIDs[$permission]
                if ($script:intunePermissionIDs[$permission] -notin $existingIntuneAPIResource.ResourceAccess.Id) {
                    $existingIntuneAPIResource.ResourceAccess += @{ Id = $script:intunePermissionIDs[$permission]; Type = "Role" }
                    Out-Logfile V "Adding permission $permission to existing Intune application permissions."
                }
                else {
                    Out-Logfile V "$permission was found in existing Intune application permissions."
                }
            }
        }
        else {
            Out-Logfile I "We have found an Intune Service Principal (or Subscription) in your tenant. Adding permissions now." Green
            $requiredResourceAccess = New-object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess
            $requiredResourceAccess.ResourceAppId = "c161e42e-d4df-4a3d-9b42-e7a3c31f59d4" # Intune
    
            foreach ($permission in $script:intunePermissionIDs.Keys) {
                $requiredResourceAccess.ResourceAccess += @{ Id = $script:intunePermissionIDs[$permission]; Type = "Role" }
                Out-Logfile V "Adding permission $permission to existing Intune application permissions."
                $addedPermissions.addedIntunePermissions += $script:intunePermissionIDs[$permission]
            }
            $resourceAccessGrant.Add($requiredResourceAccess)
        }
    }

    return @{
        resourceAccessGrant = $resourceAccessGrant
        addedGrants = $addedPermissions
    }
}

function Grant-AdminConsentForResourceGrants {
    param(
        [parameter(Mandatory = $true)]
        [string]$appId,
        [parameter(Mandatory = $true)]
        [object]$addedAccessGrants
    )

    Out-Logfile I "Granting Admin consent for added permissions."

    $app = Get-MgServicePrincipal -filter "AppId eq '$appId'"

    if($addedAccessGrants.addedGraphPermissions.Count -gt 0) {
        Out-Logfile I "Granting Admin consent for Microsoft Graph API permissions." Green
        $count = 0
        $successfulCount = 0
        foreach ($permission in $addedAccessGrants.addedGraphPermissions) {
            try {
                $count++
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.id -PrincipalId $app.id -ResourceId $script:graphServicePrincipal.id -AppRoleID $permission -ErrorAction stop | out-null
                Out-Logfile V "Approved permission $count of $($addedAccessGrants.addedGraphPermissions.Count)."
                $successfulCount++
            } catch {
                $exceptionMessage = $_.Exception.Message
                $script:entraIDPermissionIDs.GetEnumerator() | where-object {$_.Value -eq $permission} | ForEach-Object {
                    if($exceptionMessage -like "*Permission being assigned already exists on the object*") {
                        Out-Logfile I "Permission $count has already been approved."
                        $successfulCount++
                    } else {
                        Out-Logfile E "There has been an error when trying to approve permission $($_.Name) for Microsoft Graph API. Error is $exceptionMessage." Red
                    }
                }
            }
        }
        Out-Logfile I "Successfully approved $successfulCount of $($addedAccessGrants.addedGraphPermissions.Count) permissions." Green
    }

    if($script:o365ServicePrincipal -and $addedAccessGrants.addedO365Permissions.Count -gt 0) {
        Out-Logfile I "Granting Admin consent for O365 permissions." Green
        $count = 0
        $successfulCount = 0
        foreach ($permission in $addedAccessGrants.addedO365Permissions) {
            try {
                $count++
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.id -PrincipalId $app.id -ResourceId $script:o365ServicePrincipal.id -AppRoleID $permission -ErrorAction stop | out-null
                Out-Logfile V "Approved permission $count of $($addedAccessGrants.addedO365Permissions.Count)."
                $successfulCount++
            } catch {
                $exceptionMessage = $_.Exception.Message
                $script:o365PermissionIDs.GetEnumerator() | where-object {$_.Value -eq $permission} | ForEach-Object {
                    if($exceptionMessage -like "*Permission being assigned already exists on the object*") {
                        Out-Logfile I "Permission $count has already been approved."
                        $successfulCount++
                    } else {
                        Out-Logfile E "There has been an error when trying to approve permission $($_.Name) for Office 365. Error is $exceptionMessage." Red
                    }
                }
            }
        }
        Out-Logfile I "Successfully approved $successfulCount of $($addedAccessGrants.addedO365Permissions.Count) permissions." Green
    }

    if($script:ATPServicePrincipal -and $addedAccessGrants.addedATPPermissions.count -gt 0) {
        Out-Logfile I "Granting Admin consent for Windows Defender ATP permissions." Green
        $count = 0
        $successfulCount = 0
        foreach ($permission in $addedAccessGrants.addedATPPermissions) {
            try {
                $count++
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.id -PrincipalId $app.id -ResourceId $script:ATPServicePrincipal.id -AppRoleID $permission -ErrorAction stop | out-null
                Out-Logfile V "Approved permission $count of $($addedAccessGrants.addedATPPermissions.Count)."
                $successfulCount++
            } catch {
                $exceptionMessage = $_.Exception.Message
                $script:defenderATPPermissionIDs.GetEnumerator() | where-object {$_.Value -eq $permission} | ForEach-Object {
                    if($exceptionMessage -like "*Permission being assigned already exists on the object*") {
                        Out-Logfile I "Permission $count has already been approved."
                        $successfulCount++
                    } else {
                        Out-Logfile E "There has been an error when trying to approve permission $($_.Name) for Windows Defender ATP. Error is $exceptionMessage." Red
                    }
                }
            }
        }
        Out-Logfile I "Successfully approved $successfulCount of $($addedAccessGrants.addedATPPermissions.Count) permissions." Green
    }

    if($script:IntuneServicePrincipal -and $addedAccessGrants.addedIntunePermissions.count -gt 0) {
        Out-Logfile I "Granting Admin consent for Intune permissions." Green
        $count = 0
        $successfulCount = 0
        foreach ($permission in $addedAccessGrants.addedIntunePermissions) {
            try {
                $count++
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.id -PrincipalId $app.id -ResourceId $script:IntuneServicePrincipal.id -AppRoleID $permission -ErrorAction stop | out-null
                Out-Logfile V "Approved permission $count of $($addedAccessGrants.addedIntunePermissions.Count)."
                $successfulCount++
            } catch {
                $exceptionMessage = $_.Exception.Message
                $script:intunePermissionIDs.GetEnumerator() | where-object {$_.Value -eq $permission} | ForEach-Object {
                    if($exceptionMessage -like "*Permission being assigned already exists on the object*") {
                        Out-Logfile I "Permission $count has already been approved."
                        $successfulCount++
                    } else {
                        Out-Logfile E "There has been an error when trying to approve permission $($_.Name) for Intune. Error is $exceptionMessage." Red
                    }
                }
            }
        }
        Out-Logfile I "Successfully approved $successfulCount of $($addedAccessGrants.addedIntunePermissions.Count) permissions." Green
    }
}

function Write-FinalOutput () {
    #Final Output Of Information To Input Into Adlumin Azure Integration
    Out-Logfile I "The following information will only be sent to the console. Logging will stop." 
    Out-Logfile I "*****************************************************************************************" Cyan -logToConsoleOnly $true
    Out-Logfile I "The Following Items Should Be Entered Into the Adlumin Azure Integration Section For Tenant" Cyan -logToConsoleOnly $true
    Out-Logfile I "" Cyan -logToConsoleOnly $true
    Out-Logfile I "Domain Name:    $($script:outputParams.domainName)" Cyan -logToConsoleOnly $true
    Out-Logfile I "ClientID:       $($script:outputParams.AppId)" Cyan -logToConsoleOnly $true
    Out-Logfile I "TenantID:       $($script:outputParams.TenantId)" Cyan -logToConsoleOnly $true
    Out-Logfile I "Client Secret:  $($script:outputParams.ClientSecret)" Cyan -logToConsoleOnly $true
    Out-Logfile I "" Cyan -logToConsoleOnly $true
    if($script:outputParams.AuditLoggingEnabled) {
        Out-Logfile I "Audit Logging is fully enabled." Green -logToConsoleOnly $true
    }
    else {
        Out-Logfile I "Audit Logging is not enabled." Red -logToConsoleOnly $true
    }
    if($script:outputParams.directoryRoleAssignment) {
        Out-Logfile I "The app has been assigned to the Privileged Authentication Administrator role in tenant wide scope." Green -logToConsoleOnly $true
    }
    else {
        Out-Logfile I "The app has not been assigned to the Privileged Authentication Administrator role in Tenant wide scope." Red -logToConsoleOnly $true
    }
    Out-Logfile I "*****************************************************************************************" Cyan -logToConsoleOnly $true
}

function Disconnect-Connections {
    Disconnect-MgGraph -erroraction SilentlyContinue| out-null
    Disconnect-ExchangeOnline -Confirm:$false
}

New-LogFileAndWorkingDirectory $workingDirectory $logFile
Import-MicrosoftGraphModules
Connect-EntraIDTenant
Get-TenantAuditLogs
if(!(Confirm-ExistingApp)) {
    Register-EntraIDApp
}
Write-FinalOutput
#Close connections
Disconnect-Connections