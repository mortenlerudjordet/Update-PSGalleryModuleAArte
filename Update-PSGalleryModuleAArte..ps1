<#
.SYNOPSIS
    This Azure Automation Runbook updates to the latest version of installed modules in Automation Account runtime environment from PowerShell Gallery.
    It can also only update the Azure modules by setting a parameter. This is meant to only run from an Automation account.

    Use Update-PSGalleryModuleAArte to update modules in a runtime environment in Automation account

.DESCRIPTION
    This Azure Automation Runbook updates to the latest version from PowerShell Gallery of all modules in an
    Automation Runtime Environment. By connecting the Runbook to an Automation schedule, you can ensure all modules in
    your Automation account stay up to date. Or only update the Azure modules

    NOTE:
    This module can not be run locally as it uses system managed identity

    Make sure to create an connection asset of the type AzureServicePrincipal and call it AzureRunAsConnection.
    Only need to populate TenantId and SubscriptionId with real values, the other just set NA.

.PARAMETER AutomationResourceGroupName
    Optional. The name of the Azure Resource Group containing the Automation account to update all modules for.
    If a resource group is not specified, then the logic will try to discover it by getting running jobs from automation accounts in the same sub

.PARAMETER AutomationAccountName
    Optional. The name of the Automation account to update all modules for.
    If an automation account is not specified, , then the logic will try to discover it by getting running jobs from automation accounts in the same sub

.PARAMETER AutomationRuntimeEnvName
    Optional. Name of runtime environment to target package import to.
    If an runtime environment is not specified, then the logic will try to discover it by getting running jobs from automation accounts in the same sub

.PARAMETER UpdateAzureModulesOnly
    Optional. Set to $false to have logic try to update all modules installed in account.
    Default is $true, and this will only update Azure modules.

.PARAMETER Force
    Optional. Set to $true to force update of all modules, also previous failed module updates
    Default is $false

.EXAMPLE

.NOTES
    AUTHOR:    Morten Lerudjordet
#>

param(
    [Parameter(Mandatory = $false)]
    [String] $AutomationResourceGroupName,

    [Parameter(Mandatory = $false)]
    [String] $AutomationAccountName,

    [Parameter(Mandatory = $false)]
    [String] $AutomationRuntimeEnvName,

    [Parameter(Mandatory = $false)]
    [ValidateSet($true, $false)]
    [bool]$UpdateAzureModulesOnly = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet($true, $false)]
    [bool]$Force = $false
)
$VerbosePreference = "silentlycontinue"
$WarningPreference = 'silentlycontinue'
$RunbookName = "Update-PSGalleryModuleAArte"
Write-Output -InputObject "Starting Runbook: $RunbookName at time: $(get-Date -format r).`nRunning PS version: $($PSVersionTable.PSVersion)`nOn host: $($env:computername)`nLocale: $([system.threading.thread]::currentthread.currentculture)"

#region Import Modules
# Test to se if Az modules are pressent in the rt env
$MandatoryModules = @("Az.Accounts", "Az.Automation","Az.Resources")
$ImportError = $false
foreach( $Module in $MandatoryModules ) {
    Import-Module -Name $Module -ErrorAction Continue -ErrorVariable oErr
    if( $oErr ) {
        Write-Error -Message "$Module is mandatory for Runbook and is missing from the runtime environment" -ErrorAction Continue
        $ImportError = $true
        $oErr = $null
    }
}
if( $ImportError ) {
    Write-Error -Message "One or more of the mandatory modules are missing from runtime environment" -ErrorAction Stop
}

if((Get-Module -Name "Az.Accounts" -ListAvailable) -and (Get-Module -Name "Az.Automation" -ListAvailable) -and (Get-Module -Name "Az.Resources" -ListAvailable))
{
    $AccountsModule = Get-Module -Name Az.Accounts -ListAvailable | Sort-Object -Unique -Descending -Property Version | Select-Object -First 1
    $AutomationModule = Get-Module -Name Az.Automation -ListAvailable | Sort-Object -Unique -Descending -Property Version | Select-Object -First 1
    $ResourcesModule = Get-Module -Name Az.Resources -ListAvailable | Sort-Object -Unique -Descending -Property Version | Select-Object -First 1

    Write-Output -InputObject "Running Az.Account version: $($AccountsModule.Version)"
    Write-Output -InputObject "Running Az.Automation version: $($AutomationModule.Version)"
    Write-Output -InputObject "Running Az.Resources version: $($ResourcesModule.Version)"

    Import-Module -Name Az.Accounts, Az.Automation, Az.Resources -ErrorAction Continue -ErrorVariable oErr
    if($oErr)
    {
        Write-Error -Message "Failed to load needed modules for Runbook: Az.Accounts, Az.Automation,Az.Resources" -ErrorAction Continue
        throw "Check AA account for modules"
    }
}
else
{
    Write-Error -Message "Did not find Az modules installed in Automation account: $AutomationAccountName" -ErrorAction Stop
}

$VerbosePreference = "continue"
$WarningPreference = 'continue'
#endregion

#region Variables
$script:ModulesImported = [System.Collections.ArrayList]@()
# track depth of module dependencies import
$script:RecursionDepth = 0
# Make sure not to try to import dependencies of dependencies, like AzureRM module where some of the sub modules have different version dependencies on AzureRM.Accounts
$script:RecursionDepthLimit = 3
#endregion

#region Constants
$script:AzureSdkOwnerName = "azure-sdk"
$script:PsGalleryApiUrl = 'https://www.powershellgallery.com/api/v2'
#endregion

#region Functions

#region Get-AutomationJob
function Get-AutomationJob
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $AutomationAccountName,

        [Parameter(Mandatory = $false)]
        [String] $RunbookName = $null,

        [Parameter(Mandatory = $false)]
        [String] $Status = $null
    )
    try {
        $ReturnJobs = @()
        $AzContext = Get-AzContext
        if( $AzContext  ) {
            $AArtEnvURL = "https://management.azure.com/subscriptions/$($AzContext.Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs?api-version=2023-05-15-preview"

            $Response = Invoke-AzRestMethod -Uri $AArtEnvURL -Method GET -ErrorAction Continue -ErrorVariable oErr
            if($oErr) {
                Write-Error -Message "Failed to get packages from runtime environment: $RuntimeEnvironmentName in automation account: $AutomationAccountName" -ErrorAction Stop
            }
            else {
                if( $Response ) {
                    $AAjobs = ($Response.Content | ConvertFrom-Json ).value

                    if( $RunbookName -and $Status) {
                        $AAfilteredJobs = $AAjobs | Where-Object {$PSItem.properties.runbook.name -eq $RunbookName -and $PSItem.properties.status -eq $Status}
                    }
                    elseif( $RunbookName ) {
                        $AAfilteredJobs = $AAjobs | Where-Object {$PSItem.properties.runbook.name -eq $RunbookName }
                    }
                    elseif( $Status) {
                        $AAfilteredJobs = $AAjobs | Where-Object {$PSItem.properties.status -eq $Status }
                    }
                    else {
                        $AAfilteredJobs = $AAjobs
                    }

                    foreach($Job in $AAfilteredJobs) {
                        $CustomJob = [PSCustomObject][ordered]@{
                            ResourceGroupName       = $ResourceGroupName
                            AutomationAccountName   = $AutomationAccountName
                            RunbookName             = $Job.properties.runbook.name
                            RuntimeEnvironmentName  = $Job.properties.jobRuntimeEnvironment.runtimeEnvironmentName
                            Status                  = $Job.properties.status
                        }
                        $ReturnJobs += $CustomJob
                        $CustomJob = $null
                    }
                    if( $ReturnJobs ) {
                        return $ReturnJobs
                    }
                    else {
                        if( $RunbookName -and $Status) {
                            Write-Warning -Message "No jobs found for runbook: $RunbookName with status: $Status in automation account: $AutomationAccountName"
                        }
                        elseif( $Status ) {
                            Write-Warning -Message "No jobs found with status: $Status in automation account: $AutomationAccountName"
                        }
                        elseif( $RunbookName ) {
                            Write-Warning -Message "No jobs found for runbook: $RunbookName in automation account: $AutomationAccountName"
                        }
                        else {
                            Write-Warning -Message "No jobs found in automation account: $AutomationAccountName"
                        }
                    }
                }
                else {
                    Write-Error -Message "No data returned from api targeting runtime environment: $RuntimeEnvironmentName in automation account: $AutomationAccountName" -ErrorAction Stop
                }
            }
        }
        else {
            Write-Error -Message "Faild to retrieve az context with subscription id" -ErrorAction Stop
        }

    }
    catch {
        if ($_.Exception.Message)
        {
            Write-Error -Message "$($_.Exception.Message)" -ErrorAction Continue
        }
        else
        {
            Write-Error -Message "$($_.Exception)" -ErrorAction Continue
        }
        throw "$($_.Exception)"
    }
}
#endregion

#region Get-RuntimeEnvAutomationModule
function Get-RuntimeEnvAutomationModule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $AutomationAccountName,

        [Parameter(Mandatory = $true)]
        [String] $RuntimeEnvironmentName,

        [Parameter(Mandatory = $false)]
        [String] $Name = $null
    )
    try {
        $CustomAArtEnvPackages = @()
        $AzContext = Get-AzContext
        if( $AzContext  ) {
            if( $Name ) {
                $AArtEnvURL = "https://management.azure.com/subscriptions/$($AzContext.Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$RuntimeEnvironmentName/packages/$($Name)?api-version=2023-05-15-preview"
            }
            else {
                $AArtEnvURL = "https://management.azure.com/subscriptions/$($AzContext.Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$($RuntimeEnvironmentName)/packages?api-version=2023-05-15-preview"
            }

            $Response = Invoke-AzRestMethod -Uri $AArtEnvURL -Method GET -ErrorAction Continue -ErrorVariable oErr
            if($oErr) {
                Write-Error -Message "Failed to get packages from runtime environment: $RuntimeEnvironmentName in automation account: $AutomationAccountName" -ErrorAction Stop
            }
            else {
                if( $Response ) {
                    if( $Name ) {
                        $AArtEnvPackages = ($Response.Content | ConvertFrom-Json )
                    }
                    else {
                        $AArtEnvPackages = ($Response.Content | ConvertFrom-Json ).value
                    }

                    ForEach($Package in $AArtEnvPackages) {
                        $CustomAPackage = [PSCustomObject][ordered]@{
                            ResourceGroupName       = $ResourceGroupName
                            AutomationAccountName   = $AutomationAccountName
                            RuntimeEnvironmentName  = $RuntimeEnvironmentName
                            Name                    = $Package.name
                            Version                 = $Package.Properties.version
                            SizeInBytes             = $Package.Properties.sizeInBytes
                            CreationTime            = $Package.systemData.createdAt
                            LastModifiedTime        = $Package.systemData.lastModifiedAt
                            ProvisioningState       = $Package.Properties.provisioningState
                        }
                        $CustomAArtEnvPackages += $CustomAPackage
                        $CustomAPackage = $null
                    }
                    if( $CustomAArtEnvPackages ) {
                        return $CustomAArtEnvPackages
                    }
                    else {
                        if( $Name ) {
                            Write-Warning -Message "No packages with name: $Name found in runtime environment: $RuntimeEnvironmentName hosted in automation account: $AutomationAccountName"
                        }
                        else {
                            Write-Warning -Message "No packages found in runtime environment: $RuntimeEnvironmentName hosted in automation account: $AutomationAccountName"
                        }
                    }
                }
                else {
                    Write-Error -Message "No data returned from api targeting runtime environment: $RuntimeEnvironmentName in automation account: $AutomationAccountName" -ErrorAction Stop
                }
            }
        }
        else {
            Write-Error -Message "Faild to retrieve az context with subscription id" -ErrorAction Stop
        }

    }
    catch {
        if ($_.Exception.Message)
        {
            Write-Error -Message "$($_.Exception.Message)" -ErrorAction Continue
        }
        else
        {
            Write-Error -Message "$($_.Exception)" -ErrorAction Continue
        }
        throw "$($_.Exception)"
    }
}
#endregion

#region New-RuntimeEnvAutomationModule
function New-RuntimeEnvAutomationModule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $AutomationAccountName,

        [Parameter(Mandatory = $true)]
        [String] $RuntimeEnvironmentName,

        [Parameter(Mandatory = $true)]
        [String] $Name,

        [Parameter(Mandatory = $true)]
        [String]$ContentLink
    )
    try {
        $CustomAArtEnvPackages = @()
        $AzContext = Get-AzContext
        if( $AzContext  ) {
            $AArtEnvURL = "https://management.azure.com/subscriptions/$($AzContext.Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$RuntimeEnvironmentName/packages/$($Name)?api-version=2023-05-15-preview"
            $Payload = @{
                "properties" = @{
                  "contentLink" = @{
                      "uri" = $ContentLink
                  }
                }
              }
            $Response = Invoke-AzRestMethod -Uri $AArtEnvURL -Payload $($Payload | ConvertTo-Json) -Method PUT -ErrorAction Continue -ErrorVariable oErr
            if($oErr) {
                Write-Error -Message "Failed to upload packages for environment: $RuntimeEnvironmentName in account: $AutomationAccountName" -ErrorAction Stop
            }
            elseif( $Response.StatusCode -notmatch '20[01]' ) {
                Write-Error -Message "API returned status code: $($Response.StatusCode) trying to upload package: $Name to environment: $RuntimeEnvironmentName in account: $AutomationAccountName" -ErrorAction Continue
                $ResponseContent = $Response.Content | ConvertFrom-Json
                if( $ResponseContent.error ) {
                    Write-Error -Message "Error message: $($ResponseContent.error.message)" -ErrorAction Stop
                }
            }
            else {
                if( $Response ) {
                    $ResponseInfo = $Response.Content | ConvertFrom-Json
                    Write-Output -InputObject "Package Upload status: $($ResponseInfo.properties.provisioningState)"
                    $ResponseInfo = $Response.Content | ConvertFrom-Json
                    $PackageInfo = [PSCustomObject][ordered]@{
                        ResourceGroupName       = $ResourceGroupName
                        AutomationAccountName   = $AutomationAccountName
                        RuntimeEnvironmentName  = $RuntimeEnvironmentName
                        Name                    = $Name
                        ContentLink             = $ContentLink
                        ProvisioningState       = $ResponseInfo.Properties.provisioningState
                    }
                    return $PackageInfo
                }
                else {
                    Write-Error -Message "Response from package upload is empty" -ErrorAction Stop
                }
            }
        }
        else {
            Write-Error -Message "Faild to retrieve az context with subscription id" -ErrorAction Stop
        }
    }
    catch {
        if ($_.Exception.Message)
        {
            Write-Error -Message "$($_.Exception.Message)" -ErrorAction Continue
        }
        else
        {
            Write-Error -Message "$($_.Exception)" -ErrorAction Continue
        }
        throw "$($_.Exception)"
    }
}
#endregion

#region doModuleImport
function doModuleImport
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String] $AutomationResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $AutomationAccountName,

        [Parameter(Mandatory = $true)]
        [String] $RuntimeEnvironmentName,

        [Parameter(Mandatory = $true)]
        [String] $ModuleName,

        # if not specified latest version will be imported
        [Parameter(Mandatory = $false)]
        [String] $ModuleVersion
    )
    try
    {
        $Filter = @($ModuleName.Trim('*').Split('*') | ForEach-Object { "substringof('$_',Id)" }) -join " and "
        $Url = "$script:PsGalleryApiUrl/Packages?`$filter=$Filter and IsLatestVersion"

        # Fetch results and filter them with -like, and then shape the output
        $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -ErrorAction Continue -ErrorVariable oErr | Where-Object { $_.title.'#text' -like $ModuleName } |
            Select-Object @{n = 'Name'; ex = {$_.title.'#text'}},
        @{n = 'Version'; ex = {$_.properties.version}},
        @{n = 'Url'; ex = {$_.Content.src}},
        @{n = 'Dependencies'; ex = {$_.properties.Dependencies}},
        @{n = 'Owners'; ex = {$_.properties.Owners}}
        If($oErr)
        {
            # Will stop runbook, though message will not be logged
            Write-Error -Message "Failed to retrieve details of module: $ModuleName from Gallery" -ErrorAction Stop
        }
        # Should not be needed as filter will only return one hit, though will keep the code to strip away if search ever get multiple hits
        if($SearchResult.Length -and $SearchResult.Length -gt 1)
        {
            $SearchResult = $SearchResult | Where-Object -FilterScript {
                return $_.Name -eq $ModuleName
            }
        }

        if(-not $SearchResult)
        {
            Write-Warning "Could not find module '$ModuleName' on PowerShell Gallery. This may be a module you imported from a different location"
        }
        else
        {
            $ModuleName = $SearchResult.Name # get correct casing for the module name

            if(-not $ModuleVersion)
            {
                # get latest version
                $ModuleContentUrl = $SearchResult.Url
            }
            else
            {
                $ModuleContentUrl = "$($script:PsGalleryApiUrl)/package/$ModuleName/$ModuleVersion"
            }

            # Make sure module dependencies are imported
            $Dependencies = $SearchResult.Dependencies

            if($Dependencies -and $Dependencies.Length -gt 0)
            {
                # Track recursion depth
                $script:RecursionDepth ++
                $Dependencies = $Dependencies.Split("|")

                # parse dependencies, which are in the format: module1name:module1version:|module2name:module2version:
                $Dependencies | ForEach-Object {

                    if( $_ -and $_.Length -gt 0 )
                    {
                        $Parts = $_.Split(":")
                        $DependencyName = $Parts[0]
                        # Gallery is returning double the same version number on some modules: Az.Aks:[1.0.1, 1.0.1] some do [1.0.1, ]
                        if($Parts[1] -match ",")
                        {
                            $DependencyVersion = (($Parts[1]).Split(","))[0] -replace "[^0-9.]", ''
                        }
                        else
                        {
                            $DependencyVersion = $Parts[1] -replace "[^0-9.]", ''
                        }
                        # check if we already imported this dependency module during execution of this script
                        if( -not $script:ModulesImported.Contains($DependencyName) )
                        {
                            # check if Automation account already contains this dependency module of the right version
                            $AutomationModule = $null
                            $AutomationModule = Get-RuntimeEnvAutomationModule `
                                -ResourceGroupName $AutomationResourceGroupName `
                                -AutomationAccountName $AutomationAccountName `
                                -RuntimeEnvironmentName $AutomationRuntimeEnvName `
                                -Name $DependencyName `
                                -ErrorAction SilentlyContinue
                            # Filter out Global modules
                            $AutomationModule = $AutomationModule | Where-Object { $PsItem.IsGlobal -eq $false }
                            # Do not downgrade version of module if newer exists in Automation account (limitation of AA that one can only have only one version of a module imported)
                            # limit also recursion depth of dependencies search
                            if( ($script:RecursionDepth -le $script:RecursionDepthLimit) -and ((-not $AutomationModule) -or [System.Version]$AutomationModule.Version -lt [System.Version]$DependencyVersion) )
                            {
                                Write-Output -InputObject "$ModuleName depends on: $DependencyName with version $DependencyVersion, importing this module first"

                                # this dependency module has not been imported, import it first
                                doModuleImport `
                                    -AutomationResourceGroupName $AutomationResourceGroupName `
                                    -AutomationAccountName $AutomationAccountName `
                                    -RuntimeEnvironmentName $AutomationRuntimeEnvName `
                                    -ModuleName $DependencyName `
                                    -ModuleVersion $DependencyVersion -ErrorAction Continue
                                # Register module has been imported
                                # TODO: If module import fails, do not add and remove the failed imported module from AA account
                                $null = $script:ModulesImported.Add($DependencyName)
                                $script:RecursionDepth --
                            }
                            else
                            {
                                Write-Output -InputObject "$ModuleName has a dependency on: $DependencyName with version: $DependencyVersion, though this is already installed with version: $($AutomationModule.Version)"
                            }
                        }
                        else
                        {
                            Write-Output -InputObject "$DependencyName already imported to Automation account"
                        }
                    }
                }
            }

            # Find the actual blob storage location of the module
            do
            {
                $ActualUrl = $ModuleContentUrl
                # In PS 7.1 settting -MaximumRedirection 0 will throw an termination error
                if( $PSVersionTable.PSVersion.Major -eq 7 )
                {
                    Write-Verbose -Message "Running under PS 7 or newer"
                    try
                    {
                        $Content = Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction Ignore
                    }
                    catch
                    {
                        Write-Verbose -Message "Invoke-WebRequest termination error detected"
                    }
                }
                else
                {
                    Write-Verbose -Message "Running under PS 5.1"
                    $Content = Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore
                }
                [String]$ModuleContentUrl = $Content.Headers.Location
                Write-Verbose -Message "Module content location URL found inside loop is: $ModuleContentUrl"
            }
            while( $ModuleContentUrl -notmatch ".nupkg" -or [string]::IsNullOrEmpty($ModuleContentUrl) )

            Write-Verbose -Message "Do/While loop ended"

            if( [string]::IsNullOrEmpty($ModuleContentUrl) )
            {
                Write-Error -Message "Fetching module content URL returned empty value." -ErrorAction Stop
            }
            else
            {
                Write-Verbose -Message "Final Module content location URL is: $ModuleContentUrl"
            }

            $ActualUrl = $ModuleContentUrl

            if($ModuleVersion)
            {
                Write-Output -InputObject "Importing version: $ModuleVersion of module: $ModuleName to Automation account"
            }
            else
            {
                Write-Output -InputObject "Importing version: $($SearchResult.Version) of module: $ModuleName to Automation account"
            }
            if(-not ([string]::IsNullOrEmpty($ActualUrl)))
            {
                $AutomationModule = New-RuntimeEnvAutomationModule `
                    -ResourceGroupName $AutomationResourceGroupName `
                    -AutomationAccountName $AutomationAccountName `
                    -RuntimeEnvironmentName $AutomationRuntimeEnvName `
                    -Name $ModuleName `
                    -ContentLink $ActualUrl -ErrorAction continue
                $oErr = $null
                while(
                    (-not ([string]::IsNullOrEmpty($AutomationModule))) -and
                    $AutomationModule.ProvisioningState -ne "Created" -and
                    $AutomationModule.ProvisioningState -ne "Succeeded" -and
                    $AutomationModule.ProvisioningState -ne "Failed" -and
                    [string]::IsNullOrEmpty($oErr)
                )
                {
                    Start-Sleep -Seconds 5
                    Write-Verbose -Message "Polling module import status for: $($AutomationModule.Name)"
                    $AutomationModule = Get-RuntimeEnvAutomationModule `
                        -ResourceGroupName $AutomationResourceGroupName `
                        -AutomationAccountName $AutomationAccountName `
                        -RuntimeEnvironmentName $AutomationRuntimeEnvName `
                        -Name $AutomationModule.Name `
                        -ErrorAction SilentlyContinue -ErrorVariable oErr
                    if($oErr)
                    {
                        Write-Error -Message "Error fetching module status for: $($AutomationModule.Name)" -ErrorAction Continue
                    }
                    else
                    {
                        Write-Verbose -Message "Module import pull status: $($AutomationModule.ProvisioningState)"
                    }
                }
                if( ($AutomationModule.ProvisioningState -eq "Failed") -or $oErr )
                {
                    Write-Error -Message "Failed to import of $($AutomationModule.Name) module to Automation account: $AutomationAccountName." -ErrorAction Continue
                    $oErr = $null
                }
                else
                {
                    Write-Output -InputObject "Import of $ModuleName module to Automation account succeeded."
                }
            }
            else
            {
                Write-Error -Message "Failed to retrieve download URL of module: $ModuleName in Gallery, update of module aborted" -ErrorId continue
            }
        }
    }
    catch
    {
        if ($_.Exception.Message)
        {
            Write-Error -Message "$($_.Exception.Message)" -ErrorAction Continue
        }
        else
        {
            Write-Error -Message "$($_.Exception)" -ErrorAction Continue
        }
        throw "$($_.Exception)"
    }
}
#endregion

#endregion

#region Main
try
{
    $AAconAsset = "AzureRunAsConnection"
    $RunAsConnection = Get-AutomationConnection -Name $AAconAsset
    if ( [string]::IsNullOrEmpty($RunAsConnection) ) {
        Write-Error -Message "AA asset: $AAconAsset is empty or missing. Check that the asset is created in AA and has valid entries" -ErrorAction Stop
    }
    if($RunAsConnection)
    {
        Write-Output -InputObject ("Authenticating...")

        $Null = Connect-AzAccount -Identity -ErrorAction Continue -ErrorVariable oErr
        if($oErr)
        {
            Write-Error -Message "Failed to connect to Azure Resource Manager using Managed Service Identity" -ErrorAction Stop
        }

        Write-Verbose -Message "Selecting subscription to use"
        $Subscription = Select-AzSubscription -SubscriptionId $RunAsConnection.SubscriptionID -TenantId $RunAsConnection.TenantId -ErrorAction Continue -ErrorVariable oErr
        if($oErr)
        {
            Write-Error -Message "Failed to select Azure subscription" -ErrorAction Stop
        }
        else
        {
            Write-Output -InputObject "Running in subscription: $($Subscription.Subscription.Name) and tenantId: $($Subscription.Tenant.Id)"
        }
    }
    else
    {
        Write-Error -Message "Check that AzureRunAsConnection is configured for AA account: $AutomationAccountName" -ErrorAction Stop
    }

    # Find the automation account or resource group is not specified
    if  (([string]::IsNullOrEmpty($AutomationResourceGroupName)) -or ([string]::IsNullOrEmpty($AutomationAccountName)))
    {

        $AutomationResources = Get-AzResource -ResourceType Microsoft.Automation/AutomationAccounts -ErrorAction Continue -ErrorVariable oErr
        if( $oErr ) {
            Write-Error -Message "Failed to retrieve automation accounts in subscription: $($Subscription.Subscription.Name)" -ErrorAction Stop
        }

        foreach ($Automation in $AutomationResources)
        {
            $Job = Get-AutomationJob -ResourceGroupName $Automation.ResourceGroupName -AutomationAccountName $Automation.Name -RunbookName $RunbookName -Status "Running" -ErrorAction SilentlyContinue
            if (-not ([string]::IsNullOrEmpty($Job)))
            {
                $AutomationResourceGroupName = $Job.ResourceGroupName
                $AutomationAccountName = $Job.AutomationAccountName
                $AutomationRuntimeEnvName = $Job.RuntimeEnvironmentName
                break;
            }
            else {
                Write-Warning -Message "No running jobs found for Runbook: $RunbookName in account: $($Automation.Name) using runtime environment: $AutomationRuntimeEnvName"
            }
        }
        if($AutomationAccountName)
        {
            Write-Output -InputObject "Using AA account: $AutomationAccountName in resource group: $AutomationResourceGroupName and runtime environment: $AutomationRuntimeEnvName"
        }
        else
        {
            Write-Error -Message "Failed to discover automation account, execution stopped" -ErrorAction Stop
        }
    }

    $Modules = Get-RuntimeEnvAutomationModule `
        -ResourceGroupName $AutomationResourceGroupName `
        -AutomationAccountName $AutomationAccountName `
        -RuntimeEnvironmentName $AutomationRuntimeEnvName `
        -ErrorAction Continue -ErrorVariable oErr
    if($oErr)
    {
        Write-Error -Message "Failed to retrieve modules from runtime env: $AutomationRuntimeEnvName in AA account $AutomationAccountName" -ErrorAction Stop
    }
    if($Modules)
    {
        foreach($Module in $Modules)
        {
            $ModuleName = $Module.Name
            $ModuleVersionInAutomation = $Module.Version

            $Filter = @($ModuleName.Trim('*').Split('*') | ForEach-Object { "substringof('$_',Id)" }) -join " and "
            $Url = "$script:PsGalleryApiUrl/Packages?`$filter=$Filter and IsLatestVersion"

            # Fetch results and filter them with -like, and then shape the output
            $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -ErrorAction Continue -ErrorVariable oErr | Where-Object { $_.title.'#text' -like $ModuleName } |
                Select-Object @{n = 'Name'; ex = {$_.title.'#text'}},
            @{n = 'Version'; ex = {$_.properties.version}},
            @{n = 'Url'; ex = {$_.Content.src}},
            @{n = 'Dependencies'; ex = {$_.properties.Dependencies}},
            @{n = 'Owners'; ex = {$_.properties.Owners}}
            if($oErr)
            {
                Write-Error -Message "Failed to query Gallery for module $ModuleName" -ErrorAction Continue
                $oErr = $Null
            }
            if($SearchResult)
            {
                # Should not be needed anymore, though in the event of the search returning more than one hit this will strip it down
                if($SearchResult.Length -and $SearchResult.Length -gt 1)
                {
                    $SearchResult = $SearchResult | Where-Object -FilterScript {
                        return $_.Name -eq $ModuleName
                    }
                }

                $UpdateModule = $false
                if($UpdateAzureModulesOnly)
                {
                    if($SearchResult.Owners -eq $script:AzureSdkOwnerName)
                    {
                        Write-Output -InputObject "Checking if azure module '$ModuleName' is up to date in your automation account"
                        $UpdateModule = $true
                    }
                }
                else
                {
                    Write-Output -InputObject "Checking if module '$ModuleName' is up to date in your automation account"
                    $UpdateModule = $true
                }
                if($UpdateModule)
                {
                    if(-not $SearchResult)
                    {
                        Write-Output -InputObject "Could not find module '$ModuleName' on PowerShell Gallery. This may be a module imported from a different location"
                    }
                    else
                    {
                        $LatestModuleVersionOnPSGallery = $SearchResult.Version
                        if( $Module.ProvisioningState -ne "Failed" -or [System.Convert]::ToBoolean($Force) -eq $true )
                        {
                            if( ($ModuleVersionInAutomation -ne $LatestModuleVersionOnPSGallery) -or ($Module.ProvisioningState -eq "Failed" -and [System.Convert]::ToBoolean($Force) -eq $true) )
                            {
                                Write-Output -InputObject "Module '$ModuleName' is not up to date. Latest version on PS Gallery is '$LatestModuleVersionOnPSGallery' but this automation account has version '$ModuleVersionInAutomation'"
                                Write-Output -InputObject "Importing latest version of '$ModuleName' into your automation account"

                                doModuleImport `
                                    -AutomationResourceGroupName $AutomationResourceGroupName `
                                    -AutomationAccountName $AutomationAccountName `
                                    -RuntimeEnvironmentName $AutomationRuntimeEnvName `
                                    -ModuleName $ModuleName -ErrorAction Continue
                            }
                            else
                            {
                                Write-Output -InputObject "Module '$ModuleName' is up to date."
                            }
                        }
                        else
                        {
                            if($Module.ProvisioningState -eq "Failed")
                            {
                                Write-Error -Message "Module '$ModuleName' import has previously failed, skipping update of module" -ErrorAction Continue
                            }
                            else
                            {
                                Write-Warning -Message "Module '$ModuleName' in automation account has no version data. Skipping update of module" -WarningAction Continue
                            }
                        }
                    }
                }
            }
            else
            {
                if( -not $UpdateAzureModulesOnly )
                {
                    Write-Output -InputObject "No result from querying PS Gallery for module: $ModuleName"
                }
            }
        }
    }
    else
    {
        Write-Error -Message "No modules found in AA account: $AutomationAccountName" -ErrorAction Stop
    }
}
catch
{
    if ($_.Exception.Message)
    {
        Write-Error -Message "$($_.Exception.Message)" -ErrorAction Continue
    }
    else
    {
        Write-Error -Message "$($_.Exception)" -ErrorAction Continue
    }
    throw "$($_.Exception)"
}
finally
{
    Write-Output -InputObject "Runbook: $RunbookName ended at time: $(get-Date -format r)"
}
#endregion Main