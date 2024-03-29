#################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-Update
# PowerShell V2
# Version: 1.0.0
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-Paxton-Net2Error {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            # Make sure to inspect the error result object and add only the error message as a FriendlyMessage.
            $httpErrorObj.FriendlyMessage = $errorDetailsObject.message
        } catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Compare-Properties {
    [CmdletBinding()]
    param (
        [parameter(Mandatory)]
        [PSCustomObject]
        $CurrentAccount,

        [parameter(Mandatory)]
        [PSCustomObject]
        $DesiredAccount
    )
    try {
        $propertiesChanged = [System.Collections.Generic.list[string]]::new()
        foreach ($prop in  $DesiredAccount.PsObject.Properties) {
            if ($CurrentAccount.$($prop.name) -ne $DesiredAccount.$($prop.name)) {
                $propertiesChanged.Add($($prop.name))
            }
        }
        Write-Output $propertiesChanged -NoEnumerate
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Compare-CustomField {
    param(
        [Parameter(Mandatory)]
        [string]
        $FieldToCompare
    )
    if ($actionContext.data.PsObject.Properties.Name -notcontains $FieldToCompare) {
        Write-Verbose "Specified Field [$FieldToCompare] not found in FieldMapping" -Verbose
        return
    }

    $customField = $existingAccount.customFields | Where-Object { $_.id -eq $actionContext.data.$FieldToCompare.id }
    if (-not $customField.id -or -not $customField.value) {
        Write-Error "The field [$FieldToCompare] is specified but mandatory values 'id' and 'value' are not present."
        return
    }

    if ($customField.value -ne $actionContext.data.$FieldToCompare.value) {
        Write-Output $FieldToCompare
    }
}

function Get-AccessToken {
    [CmdletBinding()]
    param ()
    try {
        $tokenHeaders = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        $tokenBody = @{
            username   = $actionContext.Configuration.UserName
            password   = $actionContext.Configuration.Password
            grant_type = 'password'
            client_id  = $actionContext.Configuration.ClientId
        }
        $splatGetTokenParams = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/api/v1/authorization/tokens"
            Method      = 'POST'
            Headers     = $tokenHeaders
            Body        = $tokenBody
            ContentType = 'application/x-www-form-urlencoded'
        }
        $token = Invoke-RestMethod @splatGetTokenParams -Verbose:$false
        Write-Output $token.access_token
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }
    $accessToken = Get-AccessToken
    $headers = @{
        'Authorization' = "Bearer $($accessToken)"
        "Content-type"  = "application/json"
    }

    Write-Verbose "Verifying if a Paxton-Net2 account for [$($personContext.Person.DisplayName)] exists" -Verbose
    $splatGetUserParams = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $existingAccount = Invoke-RestMethod @splatGetUserParams -Verbose:$false
        $outputContext.PreviousData = $existingAccount
    } catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    if ($null -ne $existingAccount) {
        Write-Verbose 'Get Paxton-Net2 account existing assigned Department' -Verbose
        $splatGetUserParams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/departments"
            Method  = 'GET'
            Headers = $headers
        }
        $existingDepartment = (Invoke-RestMethod @splatGetUserParams -Verbose:$false ) | Select-Object -First 1

        # [$_. DepartmentNet2] and [$_. Department] Should match the name of the Header in de CSV Mapping file
        $mapping = Import-Csv $actionContext.Configuration.departmentMapping
        if ($null -eq $mapping -and ($mapping.DepartmentNet2 | Measure-Object).count -lt 1) {
            Throw "No valid Mapping File found: [$($actionContext.Configuration.departmentMapping)] "
        }
        $mappedDepartment = $mapping | Where-Object { $_.Department -eq $actionContext.Data.Department }
        if (($mappedDepartment | Measure-Object).count -lt 1) {
            throw  "No Net2 Department found in mapping with HelloId values: [$($departmentField) : [$($actionContext.Data.Department)]]"
        } elseif (($mappedDepartment | Measure-Object).count -gt 1) {
            throw  "Multiple Net2 Departments found in mapping with HelloId values: [$($departmentField) :[$($actionContext.Data.Department)]]"
        }

        # Retrieve department to retrieve department ID
        $splatDepartments = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/customquery/querydb?query=SELECT * From sdk.departments WHERE departmentName='$($mappedDepartment.DepartmentNet2)'"
            Method  = 'GET'
            Headers = $headers
        }
        $desiredDepartment = Invoke-RestMethod @splatDepartments | Select-Object -First 1 # Always one

        # Verify if department exists
        $desiredDepartmentCount = ($desiredDepartment | Measure-Object).count
        if ($desiredDepartmentCount -lt 1) {
            throw "Mapped department [$($mappedDepartment.DepartmentNet2)] does not exist in Net2"
        }
    }

    # Define required actions
    $actionList = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $existingAccount) {
        $splatCompareProperties = @{
            CurrentAccount = $existingAccount
            DesiredAccount = ($actionContext.data | Select-Object * -ExcludeProperty Department, Email, PersonnelNumber)
        }
        $propertiesChanged = (Compare-Properties @splatCompareProperties)
        $propertiesChanged += Compare-CustomField 'Email'

        if ($propertiesChanged) {
            $actionList.Add('UpdateAccount')
            $dryRunMessage = "Account property(s) required to update: $($propertiesChanged.Where({$null -ne $_}) -join ', ')"
        } else {
            $actionList.Add('NoChanges')
            $dryRunMessage = 'No changes will be made to the account during enforcement'
        }
        if ($existingDepartment.name -ne $desiredDepartment.departmentName) {
            $actionList.Add('UpdateDepartment')
        }
    } else {
        $actionList.Add('NotFound')
        $dryRunMessage = "Paxton-Net2 account for: [$($personContext.Person.DisplayName)] not found. Possibly deleted."
    }


    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Verbose "[DryRun] $dryRunMessage" -Verbose

        if ($actionList.Contains('UpdateDepartment')) {
            Write-Verbose "[DryRun] Department update will be executed during enforcement, new department will be [$($desiredDepartment.departmentName)]" -Verbose
        }
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        foreach ($action in $actionList) {
            switch ($action) {
                'UpdateAccount' {
                    Write-Verbose "Updating Paxton-Net2 account with accountReference: [$($actionContext.References.Account)]"

                    $createUserBody = [PSCustomObject]@{
                        Id = $actionContext.References.Account
                    }

                    # foreach propertiesChanged add to body
                    foreach ($property in $propertiesChanged) {
                        if ($property -ne "Id" -and $property -ne "Email") {
                            $createUserBody | Add-Member -MemberType NoteProperty -Name $property -Value $actionContext.Data.$property
                        }
                    }

                    if ($propertiesChanged -eq 'Email') {
                        Write-Verbose 'Update CustomField in body ' -Verbose

                        $customFieldEmail = @(
                            @{
                                "id"    = $actionContext.Data.email.id
                                "value" = $actionContext.Data.email.value
                            })
                        $createUserBody | Add-Member -MemberType NoteProperty -Name "customFields" -Value $customFieldEmail
                    }

                    $splatUpdateUser = @{
                        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)"
                        Method  = 'PUT'
                        Headers = $headers
                        Body    = ([System.Text.Encoding]::UTF8.GetBytes(($createUserBody | ConvertTo-Json -Depth 10)))
                    }

                    $null = Invoke-RestMethod @splatUpdateUser

                    $outputContext.Success = $true
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged -join ',')]"
                            IsError = $false
                        })
                    break
                }
                'UpdateDepartment' {
                    Write-Verbose "Update Department $($desiredDepartment.departmentName)" -Verbose
                    $body = @{
                        Id   = $desiredDepartment.departmentID
                        Name = $desiredDepartment.departmentName
                    }
                    $splatUpdateUserWithDepartment = @{
                        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/departments"
                        Method  = 'PUT'
                        Headers = $headers
                        Body    = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json)))
                    }

                    $null = Invoke-RestMethod @splatUpdateUserWithDepartment

                    $outputContext.Success = $true
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Department update from [$($existingDepartment.Name)] to [$($desiredDepartment.departmentName)] was successful"
                            IsError = $false
                        })
                }

                'NoChanges' {
                    Write-Verbose "No changes to Paxton-Net2 account with accountReference: [$($actionContext.References.Account)]"

                    $outputContext.Success = $true
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = 'No changes will be made to the account during enforcement'
                            IsError = $false
                        })
                    break
                }

                'NotFound' {
                    $outputContext.Success = $false
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Paxton-Net2 account for: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted"
                            IsError = $true
                        })
                    break
                }
            }
        }
    }
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
        $auditMessage = "Could not update Paxton-Net2 account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not update Paxton-Net2 account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}

