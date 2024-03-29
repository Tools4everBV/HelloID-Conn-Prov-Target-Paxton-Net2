#################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-Create
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
    # AccountReference must have a value
    $outputContext.AccountReference = 'Currently not available'

    $accessToken = Get-AccessToken
    $headers = @{
        Authorization  = "Bearer $($accessToken)"
        "Content-type" = "application/json"
    }

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.PersonField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [PersonFieldValue] is empty. Please make sure it is correctly mapped'
        }
        if ([string]::IsNullOrEmpty($($actionContext.Data.PersonnelNumber.Id))) {
            throw 'Correlation is enabled but [PersonnelNumber.Id] in the field mapping is empty. Please make sure it is correctly mapped'
        }

        $splatGetUserParams = @{
            Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/customquery/querydb?query=SELECT * From sdk.usersex WHERE field$($actionContext.Data.PersonnelNumber.Id)_50=$($correlationValue)"
            Method  = 'GET'
            Headers = $headers
        }

        $correlatedAccount = Invoke-RestMethod @splatGetUserParams -Verbose:$false
    }

    $correlatedAccountCount = ($correlatedAccount | Measure-Object).Count
    if ($correlatedAccountCount -eq 1) {
        $correlatedAccount = $correlatedAccount | Select-Object -First 1
        $action = 'CorrelateAccount'
        $dryRunMessage = "[DryRun] CorrelateAccount Paxton-Net2 account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
    } elseif (($correlatedAccount | Measure-Object).Count -gt 1) {
        throw "Multiple accounts found with Correlation: $correlationField - $correlationValue"
    } else {
        $action = 'CreateAccount'
        $dryRunMessage = "[DryRun] CreateAccount Paxton-Net2 account for: [$($personContext.Person.DisplayName)], will be executed during enforcement"
    }

    if ($action -eq 'CreateAccount') {
        # Department Mapping
        $departmentField = 'Department'
        if ($actionContext.Data.PsObject.Properties.name -NotContains "$departmentField") {
            throw "No Field [$departmentField] found in the field mapping"
        }

        $mapping = Import-Csv $actionContext.Configuration.departmentMapping

        # [$_. DepartmentNet2] Should match the name of the Header in de CSV Mapping file
        if ($null -eq $mapping -and ($mapping.DepartmentNet2 | Measure-Object).count -lt 1) {
            Throw "No valid Mapping File found: [$($actionContext.Configuration.departmentMapping)] "
        }

        # [$_. Department] Should match the name of the Header in de CSV Mapping file
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

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Verbose "$($dryRunMessage)" -Verbose
        if ($action -eq 'CreateAccount') {
            Write-Verbose "[DryRun] Paxton-Net2 account for: [$($personContext.Person.DisplayName)] will be added to department [$($desiredDepartment.departmentName)] during enforcement" -Verbose
        }
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'CreateAccount' {
                Write-Verbose 'Creating and correlating Paxton-Net2 account'
                $customFields = @(
                    @{
                        "id"    = $actionContext.Data.email.id
                        "value" = $actionContext.Data.email.value
                    },
                    @{
                        "id"    = $actionContext.Data.personnelNumber.id
                        "value" = $actionContext.Data.personnelNumber.value
                    })
                $createUserBody = $actionContext.data
                $createUserBody = $createUserBody | Select-Object * -ExcludeProperty Id, Department, email, personnelNumber
                $createUserBody | Add-Member -Name "customFields" -Value $customFields -MemberType NoteProperty

                $createUserBody | Add-Member @{
                    expiryDate = "$((Get-Date).AddDays(-1).ToShortDateString())"
                } -Force
                $splatCreateUser = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users"
                    Method  = 'POST'
                    Headers = $headers
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes(($createUserBody | ConvertTo-Json -Depth 10)))
                }

                $createdAccount = Invoke-RestMethod @splatCreateUser

                $outputContext.Data = $createdAccount
                $outputContext.AccountReference = $createdAccount.id

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })

                $body = @{
                    Id   = $desiredDepartment.departmentID
                    Name = $desiredDepartment.departmentName
                }
                $splatUpdateUserWithDepartment = @{
                    Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($outputContext.AccountReference)/departments"
                    Method  = 'PUT'
                    Headers = $headers
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json)))
                }
                $null = Invoke-RestMethod @splatUpdateUserWithDepartment

                $outputContext.Data | Add-Member @{ Department = $desiredDepartment.departmentName } -Force
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Account: [$($outputContext.AccountReference)] added to Department: [$($desiredDepartment.departmentName)]"
                        IsError = $false
                    })
                break
            }

            'CorrelateAccount' {
                Write-Verbose 'Correlating Paxton-Net2 account'
                $outputContext.AccountReference = $correlatedAccount.userID
                $outputContext.Data = $correlatedAccount
                $outputContext.Data | Add-Member @{ Department = $desiredDepartment.departmentName } -Force
                $outputContext.AccountCorrelated = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = $action
                        Message = "Correlated account: [$($correlatedAccount.userID)] on field: [$($correlationField)] with value: [$($correlationValue)]"
                        IsError = $false
                    })
                break
            }
        }
    }
    $outputContext.success = $true
} catch {
    if ($actionContext.DryRun -eq $true) {
        $outputContext.AccountReference = 'Error'
    }

    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex

        if ($ex.TargetObject.RequestUri.AbsoluteUri -match 'departments' -and $ex.TargetObject.Method -eq 'PUT') {
            $auditMessage = "Failed to add account: [$($outputContext.AccountReference)] to Department: [$($desiredDepartment.departmentName)] Error: $($errorObj.FriendlyMessage)"
            Write-Warning "Failed to add account: [$($outputContext.AccountReference)] to Department: [$($desiredDepartment.departmentName)] Error: $($errorObj.FriendlyMessage)"
        } else {
            $auditMessage = "Could not $action Paxton-Net2 account. Error: $($errorObj.FriendlyMessage)"
            Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        }
    } else {
        $auditMessage = "Could not $action Paxton-Net2 account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}