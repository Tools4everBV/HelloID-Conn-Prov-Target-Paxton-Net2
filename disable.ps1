##################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-Disable
# PowerShell V2
# Version: 1.0.0
##################################################

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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }
    if ([string]::IsNullOrEmpty($( $actionContext.Configuration.archivedDepartmentId))) {
        throw 'The [Terminated Employment Department Id] could not be found, please verify your configuration'
    }
    $accessToken = Get-AccessToken
    $headers = @{
        'Authorization' = "Bearer $($accessToken)"
    }

    Write-Verbose "Verifying if a Paxton-Net2 account for [$($personContext.Person.DisplayName)] exists" -Verbose
    $splatGetUserParams = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $existingAccount = Invoke-RestMethod @splatGetUserParams -Verbose:$false
    } catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    $actionList = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $existingAccount) {
        $actionList.Add('DisableAccount')
        $actionList.Add('UpdateDepartment')
        $dryRunMessage = "Disable Paxton-Net2 account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] will be executed during enforcement"
    } else {
        $actionList.Add('NotFound')
        $dryRunMessage = "Paxton-Net2 account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted"
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Verbose "[DryRun] $dryRunMessage"  -Verbose
        if ($actionList.Contains('UpdateDepartment')) {
            Write-Verbose "Department update will be executed during enforcement, new department will be [Terminated Employment [id = $($actionContext.Configuration.archivedDepartmentId)]]" -Verbose
        }
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        foreach ($action in $actionList) {
            switch ($action) {
                'DisableAccount' {
                    Write-Verbose "Disabling Paxton-Net2 account with accountReference: [$($actionContext.References.Account)]" -Verbose
                    $body = @{
                        id         = "$($actionContext.References.Account)"
                        expiryDate = (Get-Date).AddDays(-1).ToShortDateString()
                    }

                    $splatDisable = @{
                        Uri         = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)"
                        Method      = 'PUT'
                        Headers     = $headers
                        body        = ($body | ConvertTo-Json)
                        ContentType = 'application/json'
                    }
                    $null = Invoke-RestMethod @splatDisable -Verbose:$false
                    $outputContext.Success = $true
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = 'Disable account was successful'
                            IsError = $false
                        })
                    break
                }

                'UpdateDepartment' {
                    $body = @{
                        id = $actionContext.Configuration.archivedDepartmentId
                    }
                    $splatDepartment = @{
                        Uri         = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/departments"
                        Method      = 'PUT'
                        Headers     = $headers
                        body        = ($body | ConvertTo-Json)
                        ContentType = 'application/json'
                    }
                    $null = Invoke-RestMethod @splatDepartment

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Department update was successful, new department is [Terminated Employment [id = $($actionContext.Configuration.archivedDepartmentId)]]"
                            IsError = $false
                        })
                    $outputContext.Success = $true
                    break
                }

                'NotFound' {
                    $outputContext.Success = $true
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Paxton-Net2 account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted"
                            IsError = $false
                        })
                    break
                }
            }
        }
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
        $auditMessage = "Could not disable Paxton-Net2 account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not disable Paxton-Net2 account. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
