################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-GrantPermission
# PowerShell V2
# Version: 1.0.0
################################################

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

# Begin
try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }
    $accessToken = Get-AccessToken
    $headers = @{
        'Authorization' = "Bearer $($accessToken)"
    }

    Write-Verbose "Verifying if a Paxton-Net2 account for [$($personContext.Person.DisplayName)] exists" -Verbose
    $splatGetUserParams = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/doorpermissionset"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $existingPermissions = Invoke-RestMethod @splatGetUserParams -Verbose:$false
    } catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }
    if ($null -ne $existingPermissions) {
        $action = 'GrantPermission'
        $dryRunMessage = "Grant Paxton-Net2 entitlement: [$($actionContext.References.Permission.DisplayName)], will be executed during enforcement"
    } else {
        $action = 'NotFound'
        $dryRunMessage = "Paxton-Net2 account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted"
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {
        Write-Verbose "$($dryRunMessage)" -Verbose
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        switch ($action) {
            'GrantPermission' {
                Write-Verbose "Granting Paxton-Net2 entitlement: [$($actionContext.References.Permission.DisplayName)]" -Verbose
                if (-not $existingPermissions.accessLevels.Contains($($actionContext.References.Permission.Reference))) {
                    $existingPermissions.accessLevels += $($actionContext.References.Permission.Reference)

                    # $Net2Lite = $true
                    # if ($Net2Lite -and (($existingPermissions.accessLevels | Measure-Object).count -gt 1)) {
                    #     Write-Warning 'The Net2 Lite version only supports one access level; existing access levels are overwritten.'
                    #     $existingPermissions.accessLevels = @($($actionContext.References.Permission.Reference))
                    # }
                    $splatGrant = @{
                        Uri         = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/doorpermissionset"
                        Method      = 'PUT'
                        Headers     = $headers
                        body        = ($existingPermissions | ConvertTo-Json)
                        ContentType = 'application/json'
                    }
                    $null = Invoke-RestMethod @splatGrant -Verbose:$false
                }
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Grant permission [$($actionContext.References.Permission.DisplayName)] was successful"
                        IsError = $false
                    })
            }

            'NotFound' {
                $outputContext.Success = $false
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Paxton-Net2 account: [$($actionContext.References.Account)] for person: [$($personContext.Person.DisplayName)] could not be found, possibly indicating that it could be deleted"
                        IsError = $true
                    })
                break
            }
        }
    }
} catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
        $auditMessage = "Could not grant Paxton-Net2 permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not grant Paxton-Net2 permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
