################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-Permissions
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

try {
    Write-Verbose 'Retrieving permissions' -Verbose
    $accessToken = Get-AccessToken
    $headers = @{
        'Authorization' = "Bearer $($accessToken)"
    }

    $splatGetAccessLevels = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/accesslevels"
        Method  = 'GET'
        Headers = $headers
    }
    $retrievedPermissions = Invoke-RestMethod @splatGetAccessLevels -Verbose:$false

    foreach ($permission in $retrievedPermissions) {
        $outputContext.Permissions.Add(
            @{
                DisplayName    = $permission.name
                Identification = @{
                    Reference   = $permission.id
                    DisplayName = $permission.name
                }
            }
        )
    }
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}

