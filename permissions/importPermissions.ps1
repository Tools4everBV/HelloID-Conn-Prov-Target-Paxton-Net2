#################################################
# HelloID-Conn-Prov-Target-Paxton-Net2
# PowerShell V2
#################################################

# Wait 2 seconds before executing script in order to prevent errors on getting the accesstoken (max 2 requests per second)
Start-Sleep -Seconds 2

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
    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to Paxton Net2'
    $accessToken = Get-AccessToken
    $headers = @{
        Authorization  = "Bearer $($accessToken)"
        "Content-type" = "application/json"
    }
		
	$accountCount = 0
	$splatGetUsers = @{
		Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users"
		Method  = 'GET'
		Headers = $headers
	}
	$existingAccounts = Invoke-RestMethod @splatGetUsers
	
	$splatGetAccessLevels = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/accesslevels"
        Method  = 'GET'
        Headers = $headers
    }
    $allPermissions = Invoke-RestMethod @splatGetAccessLevels
	
	$allPermissionsGrouped = $allPermissions | Group-Object "id" -AsHashTable 

	foreach ($account in $existingAccounts){
		$splatGetPermissions = @{
			Uri         = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($account.id)/doorpermissionset"
			Method      = 'GET'
			Headers     = $headers
			ContentType = 'application/json'
		}

		$currentAccountPermissions = Invoke-RestMethod @splatGetPermissions

		foreach ($accountPermission in $currentAccountPermissions.accessLevels) {

			$permission = $allPermissionsGrouped[$accountPermission]
           
            # Make sure the displayName has a value of max 100 char
            if (-not([string]::IsNullOrEmpty($permission.name))) {
                $displayName = "$($permission.name)"
                $displayName = $($displayName).substring(0, [System.Math]::Min(100, $($displayName).Length))
            }
            else {
                $displayName = "$($permission.id)"
            }
            # Make sure the description has a value of max 100 char
            $description = $displayName

            Write-Output @(
                @{
                    AccountReferences   = @( $account.id )
                    PermissionReference = @{ Reference = $permission.id }                        
                    Description         = $description
                    DisplayName         = $displayName
                }
            )
        }
	}   
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}