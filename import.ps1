#################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-Create
# PowerShell V2
#################################################

# Wait 4 seconds before executing script in order to prevent errors on getting the accesstoken (max 2 requests per second)
Start-Sleep -Seconds 4

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
    Write-Information 'Starting target account import'

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
	
	foreach ($account in $existingAccounts) {
		# Make sure the DisplayName has a value
		if (-not([string]::IsNullOrEmpty($account.firstName))) {
			$displayName = "$($account.firstName) $($account.middleName) $($account.lastName)" -replace "  ", " "
            $displayName = $displayName.substring(0, [System.Math]::Min(100, $($displayName).Length))
		}
		else {
			$displayName = $account.id
		}

        # Make sure the Username has a value
		if (-not([string]::IsNullOrEmpty($account.Email.value))) {
			$userName = $($account.Email.value).substring(0, [System.Math]::Min(100, $($account.Email.value).Length))
		}
		else {
			$userName = "$($account.id)"
		}

        foreach ($customField in $account.customFields){
            switch($customField.id){
                "9"  {
                    
                    $account | Add-Member -Name "Email" -Value $customField -MemberType NoteProperty
                    break
                }
                "12" {
                    $account | Add-Member -Name "PersonnelNumber" -Value $customField -MemberType NoteProperty
                    break
                }
                "14" {
                    $account | Add-Member -Name "Title" -Value $customField -MemberType NoteProperty
                    break
                }
                default: {
                    # unknown custom field
                    break
                }
            }
        }
        
		# Return the result
		Write-Output @{
			AccountReference = $account.id
			DisplayName      = $displayName
			UserName         = $userName
			Enabled          = $account.expiryDate -eq $null
			Data             = $account
		}
		$accountCount++
	}

    Write-Information "Successfully queried [$accountCount] existing accounts"
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