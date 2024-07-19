################################################
# HelloID-Conn-Prov-Target-Paxton-Net2-Permissions
# PowerShell V2
# Version: 1.0.0
################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$mapping = Import-Csv $actionContext.Configuration.departmentMapping

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false 
$actionContext.DryRun = $false

# Set debug logging
switch ($($actionContext.Configuration.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

$aRef = $actionContext.References.Account

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{ }
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$subPermissions = New-Object Collections.Generic.List[PSCustomObject]

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
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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
        }
        catch {
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
    }
    catch {
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

    $retrievedPermissions = $retrievedPermissions | Group-Object -Property name -AsHashTable

}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}

try {
    try {
        # Verify if [aRef] has a value
        if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
            throw 'The account reference could not be found'
        }
    

    }
    catch {
        $outputContext.success = $false
        $ex = $PSItem
        if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
            $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
            $auditMessage = "Could not get Paxton user. Error: $($errorObj.FriendlyMessage)"
            Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        }
        else {
            $auditMessage = "Could not get Paxton user. Error: $($_.Exception.Message)"
            Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        }
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = $auditMessage
                IsError = $true
            })
    }


    try {
        #region Change mapping here
        $desiredPermissions = @{}
        if ($actionContext.Operation -ne "revoke") {
            # Example: Contract Based Logic:
            
            ## Debug comment this!
            $personContext.Person.Contracts = ($personContext.Person.Contracts | Where-Object { $_.Context.InConditions -eq $true })
            #

            foreach ($contract in $personContext.Person.Contracts) {
                Write-Verbose ("Contract in condition: {0}" -f $contract.Context.InConditions)
                if ($contract -OR ($actionContext.DryRun -eq $true)) {
                    #$contract.Context.InConditions
        
                    
                    # [$_. Department] Should match the name of the Header in de CSV Mapping file
                    $mappedDepartment = $mapping | Where-Object { $_.Department -eq $contract.Location.Name }
                    if (($mappedDepartment | Measure-Object).count -lt 1) {
                        throw  "No Net2 Department found in mapping with HelloId values: [Department : [$($contract.Location.Name)]]"
                    }
                    elseif (($mappedDepartment | Measure-Object).count -gt 1) {
                        throw  "Multiple Net2 Departments found in mapping with HelloId values: [Department :[$($contract.Location.Name)]]"
                    }
        
                    # [$_. TPCode] Should match the name of the Header in de CSV Mapping file
                    if ($null -eq $mapping -and ($mapping.TPCode | Measure-Object).count -lt 1) {
                        Throw "No valid Mapping File found: [$($actionContext.Configuration.departmentMapping)] "
                    }

                    # Correlation values
                    $TPCode = $mappedDepartment.TPCode 

                    <## ---- ## Extra contract specific custom permissions could be added here
                    ## For example, if a value is met, take a value from an exception column in the csv
                    if ($contract.Type.Code -eq '1') {
                        if ($mappedDepartment.TPCodeEx) {
                            $TPCode = $mappedDepartment.TPCodeEx                            
                        }
                    }

                    ## if a certain condition is met the TPCode should always be a certain value,
                    if ( ($contract.Department.Displayname -like "*Value*")) {
                        $TPCode = '1'
                       
                    }

                    ## ---- ##>
                
                    $group = $null
                    $group = $retrievedPermissions[$TPcode]

                    if ($null -eq $group) {
                        Write-Warning "No TPcode for $($contract.Location.Name)"
                    }
                    elseif ($group.id.count -gt 1) {
                        throw "Multiple Groups that matches filter '$($filter)'. Please correct this so the groups are unique."
                    }
                    else {
                        # Add group to desired permissions with the objectguid as key and the displayname as value (use objectguid to avoid issues with name changes and for uniqueness)
                        $desiredPermissions["$($group.id)"] = $group.name
                    }

                    write-verbose -verbose ($group | out-string)

                    
                }
            }

            

        }

        # Remove duplicates
        $desiredPermissions = $desiredPermissions | Select-Object -Unique

        <##  ----- ## Extra overall custom superpermissions could be added here
        ## For example, if a value is found in the desiredpermissions array, make sure this is the only value in the array 
        if ($desiredPermissions.count -gt 0) {

            ## If a value is found, make sure this is the only value in the array ##            
            if ($desiredPermissions.values -contains "2") {

                $desiredPermissions = @{}
                $group = $null
                $group = $retrievedPermissions["2"]

                if ($null -ne $group) {
                    $desiredPermissions["$($group.id)"] = $group.name
                }  
            }

            ## If a value is found, make sure other right which have an exception are removed from the array
            if ( ($desiredPermissions.values -contains "3")) {
                foreach ($value in $($desiredPermissions.values)){
                    $mappedDepartment = $mapping | Where-Object { $_.TPCode -eq $Value }
                    if ($mappedDepartment.TPCodeEx) {
                        $group = $retrievedPermissions[$value]                        
                        $desiredPermissions.Remove("$($group.id)")  
                    }
                }
            }
        }

        ## ----- ##>

    }
    catch {
        $ex = $PSItem
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "$($ex.Exception.Message)"
                IsError = $true
            })

        throw $_
    }

    Write-Information ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))

    Write-Information ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))
    #endregion Change mapping here

    # Get current permissions
    $splatGetUserParams = @{
        Uri     = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/doorpermissionset"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $existingPermissions = Invoke-RestMethod @splatGetUserParams -Verbose:$false
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    foreach ($permission in $desiredPermissions.GetEnumerator()) {

        $subPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        # Grant Groupmembership
        try {
            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "Granting permission to group '$($permission.Value) ($($permission.Name))' for user '$aRef'"

                if (-not ($existingPermissions.accessLevels -contains $($permission.name) ) ) {

                    $existingPermissions.accessLevels += $($permission.name)
                    
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Permission - [$($permission.Value)] was added to permissionlist"
                            IsError = $false
                        })

                }
                else {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Permission - [$($permission.Value)] was not added to permissionlist as permission already exists on user"
                            IsError = $false
                        })

                }  
            }
            else {
                Write-Warning "DryRun: Would grant permission to group '$($permission.Value) ($($permission.Name))' for user '$aRef'"
            }
        }
        catch {
            $ex = $PSItem
            if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
                $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
                $auditMessage = "Could not grant Paxton-Net2 permission. Error: $($errorObj.FriendlyMessage)"
                Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            }
            else {
                $auditMessage = "Could not grant Paxton-Net2 permission. Error: $($_.Exception.Message)"
                Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
            }
                    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "Error granting permission to group '$($permission.Value) ($($permission.Name))' for user '$aRef'. Error Message: $auditMessage"
                    IsError = $True
                })
        }
          
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}

    foreach ($permission in $currentPermissions.GetEnumerator()) {  

        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No Groups Defined") {
            # Revoke Groupmembership
            try {
                if (-Not($actionContext.DryRun -eq $true)) {

                    Write-Verbose "Revoking permission from group '$($permission.Value) ($($permission.Name))' for user '$aRef'"
                    if ($existingPermissions.accessLevels -contains $permission.name) {

                        $existingPermissions.accessLevels = $existingPermissions.accessLevels -ne $($permission.Name)

                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Message = "Permission - [$($permission.Value)] was removed from permissionlist"
                                IsError = $false
                            })
                    }
                    else {
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Message = "Permission - [$($permission.Value)] was not removed from permissionlist as permission did not exists on user"
                                IsError = $false
                            })
        
                    }     
                }
                else {
                    Write-Warning "DryRun: Would revoke permission to group '$($permission.Value) ($($permission.Name))' for user '$aRef'"
                }
            }
            catch {
                
                $ex = $PSItem
                if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
                    $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                    $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
                    $auditMessage = "Could not revoke Paxton-Net2 permission. Error: $($errorObj.FriendlyMessage)"
                    Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
                }
                else {
                    $auditMessage = "Could not revoke Paxton-Net2 permission. Error: $($_.Exception.Message)"
                    Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
                }
    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Error revoking permission from group '$($permission.Value) ($($permission.Name))' for user '$aRef'. Error Message: $auditMessage"
                        IsError = $True
                    })
                    
            }
    
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    } 

    try {
        ## Send the body
        $splatPermissions = @{
            Uri         = "$($actionContext.Configuration.BaseUrl)/api/v1/users/$($actionContext.References.Account)/doorpermissionset"
            Method      = 'PUT'
            Headers     = $headers
            body        = ($existingPermissions | ConvertTo-Json)
            ContentType = 'application/json'
        }

        $Result = Invoke-RestMethod @splatPermissions -Verbose:$false
        
    }
    catch {

        $ex = $PSItem
        if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
            $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObj = Resolve-Paxton-Net2Error -ErrorObject $ex
            $auditMessage = "Could not revoke Paxton-Net2 permission. Error: $($errorObj.FriendlyMessage)"
            Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        }
        else {
            $auditMessage = "Could not revoke Paxton-Net2 permission. Error: $($_.Exception.Message)"
            Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        }
                
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Error submitting the permissionsobject. Error Message: $auditMessage"
                IsError = $True
            })
    }


}
catch {
    write-verbose -verbose $_
}

finally { 

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }

    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $subPermissions.count -eq 0) {
        $subPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }

    $outputContext.SubPermissions = $subPermissions
}