
# HelloID-Conn-Prov-Target-Paxton-Net2

| :information_source: Information                                                                                                                                                                                                                                                                                                                                                       |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

<p align="center">
  <img src="https://www.paxton-access.com/wp-content/uploads/2018/12/paxton-logo.svg">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Paxton-Net2](#helloid-conn-prov-target-paxton-net2)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Correlation configuration](#correlation-configuration)
    - [Connection settings](#connection-settings)
    - [Prerequisites](#prerequisites)
    - [Remarks](#remarks)
    - [Net2 Version 7 Release – Q1 2026](#net2-version-7-release---q1-2026)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Paxton-Net2_ is a _target_ connector. _Paxton-Net2_ provides a set of REST API's that allow you to programmatically interact with its data.

The following lifecycle actions are available:

| Action          | Description                         |
| --------------- | ----------------------------------- |
| create.ps1      | Create and/or correlate the Account |
| update.ps1      | Update the Account                  |
| enable.ps1      | Enable the Account                  |
| disable.ps1     | Disable the Account                 |
| permissions.ps1 | Retrieve the permissions            |
| grant.ps1       | Grant permission                    |
| revoke.ps1      | Revoke permission                   |

## Getting started

### Provisioning PowerShell V2 connector

#### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _Paxton-Net2_ to a person in _HelloID_.

To properly setup the correlation:

1. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                   | Value               |
    | ------------------------- | ------------------- |
    | Enable correlation        | `True`              |
    | Person correlation field  | `Person.ExternalId` |
    | Account correlation field | `PersonnelNumber.Value`    |

> ℹ️ _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

#### Concurrent actions to 1
Set the number of concurrent actions to 1. Otherwise, retrieving the accesstoken will result in a 429 error indicating there are "too many requests".

### Connection settings

The following settings are required to connect to the API.

| Setting  | Description                        | Mandatory |
| -------- | ---------------------------------- | --------- |
| UserName | The UserName to connect to the API | Yes       |
| Password | The Password to connect to the API | Yes       |
| BaseUrl  | The URL to the API                 | Yes       |
| ClientID | The Client Id to the API           | Yes       |

### Prerequisites

### Remarks
- The client ID can be found in the license file.
- The 'Department' field in the field mapping is mandatory. If it is not filled correctly, it will result in errors in the account cycle scripts.
  - The Department ID cannot be found in the UI. However, the list of departments is ordered, and the ID follows this order as well, starting with 0 for the None department. So, the first department in the list will be assigned an ID of 1, and so on. The order may vary if Net2 departments have been deleted in the past. To ensure accuracy, you could perform an API call to retrieve all the departments. `{{BaseURL}}/api/v1/departments`
- The connector uses a CSV file to handle the department mapping.
- The connector relies on the CSV headers. So normally, these cannot be changed without code adjustments.
- The API utilizes custom fields to populate specific data in Net2. The connector is designed to only populate the email and personnel number fields. Each custom field has a corresponding ID, which can be located in the Net2 UI under 'Options' and then 'Field Names'. By default, the IDs for email and personnel numbers are 9 and 14, respectively.
- If you want to populate more custom fields in net2 via this connector, be aware that changes to the code are also necessary. Because it is not necessary to use these other fields there isn't a generic solution for this.
- The connector is based on Net2 Pro. The main difference between Pro and Lite is that the Pro version handles multiple authorizations, whereas the Lite version only supports one authorization. While the connector can be tested on a Lite version, it may not fully integrate with HelloId. This is because you cannot enforce that only one entitlement is granted with the business rules. There is a commented-out code snippet in the grant script, which can be used for this purpose.
- The disable script in the connector assigns the user to the 'uitdienst' department.
- If the user is disabled and therefore assigned to the department 'uitdienst,' and then later gets enabled, the user is removed from the 'uitdienst' department. The correct user will then be assigned to the correct department when the update script runs.
- As of version 6.8 the Security - Authorisation endpoint (/api/v1/authorization/tokens) is rate limited and will return code 429 if requests are over 2 requests per second. Because of this, the import scripts for accounts and memberships contain a Start-Sleep command at the beginning of the script in order to prevent multiple scripts to retrieve an accesstoken.

### Net2 Version 7 Release – Q1 2026

> [!NOTE]
> The following code has not been tested on a Paxton NET2 environment. 

In the first quarter of 2026, Net2 version 7 will be released. This update introduces a significant new security feature: Multi-Factor Authentication (MFA).
MFA can be enabled within the application to provide an additional layer of protection for user logins, using a one-time access code (OTP) delivered via email or an authenticator app.

**For customers updating to Net2 v7 or higher:**
**If MFA is not enabled**, there will be **no impact **on existing Web API integrations.
**If MFA is enabled**, **existing Web API integrations** will **need to be modified**.

To implement the 'MFA' within the connector:

1. Make sure to replace `Get-AccessToken` in __all__ lifecycle actions with:
```powershell
function Get-AccessToken {
    [CmdletBinding()]
    param ()

    try {
        $baseUrl = $actionContext.Configuration.BaseUrl

        # Stage 1: Initial login attempt with username + password
        $initialHeaders = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
        $initialBody = @{
            username   = $actionContext.Configuration.UserName
            password   = $actionContext.Configuration.Password
            grant_type = 'password'
            client_id  = $actionContext.Configuration.ClientId
        }

        $splatInitialRequest = @{
            Uri         = "$baseUrl/api/v1/authorization/tokens"
            Method      = 'POST'
            Headers     = $initialHeaders
            Body        = $initialBody
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
        }
        $initialResponse = Invoke-RestMethod @splatInitialRequest

        # If no MFA is required, return token directly
        if ($null -ne $initialResponse.access_token) {
            $initialResponse.access_token
        }

        # Stage 2: MFA required
        if ($initialResponse.error -eq 'mfa_required') {
            $challengeToken = $initialResponse.challengeToken
            $challengeType  = $actionContext.Configuration.MfaType # e.g. "email" or "otp"

            # Request MFA challenge
            $mfaRequestBody = @{
                challengeToken = $challengeToken
                challengeType  = $challengeType
            } | ConvertTo-Json

            $splatMfaRequest = @{
                Uri         = "$baseUrl/api/v1/authorization/mfa-request"
                Method      = 'POST'
                Headers     = @{ 'Content-Type' = 'application/json' }
                Body        = $mfaRequestBody
                ContentType = 'application/json'
                Verbose     = $false
            }
            $mfaRequestResponse = Invoke-RestMethod @splatMfaRequest

            # Submit MFA code
            $mfaChallengeBody = @{
                challengeToken = $challengeToken
                code           = $actionContext.Configuration.MfaCode
            } | ConvertTo-Json

            $splatMfaChallenge = @{
                Uri         = "$baseUrl/api/v1/authorization/mfa-challenge"
                Method      = 'POST'
                Headers     = @{ 'Content-Type' = 'application/json' }
                Body        = $mfaChallengeBody
                ContentType = 'application/json'
                Verbose     = $false
            }
            $mfaChallengeResponse = Invoke-RestMethod @splatMfaChallenge

            # Exchange challengeToken for final access token
            $finalTokenBody = @{
                challengeToken = $challengeToken
                grant_type     = 'mfa_2fa'
                client_id      = $actionContext.Configuration.ClientId
            }

            $splatFinalToken = @{
                Uri         = "$baseUrl/api/v1/authorization/tokens"
                Method      = 'POST'
                Headers     = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
                Body        = $finalTokenBody
                ContentType = 'application/x-www-form-urlencoded'
                Verbose     = $false
            }
            $finalTokenResponse = Invoke-RestMethod @splatFinalToken

            $finalTokenResponse.access_token
        }

    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
```
2. Extend the configuration with the following parameters:
   - `MfaType` e.g. _email_ or _otp_.
   - `MfaCode`.

## Getting help

> ℹ️ _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> ℹ️ _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/5051-helloid-conn-prov-target-paxton-net2)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/



