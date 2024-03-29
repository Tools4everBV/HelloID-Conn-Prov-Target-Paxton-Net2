﻿
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


## Getting help

> ℹ️ _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> ℹ️ _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/5051-helloid-conn-prov-target-paxton-net2)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/


