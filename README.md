# G-Suite ECMA2

G-Suite Management Agent for Microsoft Identity Manager (MIM) 2016

## This repo
This repo contains a .NET Visual Studio project that will allow Microsoft Identity Manager (MIM) 2016 to connect to your G-Suite and manage users and groups.

## Prerequisites
* Create your application credentials by following the directions provided by Google: https://developers.google.com/workspace/guides/create-credentials
* Allow domain-wide delegation to your Google Developer Project. Please follow this example: https://support.google.com/a/answer/162106
* Use the following scopes under your domain-wide delegation page: [admin.directory.group, admin.directory.group.member, admin.directory.orgunit, admin.directory.user, admin.directory.user.alias]
* Generate your PKCS12 key/certificate file from your Google Developer admin console. Please store the file in a folder/share accessible to the user running the MIM 2016 service.

## Installation
1. Compile the project and locate the files within the ~/bin/Debug folder of the project.
2. Copy the files to your "Extensions" folder. The default path should be: C:\Program Files\Microsoft Forefront Identity Manager\2010\Synchronization Service\Extensions
3. Create a new management agent within MIM and select Extensible Connectivity 2.0 from the dropdown. Name the agent and give it a good description.
4. Under the "Select Extension DLL" menu, select the GoogleMailCSExtension.dll from the "browse" menu and click on "Refresh interfaces".
5. Replace "example.com" with your G-Suite domain under the "Connectivity" menu.
6. Fill in the "Global Parameters" fields with the values given from the prerequisite. The "apiPrivateKeyPath" is the full folder path and name of the .p12 file.
7. Select the object types MIM will synchronize data with from the "Select Object Types" menu.
8. Select the attributes that your organization requires. Please create an issue if you require custom attributes.
9. Configure the anchor on the next page. Email is used by default and any other will require modifications to the code.
10. Configure the rest of the management agent as necessary.

