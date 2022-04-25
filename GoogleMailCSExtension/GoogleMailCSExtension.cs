/****************************** File Header ******************************\
File Name:    GoogleMailCSExtension.cs
Project:      GoogleMailCSExtension
Author:       Pedro Rivas
Email:        admin@rivas.pw

This project will create a dynamic library extension that will allow MIM
(Microsoft Identity Manager) to connect to a Google G-Suite environment.

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

using System;
using System.IO;
using Microsoft.MetadirectoryServices;
using Google;
using Google.Apis.Admin.Directory.directory_v1;
using Google.Apis.Admin.Directory.directory_v1.Data;
using Google.Apis.Auth.OAuth2;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace FimSync_Ezma
{
    public class EzmaExtension :
    IMAExtensible2CallExport,
    IMAExtensible2CallImport,
    IMAExtensible2GetSchema,
    IMAExtensible2GetCapabilities,
    IMAExtensible2Password,
    IMAExtensible2GetParameters
    {

        public EzmaExtension()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        // ECMA-type global variables
        private int m_importPageSize = 50;
        private int m_importDefaultPageSize = 50;
        private int m_importMaxPageSize = 500;
        OperationType m_importOperation;
        OperationType m_exportOperation;
        private int m_exportDefaultPageSize = 10;
        private int m_exportMaxPageSize = 20;

        // ECMA custom configurations
        log4net.ILog log;

        // Global ECMA variables
        Users allUserResult;
        Groups allGroupResult;
        Members allGroupMemberResult;
        UsersResource.ListRequest allusrQuery;
        GroupsResource.ListRequest allgroupQuery;
        MembersResource.ListRequest allGroupMemberQuery;
        DirectoryService gsvc;

        int userCount = 0;
        int groupCount = 0;
        bool moreGroups = true;
        bool moreUsers = true;

        DirectoryService service = new DirectoryService(new Google.Apis.Services.BaseClientService.Initializer());

        #region FIM MA setup
        public MACapabilities Capabilities
        {
            get
            {
                MACapabilities myCapabilities = new MACapabilities();

                myCapabilities.ConcurrentOperation = false;
                myCapabilities.ObjectRename = true;
                myCapabilities.DeleteAddAsReplace = true;
                myCapabilities.DeltaImport = false;
                myCapabilities.DistinguishedNameStyle = MADistinguishedNameStyle.Generic;
                myCapabilities.ExportType = MAExportType.AttributeUpdate;
                myCapabilities.NoReferenceValuesInFirstExport = true;
                myCapabilities.Normalizations = MANormalizations.None;

                return myCapabilities;
            }
        }
        public IList<ConfigParameterDefinition> GetConfigParameters(KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
        {
            List<ConfigParameterDefinition> configParametersDefinitions = new List<ConfigParameterDefinition>();

            switch (page)
            {
                case ConfigParameterPage.Connectivity:
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("appsDomain", "", "example.com"));
                    break;
                case ConfigParameterPage.Global:
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("apiPrivateKeyPath", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("apiServiceEmail", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("apiServiceUser", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("apiAppName", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("apiAppSecret", "", "notasecret"));
                    break;
                case ConfigParameterPage.Partition:
                    break;
                case ConfigParameterPage.RunStep:
                    break;
            }

            return configParametersDefinitions;
        }
        public ParameterValidationResult ValidateConfigParameters(KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
        {
            ParameterValidationResult myResults = new ParameterValidationResult();
            return myResults;
        }

        public Microsoft.MetadirectoryServices.Schema GetSchema(KeyedCollection<string, ConfigParameter> configParameters)
        {
            SchemaType userType = SchemaType.Create("user", false);
            userType.Attributes.Add(SchemaAttribute.CreateAnchorAttribute("employeeID", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("googleID", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("primaryEmail", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("givenName", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("familyName", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("fullName", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("isAdmin", AttributeType.Boolean));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("suspended", AttributeType.Boolean));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("orgUnitPath", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("includeInGlobalAddressList", AttributeType.Boolean));
            userType.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute("emails", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute("aliases", AttributeType.String));

            Microsoft.MetadirectoryServices.Schema schema = Microsoft.MetadirectoryServices.Schema.Create();
            schema.Types.Add(userType);

            SchemaType groupType = SchemaType.Create("group", false);
            groupType.Attributes.Add(SchemaAttribute.CreateAnchorAttribute("id", AttributeType.String));
            groupType.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute("member", AttributeType.String));
            groupType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("name", AttributeType.String));
            groupType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("email", AttributeType.String));
            
            schema.Types.Add(groupType);

            return schema;
        }
        #endregion

        private DirectoryService credentialUp(KeyedCollection<string, ConfigParameter> configParameters)
        {
            string service_email = configParameters["apiServiceEmail"].Value.ToString();

            log.Debug("Opening the certificate.");
            var certificate = new X509Certificate2(configParameters["apiPrivateKeyPath"].Value.ToString(), configParameters["apiAppSecret"].Value.ToString(), X509KeyStorageFlags.Exportable);
            ServiceAccountCredential cred;
            log.Debug("Building a credential for " + service_email + " " + configParameters["apiServiceUser"].Value.ToString() + ".");
            cred = new ServiceAccountCredential(new ServiceAccountCredential.Initializer(service_email)
            {

                User = configParameters["apiServiceUser"].Value.ToString(),
                Scopes = new[] { DirectoryService.Scope.AdminDirectoryGroup,
                                 DirectoryService.Scope.AdminDirectoryUser,
                                 DirectoryService.Scope.AdminDirectoryUserAlias,
                                 DirectoryService.Scope.AdminDirectoryOrgunit,
                                 DirectoryService.Scope.AdminDirectoryGroupMember,
                                }
            }.FromCertificate(certificate));

            log.Debug("Building the directory service.");
            service = new DirectoryService(new DirectoryService.Initializer()
            {
                HttpClientInitializer = cred,
                ApplicationName = configParameters["apiAppName"].Value.ToString()
            });

            log.Debug("Finished building the directory service.");
            return service;
        }

        public OpenImportConnectionResults OpenImportConnection(KeyedCollection<string, ConfigParameter> configParameters, Microsoft.MetadirectoryServices.Schema types, OpenImportConnectionRunStep importRunStep)
        {
            log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
            FileInfo finfo = new FileInfo(Utils.ExtensionsDirectory + "\\log4netGoogleMailCS.config");
            log4net.Config.XmlConfigurator.ConfigureAndWatch(finfo);

            log.Info("Starting the OpenImportConnection.");

            m_importOperation = importRunStep.ImportType;
            m_importPageSize = importRunStep.PageSize;
            log.Debug("Attempting to authenticate to Google's API.");

            gsvc = credentialUp(configParameters);

            log.Debug("Setting user search object to check connection.");
            UsersResource.GetRequest usr = gsvc.Users.Get(configParameters["apiServiceUser"].Value.ToString());

            try
            {
                log.Debug("Executing.");
                var result = usr.Execute();
                log.Debug("Connected as " + result.Name.GivenName + result.Name.FamilyName + result.Id + result.PrimaryEmail + ".");
                log.Debug("Finished.");
            }
            catch (Exception e)
            {
                log.Error("Unable to set user search object. " + e.Message);
            }

            log.Info("Getting a list of all users.");
            try
            {
                allusrQuery = gsvc.Users.List();
                allusrQuery.Domain = configParameters["appsDomain"].Value.ToString();
                allusrQuery.MaxResults = m_importPageSize - 1;
                log.Debug("Page size set to: " + m_importPageSize);
                log.Info("Got a list of all users.");
            }
            catch (Exception e)
            {
                log.Error("Unable to get a list of users. " + e.Message);
            }
            

            log.Info("Getting a list of all groups.");
            try
            {
                allgroupQuery = gsvc.Groups.List();
                allgroupQuery.Domain = configParameters["appsDomain"].Value.ToString();
                allgroupQuery.MaxResults = 1;
                log.Info("Got a list of all groups.");
            }
            catch (Exception e)
            {
                log.Error("Unable to get a list of users. " + e.Message);
            }

            log.Info("Done with OpenImportConnection.");

            return new OpenImportConnectionResults();
        }

        public CloseImportConnectionResults CloseImportConnection(CloseImportConnectionRunStep importRunStepInfo)
        {
            return new CloseImportConnectionResults();
        }

        public GetImportEntriesResults GetImportEntries(GetImportEntriesRunStep importRunStep)
        {
            List<CSEntryChange> csentries = new List<CSEntryChange>();
            GetImportEntriesResults importReturnInfo;

            if (OperationType.Full == m_importOperation)
            {
                #region Get all users
                if (moreUsers)
                {
                    allUserResult = allusrQuery.Execute();
                    IList<object> aliases = new List<object>();
                    IList<object> emails = new List<object>();

                    foreach (User ur in allUserResult.UsersValue)
                    {
                        log.Debug("Processing user: " + ur.Id + " - " + ur.PrimaryEmail + ".");

                        aliases = new List<object>();
                        CSEntryChange csentry1 = CSEntryChange.Create();
                        csentry1.ObjectModificationType = ObjectModificationType.Add;
                        csentry1.ObjectType = "user";
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("googleID", ur.Id));
                        
                        if (ur.Aliases != null)
                        {
                            foreach (string alias in ur.Aliases)
                            {
                                
                                aliases.Add(alias);
                            }
                        }

                        //Populate values
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("isAdmin", ur.IsAdmin));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("givenName", ur.Name.GivenName));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("familyName", ur.Name.FamilyName));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("fullName", ur.Name.FullName));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("orgUnitPath", ur.OrgUnitPath));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("suspended", ur.Suspended));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("primaryEmail", ur.PrimaryEmail));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("aliases", aliases));
                        csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("includeInGlobalAddressList", ur.IncludeInGlobalAddressList));
                        csentry1.DN = ur.PrimaryEmail;

                        csentries.Add(csentry1);

                        userCount++;
                    }
                }
                log.Info("Number of people processed: " + userCount + ".");
                #endregion

                #region Get all groups
                if (moreGroups)
                {
                    allGroupResult = allgroupQuery.Execute();
                    try
                    {
                        #region loop thru groups
                        foreach (Group gp in allGroupResult.GroupsValue)
                        {
                            IList<object> gpmembers = new List<object>();
                            log.Debug("Found group " + gp.Email + ".");

                            CSEntryChange csentry1 = CSEntryChange.Create();
                            csentry1.ObjectModificationType = ObjectModificationType.Add;
                            csentry1.ObjectType = "group";
                            csentry1.DN = gp.Email;
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("id", gp.Id));
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("name", gp.Name));
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("email", gp.Email));

                            log.Debug("Retrieving group members for " + gp.Email + ".");
                            allGroupMemberQuery = gsvc.Members.List(gp.Email);

                            int membercount = 0;
                            do
                            {
                                allGroupMemberResult = allGroupMemberQuery.Execute();

                                if (allGroupMemberResult.MembersValue == null)
                                {
                                    break;
                                }

                                foreach (Member mbr in allGroupMemberResult.MembersValue)
                                {
                                    gpmembers.Add(mbr.Email);

                                    membercount++;
                                }

                                if (allGroupMemberResult.NextPageToken != null)
                                {
                                    allGroupMemberQuery.PageToken = allGroupMemberResult.NextPageToken;
                                }
                            } while (allGroupMemberResult.NextPageToken != null);

                            log.Info("Added " + membercount + " users to " + gp.Email + ".");
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("member", gpmembers));
                            csentries.Add(csentry1);
                            
                            groupCount++;
                        }
                        #endregion
                    }
                    catch (System.NullReferenceException e)
                    {
                        log.Info("Couldn't retrieve a group! " + e.Message);
                    }

                }
                #endregion
                log.Info("Number of groups processed: " + groupCount);
            }

            if (OperationType.Delta == m_importOperation)
            {
                //Not implemented.
            }

            importReturnInfo = new GetImportEntriesResults();
            importReturnInfo.CSEntries = csentries;

            if (allUserResult.NextPageToken != null)
            {
                allusrQuery.PageToken = allUserResult.NextPageToken;
                moreUsers = true;
            }
            else
            {
                moreUsers = false;
            }

            if (allGroupResult.NextPageToken != null)
            {
                allgroupQuery.PageToken = allGroupResult.NextPageToken;
                moreGroups = true;
            }
            else
            {
                moreGroups = false;
            }

            if (moreUsers || moreGroups)
            {
                importReturnInfo.MoreToImport = true;
            }
            else
            {
                importReturnInfo.MoreToImport = false;
            }
            return importReturnInfo;
        }

        public void OpenExportConnection(KeyedCollection<string, ConfigParameter> configParameters,
            Microsoft.MetadirectoryServices.Schema types,
            OpenExportConnectionRunStep exportRunStep)
        {
            log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
            FileInfo finfo = new FileInfo(Utils.ExtensionsDirectory + "\\log4netGoogleMailCS.config");
            log4net.Config.XmlConfigurator.ConfigureAndWatch(finfo);

            log.Info("Attempting to credential");
            gsvc = credentialUp(configParameters);
        }

        public PutExportEntriesResults PutExportEntries(IList<CSEntryChange> csentries)
        {
            PutExportEntriesResults exportEntriesResults = new PutExportEntriesResults();

            foreach (CSEntryChange csentryChange in csentries)
            {
                MAExportError exportResult = MAExportError.Success;
                List<AttributeChange> attributeChanges = new List<AttributeChange>();
                switch (csentryChange.ObjectModificationType)
                {
                    case ObjectModificationType.Add:
                        #region Create User
                        if (csentryChange.ObjectType == "user")
                        {
                            log.Info("Creating new user " + csentryChange.DN);

                            User adduser = new User();
                            adduser.Password = RandomPassword();
                            adduser.Name = new UserName();
                            //UserExternalId idhax = new UserExternalId();

                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                log.Info("Adding " + ch.Name + " " + ch.ValueChanges.Count + " " + ch.ValueChanges[0].Value.ToString());
                                switch (ch.Name)
                                {
                                    #region Attribute Updates
                                    case "familyName":
                                        adduser.Name.FamilyName = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "givenName":
                                        adduser.Name.GivenName = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "fullName":
                                        adduser.Name.FullName = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "primaryEmail":
                                        adduser.PrimaryEmail = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "orgUnitPath":
                                        adduser.OrgUnitPath = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "suspended":
                                        adduser.Suspended = (bool)ch.ValueChanges[0].Value;
                                        break;
                                    case "isAdmin":
                                        adduser.IsAdmin = (bool)ch.ValueChanges[0].Value;
                                        break;
                                    case "includeInGlobalAddressList":
                                        adduser.IncludeInGlobalAddressList = (bool)ch.ValueChanges[0].Value;
                                        break;
                                        #endregion
                                }
                            }

                            try
                            {
                                var insertCmd = gsvc.Users.Insert(adduser);
                                insertCmd.Execute();
                                log.Info("Created new user" + adduser.PrimaryEmail);
                            }
                            catch (GoogleApiException e)
                            {
                                log.Info(String.Format("Google API returned the exception: {0}=>{1} || {2}",
                                    e, e.Message, e.StackTrace));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", e.Message + "||" + e.StackTrace));
                                continue;
                            }
                            catch
                            {
                                log.Info(string.Format("Unexpected error trying to create user {0}", csentryChange.DN));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected error", "IDK"));
                                continue;
                            }

                            exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult));
                        }
                        #endregion

                        #region Create Group
                        else if (csentryChange.ObjectType == "group")
                        {
                            Group addgroup = new Group();

                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                log.Info("Adding " + ch.Name + " " + ch.ValueChanges.Count + " " + ch.ValueChanges[0].Value.ToString());
                                switch (ch.Name)
                                {
                                    #region Attribute Updates
                                    case "name":
                                        addgroup.Name = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "email":
                                        addgroup.Email = ch.ValueChanges[0].Value.ToString();
                                        break;
                                        #endregion
                                }
                            }

                            try
                            {
                                var insertCmd = gsvc.Groups.Insert(addgroup);
                                insertCmd.Execute();
                                log.Info("Created new group " + addgroup.Email);
                            }
                            catch (GoogleApiException e)
                            {
                                log.Info(String.Format("Google API returned the exception: {0}=>{1} || {2}",
                                    e, e.Message, e.StackTrace));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", e.Message + "||" + e.StackTrace));
                                continue;
                            }
                            catch
                            {
                                log.Info(string.Format("Unexpected error trying to create group {0}", csentryChange.DN));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected error", "IDK"));
                                continue;
                            }
                        }
                        #endregion 
                        break;
                    case ObjectModificationType.Replace:
                    case ObjectModificationType.Update:
                        #region Update User
                        if (csentryChange.ObjectType == "user")
                        {
                            log.Info("Modifying " + csentryChange.DN);
                            var moduserQry = gsvc.Users.Get(csentryChange.DN);
                            var moduserResult = moduserQry.Execute();
                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                foreach (ValueChange vch in ch.ValueChanges)
                                {
                                    switch (vch.ModificationType)
                                    {
                                        case ValueModificationType.Add:
                                            log.Info(String.Format("New value for {0} => {1}", ch.Name, vch.Value.ToString()));
                                            switch (ch.Name)
                                            {
                                                case "familyName":
                                                    moduserResult.Name.FamilyName = vch.Value.ToString();
                                                    break;
                                                case "givenName":
                                                    moduserResult.Name.GivenName = vch.Value.ToString();
                                                    break;
                                                case "fullName":
                                                    moduserResult.Name.FullName = vch.Value.ToString();
                                                    break;
                                                case "primaryEmail":
                                                    moduserResult.PrimaryEmail = vch.Value.ToString();
                                                    break;
                                                case "orgUnitPath":
                                                    moduserResult.OrgUnitPath = vch.Value.ToString();
                                                    break;
                                                case "suspended":
                                                    moduserResult.Suspended = (bool)vch.Value;
                                                    break;
                                                case "isAdmin":
                                                    moduserResult.IsAdmin = (bool)vch.Value;
                                                    break;
                                                case "includeInGlobalAddressList":
                                                    moduserResult.IncludeInGlobalAddressList = (bool)vch.Value;
                                                    break;
                                                case "aliases":
                                                    log.Info("going to add the alias");
                                                    UsersResource.AliasesResource.InsertRequest aliasCmd;
                                                    var aliasObj = new Alias();
                                                    aliasObj.AliasValue = vch.Value.ToString();
                                                    aliasCmd = gsvc.Users.Aliases.Insert(aliasObj, csentryChange.DN);
                                                    aliasCmd.Execute();
                                                    break;
                                            }
                                            break;
                                        case ValueModificationType.Delete:
                                            log.Info(String.Format("Old value for {0} => {1}", ch.Name, vch.Value.ToString()));
                                            break;
                                    }
                                }
                            }
                            try
                            {
                                var updateOp = gsvc.Users.Update(moduserResult, csentryChange.DN);
                                var updateres = updateOp.Execute();
                            }
                            catch (GoogleApiException e)
                            {
                                log.Info(String.Format("Google API returned the exception: {0}=>{1} || \n {2}",
                                    e, e.Message, e.StackTrace));
                                exportResult = MAExportError.ExportErrorConnectedDirectoryError;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", e.Message + "||" + e.StackTrace));
                                log.Info("broke at google exception");
                                continue;
                            }
                            catch (Exception e)
                            {
                                log.Info(string.Format("Unexpected error trying to update user {0}", csentryChange.DN));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected error", e.Message + "||" + e.StackTrace));
                                log.Info("broke at general exception");
                                log.Info(e.Message + " || " + e.StackTrace);
                                continue;
                            }
                            exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult));
                        }
                        #endregion

                        #region Update Group
                        else if (csentryChange.ObjectType == "group")
                        {
                            string errMessage = "";
                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                log.Info(String.Format("Getting group: {0} {1} {2}", csentryChange.DN, ch.ModificationType, ch.IsMultiValued));

                                switch (ch.Name)
                                {
                                    case "member":
                                        foreach (ValueChange vch in ch.ValueChanges)
                                        {
                                            switch (vch.ModificationType)
                                            {
                                                case ValueModificationType.Add:
                                                    try
                                                    {
                                                        log.Info("Adding " + ch.Name + "||" + vch.ModificationType.ToString() + "||" + vch.Value.ToString());
                                                        var newgrp = new Member();
                                                        newgrp.Email = vch.Value.ToString();
                                                        newgrp.Role = "MEMBER";
                                                        var addGroupQry = gsvc.Members.Insert(newgrp, csentryChange.DN);
                                                        addGroupQry.Execute();
                                                    }
                                                    catch (GoogleApiException e)
                                                    {
                                                        log.Info(String.Format("Google API returned the exception: {0}=>{1}", e, e.Message));
                                                        exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                        errMessage = e.Message;
                                                        continue;
                                                    }
                                                    break;
                                                case ValueModificationType.Delete:
                                                    try
                                                    {
                                                        log.Info(String.Format("Deleting user {0} from group {1}", vch.Value.ToString(), csentryChange.DN));
                                                        var existingMbr = gsvc.Members.Delete(csentryChange.DN, vch.Value.ToString());
                                                        var existingMbrQry = existingMbr.Execute();
                                                    }
                                                    catch (GoogleApiException e)
                                                    {
                                                        log.Info(String.Format("Google API returned the exception: {0}=>{1}", e, e.Message));
                                                        exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                        errMessage = e.Message;
                                                        continue;
                                                    }
                                                    break;
                                            }
                                        }
                                        break;
                                }
                            }
                            exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", errMessage));
                        }
                        #endregion 
                        break;
                    case ObjectModificationType.Delete:
                        #region Delete User
                        if (csentryChange.ObjectType == "user")
                        {
                            log.Info("Deleteing " + csentryChange.DN);
                            var deleteuserQry = gsvc.Users.Get(csentryChange.DN);
                            var deleteuserResult = deleteuserQry.Execute();
                            
                            try
                            {
                                var deleteOp = gsvc.Users.Delete(csentryChange.DN);
                                var deleteres = deleteOp.Execute();
                            }
                            catch (GoogleApiException e)
                            {
                                log.Info(String.Format("Google API returned the exception: {0}=>{1} || \n {2}",
                                    e, e.Message, e.StackTrace));
                                exportResult = MAExportError.ExportErrorConnectedDirectoryError;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", e.Message + "||" + e.StackTrace));
                                log.Info("broke at google exception");
                                continue;
                            }
                            catch (Exception e)
                            {
                                log.Info(string.Format("Unexpected error trying to delete user {0}", csentryChange.DN));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected error", e.Message + "||" + e.StackTrace));
                                log.Info("broke at general exception");
                                log.Info(e.Message + " || " + e.StackTrace);
                                continue;
                            }
                            exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult));
                        }
                        #endregion

                        #region Delete Group
                        else if (csentryChange.ObjectType == "group")
                        {
                            log.Info("Deleteing " + csentryChange.DN);
                            var getgroupQry = gsvc.Groups.Get(csentryChange.DN);
                            var getgroupResult = getgroupQry.Execute();
                            
                            try
                            {
                                var deleteOp = gsvc.Groups.Delete(getgroupResult.Id);
                                var deleteres = deleteOp.Execute();
                            }
                            catch (GoogleApiException e)
                            {
                                log.Info(String.Format("Google API returned the exception: {0}=>{1} || \n {2}",
                                    e, e.Message, e.StackTrace));
                                exportResult = MAExportError.ExportErrorConnectedDirectoryError;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", e.Message + "||" + e.StackTrace));
                                log.Info("broke at google exception");
                                continue;
                            }
                            catch (Exception e)
                            {
                                log.Info(string.Format("Unexpected error trying to delete group {0}", csentryChange.DN));
                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                exportEntriesResults.CSEntryChangeResults.Add(
                                    CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected error", e.Message + "||" + e.StackTrace));
                                log.Info("broke at general exception");
                                log.Info(e.Message + " || " + e.StackTrace);
                                continue;
                            }
                            exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult));
                        }
                        #endregion 
                        break;
                    default:
                        break;
                }
            }

            return exportEntriesResults;
        }

        public void CloseExportConnection(CloseExportConnectionRunStep exportRunStep)
        {
        }

        #region Helper functions
        public int ImportMaxPageSize
        {
            get
            {
                return m_importMaxPageSize;
            }
        }

        public int ImportDefaultPageSize
        {
            get
            {
                return m_importDefaultPageSize;
            }
        }

        private string RandomPassword()
        {
            var sha1obj = new SHA1CryptoServiceProvider();
            var rand = new Random();
            string outstring = "";
            for (int count = 0; count < 15; count++)
            {
                outstring += Convert.ToChar(Convert.ToInt32((26 * rand.NextDouble() + 65)));
            }
            return outstring;
        }

        public int ExportDefaultPageSize
        {
            get
            {
                return m_exportDefaultPageSize;
            }
            set
            {
                m_exportDefaultPageSize = value;
            }
        }
        public int ExportMaxPageSize
        {
            get
            {
                return m_exportMaxPageSize;
            }
            set
            {
                m_exportMaxPageSize = value;
            }
        }
        #endregion

        #region Password management
        public static string ConvertToUnsecureString(SecureString securePassword)
        {
            if (securePassword == null)
                throw new ArgumentNullException("securePassword");

            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        public void OpenPasswordConnection(KeyedCollection<string, ConfigParameter> configParameters, Partition partition)
        {
            log.Info("Attempting to credential");
            gsvc = credentialUp(configParameters);
        }

        public void ClosePasswordConnection()
        {
            log.Info("done setting password");
        }

        public ConnectionSecurityLevel GetConnectionSecurityLevel()
        {
            return ConnectionSecurityLevel.Secure;
        }

        public void ChangePassword(CSEntry csentry, SecureString oldPassword, SecureString newPassword)
        {

        }

        public void SetPassword(CSEntry csentry, SecureString newPassword, PasswordOptions options)
        {
            log.Info("Setting password for " + csentry.DN);
            var usrQuery = gsvc.Users.Get(csentry.DN.ToString());
            var res = usrQuery.Execute();

            res.Password = ConvertToUnsecureString(newPassword);
            log.Debug(newPassword);
            var updateOp = gsvc.Users.Update(res, csentry.DN.ToString());
            log.Info("Writing to google...");
            var updateres = updateOp.Execute();
        }
        #endregion
    };
}
