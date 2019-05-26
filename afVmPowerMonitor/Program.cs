// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Microsoft.Azure.Management.Compute;
using Microsoft.Azure.Management.ResourceManager;
using Microsoft.Azure.Management.ResourceManager.Models;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure.Authentication;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace afVmPowerMonitor
{
    internal class Program
    {
        private static ILogger _log;
        private string _apiVersion = "2016-09-01";
        private string _baseUri = "https://management.azure.com";
        private string _clientId;
        private int _consecutivePoweredOnActionCount;
        private int _consecutivePoweredOnEmailCount;
        private int _executionCount;
        private string _fromEmail;
        private string _functionJsonStorageContainer;
        private string _graphToken;
        private string _kustoApiVersion = "2018-09-07-preview";
        private string _kustoExcludeFilter;
        private string _kustoIncludeFilter;
        private List<MonitoredResource> _monitoredResources = new List<MonitoredResource>();
        private StringBuilder _msgBuilder = new StringBuilder();
        private ResourceManagementClient _resourceClient;
        private string _secret;
        private string _sendGridApiKey;
        private string _subscriptionId;
        private string _tenantId;
        private string _toEmail;
        private string _token;
        private string _virtualMachineApiVersion = "2017-12-01";
        private string _vmExcludeFilter;
        private string _vmIncludeFilter;
        private string _vmssExcludeFilter;
        private string _vmssIncludeFilter;
        private string _webJobsStorage;

        public Program(ILogger log)
        {
            //https://docs.microsoft.com/en-us/rest/api/
            _log = log;
            _log.LogInformation($"Program instance .ctor: {DateTime.Now}");
            _tenantId = Environment.GetEnvironmentVariable("AzureTenantId");
            _clientId = Environment.GetEnvironmentVariable("AzureClientId");
            _secret = Environment.GetEnvironmentVariable("AzureSecret");
            _subscriptionId = Environment.GetEnvironmentVariable("AzureSubscriptionId");
            _fromEmail = Environment.GetEnvironmentVariable("FromEmail");
            _toEmail = Environment.GetEnvironmentVariable("ToEmail");
            _sendGridApiKey = Environment.GetEnvironmentVariable("SendgridApiKey");
            _consecutivePoweredOnEmailCount = Convert.ToInt32(Environment.GetEnvironmentVariable("ConsecutivePoweredOnEmailCount"));
            _consecutivePoweredOnActionCount = Convert.ToInt32(Environment.GetEnvironmentVariable("ConsecutivePoweredOnActionCount"));
            _webJobsStorage = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
            _functionJsonStorageContainer = Environment.GetEnvironmentVariable("FunctionJsonStorageContainer");

            _kustoIncludeFilter = Environment.GetEnvironmentVariable("KustoIncludeFilter");
            _kustoExcludeFilter = Environment.GetEnvironmentVariable("KustoExcludeFilter");
            _vmIncludeFilter = Environment.GetEnvironmentVariable("VmIncludeFilter");
            _vmExcludeFilter = Environment.GetEnvironmentVariable("VmExcludeFilter");
            _vmssIncludeFilter = Environment.GetEnvironmentVariable("VmssIncludeFilter");
            _vmssExcludeFilter = Environment.GetEnvironmentVariable("VmssExcludeFilter");

            if (new List<string> { _tenantId, _clientId, _secret, _subscriptionId }.Any(i => String.IsNullOrEmpty(i)))
            {
                _log.LogError("Please provide ENV vars for AzureTenantId, AzureClientId, AzureSecret and AzureSubscriptionId.");
                return;
            }
        }

        public void Execute()
        {
            _log.LogInformation($"Execute:{++_executionCount}:\r\n\t{_tenantId}\r\n\t{_clientId}\r\n\t{_secret}\r\n\t{_subscriptionId}");
            //_monitoredResources.Clear();

            Microsoft.Rest.ServiceClientCredentials serviceCreds = ApplicationTokenProvider.LoginSilentAsync(_tenantId, _clientId, _secret).Result;
            _resourceClient = new ResourceManagementClient(serviceCreds);
            _resourceClient.SubscriptionId = _subscriptionId;
            GetAccessToken();

            // load prior results if collection empty
            if (_monitoredResources.Count < 1)
            {
                MonitoredResourcesResult result = LoadResultsFromJson("all.json");

                if (result.monitoredResources != null)
                {
                    _monitoredResources.AddRange(result.monitoredResources);
                }
            }

            SyncResources();

            _log.LogInformation("Listing resource groups:");
            _resourceClient.ResourceGroups.List().ToList().ForEach(rg =>
            {
                _log.LogInformation(string.Format("\tName: {0}, Id: {1}", rg.Name, rg.Id));
            });

            CheckVmPowerStates();
            CheckVmssPowerStates();
            CheckKustoPowerStates();

            SaveResultsToJson("running.json", new MonitoredResourcesResult(_monitoredResources.Where(x => x.CurrentlyPoweredOn == true).ToArray()));
            SaveResultsToJson("all.json", new MonitoredResourcesResult(_monitoredResources.ToArray()));

            if (_msgBuilder.Length > 0)
            {
                SendGridEmail($"{_monitoredResources.Count(x => x.CurrentlyPoweredOn == true)} running resources in your subscription", _msgBuilder.ToString());
                _msgBuilder.Clear();
            }
        }

        private static string BuildMessage(MonitoredResource result)
        {
            string action = ": none";
            if (result.SendEmail)
            {
                result.SendEmail = false;
                action = $": executed email action:{result.LastEmailSent}";
            }

            if (result.ExecuteAction)
            {
                result.ExecuteAction = false;
                action = $": executed power action:{result.LastActionExecuted}";
            }

            return action;
        }

        private static string GetResponse(HttpWebRequest request)
        {
            HttpWebResponse response = null;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                _log.LogInformation($"WEB: response:{JsonConvert.SerializeObject(response, Formatting.Indented)}");
            }
            catch (Exception ex)
            {
                _log.LogError("WEB: response: error from: " + request.RequestUri + ": " + ex.Message);
                return null;
            }

            string result = null;
            using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
                _log.LogInformation($"WEB: result:{JsonConvert.SerializeObject(result, Formatting.Indented)}");
            }

            return result;
        }

        private void AddOrUpdateResourceList(MonitoredResource resource)
        {
            if (resource.FirstDiscovered == DateTime.MinValue)
            {
                resource.FirstDiscovered = DateTime.Now;
            }

            resource.TotalDiscoveries++;

            if (_monitoredResources.Contains(resource))
            {
                _monitoredResources.Remove(resource);
            }

            _monitoredResources.Add(resource);
        }

        private bool CheckKustoPowerStates()
        {
            bool retval = false;
            List<KustoClusterResults> allResults = new List<KustoClusterResults>();
            List<MonitoredResource> kustoRunningResults = new List<MonitoredResource>();
            List<string> kustoClusterIds = new List<string>();

            string response = GET("providers/Microsoft.Kusto/clusters", null, _kustoApiVersion);

            while (true)
            {
                if (string.IsNullOrEmpty(response))
                {
                    _log.LogError("CheckKustoPowerStates:ERROR:null response");
                    return false;
                }

                KustoClusterResults[] clusterResults = JsonConvert.DeserializeObject<KustoClusterResults[]>(JObject.Parse(response)["value"].ToString());
                _log.LogInformation($"{JsonConvert.SerializeObject(clusterResults, Formatting.Indented)}");

                allResults.AddRange(clusterResults);

                if (Regex.IsMatch(response, "nextLink"))
                {
                    response = GET(JObject.Parse(response)["nextLink"].ToString());
                }
                else
                {
                    break;
                }
            }

            _log.LogInformation($"kusto cluster results count: {allResults.Count}");

            // check properties/state to see if stopped or started
            foreach (KustoClusterResults result in allResults)
            {
                MonitoredResource mresource = new MonitoredResource(new GenericResource(result.id, result.name, result.type));

                if (!result.properties.state.Contains("Stopped"))
                {
                    MonitoredResource monitoredResource = UpdateResourcePoweredOn(mresource);

                    if (IncludeResource(monitoredResource, _kustoIncludeFilter, _kustoExcludeFilter))
                    {
                        if (monitoredResource.SendEmail)
                        {
                            kustoRunningResults.Add(monitoredResource);
                        }

                        if (monitoredResource.ExecuteAction)
                        {
                            // send post to turn off cluster
                            string aresult = POST($"{_baseUri}{monitoredResource.Id}/stop", null, _kustoApiVersion);
                        }
                    }

                    _log.LogWarning($"running kusto cluster {result}");
                }
                else
                {
                    UpdateResourcePoweredOff(mresource);
                }
            }

            if (kustoRunningResults.Count > 0)
            {
                _msgBuilder.AppendLine($"<b>there are running kusto clusters in subscription</b>");

                retval = true;

                foreach (MonitoredResource result in kustoRunningResults)
                {
                    _msgBuilder.AppendLine($"<p>{result.Name}{BuildMessage(result)}</p>");
                }

                _log.LogWarning($"{_msgBuilder.ToString()}");
            }
            else
            {
                _log.LogInformation("there are *no* running kusto clusters in subscription");
            }

            return retval;
        }

        private bool CheckVmPowerStates()
        {
            //GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2017-12-01
            //GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/instanceView?api-version=2017-12-01
            bool retval = false;
            List<VMResults> allResults = new List<VMResults>();
            List<MonitoredResource> vmRunningResults = new List<MonitoredResource>();

            string response = GET("providers/Microsoft.Compute/virtualMachines", null, _virtualMachineApiVersion);

            while (true)
            {
                if (string.IsNullOrEmpty(response))
                {
                    _log.LogError("CheckVmPowerStates:ERROR:null response");
                    return false;
                }

                allResults.AddRange(JsonConvert.DeserializeObject<VMResults[]>(JObject.Parse(response)["value"].ToString()));

                if (Regex.IsMatch(response, "nextLink"))
                {
                    response = GET(JObject.Parse(response)["nextLink"].ToString());
                }
                else
                {
                    break;
                }
            }

            _log.LogInformation($"vm results count: {allResults.Count}");

            foreach (VMResults result in allResults)
            {
                response = GET($"{_baseUri}{result.id}/instanceView?api-version={_virtualMachineApiVersion}");
                VMInstanceResults instance = JsonConvert.DeserializeObject<VMInstanceResults>(response);
                MonitoredResource mresource = new MonitoredResource(new GenericResource(result.id, result.name, result.type));

                if (instance.statuses.Count(x => x.code.Contains("running")) > 0)
                {
                    MonitoredResource monitoredResource = UpdateResourcePoweredOn(mresource);

                    if (IncludeResource(monitoredResource, _vmIncludeFilter, _vmExcludeFilter))
                    {
                        if (monitoredResource.SendEmail)
                        {
                            vmRunningResults.Add(monitoredResource);
                        }

                        if (monitoredResource.ExecuteAction)
                        {
                            // send post to turn off vm
                            string aresult = POST($"{_baseUri}{result.id}/deallocate", null, _virtualMachineApiVersion);
                        }
                    }
                }
                else
                {
                    UpdateResourcePoweredOff(mresource);
                }

                _log.LogInformation($"vm instance view: {JsonConvert.SerializeObject(instance, Formatting.Indented)}");
            }

            if (vmRunningResults.Count > 0)
            {
                _msgBuilder.AppendLine($"<b>there are running vm's in subscription</b>");
                retval = true;

                foreach (MonitoredResource result in vmRunningResults)
                {
                    _msgBuilder.AppendLine($"<p>{result.Name}{BuildMessage(result)}</p>");
                }

                _log.LogWarning($"{_msgBuilder.ToString()}");
            }

            return retval;
        }

        private bool CheckVmssPowerStates()
        {
            bool retval = false;
            List<VmssResults> allResults = GetVirtualMachineScaleSets();
            List<VMResults> vmssVmResults = GetVmssVmResults(allResults);
            List<MonitoredResource> vmssRunningResults = new List<MonitoredResource>();

            foreach (VMResults result in vmssVmResults)
            {
                //GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/virtualmachines/{instanceId}/instanceView?api-version=2017-12-01
                Uri instanceUri = new Uri($"{_baseUri}{result.id}/instanceView?api-version={_virtualMachineApiVersion}");
                string instanceResponse = GET(instanceUri.ToString());
                VmssVMInstanceResults vmInstance = JsonConvert.DeserializeObject<VmssVMInstanceResults>(instanceResponse);
                vmInstance.id = instanceUri.AbsolutePath;

                _log.LogInformation($"vm instance view: {JsonConvert.SerializeObject(vmInstance, Formatting.Indented)}");
                MonitoredResource mresource = new MonitoredResource(new GenericResource(result.id, result.name, result.type));

                string pattern = @".+/(\d+)$";
                if (Regex.IsMatch(result.id, pattern))
                {
                    mresource.InstanceId = Convert.ToInt32(Regex.Match(result.id, pattern).Groups[1].Value);
                }

                if (vmInstance.statuses.Count(x => x.code.Contains("running")) > 0)
                {
                    MonitoredResource monitoredResource = UpdateResourcePoweredOn(mresource);

                    if (IncludeResource(monitoredResource, _vmssIncludeFilter, _vmssExcludeFilter))
                    {
                        if (monitoredResource.SendEmail)
                        {
                            vmssRunningResults.Add(monitoredResource);
                        }

                        if (monitoredResource.ExecuteAction)
                        {
                            // send post to turn off vm
                            // POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/virtualmachines/{instanceId}/deallocate?api-version=2017-12-01
                            string aresult = POST($"{_baseUri}{result.id}/deallocate", null, _virtualMachineApiVersion);
                        }
                    }
                }
                else
                {
                    UpdateResourcePoweredOff(mresource);
                }
            }

            if (vmssRunningResults.Count > 0)
            {
                retval = true;
                _msgBuilder.AppendLine($"<b>there are running vm scaleset instances in subscription:</b>");
                _msgBuilder.AppendLine();

                foreach (MonitoredResource result in vmssRunningResults)
                {
                    string action = BuildMessage(result);

                    _msgBuilder.AppendLine($"<p>resource: {result.Id}</p>");
                    _msgBuilder.AppendLine($"<p>instance: {result.InstanceId}{action}</p>");
                }

                _log.LogWarning(_msgBuilder.ToString());
            }

            return retval;
        }

        private string GET(string stringUri)
        {
            Uri uri = new Uri(stringUri);
            _log.LogInformation($"GET:{uri.ToString()}");
            // Create the request
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + _token);
            request.ContentType = "application/json";
            request.Method = "GET";
            return GetResponse(request);
        }

        private string GET(string query, string arguments = null, string apiVersion = null)
        {
            if (string.IsNullOrEmpty(apiVersion))
            {
                apiVersion = _apiVersion;
            }

            string URI = _baseUri.TrimEnd('/') + "/subscriptions/" + _subscriptionId + "/" + query.TrimStart('/') + "?api-version=" + apiVersion + arguments;
            return GET(URI);
        }

        private void GetAccessToken()
        {
            string authContextURL = "https://login.windows.net/" + _tenantId;
            AuthenticationContext authenticationContext = new AuthenticationContext(authContextURL);
            ClientCredential credential = new ClientCredential(clientId: _clientId, clientSecret: _secret);
            AuthenticationResult result = authenticationContext.AcquireTokenAsync(resource: "https://management.azure.com/", clientCredential: credential).Result;

            if (result == null)
            {
                _log.LogError("failed to obtain JWT token");
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            _token = result.AccessToken;
            _log.LogInformation($"token:{_token}");
            return;
        }

        private List<MonitoredResource> GetCurrentResources()
        {
            List<MonitoredResource> mResources = new List<MonitoredResource>();

            foreach (GenericResource gResource in _resourceClient.Resources.List().ToList())
            {
                mResources.Add(new MonitoredResource(gResource));

                if (gResource.Type == "Microsoft.Compute/virtualMachineScaleSets")
                {
                    // add instance id resource to list as it is not enumerated by default
                    List<VmssResults> list = new List<VmssResults>();
                    list.Add((new VmssResults() { id = gResource.Id }));
                    List<VMResults> vms = GetVmssVmResults(list);

                    foreach (VMResults result in vms)
                    {
                        MonitoredResource resource = new MonitoredResource(new GenericResource(
                            result.id,
                            result.name,
                            result.type,
                            result.location,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null));

                        resource.InstanceId = Convert.ToInt32(Regex.Replace(result.id, ".+/", ""));
                        mResources.Add(resource);
                    }
                }
            }

            return mResources;
        }

        private string GetGraphAccessToken()
        {
            string authContextURL = "https://login.microsoftonline.com/" + _tenantId + "/oauth2";
            //string authContextURL = "https://login.windows.net/" + _tenantId;
            AuthenticationContext authenticationContext = new AuthenticationContext(authContextURL);
            ClientCredential credential = new ClientCredential(clientId: _clientId, clientSecret: _secret);
            AuthenticationResult graphResult = authenticationContext.AcquireTokenAsync(resource: "https://graph.microsoft.com/", clientCredential: credential).Result;

            _graphToken = graphResult.AccessToken;
            _log.LogInformation($"graph token:{_graphToken}");
            return _graphToken;
        }

        private MonitoredResource GetMonitoredResource(MonitoredResource resource, bool create = true)
        {
            MonitoredResource realResource = _monitoredResources.FirstOrDefault(x => x.ResourceHash.Equals(resource.ResourceHash));

            if (create && realResource == null)
            {
                AddOrUpdateResourceList(resource);
                return GetMonitoredResource(resource, false);
            }

            return realResource;
        }

        private CloudBlockBlob GetStorageBlobReference(string file, string containerName, bool create = false)
        {
            //gpv2 static web site
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(_webJobsStorage);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference(containerName);

            if (blobClient.ListContainersSegmentedAsync(containerName, null).Result.Results.Count() < 1)
            {
                if (create)
                {
                    container.CreateAsync(null, null).Wait();
                }
                else
                {
                    return null;
                }
            }

            CloudBlockBlob blockBlob = container.GetBlockBlobReference(file);
            return blockBlob;
        }

        private List<VmssResults> GetVirtualMachineScaleSets()
        {
            List<VmssResults> allResults = new List<VmssResults>();

            string response = GET("providers/Microsoft.Compute/virtualMachineScaleSets", null, _virtualMachineApiVersion);

            if (string.IsNullOrEmpty(response))
            {
                _log.LogError("CheckVmssPowerStates:ERROR:null response");
                return allResults;
            }

            while (true)
            {
                allResults.AddRange(JsonConvert.DeserializeObject<VmssResults[]>(JObject.Parse(response)["value"].ToString()));

                if (Regex.IsMatch(response, "nextLink"))
                {
                    response = GET(JObject.Parse(response)["nextLink"].ToString());
                }
                else
                {
                    break;
                }
            }

            _log.LogInformation($"vmss results count: {allResults.Count}");
            return allResults;
        }

        private List<VMResults> GetVmssVmResults(List<VmssResults> allResults)
        {
            List<VMResults> vmssVmResults = new List<VMResults>();

            foreach (VmssResults result in allResults)
            {
                //GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{virtualMachineScaleSetName}/virtualMachines?api-version=2017-12-01
                string response = GET($"{_baseUri}{result.id}/VirtualMachines?api-version={_virtualMachineApiVersion}");

                if (string.IsNullOrEmpty(response))
                {
                    _log.LogError("CheckVmssPowerStates:ERROR:null response");
                    return vmssVmResults;
                }

                while (true)
                {
                    vmssVmResults.AddRange(JsonConvert.DeserializeObject<VMResults[]>(JObject.Parse(response)["value"].ToString()));

                    if (Regex.IsMatch(response, "nextLink"))
                    {
                        response = GET(JObject.Parse(response)["nextLink"].ToString());
                    }
                    else
                    {
                        break;
                    }
                }
            }

            _log.LogInformation($"vmss vm results count: {vmssVmResults.Count}");
            return vmssVmResults;
        }

        private bool IncludeResource(MonitoredResource monitoredResource, string includeFilter, string excludeFilter)
        {
            bool include = false;

            if (!string.IsNullOrEmpty(includeFilter) && Regex.IsMatch(monitoredResource.Id, includeFilter, RegexOptions.IgnoreCase))
            {
                include = true;
            }

            if (!string.IsNullOrEmpty(excludeFilter) && Regex.IsMatch(monitoredResource.Id, excludeFilter, RegexOptions.IgnoreCase))
            {
                include = false;
            }

            monitoredResource.CurrentlyMonitored = include;
            _log.LogInformation($"IncludeResource:{monitoredResource.Name} include?:{include}");
            return include;
        }

        private MonitoredResourcesResult LoadResultsFromJson(string file, bool clean = true)
        {
            MonitoredResourcesResult result = new MonitoredResourcesResult();

            try
            {
                if (!string.IsNullOrEmpty(_functionJsonStorageContainer))
                {
                    string text = GetStorageBlobReference(file, _functionJsonStorageContainer, false).DownloadTextAsync().Result;

                    if (clean)
                    {
                        text = text.Replace("<tenant Id>", _tenantId);
                        text = text.Replace("<subscription Id>", _subscriptionId);
                    }

                    result = JsonConvert.DeserializeObject<MonitoredResourcesResult>(text);
                    return result;
                }
                else
                {
                    _log.LogInformation("loadresultsfromjson:json storage not configured");
                    return result;
                }
            }
            catch (Exception e)
            {
                _log.LogWarning($"unable to read results from json {e.ToString()}");
                return result;
            }
        }

        private string POST(string URI, string body, string apiVersion, string contentType = "application/x-www-form-urlencoded") //"application/json")
        {
            if (!string.IsNullOrEmpty(apiVersion))
            {
                URI = URI.TrimEnd('?') + "?api-version=" + apiVersion;
            }

            Uri uri = new Uri(String.Format(URI));

            // Create the request
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + _token);
            request.ContentLength = body == null ? 0 : body.Length;
            request.ContentType = contentType;
            request.Method = "POST";

            try
            {
                using (StreamWriter streamWriter = new StreamWriter(request.GetRequestStream()))
                {
                    streamWriter.Write(body);
                    streamWriter.Flush();
                    streamWriter.Close();
                }
            }
            catch (Exception ex)
            {
                _log.LogInformation("Error setting up stream writer: " + ex.Message);
            }

            return GetResponse(request);
        }

        private void SaveResultsToJson(string file, MonitoredResourcesResult monitoredResourcesResult)
        {
            string text = ScrubResults(JsonConvert.SerializeObject(monitoredResourcesResult, Formatting.Indented));
            SaveResultsToJson(file, text);
        }

        private void SaveResultsToJson(string file, string text)
        {
            if (!string.IsNullOrEmpty(_functionJsonStorageContainer))
            {
                CloudBlockBlob blockBlob = GetStorageBlobReference(file, _functionJsonStorageContainer, true);
                blockBlob.UploadTextAsync(text).Wait();

                // Set the content type
                blockBlob.FetchAttributesAsync().Wait();
                blockBlob.Properties.ContentType = "application/json";
                blockBlob.SetPropertiesAsync().Wait();
            }
            else
            {
                _log.LogInformation("SaveResultsToJson: json storage not configured");
            }
        }

        private string ScrubResults(string text)
        {
            text = text.Replace(_subscriptionId, "<subscription Id>");
            text = text.Replace(_tenantId, "<tenant Id>");
            text = Regex.Replace(text, "[0-9A-F-a-f]{8}-[0-9A-F-a-f]{4}-[0-9A-F-a-f]{4}-[0-9A-F-a-f]{4}-[0-9A-F-a-f]{12}", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
            return text;
        }

        private void SendGraphEmail()
        {
            // ms internal employees do not have authorization to setup application or delegated user access read or send mail rights in graph
            throw new NotImplementedException();
            /*
            //string graphSendMailUri = "https://graph.microsoft.com/v1.0/me/sendMail";A
            string graphSendMailUri = "https://graph.microsoft.com/v1.0/users/bd6e11b9-xxxxxxxxxxxxxxxx/sendMail";

            //string graphSendMailUri = "https://graph.microsoft.com/v1.0/jagilber/sendMail";
            List<SmtpPostBody.Message.ToRecipients> recipients = new List<SmtpPostBody.Message.ToRecipients>();
            recipients.Add(new SmtpPostBody.Message.ToRecipients()
            {
                emailAddress = new SmtpPostBody.Message.ToRecipients.EmailAddress()
                {
                    address = _toEmail
                }
            });

            SmtpPostBody smtpPostBody = new SmtpPostBody();
            smtpPostBody.message.body.content = "vm is having issue";
            smtpPostBody.message.body.contentType = "Text";
            smtpPostBody.message.subject = "azure vm issue";
            smtpPostBody.message.toRecipients = recipients.ToArray();

            string smtpPostBodyString = JsonConvert.SerializeObject(smtpPostBody, Formatting.None);
            _log.LogInformation($"send mail info:{smtpPostBodyString}");
            string response = POST(graphSendMailUri, smtpPostBodyString, _graphToken);
            _log.LogInformation($"sendGraphEmailRESTResponse: {response}");

         //   string smtpPostRestBody = JsonConvert.
         */
        }

        private bool SendGridEmail(string subject, string message)
        {
            // using SendGrid's C# Library
            // https://github.com/sendgrid/sendgrid-csharp
            // https://app.sendgrid.com/settings/api_keys

            if (string.IsNullOrEmpty(_sendGridApiKey) | string.IsNullOrEmpty(_toEmail) | string.IsNullOrEmpty(_fromEmail))
            {
                _log.LogInformation("sendgridemail:not configured");
                return false;
            }

            message = ScrubResults(message);
            SendGridClient client = new SendGridClient(_sendGridApiKey);
            EmailAddress from = new EmailAddress(_fromEmail, null);
            List<EmailAddress> tos = new List<EmailAddress>();

            foreach (string address in _toEmail.Split(';'))
            {
                tos.Add(new EmailAddress(address, null));
            }

            string plainTextContent = message;
            string htmlContent = $"<body>{message}</body>";
            SendGridMessage msg = MailHelper.CreateSingleEmailToMultipleRecipients(from, tos, subject, plainTextContent, htmlContent);
            Response response = client.SendEmailAsync(msg).Result;

            _log.LogInformation($"sendgrid response: {JsonConvert.SerializeObject(response, Formatting.Indented)}");
            return true;
        }

        private void SyncResources()
        {
            List<MonitoredResource> currentResources = GetCurrentResources();

            foreach (MonitoredResource resource in currentResources)
            {
                if (GetMonitoredResource(resource, false) == null)
                {
                    resource.FirstDiscovered = DateTime.Now;
                    _monitoredResources.Add(resource);
                }
            }

            foreach (MonitoredResource resource in new List<MonitoredResource>(_monitoredResources))
            {
                if (currentResources.Any(x => x.ResourceHash.Equals(resource.ResourceHash)))
                {
                    MonitoredResource currentResource = GetMonitoredResource(resource);
                    currentResource.LastSeen = DateTime.Now;
                    AddOrUpdateResourceList(currentResource);
                }
                else
                {
                    UpdateResourcePoweredOff(resource);
                }
            }
        }

        private void UpdateResourcePoweredOff(MonitoredResource resource)
        {
            MonitoredResource monitoredResource = GetMonitoredResource(resource);
            monitoredResource.CurrentlyPoweredOn = false;
            monitoredResource.LastSeen = DateTime.Now;
            monitoredResource.ConsecutivePoweredOn = 0;
            monitoredResource.SendEmail = false;
            monitoredResource.ExecuteAction = false;

            AddOrUpdateResourceList(monitoredResource);
        }

        private MonitoredResource UpdateResourcePoweredOn(MonitoredResource resource)
        {
            MonitoredResource monitoredResource = GetMonitoredResource(resource);
            _log.LogInformation($"UpdateResourcePoweredOn:{JsonConvert.SerializeObject(monitoredResource, Formatting.Indented)}");
            bool wasPoweredOn = monitoredResource.CurrentlyPoweredOn;
            monitoredResource.CurrentlyPoweredOn = true;
            monitoredResource.LastSeen = DateTime.Now;
            monitoredResource.LastSeenPoweredOn = DateTime.Now;
            monitoredResource.TotalPoweredOn++;

            if (wasPoweredOn)
            {
                monitoredResource.ConsecutivePoweredOn++;
            }
            else
            {
                monitoredResource.ConsecutivePoweredOn = 1;
            }

            if (monitoredResource.ConsecutivePoweredOn >= _consecutivePoweredOnEmailCount)
            {
                monitoredResource.LastEmailSent = DateTime.Now;
                monitoredResource.SendEmail = true;
                _log.LogWarning($"resource powered on. sending email:\r\n{JsonConvert.SerializeObject(monitoredResource, Formatting.Indented)}");
            }

            if (monitoredResource.ConsecutivePoweredOn >= _consecutivePoweredOnActionCount)
            {
                monitoredResource.LastActionExecuted = DateTime.Now;
                monitoredResource.ExecuteAction = true;
                _log.LogWarning($"resource powered on. executing action:\r\n{JsonConvert.SerializeObject(monitoredResource, Formatting.Indented)}");
            }

            AddOrUpdateResourceList(monitoredResource);
            return monitoredResource;
        }
    }
}