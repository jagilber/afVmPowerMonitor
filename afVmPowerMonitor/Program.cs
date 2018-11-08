using Microsoft.Azure.Management.Compute;
using Microsoft.Azure.Management.ResourceManager;
using Microsoft.Azure.Management.ResourceManager.Models;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure.Authentication;
using Microsoft.WindowsAzure.Management.Compute;
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
        private static TraceWriter _log;
        private string _apiVersion;
        private string _baseUri = "https://management.azure.com";
        private string _clientId;
        private int _consecutivePoweredOnActionCount;
        private int _consecutivePoweredOnEmailCount;
        private int _executionCount;
        private string _fromEmail;
        private string _functionJsonStorageContainer;
        private string _graphToken;
        private string _kustoApiVersion;
        private string _message;
        private StringBuilder _msgBuilder = new StringBuilder();
        private ResourceManagementClient _resourceClient;
        private List<MonitoredResource> _monitoredResources = new List<MonitoredResource>();
        private string _secret;
        private string _sendGridApiKey;
        private string _subscriptionId;
        private string _tenantId;
        private string _toEmail;
        private string _token;
        private string _virtualMachineApiVersion;
        private string _webJobsStorage;

        public Program(TraceWriter log)
        {
            //https://docs.microsoft.com/en-us/rest/api/
            _log = log;
            _log.Info($"Program instance .ctor: {DateTime.Now}");
            _tenantId = Environment.GetEnvironmentVariable("AzureTenantId");
            _clientId = Environment.GetEnvironmentVariable("AzureClientId");
            _secret = Environment.GetEnvironmentVariable("AzureSecret");
            _subscriptionId = Environment.GetEnvironmentVariable("AzureSubscriptionId");
            _kustoApiVersion = Environment.GetEnvironmentVariable("KustoApiVersion");
            _apiVersion = Environment.GetEnvironmentVariable("ApiVersion");
            _virtualMachineApiVersion = Environment.GetEnvironmentVariable("VirtualMachineApiVersion");
            _fromEmail = Environment.GetEnvironmentVariable("fromEmail");
            _toEmail = Environment.GetEnvironmentVariable("toEmail");
            _message = Environment.GetEnvironmentVariable("message");
            _sendGridApiKey = Environment.GetEnvironmentVariable("sendGridApiKey");
            _consecutivePoweredOnEmailCount = Convert.ToInt32(Environment.GetEnvironmentVariable("ConsecutivePoweredOnEmailCount"));
            _consecutivePoweredOnActionCount = Convert.ToInt32(Environment.GetEnvironmentVariable("ConsecutivePoweredOnActionCount"));
            //UseDevelopmentStorage=true
            _webJobsStorage = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
            _functionJsonStorageContainer = Environment.GetEnvironmentVariable("FunctionJsonStorageContainer");

            if (new List<string> { _tenantId, _clientId, _secret, _subscriptionId }.Any(i => String.IsNullOrEmpty(i)))
            {
                _log.Error("Please provide ENV vars for AzureTenantId, AzureClientId, AzureSecret and AzureSubscriptionId.");
                return;
            }
        }

        public void Execute()
        {
            _log.Info($"Execute:{++_executionCount}:\r\n\t{_tenantId}\r\n\t{_clientId}\r\n\t{_secret}\r\n\t{_subscriptionId}");
            //_monitoredResources.Clear();
            // Build the service credentials and Azure Resource Manager clients
            Microsoft.Rest.ServiceClientCredentials serviceCreds = ApplicationTokenProvider.LoginSilentAsync(_tenantId, _clientId, _secret).Result;
            _resourceClient = new ResourceManagementClient(serviceCreds);
            _resourceClient.SubscriptionId = _subscriptionId;
            GetAccessToken();

            // load prior results
            if (_monitoredResources.Count < 1)
            {
                MonitoredResourcesResult result = LoadResultsFromJson("all.json");

                if (result.monitoredResources != null)
                {
                    _monitoredResources.AddRange(result.monitoredResources);
                }
            }

            SyncResources();

            _log.Info("Listing resource groups:");
            _resourceClient.ResourceGroups.List().ToList().ForEach(rg =>
            {
                _log.Info(string.Format("\tName: {0}, Id: {1}", rg.Name, rg.Id));
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

        private void AddOrUpdateResource(MonitoredResource resource)
        {
            if (resource.FirstDiscovered == DateTime.MinValue)
            {
                resource.FirstDiscovered = DateTime.Now;
            }

            if (resource.TotalDiscoveries == 0)
            {
                resource.TotalDiscoveries++;
            }

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

            GetCurrentResources()
                .Where(x => x.Id.Contains("Microsoft.Kusto"))
                .Where(x => !x.Id.Contains("databases"))
                .ToList()
                .ForEach(res =>
                {
                    _log.Warning(string.Format("Kusto cluster \tName: {0}, Id: {1}", res.Name, res.Id));
                    kustoClusterIds.Add(res.Id);
                });

            foreach (string cluster in kustoClusterIds)
            {
                GenericResource clusterResource = _resourceClient.Resources.GetById(cluster, _kustoApiVersion);
                _log.Info(JsonConvert.SerializeObject(clusterResource, Formatting.Indented));
            }

            string response = GET("providers/Microsoft.Kusto/clusters", null, _kustoApiVersion);

            if (string.IsNullOrEmpty(response))
            {
                _log.Error("CheckKustoPowerStates:ERROR:null response");
                return false;
            }

            KustoClusterResults[] clusterResults = JsonConvert.DeserializeObject<KustoClusterResults[]>(JObject.Parse(response)["value"].ToString());

            _log.Info($"{JsonConvert.SerializeObject(clusterResults, Formatting.Indented)}");

            while (true)
            {
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

            _log.Info($"kusto cluster results count: {allResults.Count}");

            // check properties/state to see if stopped or started
            foreach (KustoClusterResults result in allResults)
            {
                MonitoredResource mresource = new MonitoredResource(new GenericResource(result.id, result.name, result.type));

                if (!result.properties.state.Contains("Stopped"))
                {
                    MonitoredResource resource = UpdateResourcePoweredOn(mresource);

                    if (resource.SendEmail)
                    {
                        kustoRunningResults.Add(resource);
                    }

                    if (resource.ExecuteAction)
                    {
                        // send post to turn off cluster
                        string aresult = POST($"{_baseUri}{resource.Id}/stop", null, _kustoApiVersion);
                    }

                    _log.Warning($"running kusto cluster {result}");
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

                    _msgBuilder.AppendLine($"<p>{result.Name}{action}</p>");
                }

                _log.Warning($"{_msgBuilder.ToString()}");
            }
            else
            {
                _log.Info("there are *no* running kusto clusters in subscription");
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

            if (string.IsNullOrEmpty(response))
            {
                _log.Error("CheckVmPowerStates:ERROR:null response");
                return false;
            }

            while (true)
            {
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

            _log.Info($"vm results count: {allResults.Count}");

            foreach (VMResults result in allResults)
            {
                response = GET($"{_baseUri}{result.id}/instanceView?api-version={_virtualMachineApiVersion}");
                VMInstanceResults instance = JsonConvert.DeserializeObject<VMInstanceResults>(response);
                MonitoredResource mresource = new MonitoredResource(new GenericResource(result.id, result.name, result.type));

                if (instance.statuses.Count(x => x.code.Contains("running")) > 0)
                {
                    MonitoredResource r = UpdateResourcePoweredOn(mresource);

                    if (r.SendEmail)
                    {
                        vmRunningResults.Add(r);
                    }

                    if (r.ExecuteAction)
                    {
                        // send post to turn off vm
                        string aresult = POST($"{_baseUri}{result.id}/deallocate", null, _virtualMachineApiVersion);
                    }
                }
                else
                {
                    UpdateResourcePoweredOff(mresource);
                }

                _log.Info($"vm instance view: {JsonConvert.SerializeObject(instance, Formatting.Indented)}");
            }

            if (vmRunningResults.Count > 0)
            {
                _msgBuilder.AppendLine($"<b>there are running vm's in subscription</b>");
                retval = true;

                foreach (MonitoredResource result in vmRunningResults)
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

                    _msgBuilder.AppendLine($"<p>{result.Name}{action}</p>");
                }

                _log.Warning($"{_msgBuilder.ToString()}");
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
                string instanceResponse = GET(instanceUri);
                VmssVMInstanceResults vmInstance = JsonConvert.DeserializeObject<VmssVMInstanceResults>(instanceResponse);
                vmInstance.id = instanceUri.AbsolutePath;

                _log.Info($"vm instance view: {JsonConvert.SerializeObject(vmInstance, Formatting.Indented)}");
                MonitoredResource mresource = new MonitoredResource(new GenericResource(result.id, result.name, result.type));

                string pattern = @".+/(\d+)$";
                if (Regex.IsMatch(result.id, pattern))
                {
                    mresource.InstanceId = Convert.ToInt32(Regex.Match(result.id, pattern).Groups[1].Value);
                }

                if (vmInstance.statuses.Count(x => x.code.Contains("running")) > 0)
                {
                    MonitoredResource r = UpdateResourcePoweredOn(mresource);

                    if (r.SendEmail)
                    {
                        vmssRunningResults.Add(r);
                    }

                    if (r.ExecuteAction)
                    {
                        // send post to turn off vm
                        // POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/virtualmachines/{instanceId}/deallocate?api-version=2017-12-01
                        string aresult = POST($"{_baseUri}{result.id}/deallocate", null, _virtualMachineApiVersion);
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

                    _msgBuilder.AppendLine($"<p>resource: {result.Id}</p>");
                    _msgBuilder.AppendLine($"<p>instance: {result.InstanceId}{action}</p>");
                }

                _log.Warning(_msgBuilder.ToString());
            }

            return retval;
        }

        private string GETASM(Uri uri)
        {
            _log.Info($"GET:{uri.ToString()}");
            // Create the request
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers.Add("x-ms-version", "2014-05-01");
            request.ContentType = "*/*";
            request.Method = "GET";

            // Get the response
            HttpWebResponse response = null;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (Exception ex)
            {
                _log.Error("Error from : " + uri + ": " + ex.Message);
                return null;
            }

            string result = null;
            using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            return result;
        }

        private string GET(Uri uri)
        {
            _log.Info($"GET:{uri.ToString()}");
            // Create the request
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + _token);
            request.ContentType = "application/json";
            request.Method = "GET";

            // Get the response
            HttpWebResponse response = null;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (Exception ex)
            {
                _log.Error("Error from : " + uri + ": " + ex.Message);
                return null;
            }

            string result = null;
            using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
            }

            return result;
        }

        private string GET(string uriString)
        {
            Uri uri = new Uri(string.Format(uriString));
            return GET(uri);
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

        private string GetAccessToken()
        {
            string authContextURL = "https://login.windows.net/" + _tenantId;
            AuthenticationContext authenticationContext = new AuthenticationContext(authContextURL);
            ClientCredential credential = new ClientCredential(clientId: _clientId, clientSecret: _secret);
            AuthenticationResult result = authenticationContext.AcquireToken(resource: "https://management.azure.com/", clientCredential: credential);

            if (result == null)
            {
                _log.Error("failed to obtain JWT token");
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            _token = result.AccessToken;
            _log.Info($"token:{_token}");

            return _token;
        }

        private string GetGraphAccessToken()
        {
            string authContextURL = "https://login.microsoftonline.com/" + _tenantId + "/oauth2";
            //string authContextURL = "https://login.windows.net/" + _tenantId;
            AuthenticationContext authenticationContext = new AuthenticationContext(authContextURL);
            ClientCredential credential = new ClientCredential(clientId: _clientId, clientSecret: _secret);
            AuthenticationResult graphResult = authenticationContext.AcquireToken(resource: "https://graph.microsoft.com/", clientCredential: credential);

            _graphToken = graphResult.AccessToken;
            _log.Info($"graph token:{_graphToken}");
            return _graphToken;
        }

        private MonitoredResource GetMonitoredResource(MonitoredResource resource, bool create = true)
        {
            MonitoredResource realResource = _monitoredResources.FirstOrDefault(x => string.Compare(x.Id, resource.Id, true) == 0
                & x.InstanceId == resource.InstanceId
                & string.Compare(x.Name, resource.Name, true) == 0
                & string.Compare(x.Type, resource.Type, true) == 0);

            if (create && realResource == null)
            {
                AddOrUpdateResource(resource);
                return GetMonitoredResource(resource, false);
            }

            return realResource;
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

        private CloudBlockBlob GetStorageBlobReference(string file, string containerName, bool create = false)
        {
            //gpv2 static web site
            //https://jagilbergpv2website.z13.web.core.windows.net/
            //https://sfkustofunc8a91.file.core.windows.net/sfkustofunc8a91/site/wwwroot/host.json
            //https://jagilbergpv2website.blob.core.windows.net/$web/running.json
            //text = $"{{\r\n\"lastRun\": \"{DateTime.Now}\",\r\n\"list\": {text}\r\n}}";

            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(_webJobsStorage);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
            CloudBlobContainer container = blobClient.GetContainerReference(containerName);

            if (blobClient.ListContainers(containerName, ContainerListingDetails.None, null, null).Count() < 1)
            {
                if (create)
                {
                    container.Create(null, null);
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
                _log.Error("CheckVmssPowerStates:ERROR:null response");
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

            _log.Info($"vmss results count: {allResults.Count}");
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
                    _log.Error("CheckVmssPowerStates:ERROR:null response");
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

            _log.Info($"vmss vm results count: {vmssVmResults.Count}");
            return vmssVmResults;
        }
        private MonitoredResourcesResult LoadResultsFromJson(string file, bool clean = true)
        {
            MonitoredResourcesResult result = new MonitoredResourcesResult();

            try
            {
                if (!string.IsNullOrEmpty(_functionJsonStorageContainer))
                {
                    string text = GetStorageBlobReference(file, _functionJsonStorageContainer, false).DownloadText();

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
                    _log.Info("loadresultsfromjson:json storage not configured");
                    return result;
                }
            }
            catch (Exception e)
            {
                _log.Warning($"unable to read results from json {e.ToString()}");
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
                _log.Info("Error setting up stream writer: " + ex.Message);
            }

            // Get the response
            HttpWebResponse response = null;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                _log.Info($"POST: response:{JsonConvert.SerializeObject(response, Formatting.Indented)}");
            }
            catch (Exception ex)
            {
                _log.Info("Error from : " + uri + ": " + ex.Message);
                return null;
            }

            string result = null;
            using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            {
                result = streamReader.ReadToEnd();
                _log.Info($"POST: result:{JsonConvert.SerializeObject(result, Formatting.Indented)}");
            }

            return result;
        }
        private void SaveResultsToJson(string file, MonitoredResourcesResult monitoredResourcesResult, bool clean = true)
        {
            string text = JsonConvert.SerializeObject(monitoredResourcesResult, Formatting.Indented);

            if (clean)
            {
                text = text.Replace(_subscriptionId, "<subscription Id>");
                text = text.Replace(_tenantId, "<tenant Id>");
                text = Regex.Replace(text, "[0-9A-F-a-f]{8}-[0-9A-F-a-f]{4}-[0-9A-F-a-f]{4}-[0-9A-F-a-f]{4}-[0-9A-F-a-f]{12}", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
            }

            SaveResultsToJson(file, text);
        }

        private void SaveResultsToJson(string file, string text)
        {
            if (!string.IsNullOrEmpty(_functionJsonStorageContainer))
            {
                CloudBlockBlob blockBlob = GetStorageBlobReference(file, _functionJsonStorageContainer, true);
                blockBlob.UploadText(text);

                // Set the content type
                blockBlob.FetchAttributes();
                blockBlob.Properties.ContentType = "application/json";

                blockBlob.SetProperties();
            }
            else
            {
                _log.Info("SaveResultsToJson: json storage not configured");
            }
        }

        private void SendGraphEmail()
        {
            // ms internal employees do not have authorization to setup application or delegated user access read or send mail rights in graph
            throw new NotImplementedException();
            /*
            //string graphSendMailUri = "https://graph.microsoft.com/v1.0/me/sendMail";
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
            _log.Info($"send mail info:{smtpPostBodyString}");
            string response = POST(graphSendMailUri, smtpPostBodyString, _graphToken);
            _log.Info($"sendGraphEmailRESTResponse: {response}");

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
                _log.Info("sendgridemail:not configured");
                return false;
            }

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

            _log.Info($"sendgrid response: {JsonConvert.SerializeObject(response, Formatting.Indented)}");
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
                if (currentResources.Any(x => x.Id == resource.Id & x.Name == resource.Name & x.Type == resource.Type && x.InstanceId == resource.InstanceId))
                {
                    GetMonitoredResource(resource).LastSeen = DateTime.Now;
                }
                else
                {
                    UpdateResourcePoweredOff(resource);
                }

            }
        }

        private void UpdateResourcePoweredOff(MonitoredResource resource)
        {
            MonitoredResource r = GetMonitoredResource(resource);
            r.CurrentlyPoweredOn = false;
            r.LastSeen = DateTime.Now;
            r.TotalDiscoveries++;
            r.ConsecutivePoweredOn = 0;
            r.SendEmail = false;
            r.ExecuteAction = false;

            AddOrUpdateResource(r);
        }

        private MonitoredResource UpdateResourcePoweredOn(MonitoredResource resource)
        {
            MonitoredResource r = GetMonitoredResource(resource);
            _log.Info($"UpdateResourcePoweredOn:{JsonConvert.SerializeObject(r, Formatting.Indented)}");
            bool wasPoweredOn = r.CurrentlyPoweredOn;
            r.CurrentlyPoweredOn = true;
            r.LastSeen = DateTime.Now;
            r.LastSeenPoweredOn = DateTime.Now;
            r.TotalDiscoveries++;
            r.TotalPoweredOn++;

            if (wasPoweredOn)
            {
                r.ConsecutivePoweredOn++;
            }
            else
            {
                r.ConsecutivePoweredOn = 1;
            }

            if (r.ConsecutivePoweredOn >= _consecutivePoweredOnEmailCount)
            {
                r.LastEmailSent = DateTime.Now;
                r.SendEmail = true;
                _log.Warning($"resource powered on. sending email:\r\n{JsonConvert.SerializeObject(r, Formatting.Indented)}");
            }

            if (r.ConsecutivePoweredOn >= _consecutivePoweredOnActionCount)
            {
                r.LastActionExecuted = DateTime.Now;
                r.ExecuteAction = true;
                _log.Warning($"resource powered on. executing action:\r\n{JsonConvert.SerializeObject(r, Formatting.Indented)}");
            }

            AddOrUpdateResource(r);
            return r;
        }
    }
}