# afVmPowerMonitor
# c# azure function v2 to monitor and deallocate virtual machine and kusto resources at specified consecutive powered on count

afVmPowerMonitor is an azure function to monitor virtual machine and kusto power states and deallocate after specified amount of time. available are include and exclude filters for different resource types for more granular control. this is useful only for test / repro environments and *not* production.


## this template deploys the following resources:
- .net framework azure function v2 (default free tier F1)
- storage account v2

## required:
- an existing or new azure application client id and secret for function authentication  
  * application client id and secret are an azure AD application and service principal name which is required for any application authenticating to azure in a non-interactive environment. there are multiple ways to create azure id and secret. one way is to copy the command below into admin powershell prompt and execute to create client id and secret. this will generate a self signed certificate on the local machine from where it is run. the certificate thumbprint will be used when creating the azure spn.
  * if needed, use one of the following options to generate a new client id and secret, save output, and use values when deploying template:
    * [create in portal.](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)
    * [create in apps.dev.microsoft.com](https://apps.dev.microsoft.com)
    * use powershell script:
```powershell
iwr "https://raw.githubusercontent.com/jagilber/powershellScripts/master/azure-rm-create-aad-application-spn.ps1"| iex
```  
## optional:
- sendgrid api key for email notifications  .
  NOTE: sendgrid account is free for 100 emails / day  
  [sendgrid signup](https://signup.sendgrid.com/)
- to disable checks for virtual machines, virtual machine scale sets, and / or kusto, remove the corresponding include filters '.' from configuration during deploy or afterwards in application settings.

## optional post deployment:
- enable static website for use in browser or querying json from powershell for example.
- **NOTE: regardless of storage account and blob permissions, enabling this website will allow anonymous read access to the files below that could be considered sensitive information and therefore is *not* recommended!**
  * to enable, after deployment, [in portal](https://portal.azure.com), navigate to storage account, select 'static web sites', 'enable', and 'save'.
  * navigate to url for static web site.
  * there are two .json files
    * running.json
    * all.json

## click button below to deploy

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjagilber%2FafVmPowerMonitor%2Fmaster%2Fazuredeploy.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fjagilber%2FafVmPowerMonitor%2Fmaster%2Fazuredeploy.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>
</p>

![portal template settings](/afVmPowerMonitor/images/portal-template-settings.1.png)

![portal flow](/afVmPowerMonitor/images/portal-flow.1.png)