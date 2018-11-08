# afVmPowerMonitor
azure function to monitor virtual machine power states and deallocate after specified amount of time
# Create Azure Function to monitor and deallocate virtual machine resources

#### This template deploys the following resources:
- .net framework azure function v2
- storage account v2

#### Required
- an existing or new azure client id and secret for function authentication  
  * client id and secret are an azure service principal name which is required for any application authenticating to azure in a non-interactive environment. there are multiple ways to create azure id and secret. one way is to copy the command below into admin powershell prompt and execute to create client id and secret. this will generate a self signed certificate on the local machine from where it is run. the certificate thumbprint will be used when creating the azure spn.
  * use the client id and secret output values from script when deploying template.
```powershell
iwr "https://raw.githubusercontent.com/jagilber/powershellScripts/master/azure-rm-create-aad-application-spn.ps1"| iex
```  
#### Optional
- sendgrid api key for email notifications  
  NOTE: sendgrid account is free for 100 emails / day  
  [sendgrid signup](https://signup.sendgrid.com/)



#### Click the button below to deploy

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjagilber%2FafVmPowerMonitor%2Fmaster%2FafVmPowerMonitor%2FafVmPowerMonitor.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fjagilber%2FafVmPowerMonitor%2Fmaster%2FafVmPowerMonitor%2FafVmPowerMonitor.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>