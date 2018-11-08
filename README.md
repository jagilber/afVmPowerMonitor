# afVmPowerMonitor
azure function to monitor virtual machine power states and deallocate after specified amount of time
# Create Azure Function to monitor and deallocate virtual machine resources

#### This template deploys the following resources:
- .net framework azure function v2
- storage account v2

#### Required
- azure client id and secret for function authentication  
```ps
pwsh
(new-object net.webclient).downloadfile("https://raw.githubusercontent.com/jagilber/powershellScripts/master/azure-rm-create-aad-application-spn.ps1","$(get-location)/azure-rm-create-aad-application-spn.ps1");
azure-rm-create-aad-application-spn.ps1 -logontype certthumb

```
    [azure cloud shell](https://shell.azure.com/)


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