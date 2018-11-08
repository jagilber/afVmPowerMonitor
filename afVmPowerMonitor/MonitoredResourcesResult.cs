using System;

namespace afVmPowerMonitor
{
    class MonitoredResourcesResult
    {
        public DateTime lastRun = DateTime.Now;
        public MonitoredResource[] monitoredResources;

        public MonitoredResourcesResult() //: this(new MonitoredResource[0])
        {
        }
        public MonitoredResourcesResult(MonitoredResource[] resources)
        {
            monitoredResources = resources;
        }

    }
}
