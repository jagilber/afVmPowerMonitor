// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Microsoft.Azure.Management.ResourceManager.Models;
using System;
using System.Collections.Generic;

namespace afVmPowerMonitor
{
    public class MonitoredResource : GenericResource, IComparable<MonitoredResource>, IEqualityComparer<MonitoredResource>
    {
        public int ConsecutivePoweredOn { get; set; }

        public bool CurrentlyMonitored { get; set; }

        public bool CurrentlyPoweredOn { get; set; }

        public bool ExecuteAction { get; internal set; }

        public DateTime FirstDiscovered { get; set; }

        public int InstanceId { get; set; }

        public DateTime LastActionExecuted { get; set; }

        public DateTime LastEmailSent { get; set; }

        public DateTime LastSeen { get; set; }

        public DateTime LastSeenPoweredOn { get; set; }

        public int ResourceHash { get; private set; }

        public bool SendEmail { get; internal set; }

        public int TotalDiscoveries { get; set; }

        public int TotalPoweredOn { get; set; }

        public MonitoredResource(GenericResource resource) : base(resource.Id,
                    resource.Name,
                    resource.Type,
                    resource.Location,
                    resource.Tags,
                    resource.Plan,
                    resource.Properties,
                    resource.Kind,
                    resource.ManagedBy,
                    resource.Sku,
                    resource.Identity)
        {
            ResourceHash = resource.Id.GetHashCode();
        }

        public int CompareTo(MonitoredResource other)
        {
            return Convert.ToInt32(!Equals(this, other));
        }

        public bool Equals(MonitoredResource x, MonitoredResource y)
        {
            return x.Id == y.Id
               & x.InstanceId == y.InstanceId
               & x.Name == y.Name
               & x.Type == y.Type;
        }

        public int GetHashCode(MonitoredResource obj)
        {
            return obj == null ? 0 : obj.GetHashCode();
        }
    }
}