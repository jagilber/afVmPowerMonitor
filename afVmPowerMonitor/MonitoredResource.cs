﻿// ------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
// Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Microsoft.Azure.Management.ResourceManager.Models;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace afVmPowerMonitor
{
    public class MonitoredResource : GenericResource, IComparable<MonitoredResource>, IEqualityComparer<MonitoredResource>
    {
        private string _resourceHash = string.Empty;

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

        public string ResourceHash
        {
            get
            {
                if (string.IsNullOrEmpty(_resourceHash))
                {
                    using (MD5 md5 = MD5.Create())
                    {
                        byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(Id.ToLower() + InstanceId.ToString()));
                        StringBuilder sBuilder = new StringBuilder();

                        for (int i = 0; i < data.Length; i++)
                        {
                            sBuilder.Append(data[i].ToString("x2"));
                        }

                        _resourceHash = sBuilder.ToString();
                    }
                }

                return _resourceHash;
            }
            set
            {
                if (_resourceHash != value)
                {
                    _resourceHash = value;
                }
            }
        }

        public bool SendEmail { get; internal set; }

        public int TotalDiscoveries { get; set; }

        public int TotalPoweredOn { get; set; }

        public MonitoredResource()
        //: this ( new GenericResource())
        {
        }

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