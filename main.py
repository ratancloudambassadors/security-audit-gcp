import os
import json
from flask import Request, jsonify
from googleapiclient import discovery
from google.oauth2 import service_account
import google.auth

PROJECT = os.environ.get("GCP_PROJECT")

# Use default credentials in Cloud Functions
credentials, _ = google.auth.default()

def list_compute_instances():
    compute = discovery.build('compute', 'v1', credentials=credentials, cache_discovery=False)
    zones_req = compute.zones().list(project=PROJECT)
    zones = []
    try:
        while zones_req is not None:
            zones_resp = zones_req.execute()
            for z in zones_resp.get('items', []):
                zones.append(z['name'])
            zones_req = compute.zones().list_next(previous_request=zones_req, previous_response=zones_resp)
    except Exception:
        pass

    instances = []
    for zone in zones:
        try:
            resp = compute.instances().list(project=PROJECT, zone=zone).execute()
            for inst in resp.get('items', []):
                instances.append({
                    "name": inst.get("name"),
                    "zone": zone,
                    "networkInterfaces": inst.get("networkInterfaces", [])
                })
        except Exception:
            continue
    return instances

def list_gke_clusters():
    try:
        container = discovery.build('container', 'v1', credentials=credentials, cache_discovery=False)
        resp = container.projects().zones().clusters().list(projectId=PROJECT, zone='-').execute()
        clusters = resp.get('clusters', []) if resp else []
        return clusters
    except Exception:
        return []

def list_sql_instances():
    try:
        sqladmin = discovery.build('sqladmin', 'v1beta4', credentials=credentials, cache_discovery=False)
        resp = sqladmin.instances().list(project=PROJECT).execute()
        return resp.get('items', [])
    except Exception:
        return []

def list_buckets():
    try:
        storage = discovery.build('storage', 'v1', credentials=credentials, cache_discovery=False)
        resp = storage.buckets().list(project=PROJECT).execute()
        return resp.get('items', [])
    except Exception:
        return []

def audit_handler(request: Request):
    findings = {}

    # Compute
    instances = list_compute_instances()
    # find public external IPs
    public_vms = []
    for i in instances:
        for ni in i.get("networkInterfaces", []):
            for ac in ni.get("accessConfigs", []) if ni.get("accessConfigs") else []:
                if ac.get("natIP"):
                    public_vms.append({"name": i.get("name"), "ip": ac.get("natIP")})
    findings['public_vms'] = public_vms
    findings['compute_instances_total'] = len(instances)

    # GKE
    clusters = list_gke_clusters()
    # check nodes with public IPs is more involved — you can extend to call GKE API / compute API
    findings['gke_clusters'] = [{"name": c.get("name"), "endpoint": c.get("endpoint")} for c in clusters]

    # Cloud SQL
    sqls = list_sql_instances()
    public_sqls = [s for s in sqls if s.get("ipAddresses")]
    findings['cloud_sql_total'] = len(sqls)
    findings['cloud_sql_with_ips'] = len(public_sqls)

    # Buckets
    buckets = list_buckets()
    public_buckets = []
    for b in buckets:
        # naive check for "allUsers" in IAM will require separate call, here we fetch ACL (cheap)
        if 'iamConfiguration' in b and b['iamConfiguration'].get('publicAccessPrevention') == 'unspecified':
            # not definitive — suggest using storage.buckets.getIamPolicy
            public_buckets.append(b.get('name'))
    findings['buckets_total'] = len(buckets)
    findings['buckets_suspected_public'] = public_buckets

    # TODO: check service accounts with owner role (use cloudresourcemanager or iam)
    # TODO: check bucket IAMs for allUsers/allAuthenticatedUsers
    # TODO: check firewall rules allowing 0.0.0.0/0 to sensitive ports

    return jsonify({"project": PROJECT, "findings": findings})
