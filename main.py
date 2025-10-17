# main.py
import os
import json
import time
import traceback
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request, abort
import google.auth
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google.cloud import storage

app = Flask(__name__)

# HTML dashboard template (simple, single-page)
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>GCP Security Audit</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f7f8fb; color: #111;}
    h1 { color: #1a73e8; }
    .summary { margin-bottom: 16px; }
    .card { background: white; padding: 12px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #eee; text-align:left; vertical-align:top; }
    th { background: #1a73e8; color: #fff; }
    .status-pass { color: #0b8043; font-weight: 600; }
    .status-fail { color: #d93025; font-weight: 700; }
    .small { font-size: 0.9em; color: #555; }
    pre { background:#f2f2f7; padding:10px; border-radius:6px; overflow:auto;}
  </style>
</head>
<body>
  <h1>🔒 GCP Security Audit Report</h1>
  <div class="summary card">
    <div><strong>Project:</strong> {{ project }}</div>
    <div><strong>Run Time:</strong> {{ run_time }}</div>
    <div><strong>Checks:</strong> {{ checks_count }}</div>
    <div class="small">Note: results are best-effort using available GCP APIs from the function's service account.</div>
  </div>

  {% for item in results %}
  <div class="card">
    <h3>{{ item.category }} — <span class="{{ 'status-fail' if item.status=='FAIL' else 'status-pass' }}">{{ item.status }}</span></h3>
    <div class="small">{{ item.check }}</div>
    <table>
      <thead><tr><th>Resource / Detail</th><th>Notes</th></tr></thead>
      <tbody>
      {% for r in item.resources %}
        <tr>
          <td><pre>{{ r|tojson(indent=2) }}</pre></td>
          <td>{{ item.notes or '' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endfor %}

  <div class="card">
    <h3>Raw output (JSON)</h3>
    <pre>{{ raw|tojson(indent=2) }}</pre>
  </div>
</body>
</html>
"""

# Helper to mark a check result
def mk_result(category, check, status, resources=None, notes=None):
    return {
        "category": category,
        "check": check,
        "status": status,
        "resources": resources or [],
        "notes": notes or ""
    }

# Initialize clients (will use application default credentials)
credentials, project = google.auth.default()
PROJECT_ID = os.environ.get("GCP_PROJECT", project)
RESULT_BUCKET = os.environ.get("RESULT_BUCKET")  # optional: save results to this GCS bucket

# Create API clients lazily
def get_service(name, version):
    return discovery.build(name, version, credentials=credentials, cache_discovery=False)

# -------------------------
# Individual checks
# -------------------------

def check_sql_public_ips():
    """Cloud SQL instances with public IP addresses"""
    try:
        sql = get_service('sqladmin', 'v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        items = resp.get('items', [])
        public = []
        for inst in items:
            ips = inst.get('ipAddresses', [])
            if ips:
                # if any ip object exists that's not private - treat as public (best-effort)
                public.append({
                    "instance": inst.get('name'),
                    "region": inst.get('region'),
                    "ipAddresses": ips
                })
        status = "FAIL" if public else "PASS"
        return mk_result("Cloud SQL", "SQL Instances with public IPs", status, public)
    except HttpError as e:
        return mk_result("Cloud SQL", "SQL Instances with public IPs", "FAIL", [], notes=f"API error: {e}")
    except Exception as e:
        return mk_result("Cloud SQL", "SQL Instances with public IPs", "FAIL", [], notes=str(e))

def check_gke_public_nodes():
    """GKE clusters with public node IPs or public endpoint (best-effort)"""
    try:
        container = get_service('container', 'v1')
        # use zones().clusters().list with zone='-' to list all clusters (may require permission)
        clusters = []
        try:
            resp = container.projects().zones().clusters().list(projectId=PROJECT_ID, zone='-').execute()
            clusters = resp.get('clusters', []) or []
        except HttpError:
            # try locations().clusters().list for newer API surfaces
            try:
                resp = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
                clusters = resp.get('clusters', []) or []
            except Exception:
                clusters = []

        flagged = []
        for c in clusters:
            name = c.get('name')
            endpoint = c.get('endpoint')  # public endpoint ip
            private_config = c.get('privateClusterConfig')
            node_pools = c.get('nodePools', []) or []
            public_nodes = False
            # If endpoint exists and not private cluster -> flag
            if endpoint and (not private_config):
                public_nodes = True
            # Inspect nodePools for config that may indicate public
            for np in node_pools:
                # node config may include tags/metadata; best-effort: mark clusters with nodePools as potentially public
                # more advanced detection requires inspecting node instances (compute API)
                if np.get('config', {}).get('tags') or np.get('config', {}).get('metadata') is not None:
                    pass
            if public_nodes:
                flagged.append({"cluster": name, "endpoint": endpoint, "privateClusterConfig": bool(private_config)})
        status = "FAIL" if flagged else "PASS"
        return mk_result("GKE", "GKE clusters with public endpoint or public nodes", status, flagged)
    except Exception as e:
        return mk_result("GKE", "GKE clusters with public endpoint or public nodes", "FAIL", [], notes=str(e))

def check_buckets_public():
    """Buckets that grant access to allUsers/allAuthenticatedUsers or have public ACLs"""
    try:
        storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = list(storage_client.list_buckets())
        public = []
        for b in buckets:
            try:
                # Best-effort: check IAM policy for allUsers/allAuthenticatedUsers
                policy = b.get_iam_policy(requested_policy_version=3)
                bindings = policy.bindings
                for bind in bindings:
                    members = bind.get('members', [])
                    if any(m in ('allUsers', 'allAuthenticatedUsers') for m in members):
                        public.append({"bucket": b.name, "role": bind.get('role'), "members": members})
                        break
                # Also check ACLs (legacy) - list blobs ACL is expensive; we check bucket acl
                acl = b.acl
                for entry in acl:
                    if entry['entity'] in ('allUsers', 'allAuthenticatedUsers'):
                        public.append({"bucket": b.name, "acl_entity": entry['entity']})
                        break
            except Exception:
                # ignore per-bucket errors but continue
                continue
        status = "FAIL" if public else "PASS"
        return mk_result("Cloud Storage", "Buckets publicly accessible (IAM or ACL)", status, public)
    except Exception as e:
        return mk_result("Cloud Storage", "Buckets publicly accessible (IAM or ACL)", "FAIL", [], notes=str(e))

def check_service_accounts_with_owner():
    """Service accounts or principals that have roles/owner on project-level bindings"""
    try:
        crm = get_service('cloudresourcemanager', 'v1')
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        bindings = policy.get('bindings', [])
        owners = []
        for b in bindings:
            if b.get('role') == 'roles/owner':
                for m in b.get('members', []):
                    owners.append(m)
        status = "FAIL" if owners else "PASS"
        return mk_result("IAM", "Principals with roles/owner at project level", status, [{"member": o} for o in owners])
    except Exception as e:
        return mk_result("IAM", "Principals with roles/owner at project level", "FAIL", [], notes=str(e))

def check_kms_separation_of_duty():
    """KMS separation of duty: naive check for keys that allow both cryptoKeys:encrypt/decrypt and iam policies that grant admin to same principal.
       This is a best-effort heuristic (detailed SOD requires org policy review)."""
    try:
        kms = get_service('cloudkms', 'v1')
        found = []
        # list keyRings under locations - we'll try common locations (global & us)
        locations = ["global", "us-central1", "us"]
        for loc in locations:
            try:
                kr_resp = kms.projects().locations().keyRings().list(parent=f"projects/{PROJECT_ID}/locations/{loc}").execute()
                keyrings = kr_resp.get('keyRings', []) or []
            except HttpError:
                keyrings = []
            for kr in keyrings:
                kr_name = kr.get('name')
                # list cryptoKeys
                try:
                    ck_resp = kms.projects().locations().keyRings().cryptoKeys().list(parent=kr_name).execute()
                    ckeys = ck_resp.get('cryptoKeys', []) or []
                except HttpError:
                    ckeys = []
                for ck in ckeys:
                    # fetch IAM policy for key to see bindings
                    try:
                        policy = kms.projects().locations().keyRings().cryptoKeys().getIamPolicy(resource=ck.get('name')).execute()
                        # heuristic: if same member in roles/cloudkms.cryptoKeyEncrypterDecrypter and roles/owner -> suspicious
                        bindings = policy.get('bindings', [])
                        encrypters = []
                        admins = []
                        for b in bindings:
                            r = b.get('role')
                            for m in b.get('members', []):
                                if r in ('roles/cloudkms.cryptoKeyEncrypterDecrypter',):
                                    encrypters.append(m)
                                if r in ('roles/owner','roles/cloudkms.admin'):
                                    admins.append(m)
                        overlap = set(encrypters) & set(admins)
                        if overlap:
                            found.append({"cryptoKey": ck.get('name'), "overlap_members": list(overlap)})
                    except Exception:
                        continue
        status = "FAIL" if found else "PASS"
        return mk_result("KMS", "KMS separation of duty (encrypter & admin overlap)", status, found)
    except Exception as e:
        return mk_result("KMS", "KMS separation of duty (encrypter & admin overlap)", "FAIL", [], notes=str(e))

def check_project_iam_policy():
    """Fetch project IAM policy and present summary (counts)"""
    try:
        crm = get_service('cloudresourcemanager', 'v1')
        policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        bindings = policy.get('bindings', [])
        summary = []
        for b in bindings:
            summary.append({"role": b.get('role'), "members_count": len(b.get('members', [])), "members_sample": b.get('members', [])[:5]})
        return mk_result("IAM", "Project IAM policy summary", "PASS", summary)
    except Exception as e:
        return mk_result("IAM", "Project IAM policy summary", "FAIL", [], notes=str(e))

def check_secrets_in_cloud_functions():
    """Detect environment variables in Cloud Functions that look like secrets (best-effort)"""
    try:
        functions_svc = get_service('cloudfunctions', 'v1')
        func_list = []
        # list functions in all locations
        try:
            resp = functions_svc.projects().locations().functions().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
            funcs = resp.get('functions', []) or []
        except HttpError:
            funcs = []
        flagged = []
        for f in funcs:
            env = f.get('environmentVariables', {}) or {}
            for k, v in env.items():
                # heuristics: keys containing 'SECRET','KEY','TOKEN','PASS' or base64-looking values
                if any(s in k.upper() for s in ('SECRET','KEY','TOKEN','PASS','PWD')) or (isinstance(v, str) and len(v) > 50):
                    flagged.append({"function": f.get('name'), "env_key": k, "value_preview": (v[:120] + '...') if len(v)>120 else v})
        status = "FAIL" if flagged else "PASS"
        return mk_result("Cloud Functions", "Secrets exposed in Cloud Functions environment variables", status, flagged)
    except Exception as e:
        return mk_result("Cloud Functions", "Secrets exposed in Cloud Functions environment variables", "FAIL", [], notes=str(e))

def check_user_managed_service_keys_and_service_account_privileges():
    """Checks for user-managed keys for service accounts and lists service-account roles (best-effort)"""
    results = []
    try:
        iam = get_service('iam', 'v1')
        # list service accounts
        sa_resp = iam.projects().serviceAccounts().list(name=f'projects/{PROJECT_ID}').execute()
        sas = sa_resp.get('accounts', []) or []
        flagged_keys = []
        sa_privs = []
        for sa in sas:
            sa_email = sa.get('email')
            # list keys for service account
            try:
                keys = iam.projects().serviceAccounts().keys().list(name=sa.get('name')).execute()
                for k in keys.get('keys', []):
                    if k.get('keyType') == 'USER_MANAGED':
                        flagged_keys.append({"serviceAccount": sa_email, "keyName": k.get('name'), "keyType": k.get('keyType')})
            except Exception:
                pass
            # check IAM bindings for this SA to find roles
            try:
                crm = get_service('cloudresourcemanager', 'v1')
                policy = crm.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
                roles = []
                for b in policy.get('bindings', []):
                    if any(member == f"serviceAccount:{sa_email}" for member in b.get('members', [])):
                        roles.append(b.get('role'))
                sa_privs.append({"serviceAccount": sa_email, "roles": roles})
            except Exception:
                pass
        status = "FAIL" if (flagged_keys or any(len(x['roles'])>0 for x in sa_privs)) else "PASS"
        return mk_result("IAM", "User-managed service account keys & service-account privileges", status, {"user_managed_keys": flagged_keys, "service_account_roles": sa_privs})
    except Exception as e:
        return mk_result("IAM", "User-managed service account keys & service-account privileges", "FAIL", [], notes=str(e))

def check_firewall_rules_for_ssh_rdp_and_legacy_networks():
    """Detect firewall rules that allow 0.0.0.0/0 to SSH (22) or RDP (3389), and legacy networks"""
    try:
        compute = get_service('compute', 'v1')
        fw_resp = compute.firewalls().list(project=PROJECT_ID).execute()
        fws = fw_resp.get('items', []) or []
        ssh_rules = []
        rdp_rules = []
        legacy_networks = []
        # check networks list for 'default' or legacy auto-create
        net_resp = compute.networks().list(project=PROJECT_ID).execute()
        nets = net_resp.get('items', []) or []
        for n in nets:
            if n.get('autoCreateSubnetworks', False):
                legacy_networks.append({"network": n.get('name'), "autoCreateSubnetworks": True})
        for fw in fws:
            allowed = fw.get('allowed', []) or []
            src_ranges = fw.get('sourceRanges', []) or []
            for a in allowed:
                ports = a.get('ports', []) or []
                # if 22 in ports or ports empty means all ports allowed for that protocol
                if any(p in ('22','tcp:22') or (p=='' and 'tcp'==a.get('IPProtocol')) for p in ports) or ('0.0.0.0/0' in src_ranges and any('22' in str(p) for p in ports)):
                    if '0.0.0.0/0' in src_ranges:
                        ssh_rules.append({"name": fw.get('name'), "sourceRanges": src_ranges, "allowed": allowed})
                if any(p in ('3389','tcp:3389') or (p=='' and 'tcp'==a.get('IPProtocol')) for p in ports) or ('0.0.0.0/0' in src_ranges and any('3389' in str(p) for p in ports)):
                    if '0.0.0.0/0' in src_ranges:
                        rdp_rules.append({"name": fw.get('name'), "sourceRanges": src_ranges, "allowed": allowed})
        results = {"ssh_firewall_rules": ssh_rules, "rdp_firewall_rules": rdp_rules, "legacy_networks": legacy_networks}
        status = "FAIL" if (ssh_rules or rdp_rules or legacy_networks) else "PASS"
        return mk_result("Network", "SSH/RDP firewall rules + legacy network detection", status, [results])
    except Exception as e:
        return mk_result("Network", "SSH/RDP firewall rules + legacy network detection", "FAIL", [], notes=str(e))

def check_logging_and_sinks():
    """Check project-level logging sinks and buckets (best-effort)"""
    try:
        logging = get_service('logging', 'v2')
        sinks_resp = logging.projects().sinks().list(parent=f"projects/{PROJECT_ID}").execute()
        sinks = sinks_resp.get('sinks', []) or []
        buckets = []
        # Cloud Logging buckets listing requires logging admin APIs; we'll call the logging API for buckets under project
        try:
            buckets_resp = logging.projects().locations().buckets().list(parent=f"projects/{PROJECT_ID}/locations/global").execute()
            buckets = buckets_resp.get('buckets', []) or []
        except Exception:
            buckets = []
        status = "PASS"
        details = {"sinks": sinks, "logging_buckets": buckets}
        return mk_result("Logging", "Project logging sinks and buckets", status, [details])
    except Exception as e:
        return mk_result("Logging", "Project logging sinks and buckets", "FAIL", [], notes=str(e))

def check_vpc_and_lb_logging():
    """Checks related to NAT, VPC Flow Logs, Load balancer logging - best-effort (uses compute API metadata)"""
    try:
        compute = get_service('compute', 'v1')
        # NATs
        nat_resp = compute.routers().list(project=PROJECT_ID, region='us-central1').execute()
        nats = []
        for r in nat_resp.get('items', []) if nat_resp else []:
            for nat in r.get('nats', []):
                nats.append({"router": r.get('name'), "nat": nat})
        # Forwarding rules (load balancers)
        fr_resp = compute.forwardingRules().list(project=PROJECT_ID, region='-').execute()
        lbs = fr_resp.get('items', []) or []
        status = "PASS"
        details = {"cloud_nat": nats, "forwarding_rules": lbs}
        return mk_result("Network", "VPC/NAT/LoadBalancer metadata", status, [details])
    except Exception as e:
        return mk_result("Network", "VPC/NAT/LoadBalancer metadata", "FAIL", [], notes=str(e))

def run_all_checks():
    """Run all checks and compose structured results"""
    results = []
    # order them in a reasonable grouping
    results.append(check_sql_public_ips())
    results.append(check_gke_public_nodes())
    results.append(check_buckets_public())
    results.append(check_service_accounts_with_owner())
    results.append(check_kms_separation_of_duty())
    results.append(check_project_iam_policy())
    results.append(check_secrets_in_cloud_functions())
    results.append(check_user_managed_service_keys_and_service_account_privileges())
    results.append(check_firewall_rules_for_ssh_rdp_and_legacy_networks())
    results.append(check_logging_and_sinks())
    results.append(check_vpc_and_lb_logging())
    return results

def save_results_to_gcs(payload):
    """Save JSON payload to RESULT_BUCKET if configured"""
    if not RESULT_BUCKET:
        return None
    try:
        client = storage.Client(project=PROJECT_ID, credentials=credentials)
        bucket = client.bucket(RESULT_BUCKET)
        if not bucket.exists():
            # create bucket in same project, location multi-regional by default
            bucket = client.create_bucket(RESULT_BUCKET, project=PROJECT_ID)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        blob = bucket.blob(f"audit-{ts}.json")
        blob.upload_from_string(json.dumps(payload, indent=2), content_type='application/json')
        return blob.name
    except Exception as e:
        # return None on failure, but include note in payload if needed
        return None

# -------------------------
# Flask / Cloud Function handlers
# -------------------------

@app.route('/')
def dashboard():
    """Render last-run results by executing a run (synchronous)"""
    run_time = datetime.utcnow().isoformat() + "Z"
    results = run_all_checks()
    raw = {"project": PROJECT_ID, "run_time": run_time, "results": results}
    # Optionally store to GCS
    saved = save_results_to_gcs(raw)
    if saved:
        # add note to top-level
        raw['_saved_to_bucket'] = saved
    checks_count = len(results)
    return render_template_string(TEMPLATE, project=PROJECT_ID, run_time=run_time, results=results, raw=raw, checks_count=checks_count)

@app.route('/run', methods=['GET','POST'])
def run_endpoint():
    """Endpoint used by scheduler — require OIDC Bearer token (Scheduler provides it)"""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        # deny non-authenticated callers
        abort(403)
    # perform run
    run_time = datetime.utcnow().isoformat() + "Z"
    results = run_all_checks()
    payload = {"project": PROJECT_ID, "run_time": run_time, "results": results}
    saved = save_results_to_gcs(payload)
    if saved:
        payload["_saved_to_bucket"] = saved
    return jsonify(payload)

# Entry point for Cloud Functions (HTTP)
def main(request):
    return dashboard()

# For local debugging:
if __name__ == "__main__":
    # run locally for quick testing
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
