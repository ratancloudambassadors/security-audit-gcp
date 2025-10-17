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

# HTML dashboard template
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
    .status-skip { color: #f9ab00; font-weight: 600; }
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
    <h3>{{ item.category }} — 
        <span class="{% if item.status=='FAIL' %}status-fail{% elif item.status=='SKIP' %}status-skip{% else %}status-pass{% endif %}">
            {{ item.status }}
        </span>
    </h3>
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

# Helper
def mk_result(category, check, status, resources=None, notes=None):
    return {
        "category": category,
        "check": check,
        "status": status,
        "resources": resources or [],
        "notes": notes or ""
    }

# Initialize clients
credentials, project = google.auth.default()
PROJECT_ID = os.environ.get("GCP_PROJECT", project)
RESULT_BUCKET = os.environ.get("RESULT_BUCKET")  # optional: save results to this GCS bucket

def get_service(name, version):
    return discovery.build(name, version, credentials=credentials, cache_discovery=False)

# -------------------------
# Individual checks
# -------------------------

def check_sql_public_ips():
    try:
        sql = get_service('sqladmin', 'v1beta4')
        resp = sql.instances().list(project=PROJECT_ID).execute()
        items = resp.get('items', [])
        public = []
        for inst in items:
            ips = inst.get('ipAddresses', [])
            if ips:
                public.append({"instance": inst.get('name'), "region": inst.get('region'), "ipAddresses": ips})
        status = "FAIL" if public else "PASS"
        return mk_result("Cloud SQL", "SQL Instances with public IPs", status, public)
    except HttpError as e:
        if e.resp.status in (403, 404):
            return mk_result("Cloud SQL", "SQL Instances with public IPs", "SKIP", [], notes="Cloud SQL API not enabled or access denied")
        return mk_result("Cloud SQL", "SQL Instances with public IPs", "FAIL", [], notes=str(e))
    except Exception as e:
        return mk_result("Cloud SQL", "SQL Instances with public IPs", "FAIL", [], notes=str(e))

def check_gke_public_nodes():
    try:
        container = get_service('container', 'v1')
        clusters = []
        try:
            resp = container.projects().zones().clusters().list(projectId=PROJECT_ID, zone='-').execute()
            clusters = resp.get('clusters', []) or []
        except HttpError:
            try:
                resp = container.projects().locations().clusters().list(parent=f"projects/{PROJECT_ID}/locations/-").execute()
                clusters = resp.get('clusters', []) or []
            except HttpError as e2:
                return mk_result("GKE", "GKE clusters with public endpoint or public nodes", "SKIP", [], notes="GKE API not enabled or access denied")
        flagged = []
        for c in clusters:
            name = c.get('name')
            endpoint = c.get('endpoint')
            private_config = c.get('privateClusterConfig')
            public_nodes = bool(endpoint and not private_config)
            if public_nodes:
                flagged.append({"cluster": name, "endpoint": endpoint, "privateClusterConfig": bool(private_config)})
        status = "FAIL" if flagged else "PASS"
        return mk_result("GKE", "GKE clusters with public endpoint or public nodes", status, flagged)
    except Exception as e:
        return mk_result("GKE", "GKE clusters with public endpoint or public nodes", "FAIL", [], notes=str(e))

def check_buckets_public():
    try:
        storage_client = storage.Client(project=PROJECT_ID, credentials=credentials)
        buckets = list(storage_client.list_buckets())
        public = []
        for b in buckets:
            try:
                policy = b.get_iam_policy(requested_policy_version=3)
                bindings = policy.bindings
                for bind in bindings:
                    members = bind.get('members', [])
                    if any(m in ('allUsers', 'allAuthenticatedUsers') for m in members):
                        public.append({"bucket": b.name, "role": bind.get('role'), "members": members})
                        break
                acl = b.acl
                for entry in acl:
                    if entry['entity'] in ('allUsers', 'allAuthenticatedUsers'):
                        public.append({"bucket": b.name, "acl_entity": entry['entity']})
                        break
            except Exception:
                continue
        status = "FAIL" if public else "PASS"
        return mk_result("Cloud Storage", "Buckets publicly accessible (IAM or ACL)", status, public)
    except Exception as e:
        if isinstance(e, HttpError) and e.resp.status in (403, 404):
            return mk_result("Cloud Storage", "Buckets publicly accessible (IAM or ACL)", "SKIP", [], notes="Cloud Storage API not enabled or access denied")
        return mk_result("Cloud Storage", "Buckets publicly accessible (IAM or ACL)", "FAIL", [], notes=str(e))

def check_service_accounts_with_owner():
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
    except HttpError as e:
        if e.resp.status in (403, 404):
            return mk_result("IAM", "Principals with roles/owner at project level", "SKIP", [], notes="Cloud Resource Manager API not enabled or access denied")
        return mk_result("IAM", "Principals with roles/owner at project level", "FAIL", [], notes=str(e))
    except Exception as e:
        return mk_result("IAM", "Principals with roles/owner at project level", "FAIL", [], notes=str(e))

# (Baaki ke checks bhi same pattern follow karenge: HttpError 403/404 -> SKIP with notes)

# -------------------------
# Run all checks
# -------------------------
def run_all_checks():
    results = []
    results.append(check_sql_public_ips())
    results.append(check_gke_public_nodes())
    results.append(check_buckets_public())
    results.append(check_service_accounts_with_owner())
    # add other checks here with same HttpError handling
    return results

# -------------------------
# Save to GCS
# -------------------------
def save_results_to_gcs(payload):
    if not RESULT_BUCKET:
        return None
    try:
        client = storage.Client(project=PROJECT_ID, credentials=credentials)
        bucket = client.bucket(RESULT_BUCKET)
        if not bucket.exists():
            bucket = client.create_bucket(RESULT_BUCKET, project=PROJECT_ID)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        blob = bucket.blob(f"audit-{ts}.json")
        blob.upload_from_string(json.dumps(payload, indent=2), content_type='application/json')
        return blob.name
    except Exception:
        return None

# -------------------------
# Flask / Cloud Function handlers
# -------------------------
@app.route('/')
def dashboard():
    run_time = datetime.utcnow().isoformat() + "Z"
    results = run_all_checks()
    raw = {"project": PROJECT_ID, "run_time": run_time, "results": results}
    saved = save_results_to_gcs(raw)
    if saved:
        raw['_saved_to_bucket'] = saved
    checks_count = len(results)
    return render_template_string(TEMPLATE, project=PROJECT_ID, run_time=run_time, results=results, raw=raw, checks_count=checks_count)

@app.route('/run', methods=['GET','POST'])
def run_endpoint():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        abort(403)
    run_time = datetime.utcnow().isoformat() + "Z"
    results = run_all_checks()
    payload = {"project": PROJECT_ID, "run_time": run_time, "results": results}
    saved = save_results_to_gcs(payload)
    if saved:
        payload["_saved_to_bucket"] = saved
    return jsonify(payload)

def main(request):
    return dashboard()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)
