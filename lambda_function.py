"""IT Helpdesk backend - one AWS Lambda function (Python 3.12).
Env vars: DSQL_ENDPOINT (cluster endpoint), FILES_BUCKET (private S3 bucket).
Libraries: boto3 (built in) + pg8000 (from the Lambda layer).
"""
import json, os, re, ssl, time, uuid
import boto3, pg8000.native
from botocore.config import Config

REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
ENDPOINT = os.environ["DSQL_ENDPOINT"]
BUCKET = os.environ["FILES_BUCKET"]
s3 = boto3.client("s3", region_name=REGION,
                  config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}))
cognito = boto3.client("cognito-idp", region_name=REGION)
dsql = boto3.client("dsql", region_name=REGION)

STATUSES = ["Open", "In Progress", "Pending", "Resolved", "Closed"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
ROLES = ["employee", "it_support", "admin"]
MAX_FILE = 5 * 1024 * 1024
OK_TYPES = {"application/pdf", "text/plain", "application/zip",
            "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}

# ---------------------------------------------------------------- SCHEMA
# Aurora DSQL rules: one DDL statement per transaction, indexes use CREATE INDEX ASYNC.
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cognito_sub TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'employee',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ticket_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subject TEXT NOT NULL,
  description TEXT NOT NULL,
  category_id UUID REFERENCES ticket_categories(id),
  priority TEXT NOT NULL DEFAULT 'Medium',
  status TEXT NOT NULL DEFAULT 'Open',
  created_by UUID NOT NULL REFERENCES users(id),
  assigned_to UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS ticket_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID NOT NULL REFERENCES tickets(id),
  assigned_to UUID REFERENCES users(id),
  assigned_by UUID NOT NULL REFERENCES users(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ticket_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID NOT NULL REFERENCES tickets(id),
  sender_id UUID NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  is_system BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ticket_attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID NOT NULL REFERENCES tickets(id),
  uploaded_by UUID NOT NULL REFERENCES users(id),
  s3_key TEXT NOT NULL,
  file_name TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ASYNC idx_tickets_created_by ON tickets (created_by);
CREATE INDEX ASYNC idx_tickets_assigned_to ON tickets (assigned_to);
CREATE INDEX ASYNC idx_messages_ticket ON ticket_messages (ticket_id);
CREATE INDEX ASYNC idx_attachments_ticket ON ticket_attachments (ticket_id);
CREATE INDEX ASYNC idx_assignments_ticket ON ticket_assignments (ticket_id);
INSERT INTO ticket_categories (name) VALUES ('Hardware') ON CONFLICT (name) DO NOTHING;
INSERT INTO ticket_categories (name) VALUES ('Software') ON CONFLICT (name) DO NOTHING;
INSERT INTO ticket_categories (name) VALUES ('Network') ON CONFLICT (name) DO NOTHING;
INSERT INTO ticket_categories (name) VALUES ('Account Access') ON CONFLICT (name) DO NOTHING;
INSERT INTO ticket_categories (name) VALUES ('Email') ON CONFLICT (name) DO NOTHING;
INSERT INTO ticket_categories (name) VALUES ('Other') ON CONFLICT (name) DO NOTHING;
"""

# ---------------------------------------------------------------- helpers
class Err(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg

C = None  # database connection for the current request


def connect():
    token = dsql.generate_db_connect_admin_auth_token(ENDPOINT, REGION)
    return pg8000.native.Connection(user="admin", host=ENDPOINT, port=5432, database="postgres",
                                    password=token, ssl_context=ssl.create_default_context(), timeout=15)


def q(sql, **p):
    for attempt in range(3):  # DSQL may ask to retry on write conflicts
        try:
            rows = C.run(sql, **p)
            cols = [c["name"] for c in (C.columns or [])]
            return [dict(zip(cols, r)) for r in (rows or [])]
        except Exception as e:
            if attempt < 2 and ("OC000" in str(e) or "40001" in str(e)):
                time.sleep(0.2 * (attempt + 1))
                continue
            raise


def out(code, obj=None):
    return {"statusCode": code,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Headers": "Authorization,Content-Type",
                        "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS"},
            "body": "" if obj is None else json.dumps(obj, default=str)}


def is_uuid(v):
    try:
        uuid.UUID(str(v))
        return True
    except ValueError:
        return False


def auth(headers):
    """Validate the Cognito access token, then find (or create) the user row."""
    t = (headers.get("authorization") or "").replace("Bearer ", "").strip()
    if not t:
        raise Err(401, "Not signed in")
    try:
        info = cognito.get_user(AccessToken=t)
    except Exception:
        raise Err(401, "Session expired. Please sign in again.")
    a = {x["Name"]: x["Value"] for x in info["UserAttributes"]}
    sub, email = a["sub"], a.get("email", info["Username"])
    cols = "id, role, is_active, full_name, email"
    rows = q(f"SELECT {cols} FROM users WHERE cognito_sub=:s", s=sub)
    if not rows:  # first login: create the profile. The very first user becomes admin.
        first = q("SELECT COUNT(*) AS n FROM users")[0]["n"] == 0
        rows = q(f"INSERT INTO users (cognito_sub,email,full_name,role) VALUES (:s,:e,:n,:r) RETURNING {cols}",
                 s=sub, e=email, n=a.get("name") or email, r="admin" if first else "employee")
    u = rows[0]
    if not u["is_active"]:
        raise Err(403, "This account is disabled")
    u["id"] = str(u["id"])
    return u


def need(u, *roles):
    if u["role"] not in roles:
        raise Err(403, "You do not have permission to do this")


def load_ticket(u, tid):
    if not is_uuid(tid):
        raise Err(404, "Ticket not found")
    r = q("""SELECT t.*, c.name AS category, cu.full_name AS created_by_name, au.full_name AS assigned_name
             FROM tickets t LEFT JOIN ticket_categories c ON c.id=t.category_id
             JOIN users cu ON cu.id=t.created_by LEFT JOIN users au ON au.id=t.assigned_to
             WHERE t.id=CAST(:id AS uuid)""", id=tid)
    if not r:
        raise Err(404, "Ticket not found")
    t = r[0]
    mine = str(t["created_by"]) == u["id"]
    assigned = t["assigned_to"] is not None and str(t["assigned_to"]) == u["id"]
    if not (u["role"] == "admin" or mine or (u["role"] == "it_support" and assigned)):
        raise Err(404, "Ticket not found")
    t["_assigned"] = assigned
    return t


def note(tid, uid, text):
    q("INSERT INTO ticket_messages (ticket_id,sender_id,body,is_system) VALUES (CAST(:t AS uuid),CAST(:u AS uuid),:b,TRUE)",
      t=tid, u=uid, b=text)


def scope(u):
    if u["role"] == "admin":
        return "TRUE"
    if u["role"] == "it_support":
        return "(t.assigned_to=CAST(:uid AS uuid) OR t.created_by=CAST(:uid AS uuid))"
    return "t.created_by=CAST(:uid AS uuid)"


def uid_params(u, sql):
    return {"uid": u["id"]} if ":uid" in sql else {}

# ---------------------------------------------------------------- routes
def r_me(u, b, qs):
    return {k: str(v) for k, v in u.items()}


def r_stats(u, b, qs):
    sc = scope(u)
    sql = f"SELECT t.status, COUNT(*) AS n FROM tickets t WHERE {sc} GROUP BY t.status"
    by = {r["status"]: r["n"] for r in q(sql, **uid_params(u, sql))}
    users = None
    if u["role"] == "admin":
        users = {r["role"]: r["n"] for r in q("SELECT role, COUNT(*) AS n FROM users GROUP BY role")}
    return {"by_status": by, "total": sum(by.values()), "users": users}


def r_categories(u, b, qs):
    return q("SELECT id, name, is_active FROM ticket_categories ORDER BY name")


def r_cat_add(u, b, qs):
    need(u, "admin")
    name = (b.get("name") or "").strip()[:60]
    if not name:
        raise Err(400, "Category name is required")
    q("INSERT INTO ticket_categories (name) VALUES (:n) ON CONFLICT (name) DO NOTHING", n=name)
    return {"ok": True}


def r_cat_toggle(u, b, qs, cid):
    need(u, "admin")
    if not is_uuid(cid):
        raise Err(404, "Not found")
    q("UPDATE ticket_categories SET is_active = NOT is_active WHERE id=CAST(:i AS uuid)", i=cid)
    return {"ok": True}


def r_tickets(u, b, qs):
    sql = f"""SELECT t.id, t.subject, t.priority, t.status, t.created_at, t.updated_at, c.name AS category,
              cu.full_name AS created_by_name, au.full_name AS assigned_name
              FROM tickets t LEFT JOIN ticket_categories c ON c.id=t.category_id
              JOIN users cu ON cu.id=t.created_by LEFT JOIN users au ON au.id=t.assigned_to
              WHERE {scope(u)}"""
    p = uid_params(u, sql)
    if qs.get("status") in STATUSES:
        sql += " AND t.status=:st"
        p["st"] = qs["status"]
    return q(sql + " ORDER BY t.created_at DESC LIMIT 200", **p)


def r_ticket_new(u, b, qs):
    subject, desc = (b.get("subject") or "").strip(), (b.get("description") or "").strip()
    pr = b.get("priority", "Medium")
    if not subject or not desc:
        raise Err(400, "Subject and description are required")
    if pr not in PRIORITIES or not is_uuid(b.get("category_id")):
        raise Err(400, "Choose a valid category and priority")
    r = q("""INSERT INTO tickets (subject,description,category_id,priority,created_by)
             VALUES (:s,:d,CAST(:c AS uuid),:p,CAST(:u AS uuid)) RETURNING id""",
          s=subject[:200], d=desc[:5000], c=b["category_id"], p=pr, u=u["id"])
    return {"id": str(r[0]["id"])}


def r_ticket_get(u, b, qs, tid):
    t = load_ticket(u, tid)
    msgs = q("""SELECT m.id, m.body, m.is_system, m.created_at, s.full_name AS sender, s.role AS sender_role
                FROM ticket_messages m JOIN users s ON s.id=m.sender_id
                WHERE m.ticket_id=CAST(:t AS uuid) ORDER BY m.created_at""", t=tid)
    atts = q("""SELECT a.id, a.file_name, a.content_type, a.size_bytes, a.s3_key, a.created_at, x.full_name AS uploader
                FROM ticket_attachments a JOIN users x ON x.id=a.uploaded_by
                WHERE a.ticket_id=CAST(:t AS uuid) ORDER BY a.created_at""", t=tid)
    for a in atts:  # short-lived private download link (5 minutes)
        a["url"] = s3.generate_presigned_url("get_object", ExpiresIn=300, Params={
            "Bucket": BUCKET, "Key": a.pop("s3_key"),
            "ResponseContentDisposition": 'attachment; filename="%s"' % a["file_name"].replace('"', "")})
    t.pop("_assigned")
    return {"ticket": t, "messages": msgs, "attachments": atts}


def r_msg_add(u, b, qs, tid):
    load_ticket(u, tid)
    body = (b.get("body") or "").strip()
    if not body:
        raise Err(400, "Message cannot be empty")
    q("INSERT INTO ticket_messages (ticket_id,sender_id,body) VALUES (CAST(:t AS uuid),CAST(:u AS uuid),:b)",
      t=tid, u=u["id"], b=body[:3000])
    q("UPDATE tickets SET updated_at=now() WHERE id=CAST(:t AS uuid)", t=tid)
    return {"ok": True}


def r_ticket_patch(u, b, qs, tid):
    t = load_ticket(u, tid)
    sets, p, logs = [], {"t": tid}, []
    staff_ok = u["role"] == "admin" or (u["role"] == "it_support" and t["_assigned"])
    if "status" in b and b["status"] != t["status"]:
        s = b["status"]
        if s not in STATUSES:
            raise Err(400, "Invalid status")
        if not (staff_ok or (u["role"] == "employee" and s in ("Open", "Closed"))):
            raise Err(403, "You cannot set this status")
        sets += ["status=:s", "resolved_at=" + ("now()" if s in ("Resolved", "Closed") else "NULL")]
        p["s"] = s
        logs.append(f"Status changed from {t['status']} to {s}")
    if "priority" in b and b["priority"] != t["priority"]:
        if b["priority"] not in PRIORITIES:
            raise Err(400, "Invalid priority")
        need(u, "admin", "it_support")
        if not staff_ok:
            raise Err(403, "Only the assigned staff can change priority")
        sets.append("priority=:pr")
        p["pr"] = b["priority"]
        logs.append(f"Priority changed from {t['priority']} to {b['priority']}")
    if "assigned_to" in b:
        need(u, "admin")
        new = b["assigned_to"] or None
        if new and not is_uuid(new):
            raise Err(400, "Invalid staff member")
        if new:
            ok = q("SELECT full_name FROM users WHERE id=CAST(:i AS uuid) AND is_active AND role IN ('it_support','admin')", i=new)
            if not ok:
                raise Err(400, "Pick an active IT support or admin user")
            who = ok[0]["full_name"]
        else:
            who = "nobody"
        if (str(t["assigned_to"]) if t["assigned_to"] else None) != new:
            sets.append("assigned_to=CAST(:a AS uuid)")
            p["a"] = new
            logs.append(f"Assigned to {who}")
            q("INSERT INTO ticket_assignments (ticket_id,assigned_to,assigned_by) VALUES (CAST(:t AS uuid),CAST(:a AS uuid),CAST(:u AS uuid))",
              t=tid, a=new, u=u["id"])
    if sets:
        q(f"UPDATE tickets SET {', '.join(sets)}, updated_at=now() WHERE id=CAST(:t AS uuid)", **p)
        for l in logs:
            note(tid, u["id"], l)
    return {"ok": True}


def r_presign(u, b, qs, tid):
    load_ticket(u, tid)
    name = re.sub(r"[^\w.\- ]", "_", (b.get("file_name") or "file"))[:100]
    ct, size = b.get("content_type") or "application/octet-stream", int(b.get("size") or 0)
    if size <= 0 or size > MAX_FILE:
        raise Err(400, "File must be 5 MB or smaller")
    if not (ct.startswith("image/") or ct in OK_TYPES):
        raise Err(400, "File type not allowed (images, PDF, text, Word, Excel, zip)")
    key = f"tickets/{tid}/{uuid.uuid4()}-{name}"
    url = s3.generate_presigned_url("put_object", ExpiresIn=300,
                                    Params={"Bucket": BUCKET, "Key": key, "ContentType": ct})
    return {"upload_url": url, "s3_key": key, "file_name": name, "content_type": ct, "size": size}


def r_attach_save(u, b, qs, tid):
    load_ticket(u, tid)
    key = b.get("s3_key") or ""
    if not key.startswith(f"tickets/{tid}/"):
        raise Err(400, "Invalid file reference")
    q("""INSERT INTO ticket_attachments (ticket_id,uploaded_by,s3_key,file_name,content_type,size_bytes)
         VALUES (CAST(:t AS uuid),CAST(:u AS uuid),:k,:n,:c,:s)""",
      t=tid, u=u["id"], k=key, n=b.get("file_name", "file"), c=b.get("content_type", ""), s=int(b.get("size") or 0))
    note(tid, u["id"], f"Attached file: {b.get('file_name', 'file')}")
    return {"ok": True}


def r_users(u, b, qs):
    need(u, "admin")
    return q("SELECT id, email, full_name, role, is_active, created_at FROM users ORDER BY created_at")


def r_staff(u, b, qs):
    need(u, "admin")
    return q("SELECT id, full_name, role FROM users WHERE is_active AND role IN ('it_support','admin') ORDER BY full_name")


def r_user_patch(u, b, qs, uid):
    need(u, "admin")
    if not is_uuid(uid):
        raise Err(404, "Not found")
    if uid == u["id"]:
        raise Err(400, "You cannot change your own role or status")
    if "role" in b:
        if b["role"] not in ROLES:
            raise Err(400, "Invalid role")
        q("UPDATE users SET role=:r WHERE id=CAST(:i AS uuid)", r=b["role"], i=uid)
    if "is_active" in b:
        q("UPDATE users SET is_active=:a WHERE id=CAST(:i AS uuid)", a=bool(b["is_active"]), i=uid)
    return {"ok": True}


ROUTES = [
    ("GET", r"/api/me", r_me), ("GET", r"/api/stats", r_stats),
    ("GET", r"/api/categories", r_categories), ("POST", r"/api/categories", r_cat_add),
    ("POST", r"/api/categories/([\w-]+)/toggle", r_cat_toggle),
    ("GET", r"/api/tickets", r_tickets), ("POST", r"/api/tickets", r_ticket_new),
    ("GET", r"/api/tickets/([\w-]+)", r_ticket_get), ("PATCH", r"/api/tickets/([\w-]+)", r_ticket_patch),
    ("POST", r"/api/tickets/([\w-]+)/messages", r_msg_add),
    ("POST", r"/api/tickets/([\w-]+)/attachments/presign", r_presign),
    ("POST", r"/api/tickets/([\w-]+)/attachments", r_attach_save),
    ("GET", r"/api/users", r_users), ("GET", r"/api/staff", r_staff),
    ("PATCH", r"/api/users/([\w-]+)", r_user_patch),
]


def init_db():
    global C
    C = connect()
    res = []
    for stmt in [s.strip() for s in SCHEMA.split(";") if s.strip()]:
        try:
            C.run(stmt)
            res.append("OK   " + stmt[:60].replace("\n", " "))
        except Exception as e:
            res.append("SKIP " + stmt[:45].replace("\n", " ") + " -> " + str(e)[:150])
    C.close()
    return res


def lambda_handler(event, context):
    global C
    if "action" in event:  # Test-event from the Lambda console: {"action": "init"}
        return init_db()
    method = event["requestContext"]["http"]["method"]
    if method == "OPTIONS":
        return out(204)
    path = event["rawPath"].rstrip("/") or "/"
    try:
        body = json.loads(event.get("body") or "{}") if method in ("POST", "PATCH") else {}
        C = connect()
        for m, pat, fn in ROUTES:
            mt = re.fullmatch(pat, path)
            if m == method and mt:
                user = auth(event.get("headers") or {})
                return out(200, fn(user, body, event.get("queryStringParameters") or {}, *mt.groups()))
        raise Err(404, "Unknown endpoint")
    except Err as e:
        return out(e.code, {"error": e.msg})
    except Exception as e:
        print("ERROR", repr(e))
        return out(500, {"error": "Server error. Check the Lambda logs in CloudWatch."})
    finally:
        try:
            C.close()
        except Exception:
            pass
