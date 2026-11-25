"""IT Helpdesk backend v3 (each administrator gets a separate helpdesk) - one AWS Lambda function (Python 3.12).
Env vars: DSQL_ENDPOINT, FILES_BUCKET, USER_POOL_ID
Libraries: boto3 (built in) + pg8000 (from the Lambda layer).
Test events: {"action":"init"} creates tables, {"action":"reset"} drops everything and recreates it.
"""
import json, os, re, ssl, time, uuid
import boto3, pg8000.native
from botocore.config import Config

REGION = os.environ.get("AWS_REGION", "ap-southeast-1")
ENDPOINT = os.environ["DSQL_ENDPOINT"]
BUCKET = os.environ["FILES_BUCKET"]
POOL = os.environ.get("USER_POOL_ID", "")
try:  # new boto3 adds checksum parameters to signed URLs, which breaks uploads straight from the browser
    S3CFG = Config(signature_version="s3v4", s3={"addressing_style": "virtual"},
                   request_checksum_calculation="when_required", response_checksum_validation="when_required")
except TypeError:  # older boto3 does not have these options and does not need them
    S3CFG = Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
s3 = boto3.client("s3", region_name=REGION, config=S3CFG)
cognito = boto3.client("cognito-idp", region_name=REGION)
dsql = boto3.client("dsql", region_name=REGION)

STATUSES = ["Open", "Pending", "In Progress", "Resolved", "Closed"]
PRIORITIES = ["Low", "Medium", "High", "Critical"]
ROLES = ["employee", "it_support", "admin"]
MAX_FILE = 5 * 1024 * 1024
OK_TYPES = {"application/pdf", "text/plain", "application/zip",
            "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
DEFAULT_CATEGORIES = ["Hardware", "Software", "Network", "Account Access", "Email", "Other"]
SORTS = {"newest": "t.created_at DESC", "oldest": "t.created_at ASC", "updated": "t.updated_at DESC",
         "priority": "CASE t.priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, t.created_at DESC",
         "status": "t.status, t.created_at DESC"}

# ---------------------------------------------------------------- SCHEMA
# Aurora DSQL rules: one DDL statement per transaction, indexes use CREATE INDEX ASYNC.
SCHEMA = """
CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS roles (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cognito_sub TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  org_id UUID NOT NULL REFERENCES organizations(id),
  role TEXT NOT NULL DEFAULT 'employee' REFERENCES roles(name),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ticket_categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id),
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
  is_internal BOOLEAN NOT NULL DEFAULT FALSE,
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
CREATE TABLE IF NOT EXISTS ticket_activity_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id UUID NOT NULL REFERENCES tickets(id),
  actor_id UUID NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  details TEXT NOT NULL,
  is_internal BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  ticket_id UUID NOT NULL REFERENCES tickets(id),
  message TEXT NOT NULL,
  is_read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ASYNC idx_users_org ON users (org_id);
CREATE INDEX ASYNC idx_categories_org ON ticket_categories (org_id);
CREATE INDEX ASYNC idx_tickets_org ON tickets (org_id);
CREATE INDEX ASYNC idx_tickets_created_by ON tickets (created_by);
CREATE INDEX ASYNC idx_tickets_assigned_to ON tickets (assigned_to);
CREATE INDEX ASYNC idx_messages_ticket ON ticket_messages (ticket_id);
CREATE INDEX ASYNC idx_attachments_ticket ON ticket_attachments (ticket_id);
CREATE INDEX ASYNC idx_assignments_ticket ON ticket_assignments (ticket_id);
CREATE INDEX ASYNC idx_logs_ticket ON ticket_activity_logs (ticket_id);
CREATE INDEX ASYNC idx_notifications_user ON notifications (user_id);
INSERT INTO roles (name, description) VALUES ('employee', 'Submits and tracks IT support requests') ON CONFLICT (name) DO NOTHING;
INSERT INTO roles (name, description) VALUES ('it_support', 'Handles, assigns and resolves tickets') ON CONFLICT (name) DO NOTHING;
INSERT INTO roles (name, description) VALUES ('admin', 'Manages user roles and monitors the whole system') ON CONFLICT (name) DO NOTHING;
"""
RESET = ["notifications", "ticket_activity_logs", "ticket_attachments", "ticket_messages",
         "ticket_assignments", "tickets", "ticket_categories", "users", "roles", "organizations"]

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
                        "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS"},
            "body": "" if obj is None else json.dumps(obj, default=str)}


def is_uuid(v):
    try:
        uuid.UUID(str(v))
        return True
    except ValueError:
        return False


def sid(tid):
    return "TKT-" + str(tid)[:8].upper()


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
    sel = """SELECT u.id, u.role, u.is_active, u.full_name, u.email, u.org_id, o.name AS org_name
             FROM users u JOIN organizations o ON o.id=u.org_id WHERE u.cognito_sub=:s"""
    rows = q(sel, s=sub)
    if not rows:  # first login of a brand-new account: it gets its OWN helpdesk and becomes its administrator
        name = a.get("name") or email
        org = q("INSERT INTO organizations (name) VALUES (:n) RETURNING id", n=name[:80] + "'s helpdesk")[0]["id"]
        for c in DEFAULT_CATEGORIES:
            q("INSERT INTO ticket_categories (org_id,name) VALUES (CAST(:o AS uuid),:n)", o=str(org), n=c)
        q("INSERT INTO users (cognito_sub,email,full_name,role,org_id) VALUES (:s,:e,:n,'admin',CAST(:o AS uuid))",
          s=sub, e=email, n=name[:100], o=str(org))
        rows = q(sel, s=sub)
    u = rows[0]
    if not u["is_active"]:
        raise Err(403, "This account is disabled")
    u["id"], u["org_id"] = str(u["id"]), str(u["org_id"])
    return u


def need(u, *roles):
    if u["role"] not in roles:
        raise Err(403, "You do not have permission to do this")


def can_work(u, t):
    """IT support may work on tickets that are unassigned or assigned to them."""
    return u["role"] == "it_support" and (t["_assigned"] or t["assigned_to"] is None)


def load_ticket(u, tid):
    if not is_uuid(tid):
        raise Err(404, "Ticket not found")
    r = q("""SELECT t.*, c.name AS category, cu.full_name AS created_by_name, au.full_name AS assigned_name
             FROM tickets t LEFT JOIN ticket_categories c ON c.id=t.category_id
             JOIN users cu ON cu.id=t.created_by LEFT JOIN users au ON au.id=t.assigned_to
             WHERE t.id=CAST(:id AS uuid) AND t.org_id=CAST(:org AS uuid)""", id=tid, org=u["org_id"])
    if not r:
        raise Err(404, "Ticket not found")
    t = r[0]
    if not (u["role"] in ("admin", "it_support") or str(t["created_by"]) == u["id"]):
        raise Err(404, "Ticket not found")  # employees only ever see their own tickets
    t["_assigned"] = t["assigned_to"] is not None and str(t["assigned_to"]) == u["id"]
    return t


def log(tid, uid, action, details, internal=False):
    q("""INSERT INTO ticket_activity_logs (ticket_id,actor_id,action,details,is_internal)
         VALUES (CAST(:t AS uuid),CAST(:u AS uuid),:a,:d,:i)""", t=tid, u=uid, a=action, d=details, i=internal)


def notify(uid, tid, text):
    if uid:
        q("INSERT INTO notifications (user_id,ticket_id,message) VALUES (CAST(:u AS uuid),CAST(:t AS uuid),:m)",
          u=str(uid), t=tid, m=text)


def notify_staff(tid, text, org):
    q("""INSERT INTO notifications (user_id,ticket_id,message)
         SELECT id, CAST(:t AS uuid), CAST(:m AS TEXT) FROM users
         WHERE role='it_support' AND is_active AND org_id=CAST(:o AS uuid)""",
      t=tid, m=text, o=org)


def scope(u):
    return "t.created_by=CAST(:uid AS uuid)" if u["role"] == "employee" else "TRUE"

# ---------------------------------------------------------------- routes
def r_me(u, b, qs):
    return {"id": u["id"], "role": u["role"], "full_name": u["full_name"], "email": u["email"], "org_name": u["org_name"]}


def r_stats(u, b, qs):
    sc = scope(u)
    p = {"org": u["org_id"]}
    if u["role"] == "employee":
        p["uid"] = u["id"]
    by = {r["status"]: r["n"] for r in q(f"SELECT t.status, COUNT(*) AS n FROM tickets t WHERE t.org_id=CAST(:org AS uuid) AND {sc} GROUP BY t.status", **p)}
    res = {"by_status": by, "total": sum(by.values())}
    if u["role"] == "admin":
        res["users"] = {r["role"]: r["n"] for r in q("SELECT role, COUNT(*) AS n FROM users WHERE org_id=CAST(:o AS uuid) GROUP BY role", o=u["org_id"])}
    if u["role"] == "it_support":
        res["mine"] = q("""SELECT COUNT(*) AS n FROM tickets WHERE assigned_to=CAST(:u AS uuid)
                           AND status NOT IN ('Resolved','Closed') AND org_id=CAST(:o AS uuid)""", u=u["id"], o=u["org_id"])[0]["n"]
        res["available"] = q("""SELECT COUNT(*) AS n FROM tickets WHERE assigned_to IS NULL
                                AND status NOT IN ('Resolved','Closed') AND org_id=CAST(:o AS uuid)""", o=u["org_id"])[0]["n"]
    return res


def r_categories(u, b, qs):
    return q("SELECT id, name, is_active FROM ticket_categories WHERE org_id=CAST(:o AS uuid) ORDER BY CASE WHEN name='Other' THEN 1 ELSE 0 END, name", o=u["org_id"])


def r_cat_add(u, b, qs):
    need(u, "admin")
    name = (b.get("name") or "").strip()[:60]
    if not name:
        raise Err(400, "Category name is required")
    if not q("SELECT 1 AS x FROM ticket_categories WHERE org_id=CAST(:o AS uuid) AND lower(name)=lower(:n)", o=u["org_id"], n=name):
        q("INSERT INTO ticket_categories (org_id,name) VALUES (CAST(:o AS uuid),:n)", o=u["org_id"], n=name)
    return {"ok": True}


def r_cat_toggle(u, b, qs, cid):
    need(u, "admin")
    if not is_uuid(cid):
        raise Err(404, "Not found")
    q("UPDATE ticket_categories SET is_active = NOT is_active WHERE id=CAST(:i AS uuid) AND org_id=CAST(:o AS uuid)", i=cid, o=u["org_id"])
    return {"ok": True}


def r_tickets(u, b, qs):
    where, p = ["(t.org_id=CAST(:org AS uuid))", "(" + scope(u) + ")"], {"org": u["org_id"]}
    if u["role"] == "employee":
        p["uid"] = u["id"]
    if qs.get("status") in STATUSES:
        where.append("(t.status=:st)"); p["st"] = qs["status"]
    if qs.get("priority") in PRIORITIES:
        where.append("(t.priority=:pr)"); p["pr"] = qs["priority"]
    if is_uuid(qs.get("category")):
        where.append("(t.category_id=CAST(:cat AS uuid))"); p["cat"] = qs["category"]
    text = (qs.get("q") or "").strip()[:60].replace("%", "").replace("_", "")
    if text:
        where.append("(t.subject ILIKE :q OR CAST(t.id AS TEXT) ILIKE :qi)")
        p["q"] = "%" + text + "%"
        p["qi"] = text.lower().replace("tkt-", "") + "%"
    if u["role"] == "it_support":
        if qs.get("view") == "mine":
            where.append("(t.assigned_to=CAST(:me AS uuid))"); p["me"] = u["id"]
        elif qs.get("view") == "available":
            where.append("(t.assigned_to IS NULL AND t.status NOT IN ('Resolved','Closed'))")
    order = SORTS.get(qs.get("sort"), SORTS["newest"])
    return q(f"""SELECT t.id, t.subject, t.priority, t.status, t.created_at, t.updated_at, c.name AS category,
                 cu.full_name AS created_by_name, au.full_name AS assigned_name
                 FROM tickets t LEFT JOIN ticket_categories c ON c.id=t.category_id
                 JOIN users cu ON cu.id=t.created_by LEFT JOIN users au ON au.id=t.assigned_to
                 WHERE {' AND '.join(where)} ORDER BY {order} LIMIT 200""", **p)


def r_ticket_new(u, b, qs):
    need(u, "employee")
    subject, desc = (b.get("subject") or "").strip(), (b.get("description") or "").strip()
    pr = b.get("priority", "Medium")
    if not subject or not desc:
        raise Err(400, "Title and description are required")
    if pr not in PRIORITIES or not is_uuid(b.get("category_id")):
        raise Err(400, "Choose a valid category and priority")
    if not q("SELECT 1 AS x FROM ticket_categories WHERE id=CAST(:c AS uuid) AND org_id=CAST(:o AS uuid) AND is_active", c=b["category_id"], o=u["org_id"]):
        raise Err(400, "Choose a valid category")
    r = q("""INSERT INTO tickets (org_id,subject,description,category_id,priority,created_by)
             VALUES (CAST(:o AS uuid),:s,:d,CAST(:c AS uuid),:p,CAST(:u AS uuid)) RETURNING id""",
          o=u["org_id"], s=subject[:200], d=desc[:5000], c=b["category_id"], p=pr, u=u["id"])
    tid = str(r[0]["id"])
    log(tid, u["id"], "created", f"Ticket created with {pr} priority")
    notify_staff(tid, f"{sid(tid)}: new ticket from {u['full_name']} - {subject[:60]}", u["org_id"])
    return {"id": tid}


def r_ticket_get(u, b, qs, tid):
    t = load_ticket(u, tid)
    staff = u["role"] != "employee"
    msgs = q("""SELECT m.id, m.body, m.is_internal, m.created_at, s.full_name AS sender, s.role AS sender_role
                FROM ticket_messages m JOIN users s ON s.id=m.sender_id
                WHERE m.ticket_id=CAST(:t AS uuid)""" + ("" if staff else " AND m.is_internal=FALSE") +
             " ORDER BY m.created_at", t=tid)
    logs = q("""SELECT l.created_at, l.action, l.details, l.is_internal, s.full_name AS actor
                FROM ticket_activity_logs l JOIN users s ON s.id=l.actor_id
                WHERE l.ticket_id=CAST(:t AS uuid)""" + ("" if staff else " AND l.is_internal=FALSE") +
             " ORDER BY l.created_at", t=tid)
    atts = q("""SELECT a.id, a.file_name, a.content_type, a.size_bytes, a.s3_key, a.created_at, x.full_name AS uploader
                FROM ticket_attachments a JOIN users x ON x.id=a.uploaded_by
                WHERE a.ticket_id=CAST(:t AS uuid) ORDER BY a.created_at""", t=tid)
    for a in atts:  # short-lived private download link (5 minutes)
        a["url"] = s3.generate_presigned_url("get_object", ExpiresIn=300, Params={
            "Bucket": BUCKET, "Key": a.pop("s3_key"),
            "ResponseContentDisposition": 'attachment; filename="%s"' % a["file_name"].replace('"', "")})
    t.pop("_assigned")
    return {"ticket": t, "messages": msgs, "attachments": atts, "logs": logs}


def r_msg_add(u, b, qs, tid):
    t = load_ticket(u, tid)
    if u["role"] == "admin":
        raise Err(403, "The administrator can monitor conversations but cannot reply. Employees and IT support handle them.")
    if u["role"] == "it_support" and not can_work(u, t):
        raise Err(403, "This ticket is assigned to another IT support member")
    body = (b.get("body") or "").strip()
    if not body:
        raise Err(400, "Message cannot be empty")
    internal = bool(b.get("internal")) and u["role"] == "it_support"
    q("""INSERT INTO ticket_messages (ticket_id,sender_id,body,is_internal)
         VALUES (CAST(:t AS uuid),CAST(:u AS uuid),:b,:i)""", t=tid, u=u["id"], b=body[:3000], i=internal)
    q("UPDATE tickets SET updated_at=now() WHERE id=CAST(:t AS uuid)", t=tid)
    if internal:
        log(tid, u["id"], "internal_note", "Added an internal note", True)
    elif u["role"] == "it_support":
        log(tid, u["id"], "replied", "Replied to the employee")
        notify(t["created_by"], tid, f"{sid(tid)}: {u['full_name']} replied to your ticket")
    else:
        if t["assigned_to"]:
            notify(t["assigned_to"], tid, f"{sid(tid)}: {u['full_name']} sent a new message")
        else:
            notify_staff(tid, f"{sid(tid)}: {u['full_name']} sent a new message", u["org_id"])
    return {"ok": True}


def r_ticket_patch(u, b, qs, tid):
    t = load_ticket(u, tid)
    sets, p, events = [], {"t": tid}, []
    staff_ok = can_work(u, t)
    if "status" in b and b["status"] != t["status"]:
        s = b["status"]
        if s not in STATUSES:
            raise Err(400, "Invalid status")
        if not (staff_ok or (u["role"] == "employee" and s in ("Open", "Closed"))):
            raise Err(403, "You cannot set this status")
        sets += ["status=:s", "resolved_at=" + ("now()" if s in ("Resolved", "Closed") else "NULL")]
        p["s"] = s
        events.append(("status_changed", f"Status changed from {t['status']} to {s}"))
    if "priority" in b and b["priority"] != t["priority"]:
        if b["priority"] not in PRIORITIES:
            raise Err(400, "Invalid priority")
        if not staff_ok:
            raise Err(403, "Only IT support can change priority")
        sets.append("priority=:pr")
        p["pr"] = b["priority"]
        events.append(("priority_changed", f"Priority changed from {t['priority']} to {b['priority']}"))
    new_assignee = None
    if "assigned_to" in b:
        if not (u["role"] == "admin" or staff_ok):
            raise Err(403, "Only IT support (or the administrator) can assign this ticket")
        new = b["assigned_to"] or None
        if new and not is_uuid(new):
            raise Err(400, "Invalid staff member")
        who = "nobody"
        if new:
            ok = q("SELECT full_name FROM users WHERE id=CAST(:i AS uuid) AND is_active AND role='it_support' AND org_id=CAST(:o AS uuid)", i=new, o=u["org_id"])
            if not ok:
                raise Err(400, "Pick an active IT support member")
            who = ok[0]["full_name"]
        if (str(t["assigned_to"]) if t["assigned_to"] else None) != new:
            sets.append("assigned_to=CAST(:a AS uuid)")
            p["a"] = new
            new_assignee = new
            events.append(("assigned", f"Assigned to {who}"))
            q("""INSERT INTO ticket_assignments (ticket_id,assigned_to,assigned_by)
                 VALUES (CAST(:t AS uuid),CAST(:a AS uuid),CAST(:u AS uuid))""", t=tid, a=new, u=u["id"])
    if sets:
        q(f"UPDATE tickets SET {', '.join(sets)}, updated_at=now() WHERE id=CAST(:t AS uuid)", **p)
        for action, text in events:
            log(tid, u["id"], action, text)
            if u["role"] == "employee":
                notify(t["assigned_to"], tid, f"{sid(tid)}: {u['full_name']} - {text}")
            else:
                notify(t["created_by"], tid, f"{sid(tid)}: {text}")
        if new_assignee and new_assignee != u["id"]:
            notify(new_assignee, tid, f"{sid(tid)}: this ticket was assigned to you")
    return {"ok": True}


def r_ticket_delete(u, b, qs, tid):
    t = load_ticket(u, tid)
    if u["role"] != "employee":
        raise Err(403, "Only the employee who submitted a ticket can delete it")
    if t["status"] != "Open" or t["assigned_to"] is not None:
        raise Err(400, "This ticket is already being handled, so it cannot be deleted. You can close it instead.")
    keys = [a["s3_key"] for a in q("SELECT s3_key FROM ticket_attachments WHERE ticket_id=CAST(:t AS uuid)", t=tid)]
    for tbl in ("notifications", "ticket_activity_logs", "ticket_messages", "ticket_attachments", "ticket_assignments"):
        q(f"DELETE FROM {tbl} WHERE ticket_id=CAST(:t AS uuid)", t=tid)
    q("DELETE FROM tickets WHERE id=CAST(:t AS uuid)", t=tid)
    for k in keys:  # best effort: remove the files too (needs s3:DeleteObject, ignored if not allowed)
        try:
            s3.delete_object(Bucket=BUCKET, Key=k)
        except Exception:
            pass
    return {"ok": True}


def check_upload(u, t):
    if u["role"] == "admin" or (u["role"] == "it_support" and not can_work(u, t)):
        raise Err(403, "You cannot attach files to this ticket")


def r_presign(u, b, qs, tid):
    check_upload(u, load_ticket(u, tid))
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
    check_upload(u, load_ticket(u, tid))
    key = b.get("s3_key") or ""
    if not key.startswith(f"tickets/{tid}/"):
        raise Err(400, "Invalid file reference")
    q("""INSERT INTO ticket_attachments (ticket_id,uploaded_by,s3_key,file_name,content_type,size_bytes)
         VALUES (CAST(:t AS uuid),CAST(:u AS uuid),:k,:n,:c,:s)""",
      t=tid, u=u["id"], k=key, n=b.get("file_name", "file"), c=b.get("content_type", ""), s=int(b.get("size") or 0))
    log(tid, u["id"], "attachment_added", f"Attached file: {b.get('file_name', 'file')}")
    return {"ok": True}


def r_notifs(u, b, qs):
    items = q("""SELECT id, ticket_id, message, is_read, created_at FROM notifications
                 WHERE user_id=CAST(:u AS uuid) ORDER BY created_at DESC LIMIT 50""", u=u["id"])
    return {"unread": sum(1 for i in items if not i["is_read"]), "items": items}


def r_notifs_read(u, b, qs):
    if is_uuid(b.get("id")):  # opening one notification marks just that one as read
        q("UPDATE notifications SET is_read=TRUE WHERE user_id=CAST(:u AS uuid) AND id=CAST(:i AS uuid)", u=u["id"], i=b["id"])
    else:
        q("UPDATE notifications SET is_read=TRUE WHERE user_id=CAST(:u AS uuid) AND is_read=FALSE", u=u["id"])
    return {"ok": True}


def r_users(u, b, qs):
    need(u, "admin")
    return q("SELECT id, email, full_name, role, is_active, created_at FROM users WHERE org_id=CAST(:o AS uuid) ORDER BY created_at", o=u["org_id"])


def r_user_create(u, b, qs):
    need(u, "admin")
    email, name = (b.get("email") or "").strip().lower(), (b.get("full_name") or "").strip()
    role, pw = b.get("role", "employee"), b.get("password") or ""
    if not email or not name or role not in ROLES:
        raise Err(400, "Name, email and a valid role are required")
    if not POOL:
        raise Err(500, "USER_POOL_ID is not set on the Lambda function")
    if q("SELECT 1 AS x FROM users WHERE email=:e", e=email):
        raise Err(400, "That email already belongs to a helpdesk account")
    note = "Account created"
    try:
        r = cognito.admin_create_user(UserPoolId=POOL, Username=email, MessageAction="SUPPRESS", UserAttributes=[
            {"Name": "email", "Value": email}, {"Name": "email_verified", "Value": "true"}, {"Name": "name", "Value": name}])
        sub = next(a["Value"] for a in r["User"]["Attributes"] if a["Name"] == "sub")
        try:
            cognito.admin_set_user_password(UserPoolId=POOL, Username=email, Password=pw, Permanent=True)
        except Exception:
            cognito.admin_delete_user(UserPoolId=POOL, Username=email)
            raise Err(400, "Password too weak: use 8+ characters with upper and lower case, a number and a symbol")
    except cognito.exceptions.UsernameExistsException:
        # The person already has a login but has not entered any helpdesk yet: link it, keep their own password.
        info = cognito.admin_get_user(UserPoolId=POOL, Username=email)
        sub = next(a["Value"] for a in info["UserAttributes"] if a["Name"] == "sub")
        note = "That email already had a login, so it was linked to your helpdesk. They keep their own password."
    q("INSERT INTO users (cognito_sub,email,full_name,role,org_id) VALUES (:s,:e,:n,:r,CAST(:o AS uuid))",
      s=sub, e=email, n=name[:100], r=role, o=u["org_id"])
    return {"ok": True, "note": note}


def r_user_patch(u, b, qs, uid):
    need(u, "admin")  # only administrators can change roles or account status
    if not is_uuid(uid):
        raise Err(404, "Not found")
    if uid == u["id"]:
        raise Err(400, "You cannot change your own role or status")
    if not q("SELECT 1 AS x FROM users WHERE id=CAST(:i AS uuid) AND org_id=CAST(:o AS uuid)", i=uid, o=u["org_id"]):
        raise Err(404, "User not found")
    if "role" in b:
        if b["role"] not in ROLES:
            raise Err(400, "Invalid role")
        q("UPDATE users SET role=:r WHERE id=CAST(:i AS uuid)", r=b["role"], i=uid)
    if "is_active" in b:
        q("UPDATE users SET is_active=:a WHERE id=CAST(:i AS uuid)", a=bool(b["is_active"]), i=uid)
    return {"ok": True}


def r_user_delete(u, b, qs, uid):
    need(u, "admin")
    if not is_uuid(uid):
        raise Err(404, "Not found")
    if uid == u["id"]:
        raise Err(400, "You cannot delete your own account")
    row = q("SELECT email, cognito_sub FROM users WHERE id=CAST(:i AS uuid) AND org_id=CAST(:o AS uuid)", i=uid, o=u["org_id"])
    if not row:
        raise Err(404, "User not found")
    # Keep the ticket history intact: only accounts with no tickets, messages, files or actions can be deleted.
    used = q("""SELECT
        (SELECT COUNT(*) FROM tickets WHERE created_by=CAST(:i AS uuid) OR assigned_to=CAST(:i AS uuid)) +
        (SELECT COUNT(*) FROM ticket_messages WHERE sender_id=CAST(:i AS uuid)) +
        (SELECT COUNT(*) FROM ticket_attachments WHERE uploaded_by=CAST(:i AS uuid)) +
        (SELECT COUNT(*) FROM ticket_assignments WHERE assigned_to=CAST(:i AS uuid) OR assigned_by=CAST(:i AS uuid)) +
        (SELECT COUNT(*) FROM ticket_activity_logs WHERE actor_id=CAST(:i AS uuid)) AS n""", i=uid)[0]["n"]
    if used:
        raise Err(400, "This user already has tickets or activity, so deleting would break the ticket history. Untick Active to disable the account instead.")
    q("DELETE FROM notifications WHERE user_id=CAST(:i AS uuid)", i=uid)
    q("DELETE FROM users WHERE id=CAST(:i AS uuid)", i=uid)
    if POOL:  # also remove the login so the person cannot sign in again
        for name in (row[0]["email"], row[0]["cognito_sub"]):
            try:
                cognito.admin_delete_user(UserPoolId=POOL, Username=name)
                break
            except Exception:
                continue
    return {"ok": True}


def r_staff(u, b, qs):
    need(u, "admin", "it_support")
    return q("SELECT id, full_name FROM users WHERE is_active AND role='it_support' AND org_id=CAST(:o AS uuid) ORDER BY full_name", o=u["org_id"])


def r_activity(u, b, qs):
    need(u, "admin")  # what IT support staff have been doing
    return q("""SELECT l.created_at, l.action, l.details, s.full_name AS actor, t.id AS ticket_id, t.subject
                FROM ticket_activity_logs l JOIN users s ON s.id=l.actor_id JOIN tickets t ON t.id=l.ticket_id
                WHERE s.role='it_support' AND t.org_id=CAST(:o AS uuid)
                ORDER BY l.created_at DESC LIMIT 100""", o=u["org_id"])


ROUTES = [
    ("GET", r"/api/me", r_me), ("GET", r"/api/stats", r_stats),
    ("GET", r"/api/categories", r_categories), ("POST", r"/api/categories", r_cat_add),
    ("POST", r"/api/categories/([\w-]+)/toggle", r_cat_toggle),
    ("GET", r"/api/tickets", r_tickets), ("POST", r"/api/tickets", r_ticket_new),
    ("GET", r"/api/tickets/([\w-]+)", r_ticket_get), ("PATCH", r"/api/tickets/([\w-]+)", r_ticket_patch),
    ("DELETE", r"/api/tickets/([\w-]+)", r_ticket_delete),
    ("POST", r"/api/tickets/([\w-]+)/messages", r_msg_add),
    ("POST", r"/api/tickets/([\w-]+)/attachments/presign", r_presign),
    ("POST", r"/api/tickets/([\w-]+)/attachments", r_attach_save),
    ("GET", r"/api/notifications", r_notifs), ("POST", r"/api/notifications/read", r_notifs_read),
    ("GET", r"/api/activity", r_activity), ("GET", r"/api/staff", r_staff),
    ("GET", r"/api/users", r_users), ("POST", r"/api/users", r_user_create),
    ("PATCH", r"/api/users/([\w-]+)", r_user_patch), ("DELETE", r"/api/users/([\w-]+)", r_user_delete),
]


def run_schema(reset):
    global C
    C = connect()
    stmts = [f"DROP TABLE IF EXISTS {t}" for t in RESET] if reset else []
    stmts += [s.strip() for s in SCHEMA.split(";") if s.strip()]
    res = []
    for stmt in stmts:
        try:
            C.run(stmt)
            res.append("OK   " + stmt[:60].replace("\n", " "))
        except Exception as e:
            res.append("SKIP " + stmt[:45].replace("\n", " ") + " -> " + str(e)[:150])
    C.close()
    return res


def lambda_handler(event, context):
    global C
    if "action" in event:  # Test event from the Lambda console: {"action":"init"} or {"action":"reset"}
        return run_schema(event["action"] == "reset")
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
