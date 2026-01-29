import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from firebase_admin import auth, credentials, firestore, initialize_app, storage

APP_TIMEZONE = timezone.utc
STORY_TTL_HOURS = 24
MESSAGE_TTL_DAYS = 7
SIGNED_URL_MINUTES = 10
STORY_VIEW_URL_MINUTES = 2
IMAGE_EXTENSIONS = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}
RATE_LIMITS = {
    "stories:create": (5, 24 * 60 * 60),
    "messages:create": (200, 60),
    "reports:create": (60, 60 * 60),
    "connections:invite": (20, 60 * 60),
}

RATE_BUCKETS = {}

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")


def init_firebase():
    """Initialize the Firebase Admin SDK from a service-account file.

    Reads the path from the `FIREBASE_CREDENTIALS_PATH` environment
    variable (defaults to `firebase-sa-creds.json`) and calls
    `initialize_app` with the loaded credentials.

    Raises:
        FileNotFoundError: if the credentials file cannot be found.
    """

    creds_path = os.getenv("FIREBASE_CREDENTIALS_PATH", "firebase-sa-creds.json")
    if not os.path.exists(creds_path):
        raise FileNotFoundError(
            "Firebase credentials file not found. Set FIREBASE_CREDENTIALS_PATH or "
            "place firebase-sa-creds.json in the project root."
        )

    cred = credentials.Certificate(creds_path)
    initialize_app(cred)


init_firebase()

import json
creds_path = os.getenv("FIREBASE_CREDENTIALS_PATH", "firebase-sa-creds.json")
with open(creds_path, "r", encoding="utf-8") as f:
    sa = json.load(f)
project_id = sa["project_id"]
bucket_name = sa.get("storageBucket", f"{project_id}.appspot.com")

firebase_web_config_path = os.getenv("FIREBASE_WEB_CONFIG_PATH", "firebase-creds.json")
with open(firebase_web_config_path, "r", encoding="utf-8") as f:
    firebase_web_config = json.load(f)

db = firestore.client()
bucket = storage.bucket(bucket_name)


def now_utc():
    """Return the current timezone-aware UTC datetime.

    Returns:
        datetime: timezone-aware datetime in UTC (as defined by APP_TIMEZONE).
    """
    return datetime.now(APP_TIMEZONE)


def serialize_datetime(value):
    """Serialize a datetime to an ISO 8601 string for JSON responses.

    If `value` is a `datetime` instance, returns its ISO string, otherwise
    returns the value unchanged.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def get_user_doc(uid):
    """Return a Firestore DocumentReference for `users/{uid}`.

    Args:
        uid (str): Firebase user UID.

    Returns:
        google.cloud.firestore_v1.document.DocumentReference
    """
    return db.collection("users").document(uid)


def get_chat_doc(chat_id):
    """Return a Firestore DocumentReference for `chats/{chat_id}`.

    Args:
        chat_id (str): Chat identifier.
    """
    return db.collection("chats").document(chat_id)


def get_story_doc(story_id):
    """Return a Firestore DocumentReference for `stories/{story_id}`.

    Args:
        story_id (str): Story identifier.
    """
    return db.collection("stories").document(story_id)


def get_story_media_doc(media_id):
    """Return a Firestore DocumentReference for `story_media/{media_id}`.

    Args:
        media_id (str): Story media identifier.
    """
    return db.collection("story_media").document(media_id)


def get_message_doc(message_id):
    """Return a Firestore DocumentReference for `messages/{message_id}`.

    Args:
        message_id (str): Message identifier.
    """
    return db.collection("messages").document(message_id)


def get_connection_doc(connection_id):
    """Return a Firestore DocumentReference for `connections/{connection_id}`.

    Args:
        connection_id (str): Connection identifier.
    """
    return db.collection("connections").document(connection_id)


def check_rate_limit(uid, action_key):
    """Simple in-memory rate limiter.

    Tracks timestamps per `(uid, action_key)` and aborts with HTTP 429
    when the number of events in the configured window exceeds the limit.

    Args:
        uid (str): User identifier.
        action_key (str): Key for the rate limit defined in RATE_LIMITS.
    """
    limit, window_seconds = RATE_LIMITS[action_key]
    now_ts = time.time()
    bucket_key = (uid, action_key)
    timestamps = RATE_BUCKETS.get(bucket_key, [])
    timestamps = [ts for ts in timestamps if now_ts - ts < window_seconds]
    if len(timestamps) >= limit:
        abort(429, description="Rate limit exceeded")
    timestamps.append(now_ts)
    RATE_BUCKETS[bucket_key] = timestamps


def verify_id_token():
    """Verify and decode a Firebase ID token from the `Authorization` header.

    Expects header in the form `Authorization: Bearer <id_token>`. Returns the
    decoded token (claims) on success or aborts with HTTP 401 on failure.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        abort(401, description="Missing auth token")
    token = auth_header.split(" ", 1)[1].strip()
    try:
        return auth.verify_id_token(token)
    except Exception as exc:
        abort(401, description=f"Invalid auth token: {exc}")


def require_auth(fn):
    """Decorator for endpoints that require a valid, verified user.

    Verifies the incoming ID token, enforces `email_verified`, checks for a
    suspended account in Firestore, and attaches a lightweight `request.user`
    dict with `uid`, `email`, and `name` for use in the handler.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        decoded = verify_id_token()

        if not decoded.get("email_verified"):
            abort(403, description="Email not verified")

        uid = decoded.get("uid")
        if not uid:
            abort(401, description="Invalid auth token")

        user_snap = get_user_doc(uid).get()
        if user_snap.exists and user_snap.to_dict().get("isSuspended"):
            abort(403, description="Account suspended")

        request.user = {
            "uid": uid,
            "email": decoded.get("email"),
            "name": decoded.get("name"),
        }
        return fn(*args, **kwargs)

    return wrapper


def ensure_user_profile(uid):
    """Ensure a Firestore `users/{uid}` profile exists and return it.

    Aborts with HTTP 400 if the profile document is missing.
    """
    user_snap = get_user_doc(uid).get()
    if not user_snap.exists:
        abort(400, description="User profile not found. Create profile first.")
    return user_snap.to_dict()


def get_user_profile(uid):
    """Return the `users/{uid}` profile dict or None if it doesn't exist."""
    user_snap = get_user_doc(uid).get()
    return user_snap.to_dict() if user_snap.exists else None


def render_page(template_name, **context):
    """Render a Jinja template and inject `firebase_web_config`.

    This helper centralizes rendering so templates have client Firebase
    configuration available as `firebase_config`.
    """
    return render_template(
        template_name,
        firebase_config=firebase_web_config,
        **context,
    )


@app.before_request
def enforce_page_auth():
    if request.path.startswith("/api"):
        return None
    if request.path.startswith("/static"):
        return None
    if request.path in {"/login", "/health"}:
        return None
    if request.path == "/":
        if session.get("uid") and session.get("verified"):
            return redirect(url_for("home"))
        return redirect(url_for("login"))

    uid = session.get("uid")
    verified = session.get("verified")
    if not uid:
        return redirect(url_for("login"))
    if not verified:
        return redirect(url_for("login", verify="true"))
    return None


def generate_storage_path(prefix, entity_id, content_type):
    """Generate a storage path for uploads using the content type's extension.

    Args:
        prefix (str): Storage prefix (e.g. "stories/{uid}/{story_id}").
        entity_id (str): Unique id to use as filename (without extension).
        content_type (str): MIME type of the file (must be in IMAGE_EXTENSIONS).

    Returns:
        str: A storage path like "prefix/entity_id.ext".

    Raises:
        aborts with 400 if content_type is unsupported.
    """
    extension = IMAGE_EXTENSIONS.get(content_type)
    if not extension:
        abort(400, description="Unsupported content type")
    return f"{prefix}/{entity_id}.{extension}"


def generate_signed_url(path, method, content_type=None, minutes=SIGNED_URL_MINUTES):
    """Generate a signed URL for a storage object.

    Args:
        path (str): Storage object path within the bucket.
        method (str): HTTP method allowed for the signed URL (e.g. 'GET', 'PUT').
        content_type (str|None): Optional content type to restrict upload.
        minutes (int): URL expiration in minutes.

    Returns:
        str: A signed URL string.
    """
    blob = bucket.blob(path)
    return blob.generate_signed_url(
        expiration=timedelta(minutes=minutes),
        method=method,
        content_type=content_type,
    )


def require_chat_member(chat_id, uid):
    chat_snap = get_chat_doc(chat_id).get()
    if not chat_snap.exists:
        abort(404, description="Chat not found")
    chat = chat_snap.to_dict()
    participants = chat.get("participants", [])
    if uid not in participants:
        abort(403, description="Not authorized for this chat")
    return chat


def check_connection_status(uid1, uid2):
    """Check if two users have an accepted connection.
    
    Returns connection dict if accepted, None otherwise.
    """
    # Check in both directions
    query1 = db.collection("connections").where(
        "requesterUid", "==", uid1
    ).where("recipientUid", "==", uid2).where("status", "==", "ACCEPTED").limit(1).stream()
    
    for doc in query1:
        return doc.to_dict()
    
    query2 = db.collection("connections").where(
        "requesterUid", "==", uid2
    ).where("recipientUid", "==", uid1).where("status", "==", "ACCEPTED").limit(1).stream()
    
    for doc in query2:
        return doc.to_dict()
    
    return None


def get_pending_connection(uid1, uid2):
    """Get pending connection between two users if exists.
    
    Returns tuple (connection_id, connection_dict, direction) where direction is 
    'sent' if uid1 is requester, 'received' if uid1 is recipient, None if no pending connection.
    """
    # Check if uid1 sent to uid2
    query1 = db.collection("connections").where(
        "requesterUid", "==", uid1
    ).where("recipientUid", "==", uid2).where("status", "==", "PENDING").limit(1).stream()
    
    for doc in query1:
        return doc.id, doc.to_dict(), "sent"
    
    # Check if uid2 sent to uid1
    query2 = db.collection("connections").where(
        "requesterUid", "==", uid2
    ).where("recipientUid", "==", uid1).where("status", "==", "PENDING").limit(1).stream()
    
    for doc in query2:
        return doc.id, doc.to_dict(), "received"
    
    return None, None, None


@app.route("/")
def index():
    """Root page redirect.

    Redirects authenticated & verified users to `/home`, otherwise to `/login`.
    """
    if session.get("uid") and session.get("verified"):
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/login")
def login():
    """Render the login page.

    Query string `verify=true` will show verification instructions.
    """
    return render_page("login.html", verify=request.args.get("verify") == "true")


@app.route("/home")
def home():
    """Render the authenticated user's home page.

    Requires the lightweight session populated by `/api/session` for routing.
    """
    return render_page("home.html")


@app.route("/messages")
def messages_home():
    """Render the messages list page for the signed-in user."""
    return render_page("messages.html")


@app.route("/messages/<user_id>")
def messages_thread(user_id):
    """Render a direct message thread with `partner_uid`.

    Args:
        user_id: partner user's UID, injected into the template as `partner_uid`.
    """
    return render_page("message_thread.html", partner_uid=user_id)


@app.route("/addstory")
def add_story():
    """Render the page for creating/uploading a new story."""
    return render_page("add_story.html")


@app.route("/health")
def health():
    """Health check endpoint.

    Returns current server time and status OK.
    """
    return jsonify({"status": "ok", "time": now_utc().isoformat()})


@app.route("/api/auth/verify", methods=["POST"])
@require_auth
def verify_auth():
    """Confirm that the presented ID token belongs to a verified user.

    Protected by `require_auth` which enforces `email_verified` on the token.
    Returns the `uid` and `email` on success.
    """
    return jsonify({
        "uid": request.user["uid"],
        "email": request.user["email"],
        "verified": True,
    })


@app.route("/api/session", methods=["POST"])
def create_session():
    """Create a lightweight server session from a Firebase ID token.

    Expects header: `Authorization: Bearer <id_token>`.
    Stores `uid`, `verified` and `email` in the Flask session for page routing.
    Returns the stored session values as JSON.
    """
    decoded = verify_id_token()
    session["uid"] = decoded.get("uid")
    session["verified"] = bool(decoded.get("email_verified"))
    session["email"] = decoded.get("email")
    return jsonify({
        "uid": session.get("uid"),
        "verified": session.get("verified"),
        "email": session.get("email"),
    })


@app.route("/api/session", methods=["DELETE"])
def clear_session():
    """Clear the server-side session (sign out).

    Removes all session keys. Client should also sign out from Firebase.
    """
    session.clear()
    return jsonify({"status": "signed_out"})


@app.route("/api/users/bootstrap", methods=["POST"])
def bootstrap_user():
    """Create minimal user profile document if missing.

    Expects a valid ID token in the `Authorization` header. If the
    `users/{uid}` document does not exist, initializes default profile fields.
    Returns the `uid`.
    """
    decoded = verify_id_token()
    uid = decoded.get("uid")
    if not uid:
        abort(401, description="Invalid auth token")

    user_ref = get_user_doc(uid)
    user_snap = user_ref.get()
    if not user_snap.exists:
        user_ref.set({
            "username": None,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "isSuspended": False,
            "storyPosted": False,
            "storyPostedAt": None,
        })

    return jsonify({"uid": uid})


@app.route("/api/users", methods=["POST"])
@require_auth
def create_user():
    """Create or update the authenticated user's profile.

    JSON body: {"username": "desired_name"}
    Requires authentication via `require_auth`. Ensures username uniqueness.
    Returns `uid` and `username` on success.
    """
    payload = request.get_json(force=True)
    username = payload.get("username", "").strip()
    if not username:
        abort(400, description="username is required")

    existing = db.collection("users").where("username", "==", username).limit(1).get()
    if existing:
        abort(409, description="Username already taken")

    user_ref = get_user_doc(request.user["uid"])
    user_ref.set({
        "username": username,
        "createdAt": firestore.SERVER_TIMESTAMP,
        "isSuspended": False,
        "storyPosted": False,
        "storyPostedAt": None,
    }, merge=True)

    return jsonify({"uid": request.user["uid"], "username": username})


@app.route("/api/users/me", methods=["GET"])
@require_auth
def get_me():
    """Return the authenticated user's profile summary.

    Requires `require_auth`. Returns `uid`, `username`, and story metadata.
    """
    profile = ensure_user_profile(request.user["uid"])
    return jsonify({
        "uid": request.user["uid"],
        "username": profile.get("username"),
        "storyPosted": profile.get("storyPosted", False),
        "storyPostedAt": serialize_datetime(profile.get("storyPostedAt")),
    })


@app.route("/api/users/friends", methods=["GET"])
@require_auth
def list_friends():
    """List other users as potential friends.

    Returns a list of user summaries (uid, username). Requires auth.
    """
    friends = []
    for doc in db.collection("users").stream():
        if doc.id == request.user["uid"]:
            continue
        data = doc.to_dict()
        friends.append({
            "uid": doc.id,
            "username": data.get("username") or "Unknown",
        })
    return jsonify({"friends": friends})


@app.route("/api/stories", methods=["GET"])
@require_auth
def list_stories():
    """List active stories visible to the user.

    This function retrieves and returns a list of active stories that are visible to the authenticated user. 
    A story is considered active if its `expiresAt` timestamp is in the future. Each story includes information 
    about the story's owner, media, and timestamps.

    Returns:
        flask.Response: A JSON response containing a list of active stories. Each story in the list includes:
            - storyId (str): The unique identifier of the story.
            - ownerUid (str): The unique identifier of the story's owner.
            - ownerUsername (str): The username of the story's owner. Defaults to "Unknown" if the owner's profile is unavailable.
            - mediaId (str): The unique identifier of the associated media.
            - createdAt (str): The creation timestamp of the story, serialized as a string.
            - expiresAt (str): The expiration timestamp of the story, serialized as a string.

    Raises:
        Exception: If the user's profile cannot be ensured or if there are issues retrieving data from the database.

    Notes:
        - This function requires the user to be authenticated.
        - The `ensure_user_profile` function is called to verify the user's profile.
        - The `serialize_datetime` function is used to convert datetime objects to strings.
    """
    ensure_user_profile(request.user["uid"])
    now = now_utc()
    stories = []
    for doc in db.collection("stories").where("expiresAt", ">", now).stream():
        data = doc.to_dict()
        media_snapshots = (
            db.collection("story_media")
            .where("storyId", "==", doc.id)
            .limit(1)
            .stream()
        )
        media_doc = next(media_snapshots, None)
        if not media_doc:
            continue
        owner_profile = get_user_profile(data.get("ownerUid"))
        stories.append({
            "storyId": doc.id,
            "ownerUid": data.get("ownerUid"),
            "ownerUsername": owner_profile.get("username") if owner_profile else "Unknown",
            "mediaId": media_doc.id,
            "createdAt": serialize_datetime(data.get("createdAt")),
            "expiresAt": serialize_datetime(data.get("expiresAt")),
        })
    return jsonify({"stories": stories})


@app.route("/api/stories", methods=["POST"])
@require_auth
def create_story():
    """
    Endpoint to create a new story.
    This endpoint allows an authenticated user to create a new story. It enforces rate limits
    and ensures that users cannot post multiple stories within a specified time-to-live (TTL) period.
    Returns:
        JSON response containing:
            - storyId (str): Unique identifier for the created story.
            - mediaId (str): Unique identifier for the associated media.
            - storagePath (str): Path for client-side Firebase Storage upload.
            - expiresAt (str): ISO 8601 timestamp indicating when the story will expire.
    Raises:
        429 Too Many Requests: If the user has already posted a story within the TTL period.
        400 Bad Request: If the required `contentType` field is missing in the request payload.
    """
    """Create a new story and return a storage path for client-side upload."""
    profile = ensure_user_profile(request.user["uid"])
    check_rate_limit(request.user["uid"], "stories:create")

    if profile.get("storyPosted"):
        posted_at = profile.get("storyPostedAt")
        if isinstance(posted_at, datetime) and now_utc() - posted_at < timedelta(hours=STORY_TTL_HOURS):
            abort(429, description="Story limit reached")

    payload = request.get_json(force=True)
    content_type = payload.get("contentType")
    if not content_type:
        abort(400, description="contentType is required")

    story_id = str(uuid.uuid4())
    media_id = str(uuid.uuid4())
    created_at = now_utc()
    expires_at = created_at + timedelta(hours=STORY_TTL_HOURS)

    get_story_doc(story_id).set({
        "ownerUid": request.user["uid"],
        "createdAt": created_at,
        "expiresAt": expires_at,
    })

    storage_path = generate_storage_path(
        f"stories/{request.user['uid']}/{story_id}", media_id, content_type
    )
    get_story_media_doc(media_id).set({
        "storyId": story_id,
        "ownerUid": request.user["uid"],
        "storagePath": storage_path,
        "createdAt": created_at,
        "viewedBy": [],
    })

    get_user_doc(request.user["uid"]).set({
        "storyPosted": True,
        "storyPostedAt": created_at,
    }, merge=True)

    # Return storagePath for client-side Firebase Storage upload (no signed URL → no CORS)
    return jsonify({
        "storyId": story_id,
        "mediaId": media_id,
        "storagePath": storage_path,
        "expiresAt": expires_at.isoformat(),
    })


@app.route("/api/stories/<story_id>/media/<media_id>/view", methods=["POST"])
@require_auth
def view_story_media(story_id, media_id):
    """Mark a story media as viewed and return a short-lived view URL.

    Requires auth. Ensures the story is not expired and the requesting user
    hasn't already viewed the media. Returns a signed `viewUrl` valid for a
    short duration (configured by STORY_VIEW_URL_MINUTES).
    """
    ensure_user_profile(request.user["uid"])

    story_snap = get_story_doc(story_id).get()
    if not story_snap.exists:
        abort(404, description="Story not found")
    story = story_snap.to_dict()
    if story.get("expiresAt") and story["expiresAt"] <= now_utc():
        abort(410, description="Story expired")

    media_snap = get_story_media_doc(media_id).get()
    if not media_snap.exists:
        abort(404, description="Story media not found")
    media = media_snap.to_dict()
    if media.get("storyId") != story_id:
        abort(400, description="Media does not belong to story")

    if request.user["uid"] in media.get("viewedBy", []):
        abort(403, description="Story already viewed")

    media_ref = get_story_media_doc(media_id)
    media_ref.update({"viewedBy": firestore.ArrayUnion([request.user["uid"]])})

    signed_url = generate_signed_url(
        media["storagePath"],
        method="GET",
        minutes=STORY_VIEW_URL_MINUTES,
    )
    return jsonify({"viewUrl": signed_url})


@app.route("/api/chats", methods=["POST"])
@require_auth
def create_chat():
    """Create (or return existing) a one-to-one chat between two users.

    JSON body: {"participantUid": "other-user-uid"}
    Requires auth. Returns `chatId` and `participants`.
    Requires an accepted connection between users.
    """
    ensure_user_profile(request.user["uid"])
    payload = request.get_json(force=True)
    participant_uid = payload.get("participantUid")
    if not participant_uid:
        abort(400, description="participantUid is required")
    
    # Check if connection is accepted
    connection = check_connection_status(request.user["uid"], participant_uid)
    if not connection:
        abort(403, description="Connection must be accepted before messaging")

    participants = sorted({request.user["uid"], participant_uid})
    chat_id = "_".join(participants)
    chat_ref = get_chat_doc(chat_id)
    if not chat_ref.get().exists:
        chat_ref.set({
            "participants": participants,
            "createdAt": firestore.SERVER_TIMESTAMP,
        })

    return jsonify({"chatId": chat_id, "participants": participants})


@app.route("/api/chats", methods=["GET"])
@require_auth
def list_chats():
    """List chats that include the authenticated user.

    Returns chat summaries including `chatId`, `participants`, and `createdAt`.
    """
    ensure_user_profile(request.user["uid"])
    chats = []
    for doc in db.collection("chats").where("participants", "array_contains", request.user["uid"]).stream():
        data = doc.to_dict()
        chats.append({
            "chatId": doc.id,
            "participants": data.get("participants", []),
            "createdAt": serialize_datetime(data.get("createdAt")),
        })
    return jsonify({"chats": chats})


@app.route("/api/chats/<chat_id>/messages", methods=["GET"])
@require_auth
def list_messages(chat_id):
    """List recent messages for a chat.

    Query params: `limit` (optional, default 50). Requires membership in the chat.
    Returns messages ordered by `createdAt` descending.
    """
    ensure_user_profile(request.user["uid"])
    require_chat_member(chat_id, request.user["uid"])
    limit = int(request.args.get("limit", 50))
    messages = []
    query = (
        db.collection("messages")
        .where("chatId", "==", chat_id)
        .order_by("createdAt", direction=firestore.Query.DESCENDING)
        .limit(limit)
    )
    for doc in query.stream():
        data = doc.to_dict()
        messages.append({
            "messageId": doc.id,
            "chatId": data.get("chatId"),
            "senderUid": data.get("senderUid"),
            "type": data.get("type"),
            "contentRef": data.get("contentRef"),
            "viewedBy": data.get("viewedBy", []),
            "createdAt": serialize_datetime(data.get("createdAt")),
        })
    return jsonify({"messages": messages})


@app.route("/api/chats/<chat_id>/messages", methods=["POST"])
@require_auth
def create_message(chat_id):
    """Create a new message in a chat.

    JSON body for text: {"type": "text", "text": "..."}
    JSON body for image: {"type": "image", "contentType": "image/png"}
    Returns `messageId` and, for image messages, an `uploadUrl`.
    """
    ensure_user_profile(request.user["uid"])
    check_rate_limit(request.user["uid"], "messages:create")
    chat = require_chat_member(chat_id, request.user["uid"])

    payload = request.get_json(force=True)
    message_type = payload.get("type")
    if message_type not in {"text", "image"}:
        abort(400, description="type must be text or image")

    message_id = str(uuid.uuid4())
    message_ref = get_message_doc(message_id)

    base_message = {
        "chatId": chat_id,
        "senderUid": request.user["uid"],
        "type": message_type,
        "createdAt": now_utc(),
        "viewedBy": [],
    }

    if message_type == "text":
        content = payload.get("text", "").strip()
        if not content:
            abort(400, description="text is required")
        base_message["contentRef"] = content
        message_ref.set(base_message)
        return jsonify({"messageId": message_id})

    content_type = payload.get("contentType")
    if not content_type:
        abort(400, description="contentType is required for image messages")

    storage_path = generate_storage_path(
        f"messages/{chat_id}/{message_id}",
        message_id,
        content_type,
    )
    base_message["contentRef"] = storage_path
    base_message["viewed"] = False
    message_ref.set(base_message)

    upload_url = generate_signed_url(
        storage_path,
        method="PUT",
        content_type=content_type,
    )
    return jsonify({"messageId": message_id, "uploadUrl": upload_url, "chat": chat})


@app.route("/api/messages/<message_id>/view", methods=["POST"])
@require_auth
def view_message(message_id):
    """Mark an image message as viewed once and return a short-lived URL.

    Only image messages may be viewed this way. Marks the viewer in `viewedBy`
    and sets `deleteAfter` for the message. Returns a signed `viewUrl`.
    """
    ensure_user_profile(request.user["uid"])
    message_snap = get_message_doc(message_id).get()
    if not message_snap.exists:
        abort(404, description="Message not found")

    message = message_snap.to_dict()
    if message.get("type") != "image":
        abort(400, description="Only image messages can be viewed once")

    chat_id = message.get("chatId")
    require_chat_member(chat_id, request.user["uid"])

    if request.user["uid"] == message.get("senderUid"):
        abort(403, description="Sender cannot view their own image")

    if request.user["uid"] in message.get("viewedBy", []):
        abort(403, description="Image already viewed")

    message_ref = get_message_doc(message_id)
    message_ref.update({
        "viewedBy": firestore.ArrayUnion([request.user["uid"]]),
        "viewed": True,
        "deleteAfter": now_utc() + timedelta(minutes=5),
    })

    signed_url = generate_signed_url(
        message["contentRef"],
        method="GET",
        minutes=STORY_VIEW_URL_MINUTES,
    )
    return jsonify({"viewUrl": signed_url})


@app.route("/api/connections/invite", methods=["POST"])
@require_auth
def send_invite():
    """Send a connection invitation to another user.
    
    JSON body: {
        "recipientUid": "uid",
        "inviteMessage": "optional message",
        "contextType": "group|post|null",
        "contextId": "optional id"
    }
    Requires auth. Returns the created connectionId.
    """
    ensure_user_profile(request.user["uid"])
    check_rate_limit(request.user["uid"], "connections:invite")
    
    payload = request.get_json(force=True)
    recipient_uid = payload.get("recipientUid")
    invite_message = payload.get("inviteMessage", "").strip()
    context_type = payload.get("contextType")
    context_id = payload.get("contextId")
    
    if not recipient_uid:
        abort(400, description="recipientUid is required")
    
    if recipient_uid == request.user["uid"]:
        abort(400, description="Cannot invite yourself")
    
    # Check if recipient exists
    recipient = get_user_profile(recipient_uid)
    if not recipient:
        abort(404, description="Recipient user not found")
    
    # Check for existing connection
    existing_query = db.collection("connections").where(
        "requesterUid", "==", request.user["uid"]
    ).where("recipientUid", "==", recipient_uid).where(
        "status", "in", ["PENDING", "ACCEPTED"]
    ).limit(1).stream()
    
    if any(existing_query):
        abort(400, description="Connection request already exists")
    
    # Check for reverse connection
    reverse_query = db.collection("connections").where(
        "requesterUid", "==", recipient_uid
    ).where("recipientUid", "==", request.user["uid"]).where(
        "status", "in", ["PENDING", "ACCEPTED"]
    ).limit(1).stream()
    
    if any(reverse_query):
        abort(400, description="Connection already exists")
    
    # Create connection
    connection_id = str(uuid.uuid4())
    get_connection_doc(connection_id).set({
        "requesterUid": request.user["uid"],
        "recipientUid": recipient_uid,
        "status": "PENDING",
        "inviteMessage": invite_message,
        "contextType": context_type,
        "contextId": context_id,
        "createdAt": now_utc(),
        "updatedAt": now_utc(),
    })
    
    return jsonify({"connectionId": connection_id})


@app.route("/api/connections/requests", methods=["GET"])
@require_auth
def list_connection_requests():
    """List pending connection requests received by the authenticated user.
    
    Returns a list of pending invitations with requester info.
    """
    ensure_user_profile(request.user["uid"])
    requests = []
    
    query = db.collection("connections").where(
        "recipientUid", "==", request.user["uid"]
    ).where("status", "==", "PENDING").order_by("createdAt", direction=firestore.Query.DESCENDING)
    
    for doc in query.stream():
        data = doc.to_dict()
        requester_profile = get_user_profile(data.get("requesterUid"))
        requests.append({
            "connectionId": doc.id,
            "requesterUid": data.get("requesterUid"),
            "requesterUsername": requester_profile.get("username") if requester_profile else "Unknown",
            "inviteMessage": data.get("inviteMessage"),
            "contextType": data.get("contextType"),
            "contextId": data.get("contextId"),
            "createdAt": serialize_datetime(data.get("createdAt")),
        })
    
    return jsonify({"requests": requests})


@app.route("/api/connections/sent", methods=["GET"])
@require_auth
def list_sent_invites():
    """List pending connection invites sent by the authenticated user.
    
    Returns a list of pending invitations sent to others.
    """
    ensure_user_profile(request.user["uid"])
    sent = []
    
    query = db.collection("connections").where(
        "requesterUid", "==", request.user["uid"]
    ).where("status", "==", "PENDING").order_by("createdAt", direction=firestore.Query.DESCENDING)
    
    for doc in query.stream():
        data = doc.to_dict()
        recipient_profile = get_user_profile(data.get("recipientUid"))
        sent.append({
            "connectionId": doc.id,
            "recipientUid": data.get("recipientUid"),
            "recipientUsername": recipient_profile.get("username") if recipient_profile else "Unknown",
            "inviteMessage": data.get("inviteMessage"),
            "createdAt": serialize_datetime(data.get("createdAt")),
        })
    
    return jsonify({"sent": sent})


@app.route("/api/connections/<connection_id>/accept", methods=["POST"])
@require_auth
def accept_connection(connection_id):
    """Accept a pending connection request.
    
    Requires the authenticated user to be the recipient.
    Updates status to ACCEPTED.
    """
    ensure_user_profile(request.user["uid"])
    
    connection_snap = get_connection_doc(connection_id).get()
    if not connection_snap.exists:
        abort(404, description="Connection not found")
    
    connection = connection_snap.to_dict()
    if connection.get("recipientUid") != request.user["uid"]:
        abort(403, description="Only the recipient can accept this connection")
    
    if connection.get("status") != "PENDING":
        abort(400, description="Connection is not pending")
    
    get_connection_doc(connection_id).update({
        "status": "ACCEPTED",
        "updatedAt": now_utc(),
    })
    
    return jsonify({"status": "accepted"})


@app.route("/api/connections/<connection_id>/decline", methods=["POST"])
@require_auth
def decline_connection(connection_id):
    """Decline/ignore a pending connection request.
    
    Requires the authenticated user to be the recipient.
    Updates status to DECLINED (requester is not notified).
    """
    ensure_user_profile(request.user["uid"])
    
    connection_snap = get_connection_doc(connection_id).get()
    if not connection_snap.exists:
        abort(404, description="Connection not found")
    
    connection = connection_snap.to_dict()
    if connection.get("recipientUid") != request.user["uid"]:
        abort(403, description="Only the recipient can decline this connection")
    
    if connection.get("status") != "PENDING":
        abort(400, description="Connection is not pending")
    
    get_connection_doc(connection_id).update({
        "status": "DECLINED",
        "updatedAt": now_utc(),
    })
    
    return jsonify({"status": "declined"})


@app.route("/api/connections/<connection_id>/block", methods=["POST"])
@require_auth
def block_connection(connection_id):
    """Block a user and report them.
    
    Requires the authenticated user to be the recipient.
    Updates status to BLOCKED and creates a report.
    Note: Unlike accept/decline, this can be called on connections in any status,
    not just PENDING. This allows blocking users even after accepting a connection.
    """
    ensure_user_profile(request.user["uid"])
    
    connection_snap = get_connection_doc(connection_id).get()
    if not connection_snap.exists:
        abort(404, description="Connection not found")
    
    connection = connection_snap.to_dict()
    if connection.get("recipientUid") != request.user["uid"]:
        abort(403, description="Only the recipient can block this connection")
    
    requester_uid = connection.get("requesterUid")
    
    # Update connection status (works for any current status)
    get_connection_doc(connection_id).update({
        "status": "BLOCKED",
        "updatedAt": now_utc(),
    })
    
    # Create a report
    report_id = str(uuid.uuid4())
    db.collection("reports").document(report_id).set({
        "targetType": "user",
        "targetId": requester_uid,
        "reason": "Blocked from connection request",
        "reporterUid": request.user["uid"],
        "createdAt": now_utc(),
    })
    
    return jsonify({"status": "blocked", "reportId": report_id})


@app.route("/api/connections/status/<user_id>", methods=["GET"])
@require_auth
def get_connection_status_with_user(user_id):
    """Get connection status with a specific user.
    
    Returns connection status: 'accepted', 'pending_sent', 'pending_received', 'none', 'blocked'.
    """
    ensure_user_profile(request.user["uid"])
    
    if user_id == request.user["uid"]:
        return jsonify({"status": "self"})
    
    # Check for accepted connection
    if check_connection_status(request.user["uid"], user_id):
        return jsonify({"status": "accepted"})
    
    # Check for pending connection
    connection_id, connection, direction = get_pending_connection(request.user["uid"], user_id)
    if connection:
        return jsonify({
            "status": f"pending_{direction}",
            "connectionId": connection_id,
            "inviteMessage": connection.get("inviteMessage") if direction == "received" else None,
            "requesterUsername": None,  # Will be filled by frontend
        })
    
    # Check if blocked
    blocked_query = db.collection("connections").where(
        "requesterUid", "==", request.user["uid"]
    ).where("recipientUid", "==", user_id).where("status", "==", "BLOCKED").limit(1).stream()
    
    if any(blocked_query):
        return jsonify({"status": "blocked"})
    
    # Check reverse block
    reverse_blocked = db.collection("connections").where(
        "requesterUid", "==", user_id
    ).where("recipientUid", "==", request.user["uid"]).where("status", "==", "BLOCKED").limit(1).stream()
    
    if any(reverse_blocked):
        return jsonify({"status": "blocked"})
    
    return jsonify({"status": "none"})


@app.route("/api/reports", methods=["POST"])
@require_auth
def create_report():
    """Create a content/user report for moderation.

    JSON body: {"targetType": "story|message|user", "targetId": "id", "reason": "..."}
    Requires auth. Returns the created `reportId`.
    """
    ensure_user_profile(request.user["uid"])
    check_rate_limit(request.user["uid"], "reports:create")

    payload = request.get_json(force=True)
    target_type = payload.get("targetType")
    target_id = payload.get("targetId")
    reason = payload.get("reason", "").strip()

    if not target_type or not target_id or not reason:
        abort(400, description="targetType, targetId, and reason are required")

    report_id = str(uuid.uuid4())
    db.collection("reports").document(report_id).set({
        "targetType": target_type,
        "targetId": target_id,
        "reason": reason,
        "reporterUid": request.user["uid"],
        "createdAt": now_utc(),
    })

    return jsonify({"reportId": report_id})


@app.route("/api/maintenance/cleanup", methods=["POST"])
@require_auth
def cleanup():
    """Run cleanup tasks for expired stories and old messages.

    Protected endpoint intended for administrative/cron use. Removes expired
    story media and messages (based on `expiresAt`, `deleteAfter`, and TTLs).
    Returns a summary of removed items.
    """
    ensure_user_profile(request.user["uid"])
    now = now_utc()
    removed = {
        "stories": 0,
        "storyMedia": 0,
        "messages": 0,
        "messageMedia": 0,
    }

    cleared_story_users = set()

    for story_doc in db.collection("stories").where("expiresAt", "<=", now).stream():
        story = story_doc.to_dict()
        removed["stories"] += 1
        for media_doc in db.collection("story_media").where("storyId", "==", story_doc.id).stream():
            media = media_doc.to_dict()
            removed["storyMedia"] += 1
            storage_delete(media.get("storagePath"))
            media_doc.reference.delete()
        story_doc.reference.delete()
        owner_uid = story.get("ownerUid")
        if owner_uid:
            cleared_story_users.add(owner_uid)

    for uid in cleared_story_users:
        get_user_doc(uid).set({"storyPosted": False, "storyPostedAt": None}, merge=True)

    for message_doc in db.collection("messages").where("deleteAfter", "<=", now).stream():
        message = message_doc.to_dict()
        removed["messages"] += 1
        if message.get("type") == "image":
            removed["messageMedia"] += 1
            storage_delete(message.get("contentRef"))
        message_doc.reference.delete()

    cutoff = now - timedelta(days=MESSAGE_TTL_DAYS)
    for message_doc in db.collection("messages").where("createdAt", "<=", cutoff).stream():
        message = message_doc.to_dict()
        removed["messages"] += 1
        if message.get("type") == "image":
            removed["messageMedia"] += 1
            storage_delete(message.get("contentRef"))
        message_doc.reference.delete()

    return jsonify({"removed": removed})


def storage_delete(path):
    if not path:
        return
    blob = bucket.blob(path)
    try:
        blob.delete()
    except Exception:
        return


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(409)
@app.errorhandler(410)
@app.errorhandler(429)
def handle_error(error):
    return jsonify({"error": error.description}), error.code


if __name__ == "__main__":
    app.run(debug=True)
