# SchoolSnapchat MVP (Flask)

Minimal Flask + Firebase MVP that supports:
- Verified auth gate
- Story metadata + view-once image access
- Direct messages (text + image)
- Report submission + cleanup endpoint

## 1) Setup

### Prereqs
- Python 3.10+
- Firebase project with Auth, Firestore, and Storage enabled
- Service account JSON downloaded from Firebase Console

### Environment
1. Copy `.env.example` → `.env` and fill values.
2. Save your Firebase service account JSON as `firebase-sa-creds.json` in the project root (this file is gitignored).
3. Save your Firebase web config JSON (apiKey/authDomain/projectId) as `firebase-creds.json`.

### Install
```bash
pip install -r requirements.txt
```

## 2) Run locally
```bash
python app.py
```

Open: `http://127.0.0.1:5000/login`

### Routes
- `/login`
- `/home`
- `/messages`
- `/messages/<userId>`
- `/addstory`

## 3) Firebase Configuration

Enable these services:
- Authentication (Email/Password)
- Firestore (Native mode)
- Storage (default bucket)

Recommended Firestore indexes:
- `messages` collection: `chatId ASC, createdAt DESC`

## 4) Testing flow

1. Sign up or sign in via Firebase Auth (email/password).
2. Verify your email (check inbox, then refresh status).
3. Create a profile username on `/login`.
4. Upload a story image (max 300 KB recommended) via `/addstory`.
5. View stories on `/home`.
6. Create a chat with another UID and send messages in `/messages/<userId>`.
7. Run cleanup (requires auth) with:
   ```bash
   curl -X POST -H "Authorization: Bearer <ID_TOKEN>" http://127.0.0.1:5000/api/maintenance/cleanup
   ```

## 5) MVP API Surface (summary)

- `POST /api/auth/verify`
- `POST /api/session`
- `DELETE /api/session`
- `POST /api/users/bootstrap`
- `POST /api/users`
- `GET /api/users/me`
- `GET /api/users/friends`
- `GET /api/stories`
- `POST /api/stories`
- `POST /api/stories/<story_id>/media/<media_id>/view`
- `POST /api/chats`
- `GET /api/chats`
- `GET /api/chats/<chat_id>/messages`
- `POST /api/chats/<chat_id>/messages`
- `POST /api/messages/<message_id>/view`
- `POST /api/reports`
- `POST /api/maintenance/cleanup`

## 6) Notes

- All media access uses signed URLs.
- Rate limits are in-memory (per instance). Swap in Redis for production.
- For image messages, call `/api/messages/<message_id>/view` to get a signed URL. After viewing, the file is deleted on cleanup.
