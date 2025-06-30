import os, json
from datetime import datetime
from flask import Flask, request, session, jsonify
from flask_cors import CORS
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import google.oauth2.credentials
from google.oauth2 import id_token
from google.auth.transport import requests
import time
from google.auth.exceptions import InvalidValue
import re
from dateutil.parser import parse as parse_date
from datetime import datetime, timedelta
 
load_dotenv()
 
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["SESSION_TYPE"] = "filesystem"
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///tokens.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
 
Session(app)
CORS(app, supports_credentials=True)
db = SQLAlchemy(app)
 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
 
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "https://new-calendar-0a1v.onrender.com/oauth2callback"
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/userinfo.email"
]
 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    token_uri = db.Column(db.Text)
    client_id = db.Column(db.Text)
    client_secret = db.Column(db.Text)
    scopes = db.Column(db.Text)
 
    def to_creds(self):
        return google.oauth2.credentials.Credentials(
            token=self.token,
            refresh_token=self.refresh_token,
            token_uri=self.token_uri,
            client_id=self.client_id,
            client_secret=self.client_secret,
            scopes=json.loads(self.scopes)
        )
 
def get_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

def get_current_month_range():
    now = datetime.utcnow()
    time_min = datetime(now.year, now.month, 1)
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1)
    else:
        next_month = datetime(now.year, now.month + 1, 1)

    time_max = next_month - timedelta(seconds=1)
    return time_min.isoformat() + 'Z', time_max.isoformat() + 'Z'

def get_date_range(range_type):
    now = datetime.utcnow()

    if range_type == "today":
        start = datetime(now.year, now.month, now.day)
        end = start + timedelta(days=1) - timedelta(seconds=1)
    elif range_type == "this_week":
        start = now - timedelta(days=now.weekday()) 
        start = datetime(start.year, start.month, start.day)
        end = start + timedelta(days=7) - timedelta(seconds=1)
    elif range_type == "this_month":
        start = datetime(now.year, now.month, 1)
        if now.month == 12:
            end = datetime(now.year + 1, 1, 1) - timedelta(seconds=1)
        else:
            end = datetime(now.year, now.month + 1, 1) - timedelta(seconds=1)
    else:
        try:
            parsed_date = parse_date(range_type)
            start = datetime(parsed_date.year, parsed_date.month, parsed_date.day)
            end = start + timedelta(days=1) - timedelta(seconds=1)
        except:
            
            start = datetime(now.year, now.month, 1)
            if now.month == 12:
                end = datetime(now.year + 1, 1, 1) - timedelta(seconds=1)
            else:
                end = datetime(now.year, now.month + 1, 1) - timedelta(seconds=1)

    return start.isoformat() + 'Z', end.isoformat() + 'Z'


def interpret_natural_query(query_text):
    query_text = query_text.lower().strip()

    if "today" in query_text:
        return "today"
    elif "week" in query_text:
        return "this_week"
    elif "month" in query_text:
        return "this_month"
    elif "year" in query_text:
        return "this_year"
    else:
        
        match = re.search(r'\d{4}-\d{2}-\d{2}', query_text)
        if match:
            try:
                datetime.strptime(match.group(), "%Y-%m-%d")
                return match.group()
            except ValueError:
                pass
        return "this_month"

 
@app.route("/start")
def start():
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "Email required"}), 400
    session["email"] = email
    flow = get_flow()
    auth_url, _ = flow.authorization_url(access_type="offline", prompt="consent")
    return jsonify({"auth_url": auth_url})
 
@app.route("/oauth2callback")
def oauth2callback():
    flow = get_flow()

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        return f"Token fetch error: {str(e)}", 400

    creds = flow.credentials
    request_adapter = requests.Request()

    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            info = id_token.verify_oauth2_token(creds.id_token, request_adapter, GOOGLE_CLIENT_ID)
            break  
        except InvalidValue as e:
            msg = str(e)
            if "Token used too early" in msg and attempt < max_attempts - 1:
                match = re.search(r"Token used too early, (\d+) < (\d+)", msg)
                if match:
                    now, valid = map(int, match.groups())
                    wait_time = valid - now + 1
                    print(f"[oauth2callback] Waiting {wait_time}s for token to become valid...")
                    time.sleep(wait_time)
                    continue
            raise

    email = info.get("email")
    if not email:
        return "Unable to get user email", 400

    user = User.query.filter_by(email=email).first() or User(email=email)
    user.token = creds.token
    user.refresh_token = creds.refresh_token
    user.token_uri = creds.token_uri
    user.client_id = creds.client_id
    user.client_secret = creds.client_secret
    user.scopes = json.dumps(creds.scopes)

    db.session.add(user)
    db.session.commit()

    return "<script>window.close()</script>Authorized! You may close this window."

@app.route("/create_event", methods=["POST"])
def create_event():
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "Missing email in query params"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not authorized"}), 401

    creds = user.to_creds()
    service = build('calendar', 'v3', credentials=creds)

    data = request.get_json()
    event = {
        "summary": data.get("summary", "Sample Event"),
        "location": data.get("location", ""),
        "description": data.get("description", ""),
        "start": {
            "dateTime": data.get("start"),
            "timeZone": "Asia/Kolkata"
        },
        "end": {
            "dateTime": data.get("end"),
            "timeZone": "Asia/Kolkata"
        }
    }

    created_event = service.events().insert(calendarId="primary", body=event).execute()
    return jsonify(created_event)

@app.route("/fetch_events", methods=["GET"])
def fetch_events():
    email = request.args.get("email")
    user_query = request.args.get("query", "this month")

    if not email:
        return jsonify({"error": "Missing email in query params"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not authorized"}), 401

    creds = user.to_creds()
    service = build('calendar', 'v3', credentials=creds)

    range_type = interpret_natural_query(user_query)
    time_min, time_max = get_date_range(range_type)

    events_result = service.events().list(
        calendarId='primary',
        timeMin=time_min,
        timeMax=time_max,
        singleEvents=True,
        orderBy='startTime'
    ).execute()

    events = events_result.get('items', [])
    return jsonify(events)

@app.route("/delete_event", methods=["DELETE"])
def delete_event():
    email = request.args.get("email")
    event_id = request.args.get("event_id")

    if not email or not event_id:
        return jsonify({"error": "Missing email or event_id in query params"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not authorized"}), 401

    creds = user.to_creds()
    service = build('calendar', 'v3', credentials=creds)

    try:
        service.events().delete(calendarId='primary', eventId=event_id).execute()
        return jsonify({"status": "deleted", "event_id": event_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/update_event", methods=["PATCH"])
def update_event():
    email = request.args.get("email")
    event_id = request.args.get("event_id")

    if not email or not event_id:
        return jsonify({"error": "Missing email or event_id in query params"}), 400

    data = request.get_json()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not authorized"}), 401

    creds = user.to_creds()
    service = build('calendar', 'v3', credentials=creds)

    try:
        event = service.events().get(calendarId='primary', eventId=event_id).execute()

        if 'summary' in data: event['summary'] = data['summary']
        if 'location' in data: event['location'] = data['location']
        if 'description' in data: event['description'] = data['description']
        if 'start' in data: event['start']['dateTime'] = data['start']
        if 'end' in data: event['end']['dateTime'] = data['end']

        updated_event = service.events().update(calendarId='primary', eventId=event_id, body=event).execute()
        return jsonify(updated_event)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

 
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)
