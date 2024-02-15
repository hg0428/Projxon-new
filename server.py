from quart import Quart, request, render_template, websocket
import auth
import secrets
import datetime
import asyncio
from flask_cors import CORS


pycountry = auth.pycountry
countries = pycountry.countries.objects
countries.sort(key=lambda x: x.name)


def make_id(length=32):
    token = secrets.token_urlsafe(length)
    return token


app = Quart(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

CSRF_TOKENS = {}
AUTHENTICATION_SESSIONS = {}


def generate_csrf_token(request, scope):
    csrf_token = make_id()
    if csrf_token in CSRF_TOKENS:
        return generate_csrf_token(request, scope)
    CSRF_TOKENS[csrf_token] = {
        "token": csrf_token,
        "expires": datetime.datetime.now() + datetime.timedelta(hours=3),
        "user-agent": request.headers.get("User-Agent"),
        "ip": request.remote_addr,
        "scope": scope,
    }
    return csrf_token


def check_csrf_token(csrf_token, scope):
    # Make sure the token exists
    if csrf_token not in CSRF_TOKENS:
        return False
    # Make sure the token is not expired
    if CSRF_TOKENS[csrf_token]["expires"] < datetime.datetime.now():
        del CSRF_TOKENS[
            csrf_token
        ]  # There's no purpose of an expired token besides to take up space.
        return False
    # Make sure the token is from the same user agent
    if CSRF_TOKENS[csrf_token]["user-agent"] != request.headers.get("User-Agent"):
        return False
    # Make sure the token is from the same IP
    if CSRF_TOKENS[csrf_token]["ip"] != request.remote_addr:
        return False
    # Make sure all values of scope are in the token's scope
    for s in scope:
        if s not in CSRF_TOKENS[csrf_token]["scope"]:
            return False
    return True


# Decorator function to add security headers
def secure(func):
    async def wrapper(*args, **kwargs):
        response = await func(*args, **kwargs)
        # Add security headers
        response.headers.add("Content-Security-Policy", "default-src 'self'")
        response.headers.add(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"
        )
        response.headers.add("X-Content-Type-Options", "nosniff")
        response.headers.add("X-XSS-Protection", "1; mode=block")
        response.headers.add("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    return wrapper


@app.route("/")
async def index():
    return await render_template("index.html")


@secure
@app.route("/auth")
async def authenticate():
    # country = (await get_ip_details(request.remote_addr)).all
    # print(country)
    return await render_template(
        "authenticate.html",
        csrf_token=generate_csrf_token(request, ["authentication"]),
        countries=countries,
        # predicted_country=country,
    )


@secure
@app.route("/api/begin-registration", methods=["POST"])
async def begin_registration():
    # Get request json
    request_json = await request.get_json()
    csrf_token = request_json["csrf-token"]
    if not check_csrf_token(csrf_token, ["authentication"]):
        return "Invalid CSRF token", 400
    authentication_session = auth.authenticate()
    authentication_session_id = make_id()
    AUTHENTICATION_SESSIONS[authentication_session_id] = {
        "session": authentication_session,
        "csrf-token": csrf_token,
        "session-id": authentication_session_id,
    }
    token_time_remaining = CSRF_TOKENS[csrf_token]["expires"] - datetime.datetime.now()
    data = next(authentication_session)
    print(data)
    data["session-id"] = authentication_session_id
    if token_time_remaining < datetime.timedelta(minutes=10):
        # Renew the token if it is running out.
        data["csrf-token"] = generate_csrf_token(request, ["authentication"])
    return data


@secure
@app.route("/api/registration/send", methods=["POST"])
async def send_to_registration_session():
    # Get request json
    request_json = await request.get_json()
    csrf_token = request_json["csrf-token"]
    if not check_csrf_token(csrf_token, ["authentication"]):
        return "Invalid CSRF token", 400
    authentication_session_id = request_json["session-id"]
    if authentication_session_id not in AUTHENTICATION_SESSIONS:
        return "Invalid session", 400
    if AUTHENTICATION_SESSIONS[authentication_session_id]["csrf-token"] != csrf_token:
        return "CSRF Token does not match session", 400
    authentication_session = AUTHENTICATION_SESSIONS[authentication_session_id][
        "session"
    ]
    token_time_remaining = CSRF_TOKENS[csrf_token]["expires"] - datetime.datetime.now()
    try:
        data = authentication_session.send(request_json["data"])
    except StopIteration:
        return {"errors": ["Registration complete. Internal Server Error."]}
    if token_time_remaining < datetime.timedelta(minutes=10):
        # Renew the token if it is running out.
        data["csrf-token"] = generate_csrf_token(request, ["authentication"])
    return data


def begin_server():
    certfile = "localhost.pem"
    keyfile = "localhost-key.pem"

    # 423
    app.run(
        host="localhost",
        port=8080,
        certfile=certfile,
        keyfile=keyfile,
        use_reloader=False,
    )
    # app.run(port=8080, use_reloader=False)


# Activate the server
if __name__ == "__main__":
    # Activate the server
    begin_server()
