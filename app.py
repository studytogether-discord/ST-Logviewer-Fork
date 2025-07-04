__version__ = "1.1.2"

import html
import os
import json

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from sanic import Sanic, response
from sanic.exceptions import NotFound
from jinja2 import Environment, FileSystemLoader

from core.models import LogEntry
from auth import DiscordAuth

load_dotenv()

if "URL_PREFIX" in os.environ:
    print("Using the legacy config var `URL_PREFIX`, rename it to `LOG_URL_PREFIX`")
    prefix = os.environ["URL_PREFIX"]
else:
    prefix = os.getenv("LOG_URL_PREFIX", "/logs")

if prefix == "NONE":
    prefix = ""

REDIRECT_URI = f"http://localhost:{os.getenv('PORT', '8000')}/auth"

MONGO_URI = os.getenv("MONGO_URI") or os.getenv("CONNECTION_URI")
if not MONGO_URI:
    print("No CONNECTION_URI config var found. "
          "Please enter your MongoDB connection URI in the configuration or .env file.")
    exit(1)

config = {}
with open("config.json", "r") as jsonfile:
    config = json.load(jsonfile)
    if not len(config):
        log.error("configfile not loaded (correctly)")

app = Sanic(__name__)
app.static("/static", "./static")

discord_auth = DiscordAuth(
    redirect_uri=REDIRECT_URI,
    member_roles = config["member_roles"], 
    admin_roles = config["admin_roles"]
)

jinja_env = Environment(loader=FileSystemLoader("templates"))


def render_template(name, *args, **kwargs):
    template = jinja_env.get_template(name + ".html")
    return response.html(template.render(*args, **kwargs))


app.ctx.render_template = render_template


def strtobool(val):
    """
    Copied from distutils.strtobool.

    Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))


@app.listener("before_server_start")
async def init(app, loop):
    app.ctx.db = AsyncIOMotorClient(MONGO_URI).modmail_bot
    use_attachment_proxy = strtobool(os.getenv("USE_ATTACHMENT_PROXY", "no"))
    if use_attachment_proxy:
        app.ctx.attachment_proxy_url = os.getenv("ATTACHMENT_PROXY_URL", "https://cdn.discordapp.xyz")
        app.ctx.attachment_proxy_url = html.escape(app.ctx.attachment_proxy_url).rstrip("/")
    else:
        app.ctx.attachment_proxy_url = None

@app.exception(NotFound)
async def not_found(request, exc):
    return render_template("not_found")


@app.get("/")
@discord_auth.protected()
async def index(request):
    return render_template("index")

@app.route('/auth')
async def auth(request):
    code = request.args.get("code")
    state = request.args.get("state") or "/"

    if not code:
        return response.text("Missing code", status=400)

    token = await discord_auth.authenticate(code)
    if token is not None:
        res = response.redirect(state)
        res.add_cookie("auth_token", token, httponly=True, secure=False, samesite="Lax")
        return res
    else:
        return response.text("Missing access", status=500)

@app.get(prefix + "/raw/<key>")
@discord_auth.protected()
async def get_raw_logs_file(request, key):
    """Returns the plain text rendered log entry"""
    document = await app.ctx.db.logs.find_one({"key": key})

    if document is None:
        raise NotFound

    log_entry = LogEntry(app, document)

    return log_entry.render_plain_text()


@app.get(prefix + "/<key>")
@discord_auth.protected()
async def get_logs_file(request, key):
    """Returns the html rendered log entry"""
    print(key)
    document = await app.ctx.db.logs.find_one({"key": key})
    print(str(document))
    if document is None:
        raise NotFound

    log_entry = LogEntry(app, document)

    return log_entry.render_html()


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        debug=bool(os.getenv("DEBUG", False)),
    )
