import os
import json

from authlib.integrations.httpx_client import AsyncOAuth2Client
from dotenv import load_dotenv
from functools import wraps
import jwt
import secrets
from sanic import response
from datetime import datetime, timezone, timedelta

load_dotenv()

config = {}
with open("config.json", "r") as jsonfile:
    config = json.load(jsonfile)
    if not len(config):
        log.error("configfile not loaded (correctly)")

DISCORD_CLIENT_SECRET = os.getenv("CLIENT_SECRET")

class DiscordAuthLevel:
	default=0
	member=1
	admin=5

class DiscordAuth:
	__auth_member_list = {}
	__secret_len = config["token_length"]
	__secret = None

	def __init__(self, redirect_uri, member_roles, admin_roles):
		self.__oauth_client = AsyncOAuth2Client(
			client_id=config["client_id"], 
			client_secret=DISCORD_CLIENT_SECRET, 
			redirect_uri=redirect_uri
		)
		self.redirect_uri = redirect_uri

		self.member_roles = member_roles
		self.admin_roles = admin_roles

		self.roll_token()

	async def reauthenticate(self, token):
		oauth_client = AsyncOAuth2Client(
			client_id=config["client_id"],
			client_secret=DISCORD_CLIENT_SECRET,
			token=token
		)

		new_token = await oauth_client.refresh_token(
			"https://discord.com/api/oauth2/token",
			refresh_token=stored_refresh_token
		)

		return await self.check_member_info(m_oauth_client, token)

	async def authenticate(self, code):
		m_oauth_client = AsyncOAuth2Client(
			client_id=config["client_id"], 
			client_secret=DISCORD_CLIENT_SECRET, 
			redirect_uri=self.redirect_uri
		)

		token = await m_oauth_client.fetch_token(
			"https://discord.com/api/oauth2/token",
			grant_type="authorization_code",
			code=code,
			client_secret=DISCORD_CLIENT_SECRET,
		)

		return await self.check_member_info(m_oauth_client, token)

	async def check_member_info(self, m_oauth_client, token):
		member_resp = await m_oauth_client.get(f"https://discord.com/api/users/@me/guilds/{config['guild_id']}/member")

		if member_resp.status_code == 200:
			member = member_resp.json()
			member_id = member["user"]["id"]
			self.roll_token()
			discord_token_expires = (datetime.now(tz=timezone.utc) + timedelta(seconds=token["expires_in"])).isoformat()
			jwt_token = jwt.encode({"id": member_id, "exp": self.__secret_expiration, "token_exp": discord_token_expires}, self.__secret)

			if any((r in self.member_roles) for r in member["roles"]):
				self.__auth_member_list[member_id] = {"perm": DiscordAuthLevel.admin, "token": token}
				return jwt_token
			if any((r in self.admin_roles) for r in member["roles"]):
				self.__auth_member_list[member_id] = {"perm": DiscordAuthLevel.member, "token": token}
				return jwt_token
		return None

	async def check_token(self, jwt_token, auth_level):
		if not jwt_token:
			return False
		try:
			jwt_data = jwt.decode(jwt_token, self.__secret, algorithms=["HS256"])
			if datetime.fromisoformat(jwt_data["token_exp"]) < datetime.now(tz=timezone.utc):
				new_jwt_token = await self.reauthenticate(jwt_data["token"])
				if (await self.check_token(new_jwt_token, auth_level)):
					return new_jwt_token
				return False

			member_id = jwt_data["id"]
			member_level = self.__auth_member_list.get(member_id)

			if member_level is not None and member_level["perm"] >= auth_level:
				return True
			else:
				return False
		except jwt.ExpiredSignatureError:
			return False
		except jwt.exceptions.InvalidTokenError:
			return False
		else:
			return True

	def roll_token(self):
		if self.__secret is None or self.__secret_expiration > datetime.now(tz=timezone.utc):
			self.__secret = secrets.token_hex(self.__secret_len)
			self.__secret_expiration = datetime.now(tz=timezone.utc) + timedelta(days=config["token_days_exp"])

	def redirect_auth_page(self, next_uri="/"):
		auth_url = self.__oauth_client.create_authorization_url(
			'https://discord.com/oauth2/authorize',
			response_type="code",
			state=next_uri,
			scope="identify guilds.members.read"
		)[0]
		return response.redirect(auth_url)

	def reset_permission(self, id):
		if self.__auth_member_list.get(id) is None:
			return False
		del self.__auth_member_list[id]
		return True

	def protected(self, auth_level=DiscordAuthLevel.member):
		def decorator(f):
			@wraps(f)
			async def decorated_function(request, *args, **kwargs):
				is_authenticated = await self.check_token(request.cookies.get("auth_token"), auth_level)

				if is_authenticated==True:
					response = await f(request, *args, **kwargs)
					return response
				elif is_authenticated:
					response = await f(request, *args, **kwargs)
					response.add_cookie("auth_token", is_authenticated, httponly=True, secure=False, samesite="Strict")
					return response
				else:
					return self.redirect_auth_page(request.path)

			return decorated_function
		return decorator