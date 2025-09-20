import ssl
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import GetLoginDataRes_pb2
import DecodeWhisperMsg_pb2
import GenWhisperMsg_pb2
from datetime import datetime
import recieved_chat_pb2
import Team_msg_pb2
import spam_join_pb2
import wlxd_title_pb2
import json
from protobuf_decoder.protobuf_decoder import Parser
import bot_mode_pb2
import wlxd_special_pb2
import bot_invite_pb2
import base64
from flask import Flask, request, jsonify  # ### --- MODIFIED --- ### (Added request, jsonify)
import random_pb2
from threading import Thread
import Clan_Startup_pb2
import Team_msg_pb2
import clan_msg_pb2
import recieved_chat_pb2
import Team_Chat_Startup_pb2
import wlxd_spam_pb2
import random
import pytz
import re
import motor.motor_asyncio

app = Flask(__name__)

# --- MongoDB Setup ---
MONGO_URI = "mongodb+srv://akiru:mJz1gv50hdifcfYN@akiru.mneusih.mongodb.net/?retryWrites=true&w=majority&appName=AKIRU"
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client.bot_db
banned_users_collection = db.banned_users

# --- Owner Configuration ---
OWNER_UID = 2206344781  # <<<--- IMPORTANT: Change this to your own UID to use the ban/unban commands

# <--- Globally accessible writers and state flags --->

online_writer = None
whisper_writer = None
spam_room = True
spammer_uid = None
spam_chat_id = None
spam_uid = None

# <<<--- CORRECTED GLOBAL VARIABLES --->
captured_ghost_code = None
captured_player_uid = None
team_session_captured_event = asyncio.Event()


### --- ADDED --- ###
# Global dictionary to hold the bot's live state for the API
bot_live_state = {
    "key": None,
    "iv": None,
    "ready": False,
    "loop": None # To run async functions from a sync context
}
### --- END ADDED --- ###


headers = {
'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
'Connection': "Keep-Alive",
'Accept-Encoding': "gzip",
'Content-Type': "application/x-www-form-urlencoded",
'Expect': "100-continue",
'X-Unity-Version': "2018.4.11f1",
'X-GA': "v1 1",
'ReleaseVersion': "OB50"
}

TOKEN_EXPIRY = 7 * 60 * 60

UIDS = [
{"uid": "2206344781", "region": "ind", "telegram_id": "7047634565"},
{"uid": "12247027191", "region": "ind", "telegram_id": "7047634565"},
]
BOT_TOKEN = "7822328116:AAFrKsyWGMZPi49rrGWOWFGqqAMSQwEvWGg"

# --- Helper function for random colors ---

def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

def get_random_avatar():
    avatars = list(set([
        902050001, 902000060, 902000061, 902000065, 902000073, 902000074,
        902000075, 902000076, 902000082, 902000083, 902000084, 902000087,
        902000090, 902000091, 902000112, 902000104, 902000190, 902000191,
        902000207, 902048021, 902047018, 902042011,
        902000064, 902000066, 902000077, 902000078, 902000085, 902000094,
        902000306
    ]))
    return random.choice(avatars)

def get_random_badge():
    badges =list(set([
        800000304, 909035007, 808000001, 801000227, 801044504, 801000002, 801000005, 801000020,  801000087, 801000144
   ]))
    return random.choice(badges)

def get_random_title():
    titles =list(set([
        904090026, 904090027, 904290048, 904590058, 904590059, 904790062, 904890068, 904990069,  904990070, 904990071, 904990072, 904090023, 905090075
   ]))
    return random.choice(titles)

# --- Ban/Unban Helper Functions ---
async def is_user_banned(uid):
    """Checks if a user's UID is in the banned collection."""
    return await banned_users_collection.find_one({"uid": uid}) is not None

async def ban_user(uid):
    """Adds a user's UID to the banned collection."""
    if not await is_user_banned(uid):
        await banned_users_collection.insert_one({"uid": uid})
        return True  # Indicates success
    return False # Indicates user was already banned

async def unban_user(uid):
    """Removes a user's UID from the banned collection."""
    result = await banned_users_collection.delete_one({"uid": uid})
    return result.deleted_count > 0 # Returns True if a user was found and removed


async def send_telegram_message(chat_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                await response.text()
    except Exception as e:
        print(f"Telegram error for {chat_id}: {e}")

async def send_daily_likes_to_telegram():
    today = datetime.now().date()
    like_api_url = "https://like-api-aditya-ffm.vercel.app/like?uid={uid}&server_name={region}&key=360"
    async with aiohttp.ClientSession() as session:
        for entry in UIDS:
            try:
                end_date = datetime.strptime(entry.get("end_date", "2099-12-31"), "%Y-%m-%d").date()
                if today > end_date:
                    continue
                uid = entry['uid']
                region = entry['region']
                telegram_id = entry['telegram_id']
                url = like_api_url.format(uid=uid, region=region)
                try:
                    async with session.get(url) as response:
                        text = await response.text()
                        msg = (f"[Daily Likes]\nUID: {uid}\nRegion: {region}" f"\nStatus: {response.status}\nResponse: {text}")
                        await send_telegram_message(telegram_id, msg)
                except Exception as e:
                    await send_telegram_message(telegram_id, f"[Daily Likes] Error for UID {uid}: {e}")
                await asyncio.sleep(60)
            except Exception as e:
                await send_telegram_message(entry.get("telegram_id", "unknown"), f"[Daily Likes] General error: {e}")

async def run_scheduler():
    async def is_time_to_run(target):
        now = datetime.now(pytz.timezone("Asia/Kolkata"))
        return now.strftime("%H:%M") == target
    already_ran = set()
    while True:
        now = datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%H:%M")
        if now == "04:30" and now not in already_ran:
            already_ran.add(now)
            async def run_jobs():
                try:
                    await asyncio.gather(send_daily_likes_to_telegram())
                except Exception as e:
                    print(f"Scheduler task error: {e}")
            asyncio.create_task(run_jobs())
        if now not in already_ran:
            already_ran.clear()
        await asyncio.sleep(30)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload

async def get_random_user_agent():
    versions = ['4.0.18P6', '4.0.19P7', '4.0.20P1', '4.1.0P3', '4.1.5P2', '4.2.1P8', '4.2.3P1', '5.0.1B2', '5.0.2P4', '5.1.0P1', '5.2.0B1', '5.2.5P3', '5.3.0B1', '5.3.2P2', '5.4.0P1', '5.4.3B2', '5.5.0P1', '5.5.2P3']
    models = ['SM-A125F', 'SM-A225F', 'SM-A325M', 'SM-A515F', 'SM-A725F', 'SM-M215F', 'SM-M325FV', 'Redmi 9A', 'Redmi 9C', 'POCO M3', 'POCO M4 Pro', 'RMX2185', 'RMX3085', 'moto g(9) play', 'CPH2239', 'V2027', 'OnePlus Nord', 'ASUS_Z01QD']
    android_versions = ['9', '10', '11', '12', '13', '14']
    languages = ['en-US', 'es-MX', 'pt-BR', 'id-ID', 'ru-RU', 'hi-IN']
    countries = ['USA', 'MEX', 'BRA', 'IDN', 'RUS', 'IND']
    version = random.choice(versions)
    model = random.choice(models)
    android = random.choice(android_versions)
    lang = random.choice(languages)
    country = random.choice(countries)
    return f"GarenaMSDK/{version}({model};Android {android};{lang};{country};)"

async def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {"Host": "100067.connect.garena.com", "User-Agent": (await get_random_user_agent()), "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate, br", "Connection": "close"}
    data = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3", "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status != 200:
                return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def MajorLoginProto_Encode(open_id, access_token):
    major_login = MajorLoginReq_pb2.MajorLogin()
    major_login.event_time = "2025-06-04 19:48:07"
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "2.115.14"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019117863"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    headers['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=headers, ssl=ssl_context) as response:
            if response.status == 200:
                return await response.read()
            return None

API_KEYS = [
    "AIzaSyA8IiZS4SgA1DocEG1GA318a4baKvEWYBc",
    "AIzaSyCCr2sq-s1bWEwuK0ZIv8ITkqccxzMMCDI",
    "AIzaSyCLF8o66saIX9lKRzWt8RW9HjFZ1N8W6H0",
    "AIzaSyCM7zVQ9FM_BKI15O6Hgc6NN5F3RK3Xa0o",
    "AIzaSyCkiYnzLsWomUiRo4v6zWMx3X3yuoObRRM"
]
chat_history = [{"role": "user", "parts": [{"text": "You are a helpful assistant."}]}]
key_index = 0

async def Get_AI_Response(user_input):
    global key_index
    chat_history.append({"role": "user", "parts": [{"text": user_input}]})
    headers = {"Content-Type": "application/json"}
    for _ in range(len(API_KEYS)):
        api_key = API_KEYS[key_index]
        url = f"https://ffm-bancheck-bot-info-apis.vercel.app://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        payload = {"contents": chat_history}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                result = await response.json()
                if "candidates" in result:
                    reply = result["candidates"][0]["content"]["parts"][0]["text"]
                    chat_history.append({"role": "model", "parts": [{"text": reply}]})
                    return reply
                elif result.get("error", {}).get("code") == 429:
                    key_index = (key_index + 1) % len(API_KEYS)
                    print("⚠️ Switching API key due to rate limit.")
                    await asyncio.sleep(1)
                else:
                    return "Failed to get response: " + str(result)
    return "All keys reached rate limit."

async def MajorLogin_Decode(MajorLoginResponse):
    proto = MajorLoginRes_pb2.MajorLoginRes()
    proto.ParseFromString(MajorLoginResponse)
    return proto

async def GetLoginData_Decode(GetLoginDataResponse):
    proto = GetLoginDataRes_pb2.GetLoginData()
    proto.ParseFromString(GetLoginDataResponse)
    return proto

async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = recieved_chat_pb2.recieved_chat()
    proto.ParseFromString(packet)
    print(proto)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DecodeWhisperMsg_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto

async def base_to_hex(timestamp):
    timestamp_result = hex(timestamp)
    result = str(timestamp_result)[2:]
    if len(result) == 1:
        result = "0" + result
    return result

async def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = await parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

async def split_text_by_words(text, max_length=200):
    def insert_c_in_number(word):
        if word.isdigit():
            mid = len(word) // 2
            return word[:mid] + "[C]" + word[mid:]
        return word
    words = text.split()
    words = [insert_c_in_number(word) for word in words]
    chunks = []
    current = ""
    for word in words:
        if len(current) + len(word) + (1 if current else 0) <= max_length:
            current += (" " if current else "") + word
        else:
            chunks.append(current)
            current = word
    if current:
        chunks.append(current)
    return chunks

async def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = await parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

async def team_chat_startup(player_uid, team_session, key, iv):
    proto = Team_Chat_Startup_pb2.team_chat_startup()
    proto.field1 = 3
    proto.details.uid = player_uid
    proto.details.language = "en"
    proto.details.team_packet = team_session
    packet = proto.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "1201000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "120100000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "12010000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "1201000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check clan startup function.")
    if whisper_writer:
        whisper_writer.write(bytes.fromhex(final_packet))
        await whisper_writer.drain()

async def encrypt_packet(packet, key, iv):
    bytes_packet = bytes.fromhex(packet)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(bytes_packet, AES.block_size))
    return cipher_text.hex()

async def create_clan_startup(clan_id, clan_compiled_data, key, iv):
    proto = Clan_Startup_pb2.ClanPacket()
    proto.Clan_Pos = 3
    proto.Data.Clan_ID = 3044718496
    proto.Data.Clan_Type = 1
    proto.Data.Clan_Compiled_Data = clan_compiled_data
    packet = proto.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "1201000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "120100000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "12010000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "1201000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check clan startup function.")
    if whisper_writer:
        whisper_writer.write(bytes.fromhex(final_packet))
        await whisper_writer.drain()

async def create_group(key, iv):
    packet = "080112bc04120101180120032a02656e420d0a044944433110661a03494e444801520601090a121920580168017288040a403038303230303032433733464233454430323031303030303030303030303030303030303030303030303030303030303137424236333544303930303030303010151a8f0375505d5413070448565556000b5009070405500303560a08030354550007550f02570d03550906521702064e76544145491e0418021e11020b4d1a42667e58544776725757486575441f5a584a065b46426a5a65650e14034f7e5254047e005a7b7c555c0d5562637975670a7f765b0102537906091702044e72747947457d0d6267456859587b596073435b7205046048447d080b170c4f584a6b007e4709740661625c545b0e7458405f5e4e427f486652420c13070c484b597a717a5a5065785d4343535d7c7a6450675a787e05736418010c12034a475b71717a566360437170675a6b1c740748796065425e017e4f5d0e1a034d09660358571843475c774b5f524d47670459005a4870780e795e7a0a110a457e5e5a00776157597069094266014f716d7246754a60506b747404091005024f7e765774035967464d687c724703075d4e76616f7a184a7f057a6f0917064b5f797d05434250031b0555717b0d00611f59027e60077b4a0a5c7c0d1500480143420b5a65746803636e41556a511269087e4f5f7f675c0440600c22047c5c5754300b3a1a16024a424202050607021316677178637469785d51745a565a5a4208312e3130392e3136480650029801c902aa01024f52"
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0514000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051400000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check create_group function.")
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def wlxd_skwad(uid, key, iv):
    packet = wlxd_spam_pb2.WLXDSkwadPacket()
    packet.field1 = 33
    details = packet.field2
    details.user_id = int(uid)
    details.country_code = "IND"
    details.status1 = 1
    details.status2 = 1
    details.numbers = bytes([16, 21, 8, 10, 11, 19, 12, 15, 17, 4, 7, 2, 3, 13, 14, 18, 1, 5, 6])
    details.empty1 = ""
    details.rank = 330
    details.field8 = 19459
    details.field9 = 100
    details.region_code = "IND"
    details.uuid = bytes([
                55, 52, 50, 56, 98, 50, 53, 51, 100, 101, 102, 99,
                49, 54, 52, 48, 49, 56, 99, 54, 48, 52, 97, 49,
                101, 98, 98, 102, 101, 98, 100, 102
            ])
    details.field12 = 1
    details.repeated_uid = int(uid)
    details.field16 = 1
    details.field18 = 201
    details.field19 = 22

    nested = details.field20
    nested.server = "IDC1"
    nested.ping = 3000
    nested.country = "IND"

    details.field23 = bytes([16, 1, 24, 1])
    details.avatar = int(get_random_avatar())

    # field26 and field28 are empty messages
    details.field26.SetInParent()
    details.field28.SetInParent()

    # Serialize, encrypt, and send the packet
    serialized = packet.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(serialized, key, iv)

    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)

    if len(packet_length_hex) == 2:
        final_packet = "0514000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051400000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    else:
        print("❌ Packet length formatting failed.")
        return
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def modify_team_player(team, key, iv):
    bot_mode = bot_mode_pb2.BotMode()
    bot_mode.key1 = 17
    bot_mode.key2.uid = 2206344781
    bot_mode.key2.key2 = 1
    bot_mode.key2.key3 = int(team)
    bot_mode.key2.key4 = 62
    bot_mode.key2.byte = base64.b64decode("Gg==")
    bot_mode.key2.key8 = 5
    bot_mode.key2.key13 = 227
    packet = bot_mode.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0514000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051400000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check create_group function.")
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def invite_target(uid, key, iv):
    invite = bot_invite_pb2.invite_uid()
    invite.num = 2
    invite.Func.uid = int(uid)
    invite.Func.region = "IND"
    invite.Func.number = 1
    packet = invite.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0514000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051400000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check create_group function.")
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def left_group(key, iv):
    packet = "0807120608da89d98d27"
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0514000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051400000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check create_group function.")
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def reject_req_wlx(uid, key, iv):
    req = wlxd_special_pb2.RequestRejectwlx()
    req.type = 5
    req.data.idplayer1 = int(uid)
    req.data.flag = 1
    req.data.idplayer2 = int(uid)
    req.data.message = (
        "[FF0000]━━━━━━━━━━━━━━━━━━\n"
        "[00FF00]DEV LEADER : [FF0000]@I_SHOW_AKIRU\n"
        "[FF0000]━━━━━━━━━━━━━━━━━━\n"
        "[FFFF00]DONE HACKING [00FF00] YOUR ACCOUNT\n"
        "[FF0000]━━━━━━━━━━━━━━━━━━\n"
        "[FF0000]FUCK YOU\n"
        "[FF0000]━━━━━━━━━━━━━━━━━━\n"
        "[00FF00]POWERED BY [FFFF00]AKIRU\n"
        "[FF0000]━━━━━━━━━━━━━━━━━━\n"
        "[FFFF00]FOLLOW ME ON INSTAGRAM [00FF00]@akhil_das530\n"
        "[FF0000]━━━━━━━━━━━━━━━━━━\n"
        "[00FF00]IF YOU NOT FOLLOW ME I WILL BAN YOUR ACCOUNT\n"
        "[FF0000]━━━━━━━━━━━━━━━━━━"
    )
    packet = req.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)

    if len(packet_length_hex) == 2:
        final_packet = "0514000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051400000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05140000" + packet_length_hex + encrypted_packet
    else:
        print("something went wrong, please check create_group function.")

    online_writer.write(bytes.fromhex(final_packet))
    await online_writer.drain()

async def join_room(uid, room_id, key, iv):
    root = spam_join_pb2.spam_join()
    root.field_1 = 78
    root.field_2.field_1 = int(room_id)
    root.field_2.name = "[C][B][FF0000]TEAM-[00FF00]AKIRU"
    root.field_2.field_3.field_2 = 1
    root.field_2.field_3.field_3 = 1
    root.field_2.field_4 = 330
    root.field_2.field_5 = 6000
    root.field_2.field_6 = 201
    root.field_2.field_10 = get_random_avatar()
    root.field_2.field_11 = int(uid)
    root.field_2.field_12 = 1
    packet = root.SerializeToString().hex()
    packet_encrypt = await encrypt_packet(packet, key, iv)
    base_len = await base_to_hex(int(len(packet_encrypt) // 2))
    if len(base_len) == 2:
        header = "0e15000000"
    elif len(base_len) == 3:
        header = "0e1500000"
    elif len(base_len) == 4:
        header = "0e150000"
    elif len(base_len) == 5:
        header = "0e15000"
    else:
        header = "0e1500" # fallback
    final_packet = header + base_len + packet_encrypt
    for i in range(100):
        if online_writer:
            online_writer.write(bytes.fromhex(final_packet))
            await asyncio.sleep(0.6)
            await online_writer.drain()

async def send_clan_msg(msg, chat_id, key, iv):
    root = clan_msg_pb2.clan_msg()
    root.type = 1
    nested_object = root.data
    nested_object.uid = 2206344781
    nested_object.chat_id = chat_id
    nested_object.chat_type = 1
    nested_object.msg = msg
    nested_object.timestamp = int(datetime.now().timestamp())
    nested_object.language = "en"
    nested_object.empty_field.SetInParent()
    nested_details = nested_object.field9
    nested_details.Player_Name = "[C][B][FF0000]TEAM-[00FF00]AKIRU"
    nested_details.avatar_id = get_random_avatar()
    nested_details.banner_id = 901000173
    nested_details.rank = 330
    nested_details.badge = get_random_badge()
    nested_details.Clan_Name = "YGㅤᎬ-ꮪꮲꭷꮢꭲꮪㅤ"
    nested_details.field10 = 1
    nested_details.rank_point = 1
    nested_badge = nested_details.field13
    nested_badge.value = 2
    nested_prime = nested_details.field14
    nested_prime.prime_uid = 1158053040
    nested_prime.prime_level = 8
    nested_prime.prime_hex = "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    nested_options = nested_object.field13
    nested_options.url = "https://graph.facebook.com/v9.0/147045590125499/picture?width=160&height=160"
    nested_options.url_type = 1
    nested_options.url_platform = 1
    packet = root.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    hex_length = await base_to_hex(packet_length)
    if len(hex_length) == 2:
        final_packet = "1215000000" + hex_length + encrypted_packet
    elif len(hex_length) == 3:
        final_packet = "121500000" + hex_length + encrypted_packet
    elif len(hex_length) == 4:
        final_packet = "12150000" + hex_length + encrypted_packet
    elif len(hex_length) == 5:
        final_packet = "1215000" + hex_length + encrypted_packet
    else:
        final_packet = "121500" + hex_length + encrypted_packet # Fallback
    return bytes.fromhex(final_packet)

# ### --- MODIFIED: Added 'ghost_name' parameter --- ###
async def create_ghost(team_session, player_uid, key, iv, ghost_name="[B][C]GHOST"): 
    if not online_writer:
        print("Error: Bot not connected")
        return
    
    try:
        root = random_pb2.random()
        root.field1 = 61

        nested_object = root.field2
        nested_object.field1 = int(player_uid)
        nested_object.field3 = str(team_session)

        nested2 = nested_object.field2
        nested2.field1 = int(player_uid)
        
        bot_main_uid = 3964925117
        nested2.field2 = bot_main_uid 
        
        # ### --- MODIFIED: Use the ghost_name parameter here --- ###
        # The [B][C] is added automatically to ensure it's always bold.
        nested2.field3 = f"[B][C]{ghost_name}"
        
        nested2.field5 = int(datetime.now().timestamp())
        nested2.field6 = 15
        nested2.field7 = 1
        nested3 = nested2.field8
        nested3.field2 = 1
        nested3.field3 = 1
        nested2.field9 = 3

        serialized = root.SerializeToString().hex()
        encrypted = await encrypt_packet(serialized, key, iv)
        packet_len = len(encrypted) // 2
        packet_len_hex = await base_to_hex(packet_len)

        # Correcting the header logic to be more robust
        # The total header before the encrypted part should be 10 bytes (20 hex chars)
        # 0514 + 4 null bytes + 2 length bytes = 0514000000XX
        if len(packet_len_hex) == 2:
            final_packet = "0514000000" + packet_len_hex + encrypted
        elif len(packet_len_hex) == 3:
            final_packet = "051400000" + packet_len_hex + encrypted
        else: # Fallback for other lengths
             final_packet = "05140000" + packet_len_hex.zfill(4) + encrypted


        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()
        print(f"✅ Ghost packet sent for UID {player_uid} with code {team_session}") # Adjusted print statement

    except Exception as e:
        print(f"Ghost creation failed: {e}")

async def join_teamcode(room_id, key, iv):
    room_id_hex = ''.join(format(ord(c), 'x') for c in room_id)
    packet = f"080412b305220601090a1219202a07{room_id_hex}300640014ae8040a80013038304639324231383633453135424630323031303130303030303030303034303031363030303130303131303030323944373931333236303930303030353934313732323931343030303030303030303030303030303030303030303030303030303030303030303030303030666630303030303030306639396130326538108f011abf0377505d571709004d0b060b070b5706045c53050f065004010902060c09065a530506010851070a081209064e075c5005020808530d0604090b05050d0901535d030204005407000c5653590511000b4d5e570e02627b6771616a5560614f5e437f7e5b7f580966575b04010514034d7d5e5b465078697446027a7707506c6a5852526771057f5260504f0d1209044e695f0161074e46565a5a6144530174067a43694b76077f4a5f1d6d05130944664456564351667454766b464b7074065a764065475f04664652010f1709084d0a4046477d4806661749485406430612795b724e7a567450565b010c1107445e5e72780708765b460c5e52024c5f7e5349497c056e5d6972457f0c1a034e60757840695275435f651d615e081e090e75457e7464027f5656750a1152565f545d5f1f435d44515e57575d444c595e56565e505b555340594c5708740b57705c5b5853670957656a03007c04754c627359407c5e04120b4861037b004f6b744001487d506949796e61406a7c44067d415b0f5c0f120c4d54024c6a6971445f767d4873076e5f48716f537f695a7365755d520514064d515403717b72034a027d736b6053607e7553687a61647d7a686c610d22047c5b5655300b3a0816647b776b721c144208312e3130382e3134480350025a0c0a044944433110731a0242445a0c0a044944433210661a0242445a0c0a044944433310241a0242446a02656e8201024f52"
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = await base_to_hex(packet_length)
    if len(packet_length_hex) == 2:
        final_packet = "0519000000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 3:
        final_packet = "051900000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 4:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    elif len(packet_length_hex) == 5:
        final_packet = "05190000" + packet_length_hex + encrypted_packet
    else:
        print("Damm Something went wrong, please check join teamcode function")
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def send_team_msg(msg, chat_id, key, iv):
    root = Team_msg_pb2.GenTeamWhisper()
    root.type = 1
    nested_object = root.data
    nested_object.uid = chat_id
    nested_object.chat_id = chat_id
    nested_object.msg = msg
    nested_object.timestamp = int(datetime.now().timestamp())
    nested_object.chat_type = 2
    nested_object.language = "en"
    nested_details = nested_object.field9
    nested_details.Nickname = "[C][B][FF0000]TEAM-[00FF00]AKIRU"
    nested_details.avatar_id = get_random_avatar()
    nested_details.rank = 330
    nested_details.badge = get_random_badge()
    nested_details.Clan_Name = "YGㅤᎬ-ꮪꮲꭷꮢꭲꮪㅤ"
    nested_details.field10 = 1
    nested_details.global_rank_pos = 1
    nested_details.badge_info.value = 2
    nested_details.prime_info.prime_uid = 1158053040
    nested_details.prime_info.prime_level = 8
    nested_details.prime_info.prime_hex = "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    nested_options = nested_object.field13
    nested_options.url_type = 2
    nested_options.curl_platform = 1
    nested_object.empty_field.SetInParent()
    packet = root.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    hex_length = await base_to_hex(packet_length)
    packet_prefix = "121500" + "0" * (6 - len(hex_length))
    final_packet = packet_prefix + hex_length + encrypted_packet
    return bytes.fromhex(final_packet)

async def send_title_msg(msg, chat_id, key, iv):
    root = wlxd_title_pb2.GenTeamTitle()
    root.type = 1
    nested_object = root.data
    nested_object.uid = 1968827534
    nested_object.chat_id = chat_id
    nested_object.msg = msg
    nested_object.title = f"{{\"TitleID\":{get_random_title()},\"type\":\"Title\"}}"
    nested_object.timestamp = int(datetime.now().timestamp())
    nested_object.chat_type = 2
    nested_object.language = "en"
    nested_details = nested_object.field9
    nested_details.Nickname = "[C][B][FF0000]TEAM-[00FF00]AKIRU"
    nested_details.avatar_id = get_random_avatar()
    nested_details.rank = 330
    nested_details.badge = 827001005
    nested_details.Clan_Name = "YGㅤᎬ-ꮪꮲꭷꮢꭲꮪㅤ"
    nested_details.field10 = 1
    nested_details.global_rank_pos = 1
    nested_details.badge_info.value = 2
    nested_details.prime_info.prime_uid = 1158053040
    nested_details.prime_info.prime_level = 8
    nested_details.prime_info.prime_hex = "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    nested_options = nested_object.field13
    nested_options.url_type = 2
    nested_options.curl_platform = 1
    nested_object.empty_field.SetInParent()
    packet = root.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    hex_length = await base_to_hex(packet_length)
    packet_prefix = "121500" + "0" * (6 - len(hex_length))
    final_packet = packet_prefix + hex_length + encrypted_packet
    return bytes.fromhex(final_packet)

async def send_msg(msg, chat_id, key, iv):
    root = GenWhisperMsg_pb2.GenWhisper()
    root.type = 1
    nested_object = root.data
    nested_object.uid = 1968827534
    nested_object.chat_id = chat_id
    nested_object.chat_type = 2
    nested_object.msg = msg
    nested_object.timestamp = int(datetime.now().timestamp())
    nested_details = nested_object.field9
    nested_details.Nickname = "[C][B][FF0000]TEAM-[00FF00]AKIRU"
    nested_details.avatar_id = get_random_avatar()
    nested_details.banner_id = 901000173
    nested_details.rank = 330
    nested_details.badge = get_random_badge()
    nested_details.Clan_Name = "YGㅤᎬ-ꮪꮲꭷꮢꭲꮪㅤ"
    nested_details.field10 = 1
    nested_details.global_rank_pos = 1
    nested_badge = nested_details.field13
    nested_badge.value = 2
    nested_prime = nested_details.field14
    nested_prime.prime_uid = 1158053040
    nested_prime.prime_level = 8
    nested_prime.prime_hex = "\u0010\u0015\b\n\u000b\u0015\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
    nested_options = nested_object.field13
    nested_object.language = "en"
    nested_options.url = "https://graph.facebook.com/v9.0/147045590125499/picture?width=160&height=160"
    nested_options.url_type = 2
    nested_options.url_platform = 1
    root.data.Celebrity = 1919408565318037500
    root.data.empty_field.SetInParent()
    packet = root.SerializeToString().hex()
    encrypted_packet = await encrypt_packet(packet, key, iv)
    packet_length = len(encrypted_packet) // 2
    hex_length = await base_to_hex(packet_length)
    if len(hex_length) == 2:
        final_packet = "1215000000" + hex_length + encrypted_packet
    elif len(hex_length) == 3:
        final_packet = "121500000" + hex_length + encrypted_packet
    elif len(hex_length) == 4:
        final_packet = "12150000" + hex_length + encrypted_packet
    elif len(hex_length) == 5:
        final_packet = "1215000" + hex_length + encrypted_packet
    else:
        final_packet = "121500" + hex_length + encrypted_packet # Fallback
    return bytes.fromhex(final_packet)

# <---FIXED FUNCTION--->
# Restored this function to its original, working state.
async def get_encrypted_startup(AccountUID, token, timestamp, key, iv):
    uid_hex = hex(AccountUID)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await base_to_hex(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await encrypt_packet(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9:
        headers = '0000000'
    elif uid_length == 8:
        headers = '00000000'
    elif uid_length == 10:
        headers = '000000'
    elif uid_length == 7:
        headers = '000000000'
    else:
        # A default case to prevent errors, even if it might not work for all UIDs.
        print(f'Unexpected UID length ({uid_length}), using default header. This might fail.')
        headers = '000000'
        
    # The original structure of the packet is restored here.
    packet = f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
    return packet

async def Encrypt(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

async def uid_status(uid, key, iv):
    uid_text = {await Encrypt(uid)}
    uid_hex = next(iter(uid_text))
    packet = f"080112e8010ae301afadaea327bfbd809829a8fe89db07eda4c5f818f8a485850eefb3a39e06{uid_hex}ecb79fd623e4b3c0f506c6bdc48007d4efbc7ce688be8709c99ef7bc02e0a8bcd607d6ebe8e406dcc9a6ae07bfdab0e90a8792c28d08b58486f528cfeff0c61b95fcee8b088f96da8903effce2b726b684fbe10abfe984db28bbfebca528febd8dba28ecb98cb00baeb08de90583f28a9317a5ced6ab01d3de8c71d3a1b1be01ede292e907e5ecd0b903b2cafeae04c098fae5048cfcc0cd18d798b5f401cd9cbb61e8dce3c00299b895de1184e9c9ee11c28ed0d803f8b7ffec02a482babd011001"
    encrypted_packet = await encrypt_packet(packet, key, iv)
    header_length = len(encrypted_packet) // 2
    header_length_hex = await base_to_hex(header_length)
    if len(header_length_hex) == 2:
        final_packet = "0f15000000" + header_length_hex + encrypted_packet
    elif len(header_length_hex) == 3:
        final_packet = "0f1500000" + header_length_hex + encrypted_packet
    elif len(header_length_hex) == 4:
        final_packet = "0f150000" + header_length_hex + encrypted_packet
    elif len(header_length_hex) == 5:
        final_packet = "0f150000" + header_length_hex + encrypted_packet
    else:
        raise ValueError("error 505")
    if online_writer:
        online_writer.write(bytes.fromhex(final_packet))
        await online_writer.drain()

async def handle_tcp_online_connection(ip, port, key, iv, encrypted_startup, reconnect_delay=0.5):
    global online_writer, spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(encrypted_startup)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data:
                    break
                if data.hex().startswith("0f00"):
                    if spam_room:
                        try:
                            json_result = await get_available_room(data.hex()[10:])
                            if json_result:
                                parsed_data = json.loads(json_result)
                                if "5" in parsed_data and "data" in parsed_data["5"] and "1" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["1"] and "15" in parsed_data["5"]["data"]["1"]["data"] and "data" in parsed_data["5"]["data"]["1"]["data"]["15"]:
                                    room_id = parsed_data["5"]["data"]["1"]["data"]["15"]["data"]
                                    uid = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                                    spam_room = True
                                    message = f"Spamming on\n\nRoom ID: {str(room_id)[:5]}[C]{str(room_id)[5:]}\nUID: {str(uid)[:5]}[C]{str(uid)[5:]}"
                                    if spam_chat_id == 1:
                                        msg_packet = await send_team_msg(message, spam_uid, key, iv)
                                    elif spam_chat_id == 2:
                                        msg_packet = await send_clan_msg(message, spam_uid, key, iv)
                                    else:
                                        msg_packet = await send_msg(message, spam_uid, key, iv)
                                    if whisper_writer:
                                        whisper_writer.write(msg_packet)
                                        await whisper_writer.drain()
                                    await join_room(uid, room_id, key, iv)
                                else:
                                    message = "Player not in room"
                                    if spam_chat_id == 1:
                                        msg_packet = await send_team_msg(message, spam_uid, key, iv)
                                    elif spam_chat_id == 2:
                                        msg_packet = await send_clan_msg(message, spam_uid, key, iv)
                                    else:
                                        msg_packet = await send_msg(message, spam_uid, key, iv)
                                    if whisper_writer:
                                        whisper_writer.write(msg_packet)
                                        await whisper_writer.drain()
                                    spam_room = True
                        except Exception as e:
                            print(f"Error processing room data: {e}")
                            spam_room = True
                # <<<--- CORRECTED PACKET HANDLER --->
                elif data.hex().startswith("0500000"):
                    try:
                        global captured_ghost_code, captured_player_uid
                        response = await decode_team_packet(data.hex()[10:])
                        
                        # We need both the 'code' and the 'player_uid' from this packet.
                        if response.packet_type == 6 and response.details.code and response.details.player_uid:
                            captured_ghost_code = response.details.code
                            captured_player_uid = response.details.player_uid
                            
                            print(f"✅ Ghost Code captured: {captured_ghost_code}")
                            print(f"✅ Player UID for Ghost captured: {captured_player_uid}")
                            
                            team_session_captured_event.set() # Signal that we have the data
                            
                            # The team chat startup still correctly uses team_session
                            await team_chat_startup(response.details.player_uid, response.details.team_session, key, iv)
                    except Exception as e:
                        pass
            if online_writer:
                online_writer.close()
                await online_writer.wait_closed()
            online_writer = None
        except Exception as e:
            print(f"Error with {ip}:{port} - {e}")
            online_writer = None
        await asyncio.sleep(reconnect_delay)

async def send_help_messages(response, uid, chat_id, key, iv):
    """Sends categorized help messages."""
    user_name = response.Data.Details.Nickname
    async def send_chunk(message_text):
        if not response.Data.chat_type:
            msg_packet = await send_team_msg(message_text, uid, key, iv)
        elif response.Data.chat_type == 1:
            msg_packet = await send_clan_msg(message_text, chat_id, key, iv)
        else:
            msg_packet = await send_msg(message_text, uid, key, iv)

        if whisper_writer:
            whisper_writer.write(msg_packet)
            await whisper_writer.drain()
        await asyncio.sleep(0.5)

    # ─────────────────────────────
    # WELCOME MESSAGE
    # ─────────────────────────────
    welcome_msg = "[C][B][FFD700]Hey {user_name} Welcome To ᴀᴋɪʀᴜ ˣ ʙᴏᴛ".format(user_name=user_name)
    await send_chunk(welcome_msg)

    # ─────────────────────────────
    # GENERAL COMMANDS
    # ─────────────────────────────
    general_commands = ("[B][C][FFFF00]┌─[FFFFFF] GENERAL COMMANDS\n"    
                        "[B][C][FFFF00]├─[FFFFFF] /help [00FF00]- Show Commands.\n"    
                        "[B][C][FFFF00]├─[FFFFFF] /ms [message] [00FF00]- Send Message.\n"    
                        "[B][C][FFFF00]└─[FFFFFF] /ai [question] [00FF00]- AI Question.")
    await send_chunk(general_commands)

    # ─────────────────────────────
    # GROUP COMMANDS
    # ─────────────────────────────
    group_commands = ("[B][C][FFFF00]┌─[FFFFFF] GROUP COMMANDS\n"    
                      "[B][C][FFFF00]├─[FFFFFF] /3 [00FF00]- 3-Player Group.\n"    
                      "[B][C][FFFF00]├─[FFFFFF] /5 [00FF00]- 5-Player Group.\n"    
                      "[B][C][FFFF00]├─[FFFFFF] /6 [00FF00]- 6-Player Group.\n"    
                      "[B][C][FFFF00]├─[FFFFFF] /ghost [Team Code]- Invite Ghost.\n"
                      "[B][C][FFFF00]├─[FFFFFF] /join_tc [code] [00FF00]- Join Team.\n"    
                      "[B][C][FFFF00]└─[FFFFFF] /exit [00FF00]- Leave Group.")
    await send_chunk(group_commands)

    # ─────────────────────────────
    # SPAM & FUN COMMANDS
    # ─────────────────────────────
    spam_commands = ("[B][C][FFFF00]┌─[FFFFFF] SPAM & FUN COMMANDS\n"    
                     "[B][C][FFFF00]├─[FFFFFF] /room [uid] [00FF00]- Spam Room.\n"    
                     "[B][C][FFFF00]├─[FFFFFF] /sm [uid] [00FF00]- Spam Team.\n"
                     "[B][C][FFFF00]├─[FFFFFF] /gt [uid] [00FF00]- Ghost Tag Spam.\n" 
                     "[B][C][FFFF00]├─[FFFFFF] /lag [team_code] [00FF00]- Lag Lobby.\n"    
                     "[B][C][FFFF00] ├─[FFFFFF] /reject [00FF00]- Dark Lag.\n"
                     "[B][C][FFFF00]└─[FFFFFF] /teame [00FF00]- Lag Team Flicker.")
    await send_chunk(spam_commands)

    # ─────────────────────────────
    # UTILITY COMMANDS
    # ─────────────────────────────
    utility_commands = ("[B][C][FFFF00]┌─[FFFFFF] UTILITY COMMANDS\n"    
                        "[B][C][FFFF00]├─[FFFFFF] /info [uid] [00FF00]- Player's Info.\n"    
                        "[B][C][FFFF00]├─[FFFFFF] /region [uid] [00FF00]- Check Region.\n"
                        "[B][C][FFFF00]├─[FFFFFF] /check [uid] [00FF00]- Check Banned.\n"    
                        "[B][C][FFFF00]└─[FFFFFF] /like [uid] [00FF00]- Send Likes.")    
    await send_chunk(utility_commands)

    # ─────────────────────────────
    # FOOTER MESSAGE
    # ─────────────────────────────
    footer_msg = (
        "[B][C][0088CC]╔════════╗\n"
        "[B][C][0088CC]║ [FFFFFF]TELEGRAM: @I_SHOW_AKIRU [0088CC]║\n"
        "[B][C][0088CC]╚════════╝"
    )
    await send_chunk(footer_msg)


### --- ADDED --- ###
# This new function contains the logic for the ghost command.
# It can now be called from anywhere, including the API.
async def execute_ghost_sequence(team_code, key, iv, ghost_name):
    """
    Performs the full sequence of joining a team, capturing data, leaving,
    and sending the ghost packet.
    Returns a tuple: (success: bool, message: str)
    """
    try:
        # 1. Reset state before starting
        team_session_captured_event.clear()
        global captured_ghost_code, captured_player_uid
        captured_ghost_code = None
        captured_player_uid = None

        # 2. Bot joins the target team
        await join_teamcode(team_code, key, iv)

        # 3. Wait for the required data to be captured (with a 10-second timeout)
        print(f"⏳ Waiting for team session data for team code: {team_code}...")
        await asyncio.wait_for(team_session_captured_event.wait(), timeout=10.0)
        
        # 4. If the wait was successful, proceed.
        if captured_ghost_code and captured_player_uid and online_writer:
            await left_group(key, iv)
            await asyncio.sleep(0.5) 
            
            # ### --- MODIFIED: Pass the ghost_name to the function --- ###
            await create_ghost(captured_ghost_code, captured_player_uid, key, iv, ghost_name)
            
            return True, f"Ghost created successfully in team {team_code}."
            
        else:
            await left_group(key, iv)
            return False, "Error: Bot is not online or failed to capture required team data."

    except asyncio.TimeoutError:
        return False, f"Failed to get team data for {team_code}. Is the team valid and is a player present?"
    except Exception as e:
        # Attempt to leave on any other error to be safe
        try:
            await left_group(key, iv)
        except Exception as leave_e:
            print(f"Error during cleanup leave: {leave_e}")
        return False, f"An unexpected error occurred: {str(e)}"
### --- END ADDED --- ###

### --- ADDED: New async helper functions for API endpoints --- ###

async def execute_code_sequence(team_code, message, key, iv):
    """
    Joins a team, sends a title and a message, then leaves.
    Returns a tuple: (success: bool, message: str)
    """
    try:
        # 1. Join the team
        await join_teamcode(team_code, key, iv)
        await asyncio.sleep(2)  # Wait to settle in the team

        # 2. Send a random title message first
        # For team context, a valid UID is needed. Using the owner's as a placeholder.
        title_message = "[C][B][00FFFF]Enjoy The Show!"
        title_msg_packet = await send_title_msg(title_message, OWNER_UID, key, iv)
        if whisper_writer:
            whisper_writer.write(title_msg_packet)
            await whisper_writer.drain()
        await asyncio.sleep(1)

        # 3. Send the message with a "typing" effect
        for i in range(1, len(message) + 1):
            partial_message = message[:i]
            team_msg_packet = await send_team_msg(partial_message, OWNER_UID, key, iv)
            if whisper_writer:
                whisper_writer.write(team_msg_packet)
                await whisper_writer.drain()
            await asyncio.sleep(0.3)

        # 4. Leave the team
        await asyncio.sleep(1)
        await left_group(key, iv)

        return True, f"Message sent successfully to team {team_code}."
    except Exception as e:
        # Attempt to leave on error
        try: await left_group(key, iv)
        except: pass
        return False, f"An error occurred: {str(e)}"

async def execute_room_spam_sequence(target_uid, key, iv):
    """
    Finds a user's room and initiates spam. This is a fire-and-forget action.
    Returns a tuple: (success: bool, message: str)
    """
    global spam_room, spammer_uid, spam_chat_id, spam_uid
    try:
        if not online_writer:
            return False, "Bot's online connection is not active."
        
        # This function triggers the spam but doesn't wait for it to finish.
        # We need to set the global flags for the handler to work.
        spam_room = True
        spammer_uid = None # API doesn't have a user context
        spam_chat_id = None # No chat to reply to
        spam_uid = None
        
        await uid_status(int(target_uid), key, iv)
        
        return True, f"Room spam sequence initiated for UID {target_uid}. The bot will join and spam if the room is found."
    except Exception as e:
        return False, f"An error occurred: {str(e)}"

async def execute_sm_spam_sequence(target_uid, key, iv):
    """
    Spams a user with team join requests.
    Returns a tuple: (success: bool, message: str)
    """
    try:
        if not online_writer:
            return False, "Bot's online connection is not active."

        # Spam join requests 100 times
        for _ in range(100):
            await wlxd_skwad(target_uid, key, iv)
            await asyncio.sleep(0.3) # Small delay between requests
            
        return True, f"Successfully sent 100 team join requests to UID {target_uid}."
    except Exception as e:
        return False, f"An error occurred during spam: {str(e)}"

async def execute_teame_sequence(key, iv):
    """
    Creates a group and rapidly flickers between 5 and 6 players.
    This is a fire-and-forget action from the API's perspective.
    """
    try:
        if not online_writer:
            return False, "Bot's online connection is not active."

        await create_group(key, iv)
        await asyncio.sleep(2) # Wait for group creation

        # Flicker 100 times (50 cycles)
        for _ in range(50):
            await modify_team_player("5", key, iv)
            await asyncio.sleep(0.2)
            await modify_team_player("4", key, iv)
            await asyncio.sleep(0.2)
        
        await left_group(key, iv)
        return True, "Team flicker sequence completed."
    except Exception as e:
        try: await left_group(key, iv)
        except: pass
        return False, f"An error occurred: {str(e)}"

### --- END ADDED --- ###

async def handle_tcp_connection(ip, port, encrypted_startup, key, iv, Decode_GetLoginData, ready_event, reconnect_delay=0.5):
    global spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, online_writer
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(encrypted_startup)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            
            ### --- MODIFIED --- ###
            # The bot is now ready, update the global state for the API
            bot_live_state["key"] = key
            bot_live_state["iv"] = iv
            bot_live_state["ready"] = True
            ### --- END MODIFIED --- ###
            
            ready_event.set()
            if Decode_GetLoginData.Clan_ID:
                clan_id = Decode_GetLoginData.Clan_ID
                clan_compiled_data = Decode_GetLoginData.Clan_Compiled_Data
                await create_clan_startup(clan_id, clan_compiled_data, key, iv)
            while True:
                data = await reader.read(9999)
                if not data:
                    break
                if data.hex().startswith("120000"):
                    response = await DecodeWhisperMessage(data.hex()[10:])
                    
                    # <<<--- BAN CHECK ---<<<
                    sender_uid = response.Data.uid
                    # The owner can never be banned or ignored
                    if sender_uid != OWNER_UID and await is_user_banned(sender_uid):
                        continue  # Silently ignore the command from the banned user
                        
                    received_msg = response.Data.msg.lower()
                    if received_msg == "hi":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "Hello"
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        elif response.Data.chat_type == 2:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                    elif received_msg == "/help":
                        uid = response.Data.uid
                        user_name = response.Data.Details.Nickname
                        chat_id = response.Data.Chat_ID
                        await send_help_messages(response, uid, chat_id, key, iv)
                    elif received_msg.startswith("/sm"):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = f"[C][B][FFFFFF]Joining Request Spam Started"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            if online_writer:
                                try:
                                    for _ in range(100):
                                        await wlxd_skwad(target_uid, key, iv)
                                        await asyncio.sleep(0.5)
                                    final_message = f"[C][B][00FF00]Join Request Spam\n [FF0000]Successful"
                                except Exception as e:
                                    final_message = f"[C][B][FF0000]Error during spam"
                            else:
                                final_message = "[C][B][FF0000]Error: Bot is not connected to the server."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(final_message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(final_message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(final_message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Invalid format. Use /sm [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/ms "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        raw_message = response.Data.msg[4:].strip()
                        if raw_message:
                            cleaned_message = re.sub(r'[^\x20-\x7E]', '', raw_message).replace("(J,", "")
                            cleaned_message = " ".join(cleaned_message.split())
                            for i in range(1, len(cleaned_message) + 1):
                                partial_message = cleaned_message[:i]
                                colored = f"[C][B]{get_random_color()}{partial_message}"
                                if not response.Data.chat_type:
                                    msg_packet = await send_team_msg(colored, uid, key, iv)
                                elif response.Data.chat_type == 1:
                                    msg_packet = await send_clan_msg(colored, chat_id, key, iv)
                                elif response.Data.chat_type == 2:
                                    msg_packet = await send_msg(colored, uid, key, iv)
                                if whisper_writer:
                                    whisper_writer.write(msg_packet)
                                    await whisper_writer.drain()
                                await asyncio.sleep(0.3)
                        else:
                            message = "[C][B][FF0000]Invalid format. Use /ms [message]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            elif response.Data.chat_type == 2:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/info "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "[C][B][FFFFFF]Please wait, fetching info..."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            try:
                                url = f"https://info-api-aditya-ffm.vercel.app/player-info?uid={target_uid}&region=ind"
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(url) as resp:
                                        if resp.status == 200:
                                            data = await resp.json()
                                            player_data = data.get("player_info", {})
                                            if not player_data:
                                                message = "[C][B][FF0000]Player not found or API error."
                                            else:
                                                basic = player_data.get("basicInfo", {})
                                                social = player_data.get("socialInfo", {})
                                                clan = player_data.get("clanBasicInfo", {})
                                                captain = player_data.get("captainBasicInfo", {})
                                                nickname = basic.get('nickname', 'N/A')
                                                account_id = basic.get('accountId', 'N/A')
                                                level = basic.get('level', 'N/A')
                                                region = basic.get('region', 'N/A')
                                                likes = basic.get('liked', 'N/A')
                                                signature = social.get('signature', 'N/A')
                                                player_info = (f"[C][B]┌ [FFD700]Player Info:\n"f"-[FFFFFF]├─ Name: {nickname}\n"f"- ├─ UID: {str(account_id)[:5]}[C]{str(account_id)[5:]}\n"f"- ├─ Level: {level}\n"f"- ├─ Region: {region}\n"f"- ├─ Likes: {likes}\n"f"- └─ Bio: {signature}")
                                                if clan and captain:
                                                    clan_name = clan.get('clanName', 'N/A')
                                                    Capacity = clan.get('capacity', 'N/A')
                                                    Members = clan.get('memberNum', 'N/A')
                                                    captain_name = captain.get('nickname', 'N/A')
                                                    UID = captain.get('uid', 'N/A')
                                                    Level = captain.get('level', 'N/A')
                                                    Likes = captain.get('liked', 'N/A')
                                                    player_info += (f"\n\n[C][B]┌ [00FF00]Clan Info:\n"f"-[FFFFFF]├─ Name: {clan_name}\n"f"- ├─ Leader: {captain_name}\n"f"- ├─ UID: {UID}\n"f"- ├─ Level: {Level}\n"f"- ├─ Likes: {Likes}\n"f"- └─ Capacity: {Capacity} | Members: {Members}\n"f"\n[B][C][FFFFFF]TELEGRAM: @I_SHOW_AKIRU")
                                                message = player_info
                                        else:
                                            message = "[C][B][FF0000]Failed to fetch player info (API Error)."
                            except Exception as e:
                                message = f"[C][B][FF0000]Error: {e}"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Usage: /info [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/check "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "[C][B][FFFFFF]Checking ban status..."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            try:
                                url = f"https://bancheck-api-aditya-ffm.vercel.app/bancheck?uid={target_uid}"
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(url) as resp:
                                        if resp.status == 200:
                                            data = await resp.json()
                                            message = (f"[C][B]┌ [FFD700]Ban Check Result:\n"f"[FFFFFF]├─ Name: {data.get('nickname', 'N/A')}\n"f"├─ UID: {str(data.get('uid', 'N/A'))[:5]}[C]{str(data.get('uid', 'N/A'))[5:]}\n"f"├─ Region: {data.get('region', 'N/A')}\n"f"├─ Status: {data.get('ban_status', 'N/A')}\n"f"\n[B][C][FFFFFF]TELEGRAM: @I_SHOW_AKIRU")
                                        else:
                                            message = "[C][B][FF0000]Failed to check ban status (API Error)."
                            except Exception as e:
                                message = f"[C][B][FF0000]Error: {e}"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Usage: /check [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/add "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "[C][B][FFFFFF]Bot Add status..."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            try:
                                url = f"https://tcp-request.vercel.app/add?uid=3964925117&password=ARIIwe8H0m3z1oMYJ46b&target_uid={target_uid}"
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(url) as resp:
                                        if resp.status == 200:
                                            data = await resp.json()
                                            message = (f"[C][B]┌ [FFD700]Bot Add Results:\n"f"[FFFFFF]├─ Message: {data.get('message', 'N/A')}\n"f"\n[B][C][FFFFFF]TELEGRAM: @I_SHOW_AKIRU")
                                        else:
                                            message = "[C][B][FF0000]Failed to Add Bot (API Error)."
                            except Exception as e:
                                message = f"[C][B][FF0000]Error: {e}"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Usage: /add [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/region "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "[C][B][FFFFFF]Checking Region status..."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            try:
                                url = f"https://region-api-aditya-ffm.vercel.app/region?uid={target_uid}"
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(url) as resp:
                                        if resp.status == 200:
                                            data = await resp.json()
                                            message = (f"[C][B]┌ [FFD700]Ban Check Result:\n"f"[FFFFFF]├─ Name: {data.get('nickname', 'N/A')}\n"f"├─ UID: {str(data.get('uid', 'N/A'))[:5]}[C]{str(data.get('uid', 'N/A'))[5:]}\n"f"├─ Region: {data.get('region', 'N/A')}\n[B][C][FFFFFF]TELEGRAM: @I_SHOW_AKIRU")
                                        else:
                                            message = "[C][B][FF0000]Failed to check Region status (API Error)."
                            except Exception as e:
                                message = f"[C][B][FF0000]Error: {e}"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Usage: /region [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/reject"):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID

                        reject_message = (
                            "done boss"
                        )
                        msg_packet = None
                        if response.Data.chat_type is None:
                            msg_packet = await reject_req_wlx(uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await reject_req_wlx(uid, key, iv)
                        elif response.Data.chat_type == 2:
                            reject_packet = await reject_req_wlx(uid, key, iv)
                            whisper_writer.write(reject_packet)
                            await whisper_writer.drain()

                        if msg_packet:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                    elif received_msg.startswith("/gt"):
                        try:
                            uid = response.Data.uid
                            chat_id = response.Data.Chat_ID
                            parts = received_msg.strip().split()
                            
                            if len(parts) == 2 and parts[1].isdigit():
                                target_uid = parts[1]
                                message = f"[C][B][FFFFFF]Solo Spam Started"
                                
                                if not response.Data.chat_type:
                                    msg_packet = await send_team_msg(message, uid, key, iv)
                                elif response.Data.chat_type == 1:
                                    msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                else:
                                    msg_packet = await send_msg(message, uid, key, iv)
                                    
                                if whisper_writer:
                                    whisper_writer.write(msg_packet)
                                    await whisper_writer.drain()
                                    
                                if online_writer:
                                    try:
                                        spam_count = 50
                                        for _ in range(spam_count):
                                            await create_group(key, iv)
                                            await asyncio.sleep(0.01)

                                            await invite_target(target_uid, key, iv)
                                            await asyncio.sleep(0.01)
                                            
                                            await left_group(key, iv)
                                            await asyncio.sleep(0.01)
                                            
                                            await modify_team_player("0", key, iv)
                                            await asyncio.sleep(0.01)
                                            
                                        final_message = f"[C][B][00FF00]Solo Spam\n [FF0000]Successful\nSent {spam_count} invites to UID: {target_uid}"
                                        
                                    except Exception as e:
                                        print(f"Error in /gt command loop: {e}")
                                        final_message = f"[C][B][FF0000]Error during spam: {str(e)}"
                                else:
                                    final_message = "[C][B][FF0000]Error: Bot is not connected to the server."
                                    
                                if not response.Data.chat_type:
                                    msg_packet = await send_team_msg(final_message, uid, key, iv)
                                elif response.Data.chat_type == 1:
                                    msg_packet = await send_clan_msg(final_message, chat_id, key, iv)
                                else:
                                    msg_packet = await send_msg(final_message, uid, key, iv)
                                    
                                if whisper_writer:
                                    whisper_writer.write(msg_packet)
                                    await whisper_writer.drain()
                                    
                            else:
                                message = "[C][B][FF0000]Invalid format. Use /gt [uid]"
                                if not response.Data.chat_type:
                                    msg_packet = await send_team_msg(message, uid, key, iv)
                                elif response.Data.chat_type == 1:
                                    msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                else:
                                    msg_packet = await send_msg(message, uid, key, iv)
                                    
                                if whisper_writer:
                                    whisper_writer.write(msg_packet)
                                    await whisper_writer.drain()
                                    
                        except Exception as e:
                            print(f"Error in /gt command handler: {e}")
                            error_msg = "[C][B][FF0000]An error occurred in solo spam!"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(error_msg, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(error_msg, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(error_msg, uid, key, iv)
                                
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg == "/3":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "Please Accept My Invitation to Join Group."
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        elif response.Data.chat_type == 2:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        await create_group(key, iv)
                        await asyncio.sleep(0.4)
                        await modify_team_player("2", key, iv)
                        await asyncio.sleep(0.1)
                        await invite_target(uid, key, iv)
                        await asyncio.sleep(3)
                        await left_group(key, iv)
                    elif received_msg == "/7":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "Please Accept My Invitation to Join Group."
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        elif response.Data.chat_type == 2:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        await create_group(key, iv)
                        await asyncio.sleep(0.4)
                        await modify_team_player("6", key, iv)
                        await asyncio.sleep(0.1)
                        await invite_target(uid, key, iv)
                        await asyncio.sleep(3)
                        await left_group(key, iv)
                    elif received_msg.startswith("/room") or received_msg.startswith("/room"):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = response.Data.msg.strip().split(maxsplit=1)
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "Please Wait"
                            if not response.Data.chat_type:
                                spam_chat_id = 1
                                spam_uid = uid
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                spam_uid = chat_id
                                spam_chat_id = 2
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else: # Default to whisper
                                spam_uid = uid
                                spam_chat_id = 3
                                msg_packet = await send_msg(message, uid, key, iv)

                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                            await uid_status(int(target_uid), key, iv)
                            spam_room = True
                            spammer_uid = uid
                        else:
                            message = "[C][B][FF0000]Invalid format. Use /room [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                    elif received_msg.startswith("/like "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "[C][B][FFFFFF]Sending like, please wait..."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            try:
                                url = f"https://like-api-aditya-ffm.vercel.app/like?uid={target_uid}&server_name=ind&key=360"
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(url) as resp:
                                        if resp.status == 200:
                                            data = await resp.json()
                                            likes_given = data.get('LikesGivenByAPI', 0)
                                            if likes_given > 0:
                                                message = (f"[C][B]┌ [FFD700]Like Sent Successfully:\n"f"[FFFFFF]├─ Name: {data.get('PlayerNickname', 'N/A')}\n"f"├─ UID: {str(data.get('UID', 'N/A'))[:5]}[C]{str(data.get('UID', 'N/A'))[5:]}\n"f"├─ Likes Before: {data.get('LikesbeforeCommand', 'N/A')}\n"f"├─ Likes Given: {data.get('LikesGivenByAPI', 'N/A')}\n"f"└─ Likes After: {data.get('LikesafterCommand', 'N/A')}")
                                            else:
                                                message = f"[C][B][FFA500]Max likes already sent to {data.get('PlayerNickname', 'this player')} for today. Try again tomorrow."
                                        else:
                                            message = "[C][B][FF0000]Failed to send like (API error)."
                            except Exception as e:
                                message = f"[C][B][FF0000]Error: {e}"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Usage: /like [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/lag"):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = response.Data.msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            team_code = parts[1]
                            message = f"[C][B][FF9900]⚠️ Lag spam started for team: {team_code}"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                            JOIN_DELAY = 0.01
                            LEAVE_DELAY = 0.01
                            for i in range(500):
                                try:
                                    await join_teamcode(team_code, key, iv)
                                    await asyncio.sleep(JOIN_DELAY)
                                    await left_group(key, iv)
                                    await asyncio.sleep(LEAVE_DELAY)
                                except Exception as e:
                                    print(f"[!] Error in loop {i+1}: {e}")
                                    continue
                            message = "[C][B][FF0000]⚠️ [FFFFFF] Lag spam completed [FF0000]⚠️ "
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        else:
                            error_msg = "[C][B][FF0000]❌ Invalid format. Use /lag [team_code]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(error_msg, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(error_msg, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(error_msg, uid, key, iv)
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                    elif received_msg == "/title":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        title_message = "[C][B][00FFFF]Title Applied Successfully!"
                        msg_packet = await send_title_msg(title_message, chat_id, key, iv)
                        whisper_writer.write(msg_packet)
                        await whisper_writer.drain()
                    elif received_msg == "hello":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        title_message = "[C][B][00FFFF]Title Applied Successfully!"
                        msg_packet = await send_title_msg(title_message, chat_id, key, iv)
                        whisper_writer.write(msg_packet)
                        await whisper_writer.drain()
                    elif received_msg == "/5":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "Please Accept My Invitation to Join Group."
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        elif response.Data.chat_type == 2:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        await create_group(key, iv)
                        await asyncio.sleep(0.4)
                        await modify_team_player("4", key, iv)
                        await asyncio.sleep(0.1)
                        await invite_target(uid, key, iv)
                        await asyncio.sleep(3)
                        await left_group(key, iv)
                    elif received_msg == "/teame":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "[C][B][FF9900]⚠️ Starting extreme team sequence... Accept the invite quickly!"
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        await create_group(key, iv)
                        await asyncio.sleep(0.4)
                        await invite_target(uid, key, iv)
                        await asyncio.sleep(3)
                        flicker_count = 500
                        for i in range(flicker_count):
                            await modify_team_player("5", key, iv)
                            await asyncio.sleep(0.3)
                            await modify_team_player("4", key, iv)
                            await asyncio.sleep(0.3)
                        await left_group(key, iv)
                        final_message = f"[C][B][00FF00]✅ Extreme team sequence of {flicker_count} flickers complete."
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(final_message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(final_message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(final_message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                    elif received_msg.startswith("/join_tc "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            team_code = parts[1]
                            
                            # --- Step 1: Send confirmation message to the original chat ---
                            # This part now correctly sends the confirmation back to where the command was issued from.
                            confirmation_message = "Request received. Joining team..."
                            if not response.Data.chat_type: # User is in a team with the bot
                                msg_packet = await send_team_msg(confirmation_message, uid, key, iv)
                            elif response.Data.chat_type == 1: # User is in a clan chat
                                msg_packet = await send_clan_msg(confirmation_message, chat_id, key, iv)
                            else: # User is in a private message with the bot
                                msg_packet = await send_msg(confirmation_message, uid, key, iv)
                            
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            
                            # --- Step 2: Join the target team ---
                            await join_teamcode(team_code, key, iv)
                            
                            # --- Step 3: Wait and send the title message to the NEW team ---
                            await asyncio.sleep(2) # Increased delay slightly for stability
                            
                            title_message = "[C][B][00FFFF]Title Applied Successfully!"
                            # For the new team chat, we use the *bot's own UID* as the target for the message packet.
                            # Using the sender's UID is also correct here as the context is now the team.
                            title_msg_packet = await send_title_msg(title_message, uid, key, iv) 
                            if whisper_writer:
                                whisper_writer.write(title_msg_packet)
                                await whisper_writer.drain()
                        else:
                            # Handle incorrect format
                            error_message = "[C][B][FF0000]Invalid format. Use /join_tc [team_code]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(error_message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(error_message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(error_message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/code "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        # Use response.Data.msg to get the original case for the message
                        parts = response.Data.msg.strip().split(maxsplit=2)

                        if len(parts) == 3 and parts[1].isdigit():
                            team_code = parts[1]
                            message_to_send = parts[2]

                            # 1. Join the team
                            await join_teamcode(team_code, key, iv)
                            await asyncio.sleep(2)  # Wait for the bot to settle in the team

                            # 2. Send a random title message FIRST (CORRECTED)
                            # We must pass the UID for team context, not the chat_id.
                            title_message = "[C][B][00FFFF]Enjoy The Show!"
                            title_msg_packet = await send_title_msg(title_message, uid, key, iv) 
                            if whisper_writer:
                                whisper_writer.write(title_msg_packet)
                                await whisper_writer.drain()
                            await asyncio.sleep(1) # Wait after title

                            # 3. Send the message with a "typing" effect
                            for i in range(1, len(message_to_send) + 1):
                                partial_message = message_to_send[:i]
                                team_msg_packet = await send_team_msg(partial_message, uid, key, iv)
                                if whisper_writer:
                                    whisper_writer.write(team_msg_packet)
                                    await whisper_writer.drain()
                                await asyncio.sleep(0.5) # A short delay between messages

                            # 4. Leave the team
                            await asyncio.sleep(1)
                            await left_group(key, iv)

                            # 5. Send a confirmation message back to the user
                            final_message = f"[C][B][00FF00]✓ Command executed successfully on team {team_code}."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(final_message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(final_message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(final_message, uid, key, iv)
                            
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                        else:
                            # Handle incorrect format
                            error_message = "[C][B][FF0000]Invalid format. Use /code [team_code] [message]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(error_message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(error_message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(error_message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    elif received_msg.startswith("/ban "):
                        # Always get the context of the original message first
                        sender_uid = response.Data.uid
                        chat_id = response.Data.Chat_ID

                        if sender_uid == OWNER_UID:
                            parts = received_msg.strip().split()
                            if len(parts) == 2 and parts[1].isdigit():
                                target_uid = int(parts[1])
                                if target_uid == OWNER_UID:
                                    message = "[C][B][FF0000]You cannot ban the owner."
                                else:
                                    success = await ban_user(target_uid)
                                    if success:
                                        message = f"[C][B][00FF00]Successfully banned UID: {target_uid}"
                                    else:
                                        message = f"[C][B][FFFF00]UID {target_uid} is already banned."
                            else:
                                message = "[C][B][FF0000]Invalid format. Use /ban [uid]"
                        else:
                            message = "[C][B][FF0000]You do not have permission to use this command."

                        # Send feedback message back to the sender
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, sender_uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, sender_uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()

                    elif received_msg.startswith("/unban "):
                        # Always get the context of the original message first
                        sender_uid = response.Data.uid
                        chat_id = response.Data.Chat_ID

                        if sender_uid == OWNER_UID:
                            parts = received_msg.strip().split()
                            if len(parts) == 2 and parts[1].isdigit():
                                target_uid = int(parts[1])
                                success = await unban_user(target_uid)
                                if success:
                                    message = f"[C][B][00FF00]Successfully unbanned UID: {target_uid}"
                                else:
                                    message = f"[C][B][FFFF00]UID {target_uid} was not found in the ban list."
                            else:
                                message = "[C][B][FF0000]Invalid format. Use /unban [uid]"
                        else:
                            message = "[C][B][FF0000]You do not have permission to use this command."

                        # Send feedback message back to the sender
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, sender_uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, sender_uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                    elif received_msg.startswith("/inv "):
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        if len(parts) == 2 and parts[1].isdigit():
                            target_uid = parts[1]
                            message = "Invitation sent successfully."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                            await invite_target(target_uid, key, iv)
                        else:
                            message = "[C][B][FF0000]Invalid format. Use /inv [uid]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    
                    ### --- MODIFIED --- ###
                    # The /ghost command now calls the new, isolated function
                    elif received_msg.startswith("/ghost "):
                        sender_uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        parts = received_msg.strip().split()
                        
                        if len(parts) == 2 and parts[1].isdigit():
                            team_code = parts[1]
                            
                            message = f"[C][B][FFFFFF]Starting ghost sequence for team {team_code}..."
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, sender_uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, sender_uid, key, iv)
                            
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()

                            # Call the isolated function
                            success, final_message = await execute_ghost_sequence(team_code, key, iv)
                            
                            # Send the final status message back to the user
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(final_message, sender_uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(final_message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(final_message, sender_uid, key, iv)

                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()

                        else:
                            message = "[C][B][FF0000]Invalid format. Use /ghost [team_code]"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, sender_uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, sender_uid, key, iv)

                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
                    ### --- END MODIFIED --- ###

                    elif received_msg == "/exit":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "Leaving group..."
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        await left_group(key, iv)
                    elif received_msg == "/6":
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        message = "Please Accept My Invitation to Join Group."
                        if not response.Data.chat_type:
                            msg_packet = await send_team_msg(message, uid, key, iv)
                        elif response.Data.chat_type == 1:
                            msg_packet = await send_clan_msg(message, chat_id, key, iv)
                        else:
                            msg_packet = await send_msg(message, uid, key, iv)
                        if whisper_writer:
                            whisper_writer.write(msg_packet)
                            await whisper_writer.drain()
                        await create_group(key, iv)
                        await asyncio.sleep(0.4)
                        await modify_team_player("5", key, iv)
                        await asyncio.sleep(0.1)
                        await invite_target(uid, key, iv)
                        await asyncio.sleep(3)
                        await left_group(key, iv)
                    elif received_msg.startswith("/ai "):
                        user_input = response.Data.msg[len("/ai"):].strip()
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        if user_input:
                            ai_response = await Get_AI_Response(user_input)
                            parts = await split_text_by_words(ai_response)
                            for message in parts:
                                await asyncio.sleep(1)
                                if not response.Data.chat_type:
                                    msg_packet = await send_team_msg(message, uid, key, iv)
                                elif response.Data.chat_type == 1:
                                    msg_packet = await send_clan_msg(message, chat_id, key, iv)
                                else:
                                    msg_packet = await send_msg(message, uid, key, iv)
                                if whisper_writer:
                                    whisper_writer.write(msg_packet)
                                    await whisper_writer.drain()
                        else:
                            message = "[C][B][FF0000]Please provide a question. Ex: /ai How are you?"
                            if not response.Data.chat_type:
                                msg_packet = await send_team_msg(message, uid, key, iv)
                            elif response.Data.chat_type == 1:
                                msg_packet = await send_clan_msg(message, chat_id, key, iv)
                            else:
                                msg_packet = await send_msg(message, uid, key, iv)
                            if whisper_writer:
                                whisper_writer.write(msg_packet)
                                await whisper_writer.drain()
            
            if whisper_writer:
                whisper_writer.close()
                await whisper_writer.wait_closed()
            
            ### --- ADDED --- ###
            # If the connection drops, mark the bot as not ready
            bot_live_state["ready"] = False
            ### --- END ADDED --- ###
            
            whisper_writer = None
        except Exception as e:
            print(f"Error with {ip}:{port} - {e}")
            whisper_writer = None
            
            ### --- ADDED --- ###
            bot_live_state["ready"] = False
            ### --- END ADDED --- ###
            
        await asyncio.sleep(reconnect_delay)

async def main(uid, password):
    open_id, access_token = await get_access_token(uid, password)
    if not open_id or not access_token:
        print("Invalid Account")
        return None
    payload = await MajorLoginProto_Encode(open_id, access_token)
    MajorLoginResponse = await MajorLogin(payload)
    if not MajorLoginResponse:
        print("Account has been banned or doesn't registered")
        return None
    Decode_MajorLogin = await MajorLogin_Decode(MajorLoginResponse)
    base_url = Decode_MajorLogin.url
    token = Decode_MajorLogin.token
    AccountUID = Decode_MajorLogin.account_uid
    print(f"Account has been online with UID: {AccountUID}")
    key = Decode_MajorLogin.key
    iv = Decode_MajorLogin.iv
    timestamp = Decode_MajorLogin.timestamp
    GetLoginDataResponse = await GetLoginData(base_url, payload, token)
    if not GetLoginDataResponse:
        print("Dam Something went Wrong, Please Check GetLoginData")
        return None
    Decode_GetLoginData = await GetLoginData_Decode(GetLoginDataResponse)
    Online_IP_Port = Decode_GetLoginData.Online_IP_Port
    AccountIP_Port = Decode_GetLoginData.AccountIP_Port
    online_ip, online_port = Online_IP_Port.split(":")
    account_ip, account_port = AccountIP_Port.split(":")
    encrypted_startup = await get_encrypted_startup(int(AccountUID), token, int(timestamp), key, iv)
    ready_event = asyncio.Event()
    task1 = asyncio.create_task(handle_tcp_connection(account_ip, account_port, encrypted_startup, key, iv, Decode_GetLoginData, ready_event))
    await ready_event.wait()
    await asyncio.sleep(2)
    task2 = asyncio.create_task(handle_tcp_online_connection(online_ip, online_port, key, iv, encrypted_startup))
    await asyncio.gather(task1, task2)

@app.route('/')
def index(): # ### --- MODIFIED --- ### (Removed async)
    return 'Bot is running!'

### --- ADDED --- ###
# New API endpoint for the ghost command
### --- ADDED --- ###
# New API endpoint for the ghost command, now with a 'name' parameter
@app.route('/ghost')
def ghost_api():
    # 1. Get the team code and name from the URL query parameters
    team_code = request.args.get('tc')
    ghost_name = request.args.get('name')

    # 2. Validate the input parameters
    if not team_code or not team_code.isdigit():
        return jsonify({"status": "error", "message": "Invalid or missing 'tc' (team code) parameter."}), 400
    
    if not ghost_name:
        return jsonify({"status": "error", "message": "Missing 'name' parameter."}), 400

    # 3. Check if the bot is ready to execute commands
    if not bot_live_state["ready"]:
        return jsonify({"status": "error", "message": "Bot is not connected or ready. Please try again later."}), 503
    
    # 4. Get the necessary state variables from the live bot
    key = bot_live_state.get("key")
    iv = bot_live_state.get("iv")
    loop = bot_live_state.get("loop")

    if not all([key, iv, loop]):
        return jsonify({"status": "error", "message": "Bot state is inconsistent. Cannot execute command."}), 500

    try:
        # 5. Run the async function from our synchronous Flask context
        # We use a future to get the result back from the bot's event loop thread.
        future = asyncio.run_coroutine_threadsafe(
            execute_ghost_sequence(team_code, key, iv, ghost_name),
            loop
        )
        # Wait for the result from the bot's thread with a timeout
        success, message = future.result(timeout=20) 

        if success:
            return jsonify({"status": "success", "message": message})
        else:
            # Use a 500 internal server error for failures within the bot logic
            return jsonify({"status": "error", "message": message}), 500

    except asyncio.TimeoutError:
        return jsonify({"status": "error", "message": "The ghost creation process timed out."}), 504 # Gateway Timeout
    except Exception as e:
        return jsonify({"status": "error", "message": f"An unexpected API-level error occurred: {str(e)}"}), 500
### --- END ADDED --- ###

### --- ADDED: API endpoint for the /code command --- ###
@app.route('/code')
def code_api():
    team_code = request.args.get('tc')
    message = request.args.get('msg')

    if not all([team_code, message]) or not team_code.isdigit():
        return jsonify({"status": "error", "message": "Invalid or missing 'tc' (team code) and 'msg' parameters."}), 400

    if not bot_live_state["ready"]:
        return jsonify({"status": "error", "message": "Bot is not ready."}), 503
    
    key, iv, loop = bot_live_state["key"], bot_live_state["iv"], bot_live_state["loop"]
    if not all([key, iv, loop]):
        return jsonify({"status": "error", "message": "Bot state is inconsistent."}), 500

    try:
        future = asyncio.run_coroutine_threadsafe(execute_code_sequence(team_code, message, key, iv), loop)
        success, result_message = future.result(timeout=30) # Longer timeout for typing effect

        if success:
            return jsonify({"status": "success", "message": result_message})
        else:
            return jsonify({"status": "error", "message": result_message}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"API-level error: {str(e)}"}), 500

### --- ADDED: API endpoint for the /room command --- ###
@app.route('/room')
def room_api():
    uid = request.args.get('uid')

    if not uid or not uid.isdigit():
        return jsonify({"status": "error", "message": "Invalid or missing 'uid' parameter."}), 400

    if not bot_live_state["ready"]:
        return jsonify({"status": "error", "message": "Bot is not ready."}), 503

    key, iv, loop = bot_live_state["key"], bot_live_state["iv"], bot_live_state["loop"]
    if not all([key, iv, loop]):
        return jsonify({"status": "error", "message": "Bot state is inconsistent."}), 500

    try:
        future = asyncio.run_coroutine_threadsafe(execute_room_spam_sequence(uid, key, iv), loop)
        success, result_message = future.result(timeout=10)

        if success:
            return jsonify({"status": "success", "message": result_message})
        else:
            return jsonify({"status": "error", "message": result_message}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"API-level error: {str(e)}"}), 500

### --- ADDED: API endpoint for the /sm command --- ###
@app.route('/sm')
def sm_api():
    uid = request.args.get('uid')

    if not uid or not uid.isdigit():
        return jsonify({"status": "error", "message": "Invalid or missing 'uid' parameter."}), 400

    if not bot_live_state["ready"]:
        return jsonify({"status": "error", "message": "Bot is not ready."}), 503

    key, iv, loop = bot_live_state["key"], bot_live_state["iv"], bot_live_state["loop"]
    if not all([key, iv, loop]):
        return jsonify({"status": "error", "message": "Bot state is inconsistent."}), 500

    try:
        # This is a long-running task, so we use a longer timeout
        future = asyncio.run_coroutine_threadsafe(execute_sm_spam_sequence(uid, key, iv), loop)
        success, result_message = future.result(timeout=45)

        if success:
            return jsonify({"status": "success", "message": result_message})
        else:
            return jsonify({"status": "error", "message": result_message}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"API-level error: {str(e)}"}), 500

### --- ADDED: API endpoint for the /teame command --- ###
@app.route('/teame')
def teame_api():
    # This command doesn't need parameters
    if not bot_live_state["ready"]:
        return jsonify({"status": "error", "message": "Bot is not ready."}), 503

    key, iv, loop = bot_live_state["key"], bot_live_state["iv"], bot_live_state["loop"]
    if not all([key, iv, loop]):
        return jsonify({"status": "error", "message": "Bot state is inconsistent."}), 500

    try:
        # This is a non-blocking call. We just trigger it and report back.
        # It's better not to wait for the whole flicker sequence to finish.
        asyncio.run_coroutine_threadsafe(execute_teame_sequence(key, iv), loop)
        return jsonify({"status": "success", "message": "Team flicker sequence has been initiated."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"API-level error: {str(e)}"}), 500

async def start_bot(uid, password):
    try:
        await asyncio.wait_for(main(uid, password), timeout=TOKEN_EXPIRY)
    except asyncio.TimeoutError:
        print("Token expired after 7 hours. Restarting...")
    except Exception as e:
        print(f"TCP Error: {e}. Restarting...")

async def run_forever(uid, password):
    asyncio.create_task(run_scheduler())
    while True:
        await start_bot(uid, password)

if __name__ == '__main__':
    # Thread to run the bot so it doesn't block the Flask web server
    def run_asyncio_loop():
        ### --- MODIFIED --- ###
        # Create and set a new event loop for this background thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Now that the loop is set, store it for the API to use
        bot_live_state["loop"] = loop
        
        # Run the main async function until it completes (which is forever in this case)
        loop.run_until_complete(run_forever(
            "4162474421",
            "7MWE1ICNXOKB1DHBTKIIOK1WXF8R1SYHLC5S88KL4W2ZOGY44F3P6QVTCARMCT1J"
        ))
        ### --- END MODIFIED --- ###

    bot_thread = Thread(target=run_asyncio_loop)
    bot_thread.daemon = True
    bot_thread.start()

    # Run the Flask app
    app.run(host='0.0.0.0', port=12821)