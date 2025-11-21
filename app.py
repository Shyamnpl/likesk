#,                         ︵
#                        /'_/) 
#                      /¯ ../ 
#                    /'..../ 
#                  /¯ ../ 
#                /... ./
#   ¸•´¯/´¯ /' ...'/´¯`•¸  
# /'.../... /.... /.... /¯\
#('  (...´.(,.. ..(...../',    \
# \'.............. .......\'.    )      
#   \'....................._.•´/
#     \ ....................  /
#       \ .................. |
#         \  ............... |
#           \............... |
#             \ .............|
#               \............|
#                 \ .........|
#                   \ .......|
#                     \ .....|
#                       \ ...|
#                         \ .|
#                           \\
#                             \('-') 
#   ,,                           |_|\
#                               | |
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED

#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED
#DONT CHANGE CREDIT 
#IF YOU CHANGE MY CREDIT, I'LL FUCK YOUR MOM

from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime

#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED
#DONT CHANGE CREDIT 
#IF YOU CHANGE MY CREDIT, I'LL FUCK YOUR MOM

app = Flask(__name__)

# ✅ Per-key rate limit setup
KEY_LIMIT = 150
token_tracker = defaultdict(lambda: [0, time.time()])  # api_key: [count, last_reset_time]

def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                return json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            # NOTE: token_br.json file is missing in your project
            with open("token_br.json", "r") as f:
                return json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                return json.load(f)
    except FileNotFoundError:
        return None # Return None if a token file is missing
    except json.JSONDecodeError:
        return None # Return None if JSON is invalid

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=edata, headers=headers, timeout=5) as response:
                return response.status
        except asyncio.TimeoutError:
            return 504  # Gateway Timeout
        except Exception:
            return 500  # Internal Server Error

async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    tasks = []
    tokens = load_tokens(server_name)
    
    if not tokens:
        return [] # Return empty if no tokens loaded

    for token_obj in tokens:
        token = token_obj["token"]
        tasks.append(send_request(encrypted_uid, token, url))
    
    results = await asyncio.gather(*tasks)
    return results

def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()

def enc(uid):
    protobuf_data = create_protobuf(uid)
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    try:
        # Added verify=False and timeout
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)
        if response.status_code != 200:
             print(f"Error from server: {response.status_code}")
             return None
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        return decode_protobuf(binary)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        # [span_0](start_span)This is the error you were seeing in the logs[span_0](end_span)
        print(f"Error decoding Protobuf data: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")

    if key == "BD8014275586":
        if uid != "8014275586":
            return jsonify({"error": "This API key is only valid for UID 8014275586."}), 403
        if server_name != "BD":
             return jsonify({"error": "This API key is only valid for server_name 'BD'."}), 403
    elif key != "gst":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    def process_request():
        data = load_tokens(server_name)
        
        # --- MODIFICATION: Check if token files exist and are valid ---
        if data is None or len(data) == 0:
            if server_name == "IND":
                filename = "token_ind.json"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                filename = "token_br.json"
            else:
                filename = "token_bd.json"
            return {"error": f"Could not load tokens. '{filename}' is missing or empty/invalid.", "status": 500}
        
        info_token = data[0]['token']
        encrypt = enc(uid)

        today_midnight = get_today_midnight_timestamp()
        count, last_reset = token_tracker[key]

        if last_reset < today_midnight:
            token_tracker[key] = [0, time.time()]
            count = 0

        if count >= KEY_LIMIT:
            return {
                "error": "Daily request limit reached for this key.",
                "status": 429,
                "remains": f"(0/{KEY_LIMIT})"
            }

        before = make_request(encrypt, server_name, info_token)

        # --- MODIFICATION: Add check for None to prevent crash ---
        if before is None:
            return {
                "error": "Could not fetch player info BEFORE sending likes. The first token in your token list is likely invalid or expired. Please update your token file.",
                "status": 500
            }
        
        jsone = MessageToJson(before)
        data_json = json.loads(jsone)
        
        if 'AccountInfo' not in data_json:
             return {"error": f"Could not find player info for UID {uid} on server {server_name}. Check if UID and server are correct.", "status": 404}
        
        before_like = int(data_json['AccountInfo'].get('Likes', 0))

        # Select URL
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, url))

        after = make_request(encrypt, server_name, info_token)
        
        # --- MODIFICATION: Add check for None to prevent crash ---
        if after is None:
            return {
                "error": "Could not fetch player info AFTER sending likes. The first token in your token list is likely invalid or expired. Likes were sent, but result cannot be shown.",
                "status": 500
            }

        jsone_after = MessageToJson(after)
        data_after = json.loads(jsone_after)

        after_like = int(data_after['AccountInfo']['Likes'])
        id = int(data_after['AccountInfo']['UID'])
        name = str(data_after['AccountInfo']['PlayerNickname'])

        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2

        if like_given > 0:
            token_tracker[key][0] += 1
            count += 1

        remains = KEY_LIMIT - count

        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": name,
            "UID": id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})"
        }
        return result

    result = process_request()
    
    # Set status code for errors
    status_code = 200
    if 'status' in result and isinstance(result['status'], int):
        status_code = result['status']
    elif 'error' in result:
        status_code = 500

    return jsonify(result), status_code

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
    
    
    
    
    
#,                         ︵
#                        /'_/) 
#                      /¯ ../ 
#                    /'..../ 
#                  /¯ ../ 
#                /... ./
#   ¸•´¯/´¯ /' ...'/´¯`•¸  
# /'.../... /.... /.... /¯\
#('  (...´.(,.. ..(...../',    \
# \'.............. .......\'.    )      
#   \'....................._.•´/
#     \ ....................  /
#       \ .................. |
#         \  ............... |
#           \............... |
#             \ .............|
#               \............|
#                 \ .........|
#                   \ .......|
#                     \ .....|
#                       \ ...|
#                         \ .|
#                           \\
#                             \('-') 
#   ,,                           |_|\
#                               | |
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED 
#FUCKED BY JOBAYAR AHMED @JOBAYAR_AHMED
