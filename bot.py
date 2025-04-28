import socket
import ipaddress
import re
import time
import os
import asyncio
import logging
import traceback
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.error import NetworkError, BadRequest, Conflict, TimedOut
from aiohttp import web, ClientSession
import ping3
import whois

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Hardcoded bot token
BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
# Placeholder group ID
GROUP_ID = "-1002522049841"
# Admin chat ID
ADMIN_CHAT_ID = "6972264549"

# Global data storage
scan_locks = {}
message_ids = {}
last_message_state = {}
awaiting_input = {}
recent_pings = []
start_time = time.time()
scan_queue = asyncio.Queue(maxsize=20)
cidr_semaphore = asyncio.Semaphore(3)  # Reduced for stability
lock_timeouts = {}
cancel_tasks = set()

# HTTP server for health checks
async def health_check(request):
    client_ip = request.remote
    logger.info(f"Health check from {client_ip}: /health")
    return web.Response(text="OK")

async def start_http_server():
    try:
        logger.info("Starting HTTP server for keep-alive...")
        app = web.Application()
        app.add_routes([web.get('/health', health_check)])
        port = int(os.getenv("KEEP_ALIVE_PORT", 8080))
        logger.info(f"Binding HTTP server to port {port}")
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        logger.info(f"HTTP server bound to port {port}")
        return runner
    except Exception as e:
        logger.error(f"Failed to start HTTP server: {str(e)}\n{traceback.format_exc()}")
        raise

# Validate IP address
def is_valid_ip(ip):
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

# Check if host is alive (TCP SYN or ICMP)
async def check_host_alive(ip, chat_id):
    try:
        # Try TCP SYN to port 80 or 443
        for port in [80, 443]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                logger.debug(f"Host {ip} is alive on port {port}")
                return True, None
        # Fallback to ICMP ping
        ping_time = ping3.ping(ip, timeout=1, unit='s')
        if ping_time is not None:
            logger.debug(f"Host {ip} is alive via ICMP")
            return True, ping_time
        logger.debug(f"Host {ip} is down")
        return False, None
    except socket.error as e:
        logger.error(f"Error checking host {ip}: {str(e)}")
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error checking host {ip}: {str(e)}\n{traceback.format_exc()}")
        return False, None

# Get host details (MAC, emails, hostname, OS, banners)
async def get_host_details(ip, chat_id):
    details = {"mac": "N/A", "emails": [], "hostname": "unknown", "os": "unknown", "banners": []}
    try:
        # MAC Address (not feasible on Koyeb, log attempt)
        logger.debug(f"MAC address lookup not supported on Koyeb for {ip}")
        
        # Hostname via reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            details["hostname"] = hostname
            logger.debug(f"Resolved hostname for {ip}: {hostname}")
        except socket.herror:
            logger.debug(f"No hostname for {ip}")

        # OS Guess via TTL
        ping_time = ping3.ping(ip, timeout=1, unit='s')
        if ping_time is not None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((ip, 80 if await check_host_alive(ip, chat_id)[0] else 443))
                ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                details["os"] = "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "unknown"
                logger.debug(f"OS guess for {ip}: {details['os']} (TTL: {ttl})")
            except:
                logger.debug(f"TTL fetch failed for {ip}")
            finally:
                sock.close()

        # Emails and banners via HTTP
        async with ClientSession() as session:
            for port in [80, 443]:
                try:
                    proto = "https" if port == 443 else "http"
                    url = f"{proto}://{ip}:{port}"
                    async with session.get(url, timeout=5) as response:
                        headers = response.headers
                        details["banners"].append(f"Port {port}: {headers.get('Server', 'unknown')}")
                        # Check for emails in headers
                        for header in headers.values():
                            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', header)
                            details["emails"].extend(emails)
                        # Check body for emails
                        body = await response.text()
                        body_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', body)
                        details["emails"].extend(body_emails)
                        logger.debug(f"Found {len(emails) + len(body_emails)} emails for {ip}:{port}")
                except Exception as e:
                    logger.debug(f"No HTTP response on {ip}:{port}: {str(e)}")

        # WHOIS for emails (if hostname resolved)
        if details["hostname"] != "unknown":
            try:
                w = whois.whois(details["hostname"])
                if w.get("emails"):
                    details["emails"].extend(w["emails"] if isinstance(w["emails"], list) else [w["emails"]])
                    logger.debug(f"WHOIS emails for {details['hostname']}: {details['emails']}")
            except Exception as e:
                logger.debug(f"WHOIS failed for {details['hostname']}: {str(e)}")

        details["emails"] = list(set(details["emails"]))  # Remove duplicates
        return details
    except Exception as e:
        logger.error(f"Error getting details for {ip}: {str(e)}\n{traceback.format_exc()}")
        return details

# Clear stuck locks (admin only)
async def clear_locks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if str(chat_id) != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ Only admin can use this command.")
        return

    scan_locks.clear()
    message_ids.clear()
    last_message_state.clear()
    awaiting_input.clear()
    lock_timeouts.clear()
    for task in cancel_tasks.copy():
        task.cancel()
        cancel_tasks.discard(task)
    while not scan_queue.empty():
        try:
            scan_queue.get_nowait()
            scan_queue.task_done()
        except asyncio.QueueEmpty:
            break
    logger.info(f"Admin cleared all locks, tasks, and queue for chat_id {chat_id}")
    await update.message.reply_text("✅ All locks, tasks, and queue cleared.")

# Set group ID (admin only)
async def set_group(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if str(chat_id) != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ Only admin can use this command.")
        return

    if not context.args:
        await update.message.reply_text("⚠️ Please provide a group ID (e.g., /setgroup -1002522049841)")
        return

    new_group_id = context.args[0]
    try:
        await context.bot.get_chat(new_group_id)
        global GROUP_ID
        GROUP_ID = new_group_id
        logger.info(f"Group ID updated to {GROUP_ID} by admin {chat_id}")
        await update.message.reply_text(f"✅ Group ID updated to {GROUP_ID}")
    except Exception as e:
        logger.error(f"Failed to set group ID {new_group_id}: {str(e)}")
        await update.message.reply_text(f"⚠️ Failed to set group ID: {str(e)}. Ensure bot is added to the group.")

# Ping command
async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    awaiting_input[chat_id] = "ping_scan"
    await update.message.reply_text(
        "🏓 Enter an IP or CIDR range for ping scan (e.g., `192.168.1.1` or `192.168.1.0/24`):",
        parse_mode="Markdown"
    )

# Check cached ping results
def get_cached_ping(ip, chat_id):
    current_time = time.time()
    for ping in recent_pings:
        if ping["ip"] == ip and current_time - ping["timestamp"] <= 24 * 3600:
            return ping
    return None

# Ping scan (host discovery)
async def ping_scan(ip_or_cidr, chat_id, update, context):
    logger.info(f"Starting ping_scan for: {ip_or_cidr}, chat_id: {chat_id}")
    try:
        scan_locks[chat_id] = True
        lock_timeouts[chat_id] = time.time() + 600

        if "/" in ip_or_cidr:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
            total_ips = net.num_addresses
            live_hosts = []
            start_time = time.time()
            msg = await update.message.reply_text(
                f"🏓 Ping Scanning **{ip_or_cidr}** [0%] ({total_ips} IPs)...",
                parse_mode="Markdown"
            )
            message_ids[chat_id] = msg.message_id
            last_message_state[chat_id] = {"text": "", "live": 0}
            completed = 0
            update_interval = max(total_ips // 10, 1)

            for ip in net.hosts():
                ip_str = str(ip)
                async with cidr_semaphore:
                    cached = get_cached_ping(ip_str, chat_id)
                    if cached:
                        if cached["is_alive"]:
                            live_hosts.append((ip_str, cached["details"]))
                        completed += 1
                    else:
                        is_alive, ping_time = await check_host_alive(ip_str, chat_id)
                        if is_alive:
                            details = await get_host_details(ip_str, chat_id)
                            live_hosts.append((ip_str, details))
                        else:
                            details = {"mac": "N/A", "emails": [], "hostname": "unknown", "os": "unknown", "banners": []}
                        recent_pings.append({
                            "ip": ip_str,
                            "is_alive": is_alive,
                            "details": details,
                            "timestamp": time.time()
                        })
                        completed += 1

                    if completed % update_interval == 0:
                        progress = (completed / total_ips) * 100
                        elapsed = time.time() - start_time
                        eta = (elapsed / completed * total_ips - elapsed) if completed > 0 else 0
                        await update_buttons_ping(chat_id, context, ip_or_cidr, progress, eta, live_hosts)

            await update_buttons_ping(chat_id, context, ip_or_cidr, 100, 0, live_hosts, completed=True)
            if live_hosts:
                result_lines = [f"🟢 Live hosts in **{ip_or_cidr}**:"]
                for ip, details in live_hosts:
                    emails = ", ".join(details["emails"]) if details["emails"] else "none"
                    banners = ", ".join(details["banners"]) if details["banners"] else "none"
                    result_lines.append(
                        f"{ip} - MAC: {details['mac']}, Emails: {emails}, "
                        f"Hostname: {details['hostname']}, OS: {details['os']}, Banners: {banners}"
                    )
                result_msg = "\n".join(result_lines)
                group_msg = f"Ping scan result for {ip_or_cidr}:\n" + "\n".join(result_lines[1:]) + f"\nScanned: {time.ctime()}"
            else:
                result_msg = f"⚠️ No live hosts found in **{ip_or_cidr}**."
                group_msg = f"Ping scan result for {ip_or_cidr}:\nNo live hosts found.\nScanned: {time.ctime()}"
                
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=result_msg,
                parse_mode="Markdown"
            )
            try:
                await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                logger.info(f"Sent ping scan result to group {GROUP_ID}")
            except Exception as e:
                logger.error(f"Error sending to group: {e}")
                await update.message.reply_text(f"⚠️ Could not send to group chat: {str(e)}. Please add bot to group {GROUP_ID}.")
        else:
            if not is_valid_ip(ip_or_cidr):
                await update.message.reply_text(f"⚠️ Invalid IP: {ip_or_cidr}")
                return
            cached = get_cached_ping(ip_or_cidr, chat_id)
            if cached:
                details = cached["details"]
                status = "up" if cached["is_alive"] else "down"
                emails = ", ".join(details["emails"]) if details["emails"] else "none"
                banners = ", ".join(details["banners"]) if details["banners"] else "none"
                result_msg = (
                    f"📜 Cached ping result for **{ip_or_cidr}** (Scanned: {time.ctime(cached['timestamp'])}):\n"
                    f"Status: {status}, MAC: {details['mac']}, Emails: {emails}, "
                    f"Hostname: {details['hostname']}, OS: {details['os']}, Banners: {banners}"
                )
                await update.message.reply_text(result_msg, parse_mode="Markdown")
                return
            is_alive, ping_time = await check_host_alive(ip_or_cidr, chat_id)
            details = await get_host_details(ip_or_cidr, chat_id) if is_alive else {
                "mac": "N/A", "emails": [], "hostname": "unknown", "os": "unknown", "banners": []
            }
            recent_pings.append({
                "ip": ip_or_cidr,
                "is_alive": is_alive,
                "details": details,
                "timestamp": time.time()
            })
            status = "up" if is_alive else "down"
            emails = ", ".join(details["emails"]) if details["emails"] else "none"
            banners = ", ".join(details["banners"]) if details["banners"] else "none"
            result_msg = (
                f"{'🟢' if is_alive else '🔴'} Host **{ip_or_cidr}** is {status}\n"
                f"MAC: {details['mac']}, Emails: {emails}, "
                f"Hostname: {details['hostname']}, OS: {details['os']}, Banners: {banners}"
            )
            group_msg = (
                f"Ping scan result for {ip_or_cidr}:\nStatus: {status}, MAC: {details['mac']}, "
                f"Emails: {emails}, Hostname: {details['hostname']}, OS: {details['os']}, "
                f"Banners: {banners}\nScanned: {time.ctime()}"
            )
            await update.message.reply_text(result_msg, parse_mode="Markdown")
            try:
                await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                logger.info(f"Sent ping scan result to group {GROUP_ID}")
            except Exception as e:
                logger.error(f"Error sending to group: {e}")
                await update.message.reply_text(f"⚠️ Could not send to group chat: {str(e)}. Please add bot to group {GROUP_ID}.")
    except Exception as e:
        logger.error(f"Ping scan error for {ip_or_cidr}: {str(e)}\n{traceback.format_exc()}")
        await update.message.reply_text(f"⚠️ Ping scan failed for **{ip_or_cidr}**: {str(e)}")
    finally:
        scan_locks.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        for task in cancel_tasks.copy():
            if task.get_name().startswith(f"scan_{chat_id}_"):
                task.cancel()
                cancel_tasks.discard(task)
        logger.info(f"Cleaned up ping scan state for chat_id {chat_id}")

# Live button updater for ping scan
async def update_buttons_ping(chat_id, context, ip_or_cidr, progress, eta, live_hosts, completed=False):
    live_count = len(live_hosts)
    eta_text = f", ETA: {int(eta // 60)}m {int(eta % 60)}s" if eta > 0 else ""
    progress_text = f"🏓 Ping Scanning **{ip_or_cidr}** [{progress:.1f}%{eta_text}]"

    last_state = last_message_state.get(chat_id, {"text": "", "live": -1})
    if last_state["text"] == progress_text and last_state["live"] == live_count and not completed:
        return

    try:
        logger.info(f"Updating ping progress for {ip_or_cidr}: {progress:.1f}%, live: {live_count}")
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_ids[chat_id],
            text=progress_text,
            parse_mode="Markdown"
        )
        last_message_state[chat_id] = {"text": progress_text, "live": live_count}
    except Exception as e:
        if "Message is not modified" not in str(e):
            logger.error(f"Error updating buttons for {ip_or_cidr}: {str(e)}\n{traceback.format_exc()}")

# Handle user input
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    logger.info(f"Received input for scan: chat_id={chat_id}, text={update.message.text}")

    current_time = time.time()
    if chat_id in lock_timeouts and current_time > lock_timeouts.get(chat_id, 0):
        logger.info(f"Clearing timed out lock for chat_id {chat_id}")
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        awaiting_input.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        for task in cancel_tasks.copy():
            if task.get_name().startswith(f"scan_{chat_id}_"):
                task.cancel()
                cancel_tasks.discard(task)

    if scan_locks.get(chat_id, False):
        logger.info(f"Previous scan still running for chat_id {chat_id}, queuing new scan")
        await update.message.reply_text("⚠️ Previous scan still running. Your new scan is queued...")
        await asyncio.sleep(1)

    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Please use /ping to start a scan.")
        return

    target = update.message.text.strip()
    mode = awaiting_input[chat_id]

    logger.info(f"Queueing scan: mode={mode}, target={target}, chat_id={chat_id}")
    try:
        await scan_queue.put((mode, target, chat_id, update, context))
        logger.info(f"Scan queued successfully for {target}")
    except Exception as e:
        logger.error(f"Error queueing scan for {target}: {str(e)}\n{traceback.format_exc()}")
        await update.message.reply_text(f"⚠️ Failed to start scan: {str(e)}")

async def process_scan_queue(app):
    logger.info("Starting scan queue processor")
    while True:
        try:
            mode, target, chat_id, update, context = await asyncio.wait_for(scan_queue.get(), timeout=1200)
            logger.info(f"Processing scan queue task: mode={mode}, target={target}, chat_id={chat_id}")
            try:
                if mode == "ping_scan":
                    task = asyncio.create_task(
                        ping_scan(target, chat_id, update, context),
                        name=f"scan_{chat_id}_ping"
                    )
                    cancel_tasks.add(task)
                    await task
                    cancel_tasks.discard(task)
            except Exception as e:
                logger.error(f"Error processing scan queue task for {target}: {str(e)}\n{traceback.format_exc()}")
                await app.bot.send_message(
                    chat_id=chat_id,
                    text=f"⚠️ Scan failed: {str(e)}"
                )
            finally:
                scan_queue.task_done()
                logger.info(f"Completed scan queue task for chat_id {chat_id}")
        except asyncio.TimeoutError:
            logger.info("Scan queue timeout, continuing to next task")
            continue
        except Exception as e:
            logger.error(f"Queue processor crashed: {str(e)}\n{traceback.format_exc()}")
            await asyncio.sleep(5)
            continue

async def check_group_access(bot):
    try:
        await bot.get_chat(GROUP_ID)
        logger.info(f"Group {GROUP_ID} accessible")
        return True
    except Exception as e:
        logger.error(f"Group {GROUP_ID} not accessible: {e}")
        return False

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}\n{traceback.format_exc()}")
    if isinstance(context.error, (NetworkError, TimedOut)):
        await asyncio.sleep(5)
    elif isinstance(context.error, BadRequest):
        logger.error(f"BadRequest: {context.error}")
    elif isinstance(context.error, Conflict):
        logger.error(f"Conflict error: {context.error}")
        try:
            await context.bot.delete_webhook(drop_pending_updates=True)
            logger.info("Webhook cleared due to conflict")
        except Exception as e:
            logger.error(f"Failed to clear webhook: {str(e)}")
    elif str(context.error).startswith("TooManyRequests"):
        logger.warning("Telegram rate limit hit, applying backoff")
        await asyncio.sleep(2 ** len(str(context.error)))
    try:
        if update and update.message:
            await update.message.reply_text("⚠️ An error occurred, please try again later.")
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"⚠️ Bot error: {str(context.error)}"
        )
    except Exception as admin_e:
        logger.error(f"Failed to notify admin: {admin_e}")

async def main():
    logger.info("Bot starting...")
    try:
        app = Application.builder().token(BOT_TOKEN).build()
        logger.info(f"Bot initialized with token: {BOT_TOKEN[:10]}...")
    except Exception as e:
        logger.error(f"Error initializing bot: {str(e)}\n{traceback.format_exc()}")
        raise

    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        logger.info("Webhook cleared at startup")
    except Exception as e:
        logger.error(f"Failed to clear webhook at startup: {str(e)}")

    group_access = await check_group_access(app.bot)
    if not group_access:
        logger.warning(f"Bot will continue without group chat access. Add bot to {GROUP_ID}.")

    app.add_handler(CommandHandler("ping", ping))
    app.add_handler(CommandHandler("clearlocks", clear_locks))
    app.add_handler(CommandHandler("setgroup", set_group))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan))
    app.add_error_handler(error_handler)

    http_runner = await start_http_server()
    logger.info("HTTP server started")

    # Start scan queue processor as a task
    queue_task = asyncio.create_task(process_scan_queue(app))
    logger.info("Scan queue processor started")

    try:
        # Run polling in the same event loop
        await app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
        logger.info("Bot polling started")
    finally:
        # Cleanup
        logger.info("Shutting down...")
        queue_task.cancel()
        try:
            await queue_task
        except asyncio.CancelledError:
            logger.info("Scan queue processor cancelled")
        await app.stop()
        await http_runner.cleanup()
        logger.info("Shutdown complete")

if __name__ == "__main__":
    try:
        # Use existing event loop if available (Koyeb), else create new (local)
        loop = asyncio.get_event_loop()
        if loop.is_running():
            logger.warning("Using existing running event loop")
            loop.create_task(main())
        else:
            loop.run_until_complete(main())
    except RuntimeError:
        # Fallback for environments with no running loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
