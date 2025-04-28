import ipaddress
import re
import time
import os
import asyncio
import logging
import traceback
import nmap
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from telegram.error import NetworkError, BadRequest, Conflict, TimedOut
from aiohttp import web

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Hardcoded bot token and IDs
BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
GROUP_ID = "-1002522049841"
ADMIN_CHAT_ID = "6972264549"

# Global data storage
scan_results = {}
scan_locks = {}
message_ids = {}
scan_stop = {}
last_message_state = {}
awaiting_input = {}
recent_scans = []
start_time = time.time()
scan_expiry = {}
scan_queue = asyncio.Queue(maxsize=20)  # Max 20 queued scans
scan_semaphore = asyncio.Semaphore(5)  # Max 5 concurrent scans
lock_timeouts = {}

# HTTP server for health checks and keep-alive
async def health_check(request):
    client_ip = request.remote
    logger.info(f"Keep-alive ping received from {client_ip}")
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
        logger.info(f"HTTP server started on port {port}")
        return runner
    except Exception as e:
        logger.error(f"Failed to start HTTP server: {str(e)}")
        raise

# Validate CIDR
def is_valid_cidr(cidr):
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

# Nmap host discovery for CIDR range
async def scan_hosts_cidr(cidr, chat_id, update, context):
    async with scan_semaphore:
        try:
            scan_locks[chat_id] = True
            lock_timeouts[chat_id] = time.time() + 300  # 5 min timeout
            scan_stop[chat_id] = False
            scan_results[chat_id] = {"hosts": [], "progress": 0}
            scan_expiry[chat_id] = time.time() + 600

            net = ipaddress.ip_network(cidr, strict=False)
            total_hosts = net.num_addresses - 2  # Exclude network and broadcast
            logger.info(f"Starting host discovery for {cidr} ({total_hosts} hosts)")

            msg = await update.message.reply_text(
                f"🔍 Host Discovery for **{cidr}** [0%] (Scanning {total_hosts} hosts)",
                parse_mode="Markdown"
            )
            message_ids[chat_id] = msg.message_id
            last_message_state[chat_id] = {"text": "", "host_count": 0}

            nm = nmap.PortScanner()
            nm.scan(hosts=cidr, arguments='-v -sn')  # Verbose host discovery

            hosts_found = 0
            for host in nm.all_hosts():
                if scan_stop.get(chat_id, False):
                    break
                if nm[host].state() == 'up':
                    hostname = nm[host].hostname() or "N/A"
                    mac = nm[host].get('mac', 'N/A')
                    scan_results[chat_id]["hosts"].append({
                        "ip": host,
                        "hostname": hostname,
                        "mac": mac,
                        "timestamp": time.time()
                    })
                    hosts_found += 1
                    progress = (hosts_found / total_hosts) * 100 if total_hosts > 0 else 0
                    await update_host_buttons(chat_id, context, cidr, progress, hosts_found)

            if scan_stop.get(chat_id, False):
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"🛑 Host Discovery stopped for **{cidr}**",
                    parse_mode="Markdown"
                )
                return

            if hosts_found == 0:
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"⚠️ No live hosts found in **{cidr}**.",
                    parse_mode="Markdown"
                )
            else:
                await update_host_buttons(chat_id, context, cidr, 100, hosts_found)
                recent_scans.append({
                    "ip": cidr,
                    "hosts": scan_results[chat_id]["hosts"],
                    "timestamp": time.time()
                })
                group_msg = f"Host Discovery result for {cidr}:\nFound {hosts_found} live hosts."
                try:
                    await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                    logger.info(f"Sent host discovery result to group {GROUP_ID}")
                except Exception as e:
                    logger.error(f"Error sending to group: {str(e)}")

        except Exception as e:
            logger.error(f"Host discovery error for {cidr}: {str(e)}\nStack trace: {traceback.format_exc()}")
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=f"⚠️ Host Discovery failed for **{cidr}**: {str(e)}",
                parse_mode="Markdown"
            )
        finally:
            scan_locks.pop(chat_id, None)
            scan_stop.pop(chat_id, None)
            message_ids.pop(chat_id, None)
            last_message_state.pop(chat_id, None)
            awaiting_input.pop(chat_id, None)
            lock_timeouts.pop(chat_id, None)
            logger.info(f"Cleaned up host discovery state for chat_id {chat_id}")

# Update host buttons
async def update_host_buttons(chat_id, context, cidr, progress, host_count):
    hosts = scan_results.get(chat_id, {}).get("hosts", [])
    progress_text = f"🔍 Host Discovery for **{cidr}** [{progress:.1f}%] ({host_count} hosts found)"

    last_state = last_message_state.get(chat_id, {"text": "", "host_count": -1})
    if last_state["text"] == progress_text and last_state["host_count"] == host_count:
        return

    keyboard = [
        [InlineKeyboardButton(f"Host: {host['ip']}", callback_data=f"host_{chat_id}_{host['ip']}")]
        for host in hosts
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_ids[chat_id],
            text=progress_text,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
        last_message_state[chat_id] = {"text": progress_text, "host_count": host_count}
    except Exception as e:
        if "Message is not modified" not in str(e):
            logger.error(f"Error updating host buttons: {e}")

# Clear stuck locks (admin only)
async def clear_locks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if str(chat_id) != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ Only admin can use this command.")
        return

    scan_locks.clear()
    scan_stop.clear()
    message_ids.clear()
    last_message_state.clear()
    awaiting_input.clear()
    lock_timeouts.clear()
    while not scan_queue.empty():
        try:
            scan_queue.get_nowait()
            scan_queue.task_done()
        except asyncio.QueueEmpty:
            break
    logger.info(f"Admin cleared all locks and queue for chat_id {chat_id}")
    await update.message.reply_text("✅ All locks and queue cleared.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    keyboard = [
        [InlineKeyboardButton("🔎 Host Discovery Scan", callback_data=f"host_discovery_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔎 **Host Discovery Bot** 🔍\n\n"
        "Choose an option:\n"
        "🔎 **Host Discovery Scan**: Discover live hosts in a CIDR range (~1-2 sec/IP)",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id in scan_locks and scan_locks[chat_id]:
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Scan stopped.")
    else:
        await update.message.reply_text("⚠️ No scan in progress.")

async def get_hosts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    current_time = time.time()
    valid_results = [res for res in recent_scans if current_time - res["timestamp"] <= 24 * 3600]
    if valid_results:
        result = "Recent host discovery results:\n"
        for res in valid_results:
            hosts = [f"{host['ip']} ({host['hostname']})" for host in res["hosts"]]
            result += f"CIDR: {res['ip']}, Hosts: {', '.join(hosts)}, Scanned: {time.ctime(res['timestamp'])}\n"
    else:
        result = "No recent scan results available (within 24 hours)."
    await update.message.reply_text(result)

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    scan_count = len(recent_scans)
    await update.message.reply_text(f"Bot Stats:\nTotal Scans: {scan_count}")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = time.time() - start_time
    uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
    scan_count = len(recent_scans)
    queue_size = scan_queue.qsize()
    active_scans = sum(1 for lock in scan_locks.values() if lock)
    await update.message.reply_text(
        f"**Bot Status** 📊\n"
        f"Uptime: {uptime_str}\n"
        f"Total Scans: {scan_count}\n"
        f"Active Scans: {active_scans}\n"
        f"Queued Scans: {queue_size}",
        parse_mode="Markdown"
    )

# Button click handler
async def button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id

    logger.info(f"Button clicked: chat_id={chat_id}, data={query.data}")

    try:
        if query.data.startswith("host_discovery_"):
            awaiting_input[chat_id] = "host_discovery"
            await query.message.reply_text(
                "🔎 Enter a CIDR range for host discovery (e.g., `192.168.1.0/24`):",
                parse_mode="Markdown"
            )
        elif query.data.startswith("host_"):
            _, button_chat_id, host_ip = query.data.split("_", 2)
            logger.info(f"Host button clicked: chat_id={button_chat_id}, host_ip={host_ip}")

            if button_chat_id != str(chat_id):
                await query.message.reply_text("⚠️ Chat ID mismatch. Please start a new scan.")
                return

            if chat_id not in scan_results or time.time() > scan_expiry.get(chat_id, 0):
                await query.message.reply_text("⚠️ Scan data expired or not found. Please start a new scan.")
                return

            host_info = next((host for host in scan_results[chat_id]["hosts"] if host["ip"] == host_ip), None)
            if not host_info:
                await query.message.reply_text("⚠️ Host data not found.")
                return

            details = (
                f"**Host Details**:\n"
                f"IP: {host_info['ip']}\n"
                f"Hostname: {host_info['hostname']}\n"
                f"MAC Address: {host_info['mac']}\n"
                f"Scanned: {time.ctime(host_info['timestamp'])}"
            )
            await query.message.reply_text(details, parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Error in button_click: {e}")
        await query.message.reply_text(f"⚠️ Error processing button: {str(e)}")
        try:
            await context.bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text=f"⚠️ Bot error: {str(e)}"
            )
        except Exception as admin_e:
            logger.error(f"Failed to notify admin: {admin_e}")

# Handle user input
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id

    # Check lock timeout
    current_time = time.time()
    if chat_id in lock_timeouts and current_time > lock_timeouts[chat_id]:
        logger.info(f"Clearing timed out lock for chat_id {chat_id}")
        scan_locks.pop(chat_id, None)
        scan_stop.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        awaiting_input.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)

    # Cancel any ongoing scan for this chat_id
    if scan_locks.get(chat_id, False):
        logger.info(f"Canceling previous scan for chat_id {chat_id}")
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Previous scan stopped. Starting new scan...")
        await asyncio.sleep(1)  # Brief delay to ensure old scan stops

    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Please use /start to choose an option.")
        return

    target = update.message.text—(cidr, strict=False)
    mode = awaiting_input[chat_id]

    # Start new scan
    logger.info(f"Starting new scan: mode={mode}, ip={target}, chat_id={chat_id}")
    try:
        if mode == "host_discovery":
            if "/" in target and is_valid_cidr(target):
                await scan_hosts_cidr(target, chat_id, update, context)
            else:
                await update.message.reply_text("⚠️ Host discovery requires a CIDR range (e.g., `192.168.1.0/24`).")
    except Exception as e:
        logger.error(f"Error starting new scan for chat_id {chat_id}: {str(e)}")
        await update.message.reply_text(f"⚠️ Scan failed: {str(e)}")
        try:
            await context.bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text=f"⚠️ Scan error for chat {chat_id}: {str(e)}"
            )
        except Exception as admin_e:
            logger.error(f"Failed to notify admin: {admin_e}")

async def process_scan_queue(app):
    logger.info("Starting scan queue processor")
    while True:
        try:
            async with asyncio.timeout(1200):  # 20 min timeout per scan
                mode, target, chat_id, update, context = await scan_queue.get()
                logger.info(f"Processing scan queue task: mode={mode}, ip={target}, chat_id={chat_id}")
                try:
                    if mode == "host_discovery":
                        if "/" in target and is_valid_cidr(target):
                            await scan_hosts_cidr(target, chat_id, update, context)
                        else:
                            await app.bot.send_message(
                                chat_id=chat_id,
                                text="⚠️ Host discovery requires a CIDR range (e.g., `192.168.1.0/24`)."
                            )
                finally:
                    scan_queue.task_done()
                    logger.info(f"Completed scan queue task for chat_id {chat_id}")
                await asyncio.sleep(1)
        except asyncio.TimeoutError:
            logger.error(f"Scan queue task timed out for chat_id {chat_id}")
            try:
                await app.bot.send_message(
                    chat_id=chat_id,
                    text="⚠️ Scan timed out. Please try again."
                )
                await app.bot.send_message(
                    chat_id=ADMIN_CHAT_ID,
                    text=f"⚠️ Scan queue timeout for chat {chat_id}"
                )
            except Exception as admin_e:
                logger.error(f"Failed to notify: {admin_e}")
            scan_queue.task_done()
        except Exception as e:
            logger.error(f"Error processing scan queue: {e}")
            try:
                await app.bot.send_message(
                    chat_id=chat_id,
                    text=f"⚠️ Scan failed: {str(e)}"
                )
                await app.bot.send_message(
                    chat_id=ADMIN_CHAT_ID,
                    text=f"⚠️ Scan queue error for chat {chat_id}: {str(e)}"
                )
            except Exception as admin_e:
                logger.error(f"Failed to notify: {admin_e}")
            scan_queue.task_done()
        await asyncio.sleep(1)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}")
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
        if update:
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
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        logger.info(f"Bot initialized with token: {BOT_TOKEN[:10]}...")
    except Exception as e:
        logger.error(f"Error initializing bot: {str(e)}")
        raise

    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        logger.info("Webhook cleared at startup")
    except Exception as e:
        logger.error(f"Failed to clear webhook at startup: {str(e)}")

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("gethosts", get_hosts))
    app.add_handler(CommandHandler("info", info))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("clearlocks", clear_locks))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan))
    app.add_handler(CallbackQueryHandler(button_click))
    app.add_error_handler(error_handler)

    http_runner = await start_http_server()

    max_retries = 10
    retry_delay = 10
    for attempt in range(max_retries):
        try:
            await app.initialize()
            await app.start()
            await app.updater.start_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
            logger.info("Bot polling started")
            asyncio.create_task(process_scan_queue(app))
            break
        except Exception as e:
            logger.error(f"Error starting Telegram bot (attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                try:
                    await app.stop()
                except:
                    pass
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Max retries reached, shutting down...")
                try:
                    await app.stop()
                except:
                    pass
                await http_runner.cleanup()
                raise

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down...")
        try:
            await app.updater.stop()
            await app.stop()
        except:
            pass
        await http_runner.cleanup()
        logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
