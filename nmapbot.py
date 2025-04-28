import asyncio
import logging
import time
import nmap
import dns.resolver
import dns.reversename
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from aiohttp import web
import os
os.system('pip install python-telegram-bot==20.7 --force-reinstall')

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Bot configuration
BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
ADMIN_CHAT_ID = "6972264549"
GROUP_ID = "-1002522049841"

# Global storage
scan_results = {}
scan_locks = {}
message_ids = {}
scan_stop = {}
last_message_state = {}
awaiting_input = {}
recent_scans = []
start_time = time.time()
scan_expiry = {}
scan_semaphore = asyncio.Semaphore(5)  # Limit concurrent scans

# HTTP server for health checks
async def health_check(request):
    logger.info(f"Health check from {request.remote}")
    return web.Response(text="OK")

async def start_http_server():
    try:
        logger.info("Starting HTTP server for health checks...")
        app = web.Application()
        app.add_routes([web.get('/health', health_check)])
        port = 8080
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        logger.info(f"HTTP server started on port {port}")
        return runner
    except Exception as e:
        logger.error(f"Failed to start HTTP server: {str(e)}")
        raise

# Validate CIDR range
def is_valid_cidr(cidr):
    try:
        import ipaddress
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

# Reverse DNS lookup
def get_reverse_dns(ip):
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, 'PTR')
        return [str(rdata) for rdata in answers][0]
    except Exception:
        return "No hostname found"

# Nmap ping scan
async def nmap_ping_scan(cidr, chat_id, update, context):
    if not is_valid_cidr(cidr):
        await update.message.reply_text(f"⚠️ Invalid CIDR: {cidr}")
        return

    async with scan_semaphore:
        try:
            scan_locks[chat_id] = True
            scan_stop[chat_id] = False
            scan_results[chat_id] = {"hosts": [], "progress": 0}
            scan_expiry[chat_id] = time.time() + 600

            nm = nmap.PortScanner()
            logger.info(f"Starting Nmap ping scan for {cidr} (chat_id: {chat_id})")
            msg = await update.message.reply_text(
                f"🔍 Scanning **{cidr}** [0%] (Host discovery)", parse_mode="Markdown"
            )
            message_ids[chat_id] = msg.message_id
            last_message_state[chat_id] = {"text": "", "hosts": 0}

            # Run Nmap scan (-sn for ping scan, -v for verbose, --unprivileged for non-root)
            nm.scan(hosts=cidr, arguments='-sn -v --unprivileged')
            hosts = nm.all_hosts()
            total_hosts = len(hosts) if hosts else 1
            scanned = 0

            for host in hosts:
                if scan_stop.get(chat_id, False):
                    break
                if nm[host].state() == 'up':
                    mac = nm[host]['addresses'].get('mac', 'N/A')
                    hostname = get_reverse_dns(host)
                    scan_results[chat_id]["hosts"].append({
                        "ip": host,
                        "mac": mac,
                        "hostname": hostname,
                        "email_info": "N/A"  # Placeholder for email OSINT
                    })
                scanned += 1
                progress = (scanned / total_hosts) * 100
                scan_results[chat_id]["progress"] = progress
                await update_progress(chat_id, context, cidr, progress)

            if scan_stop.get(chat_id, False):
                await context.bot.edit_message_text(
                    chat_id=chat_id, message_id=message_ids[chat_id],
                    text=f"🛑 Scan stopped for **{cidr}**", parse_mode="Markdown"
                )
                return

            await update_progress(chat_id, context, cidr, 100)
            if scan_results[chat_id]["hosts"]:
                group_msg = f"Scan result for {cidr}:\nFound {len(scan_results[chat_id]['hosts'])} live hosts\nScanned: {time.ctime()}"
                try:
                    await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                    logger.info(f"Sent scan result to group {GROUP_ID}")
                except Exception as e:
                    logger.error(f"Error sending to group: {str(e)}")
                recent_scans.append({
                    "cidr": cidr,
                    "hosts": scan_results[chat_id]["hosts"],
                    "timestamp": time.time()
                })
            else:
                await context.bot.edit_message_text(
                    chat_id=chat_id, message_id=message_ids[chat_id],
                    text=f"⚠️ No live hosts found for **{cidr}**.", parse_mode="Markdown"
                )

        except Exception as e:
            logger.error(f"Scan error for {cidr}: {str(e)}")
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=message_ids[chat_id],
                text=f"⚠️ Scan failed for **{cidr}**: {str(e)}", parse_mode="Markdown"
            )
        finally:
            scan_locks.pop(chat_id, None)
            scan_stop.pop(chat_id, None)
            message_ids.pop(chat_id, None)
            last_message_state.pop(chat_id, None)
            awaiting_input.pop(chat_id, None)
            logger.info(f"Cleaned up scan state for chat_id {chat_id}")

# Progress update
async def update_progress(chat_id, context, cidr, progress):
    host_count = len(scan_results.get(chat_id, {}).get("hosts", []))
    progress_text = f"🔍 Scanning **{cidr}** [{progress:.1f}%]\nLive Hosts: {host_count}"

    last_state = last_message_state.get(chat_id, {"text": "", "hosts": -1})
    if last_state["text"] == progress_text and last_state["hosts"] == host_count:
        return

    keyboard = [
        [InlineKeyboardButton(f"📋 View Hosts ({host_count})", callback_data=f"view_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    try:
        await context.bot.edit_message_text(
            chat_id=chat_id, message_id=message_ids[chat_id],
            text=progress_text, parse_mode="Markdown", reply_markup=reply_markup
        )
        last_message_state[chat_id] = {"text": progress_text, "hosts": host_count}
    except Exception as e:
        if "Message is not modified" not in str(e):
            logger.error(f"Error updating progress: {e}")

# Bot commands
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    keyboard = [
        [InlineKeyboardButton("🌐 Start Scan", callback_data=f"scan_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎯 **Nmap Host Discovery Bot**\n\n"
        "Scan a CIDR range (e.g., 192.185.141.0/24) to find live hosts.\n"
        "Click below to start:", parse_mode="Markdown", reply_markup=reply_markup
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Use /start to begin.")
        return

    cidr = update.message.text.strip()
    logger.info(f"Starting scan for {cidr} (chat_id: {chat_id})")
    await nmap_ping_scan(cidr, chat_id, update, context)

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = time.time() - start_time
    uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
    scan_count = len(recent_scans)
    active_scans = sum(1 for lock in scan_locks.values() if lock)
    await update.message.reply_text(
        f"**Bot Status** 📊\n"
        f"Uptime: {uptime_str}\n"
        f"Total Scans: {scan_count}\n"
        f"Active Scans: {active_scans}", parse_mode="Markdown"
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id in scan_locks and scan_locks[chat_id]:
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        awaiting_input.pop(chat_id, None)
        await update.message.reply_text("🛑 Scan stopped.")
    else:
        await update.message.reply_text("⚠️ No scan in progress.")

# Button handler
async def button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    logger.info(f"Button clicked: chat_id={chat_id}, data={query.data}")

    try:
        if query.data.startswith("scan_"):
            awaiting_input[chat_id] = "scan"
            await query.message.reply_text(
                "🌐 Enter a CIDR range (e.g., `192.185.141.0/24`):", parse_mode="Markdown"
            )
        elif query.data.startswith("view_"):
            if chat_id not in scan_results or time.time() > scan_expiry.get(chatור_id, 0):
                await query.message.reply_text("⚠️ Scan data expired. Start a new scan.")
                return
            hosts = scan_results[chat_id].get("hosts", [])
            if not hosts:
                await query.message.reply_text("📋 No live hosts found!")
                return
            keyboard = [
                [InlineKeyboardButton(f"Host: {host['ip']}", callback_data=f"detail_{chat_id}_{i}")]
                for i, host in enumerate(hosts)
            ]
            await query.message.reply_text(
                f"📋 Found {len(hosts)} live hosts:", parse_mode="Markdown",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
        elif query.data.startswith("detail_"):
            _, _, index = query.data.split("_")
            index = int(index)
            hosts = scan_results[chat_id].get("hosts", [])
            if index >= len(hosts):
                await query.message.reply_text("⚠️ Invalid host selection.")
                return
            host = hosts[index]
            details = (
                f"**Host Details** 📋\n"
                f"IP: {host['ip']}\n"
                f"MAC: {host['mac']}\n"
                f"Hostname: {host['hostname']}\n"
                f"Email Info: {host['email_info']}"
            )
            await query.message.reply_text(details, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Error in button_click: {e}")
        await query.message.reply_text(f"⚠️ Error: {str(e)}")
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID, text=f"⚠️ Bot error: {str(e)}"
        )

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}")
    try:
        if update and update.message:
            await update.message.reply_text("⚠️ An error occurred, please try again later.")
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID, text=f"⚠️ Bot error: {str(context.error)}"
        )
    except Exception as e:
        logger.error(f"Failed to notify admin: {e}")

async def main():
    logging.info("Bot starting...")

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # Register handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan))

    # Error handler
    app.add_error_handler(error_handler)

    # Start background HTTP server (for health checks)
    asyncio.create_task(start_http_server())

    # Start the bot
    await app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())
