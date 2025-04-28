import asyncio
import logging
import time
import nmap
import dns.resolver
import dns.reversename
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from aiohttp import web

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
start_time = time.time()

# HTTP server for health checks
async def health_check(request):
    logger.info(f"Health check from {request.remote}")
    return web.Response(text="OK")

async def start_http_server():
    try:
        logger.info("Starting HTTP server on port 8080...")
        app = web.Application()
        app.add_routes([web.get('/health', health_check)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', 8080)
        await site.start()
        logger.info("HTTP server started")
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
        return "No hostname"

# Nmap ping scan
async def nmap_scan(cidr, chat_id, update, context):
    if not is_valid_cidr(cidr):
        await update.message.reply_text(f"⚠️ Invalid CIDR: {cidr}")
        return

    if chat_id in scan_locks:
        await update.message.reply_text("⚠️ Scan already in progress!")
        return

    scan_locks[chat_id] = True
    scan_results[chat_id] = {"hosts": [], "progress": 0}

    try:
        nm = nmap.PortScanner()
        logger.info(f"Starting Nmap scan for {cidr} (chat_id: {chat_id})")
        msg = await update.message.reply_text(
            f"🔍 Scanning **{cidr}** [0%]", parse_mode="Markdown"
        )
        message_ids[chat_id] = msg.message_id

        # Run Nmap scan (-sn for ping scan, -v for verbose, --unprivileged for non-root)
        nm.scan(hosts=cidr, arguments='-sn -v --unprivileged')
        hosts = nm.all_hosts()
        total_hosts = len(hosts) if hosts else 1
        scanned = 0

        for host in hosts:
            if nm[host].state() == 'up':
                mac = nm[host]['addresses'].get('mac', 'N/A')
                hostname = get_reverse_dns(host)
                scan_results[chat_id]["hosts"].append({
                    "ip": host,
                    "mac": mac,
                    "hostname": hostname,
                    "email_info": "N/A"
                })
            scanned += 1
            progress = (scanned / total_hosts) * 100
            scan_results[chat_id]["progress"] = progress

            # Update progress
            host_count = len(scan_results[chat_id]["hosts"])
            progress_text = f"🔍 Scanning **{cidr}** [{progress:.1f}%]\nLive Hosts: {host_count}"
            keyboard = [[InlineKeyboardButton(f"View Hosts ({host_count})", callback_data=f"view_{chat_id}")]]
            try:
                await context.bot.edit_message_text(
                    chat_id=chat_id, message_id=message_ids[chat_id],
                    text=progress_text, parse_mode="Markdown",
                    reply_markup=InlineKeyboardMarkup(keyboard)
                )
            except Exception as e:
                if "Message is not modified" not in str(e):
                    logger.error(f"Progress update error: {e}")

        if scan_results[chat_id]["hosts"]:
            group_msg = f"Scan result for {cidr}:\nFound {len(scan_results[chat_id]['hosts'])} hosts\nTime: {time.ctime()}"
            await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
        else:
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=message_ids[chat_id],
                text=f"⚠️ No live hosts found for **{cidr}**", parse_mode="Markdown"
            )

    except Exception as e:
        logger.error(f"Scan error for {cidr}: {str(e)}")
        await context.bot.edit_message_text(
            chat_id=chat_id, message_id=message_ids[chat_id],
            text=f"⚠️ Scan failed: {str(e)}", parse_mode="Markdown"
        )
    finally:
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)

# Bot commands
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    keyboard = [[InlineKeyboardButton("🌐 Start Scan", callback_data=f"scan_{chat_id}")]]
    await update.message.reply_text(
        "🎯 **Host Discovery Bot**\n\nEnter a CIDR range (e.g., 192.168.1.0/24):",
        parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    cidr = update.message.text.strip()
    logger.info(f"Scan requested for {cidr} (chat_id: {chat_id})")
    await nmap_scan(cidr, chat_id, update, context)

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = time.time() - start_time
    uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
    await update.message.reply_text(
        f"**Bot Status** 📊\nUptime: {uptime_str}", parse_mode="Markdown"
    )

# Button handler
async def button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id

    if query.data.startswith("scan_"):
        await query.message.reply_text("🌐 Enter a CIDR range (e.g., `192.168.1.0/24`):", parse_mode="Markdown")
        context.user_data["awaiting_cidr"] = True
    elif query.data.startswith("view_"):
        hosts = scan_results.get(chat_id, {}).get("hosts", [])
        if not hosts:
            await query.message.reply_text("📋 No hosts found!")
            return
        keyboard = [
            [InlineKeyboardButton(f"Host: {host['ip']}", callback_data=f"detail_{chat_id}_{i}")]
            for i, host in enumerate(hosts)
        ]
        await query.message.reply_text(
            f"📋 Found {len(hosts)} hosts:", parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif query.data.startswith("detail_"):
        _, _, index = query.data.split("_")
        index = int(index)
        hosts = scan_results.get(chat_id, {}).get("hosts", [])
        if index >= len(hosts):
            await query.message.reply_text("⚠️ Invalid host!")
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

# Text handler for CIDR input
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if context.user_data.get("awaiting_cidr"):
        cidr = update.message.text.strip()
        context.user_data["awaiting_cidr"] = False
        await nmap_scan(cidr, chat_id, update, context)
    else:
        await update.message.reply_text("⚠️ Use /start to begin.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}")
    try:
        if update:
            await update.message.reply_text("⚠️ An error occurred.")
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID, text=f"⚠️ Error: {str(context.error)}"
        )
    except Exception as e:
        logger.error(f"Failed to notify admin: {e}")

async def main():
    logger.info("Starting bot...")
    try:
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        logger.info("Bot initialized")
    except Exception as e:
        logger.error(f"Failed to initialize bot: {str(e)}")
        raise

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CallbackQueryHandler(button_click))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)

    http_runner = await start_http_server()

    try:
        await app.run_polling()
        logger.info("Bot polling started")
    except Exception as e:
        logger.error(f"Error running bot: {str(e)}")
        await http_runner.cleanup()
        raise

if __name__ == "__main__":
    asyncio.run(main())