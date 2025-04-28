# bot.py

import subprocess
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
from aiohttp import web

BOT_TOKEN = '8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8'
PORT = 8080

user_scans = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Please send the IP range to scan.\nExample: 192.168.1.0/24")

async def get_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    ip_range = update.message.text.strip()

    await update.message.reply_text(f"Starting scan on {ip_range}...")

    await scan_network(ip_range, update, context, user_id)

async def scan_network(ip_range, update, context, user_id):
    try:
        result = subprocess.check_output(["nmap", "-sn", ip_range], text=True)

        hosts = []
        lines = result.splitlines()
        current_ip = None

        for line in lines:
            if "Nmap scan report for" in line:
                current_ip = line.split("for")[1].strip()
                hosts.append(current_ip)

        if not hosts:
            await update.message.reply_text("No live hosts found.")
            return

        user_scans[user_id] = hosts

        buttons = []
        for ip in hosts:
            buttons.append([InlineKeyboardButton(ip, callback_data=ip)])

        reply_markup = InlineKeyboardMarkup(buttons)
        await update.message.reply_text("Live hosts found:", reply_markup=reply_markup)

    except Exception as e:
        await update.message.reply_text(f"Error during scanning: {str(e)}")

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    selected_ip = query.data

    if user_id not in user_scans or selected_ip not in user_scans[user_id]:
        await query.edit_message_text("Invalid selection.")
        return

    try:
        arp_result = subprocess.check_output(["arp", "-n", selected_ip], text=True)

        mac_address = "Unknown"
        for line in arp_result.splitlines():
            if selected_ip in line:
                parts = line.split()
                if len(parts) >= 3:
                    mac_address = parts[2]

        text = f"Details for {selected_ip}:\n\n"
        text += f"IP Address: {selected_ip}\n"
        text += f"MAC Address: {mac_address}\n"

        await query.edit_message_text(text)

    except Exception as e:
        await query.edit_message_text(f"Error fetching details: {str(e)}")

# Web server for Koyeb health check
async def handle(request):
    return web.Response(text="OK")

async def run_web_server():
    app = web.Application()
    app.router.add_get('/', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    print(f"Web server running on port {PORT}")

async def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, get_ip))
    app.add_handler(CallbackQueryHandler(button_handler))

    # Initialize app first
    await app.initialize()

    # Start web server and telegram app together
    await asyncio.gather(
        run_web_server(),
        app.start(),
        app.updater.start_polling()
    )

    # Wait for shutdown
    await app.updater.idle()

if __name__ == "__main__":
    asyncio.run(main())
