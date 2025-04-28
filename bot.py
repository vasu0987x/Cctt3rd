import asyncio
import os
import subprocess
from aiohttp import web
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
PORT = int(os.environ.get("PORT", 8080))

# Start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Please send me an IP range to scan.\nExample: `192.168.1.0/24`", parse_mode="Markdown")

# IP address message handler
async def get_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip_range = update.message.text.strip()
    await update.message.reply_text(f"Scanning IP range: {ip_range}...\nPlease wait...")

    try:
        result = subprocess.check_output(["nmap", "-sn", ip_range], text=True)
        hosts = []

        current_ip = None
        mac_address = None

        for line in result.splitlines():
            if "Nmap scan report for" in line:
                current_ip = line.split()[-1]
            if "MAC Address:" in line:
                mac_address = line.split("MAC Address:")[1].strip()
                if current_ip:
                    hosts.append((current_ip, mac_address))
                    current_ip = None
                    mac_address = None
            if current_ip and "Host is up" in line:
                hosts.append((current_ip, "Unknown"))
                current_ip = None

        if not hosts:
            await update.message.reply_text("No live hosts found.")
            return

        buttons = []
        for ip, mac in hosts:
            buttons.append([InlineKeyboardButton(text=f"{ip}", callback_data=f"DETAILS|{ip}|{mac}")])

        reply_markup = InlineKeyboardMarkup(buttons)

        await update.message.reply_text("Live hosts found:", reply_markup=reply_markup)

    except subprocess.CalledProcessError as e:
        await update.message.reply_text(f"Error scanning IP range: {e}")

# Inline button handler
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data.startswith("DETAILS|"):
        _, ip, mac = data.split("|")
        message = f"Host Details:\n\nIP Address: {ip}\nMAC Address: {mac}"
        await query.edit_message_text(text=message)

# Web server for Koyeb health check
async def handle(request):
    return web.Response(text="OK")

async def run_web_server():
    app = web.Application()
    app.router.add_get("/", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    print(f"Web server running on port {PORT}")

async def main():
    # Web server task
    web_server_task = asyncio.create_task(run_web_server())

    # Telegram bot task
    application = ApplicationBuilder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, get_ip))
    application.add_handler(CallbackQueryHandler(button_handler))

    await application.initialize()
    await application.start()
    await application.updater.start_polling()

    await web_server_task

if __name__ == "__main__":
    asyncio.run(main())
                                         
