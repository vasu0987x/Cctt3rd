import asyncio
import os
import subprocess
from aiohttp import web
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, CallbackQueryHandler, ContextTypes

# Telegram Bot Token
BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"

# Web server port
PORT = int(os.environ.get('PORT', 8080))

# Start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Send me an IP range like '192.168.1.0/24' to start scanning.")

# When user sends IP range
async def get_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip_range = update.message.text.strip()

    await update.message.reply_text(f"Scanning {ip_range}... This may take a few seconds...")

    try:
        # Run nmap ping scan
        result = subprocess.check_output(['nmap', '-sn', ip_range], universal_newlines=True)

        # Parse live hosts
        hosts = []
        current_ip = None
        for line in result.splitlines():
            if "Nmap scan report for" in line:
                current_ip = line.split("for")[-1].strip()
            if "Host is up" in line and current_ip:
                hosts.append(current_ip)
                current_ip = None

        if not hosts:
            await update.message.reply_text("No live hosts found.")
            return

        # Create InlineKeyboard
        keyboard = []
        for ip in hosts:
            keyboard.append([InlineKeyboardButton(ip, callback_data=f"info_{ip}")])

        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text("Live hosts found:", reply_markup=reply_markup)

    except Exception as e:
        await update.message.reply_text(f"Error: {str(e)}")

# When user clicks on a live IP button
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    ip = query.data.split("_")[1]

    try:
        # Run detailed scan
        result = subprocess.check_output(['nmap', '-A', ip], universal_newlines=True)
        if len(result) > 4000:
            result = result[:4000] + "\n\nOutput too long... Truncated."

        await query.message.reply_text(f"Details for {ip}:\n\n{result}")

    except Exception as e:
        await query.message.reply_text(f"Error: {str(e)}")

# Health check web server
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
    application = ApplicationBuilder().token(BOT_TOKEN).build()

    # Handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, get_ip))
    application.add_handler(CallbackQueryHandler(button_handler))

    # Start web server and bot polling together
    await asyncio.gather(
        run_web_server(),
        application.run_polling()
    )

if __name__ == "__main__":
    asyncio.run(main())
    
