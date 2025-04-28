import os
import asyncio
import subprocess
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
CHANNEL_ID = "-1002522049841"
APP_URL = "https://cctv3.koyeb.app"  # apna Koyeb app URL

up_hosts = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Bot is Live and Ready. Use /scan <ip_range> to start scanning!")

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Please provide an IP range.\nExample: `/scan 192.168.1.0/24`", parse_mode="Markdown")
        return

    ip_range = context.args[0]
    msg = await update.message.reply_text(f"Scanning {ip_range}...\nPlease wait...")

    process = await asyncio.create_subprocess_shell(
        f"nmap {ip_range} -v -sn",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        await update.message.reply_text(f"Error during scan: {stderr.decode()}")
        return

    output = stdout.decode()
    lines = output.split("\n")
    up_hosts.clear()

    for line in lines:
        if "Nmap scan report for" in line:
            parts = line.split()
            ip = parts[-1]
            name = parts[4] if len(parts) > 5 else "Unknown"
            up_hosts[ip] = {"name": name}

    if not up_hosts:
        await update.message.reply_text("No UP hosts found.")
        return

    keyboard = [
        [InlineKeyboardButton(ip, callback_data=ip)]
        for ip in up_hosts.keys()
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await msg.edit_text("Scan complete!\nClick an IP for details:", reply_markup=reply_markup)

    # Send all results to the channel
    text_to_channel = "\n".join(f"✅ {ip} ({info['name']})" for ip, info in up_hosts.items())
    await context.bot.send_message(CHANNEL_ID, f"Scan Result:\n{text_to_channel}")

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    ip = query.data
    info = up_hosts.get(ip, {"name": "Unknown"})

    text = f"""
IP: `{ip}`
Hostname: `{info['name']}`
Status: `UP`
"""

    await query.edit_message_text(text=text, parse_mode="Markdown")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CallbackQueryHandler(button))

    app.run_webhook(
        listen="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        webhook_url=f"{APP_URL}/webhook/{BOT_TOKEN}"
    )

if __name__ == "__main__":
    main()
