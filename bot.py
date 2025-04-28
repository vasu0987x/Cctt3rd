import asyncio
import subprocess
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
CHANNEL_ID = -1002522049841  # Your channel id here

UP_HOSTS = []  # Global list to store UP hosts

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Bot is ready! Use /scan to start scanning.")

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = await update.message.reply_text("Starting Nmap Scan...")

    process = await asyncio.create_subprocess_exec(
        "nmap", "-v", "-sn", "192.168.1.0/24",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    scan_output = ""
    while True:
        line = await process.stdout.readline()
        if not line:
            break

        decoded_line = line.decode('utf-8').strip()
        scan_output += decoded_line + "\n"

        if "Host is up" in decoded_line:
            last_host_line = scan_output.splitlines()[-2]
            if "Nmap scan report for" in last_host_line:
                ip = last_host_line.split()[-1]
                UP_HOSTS.append(ip)

        # Live updating message
        await message.edit_text(f"Scanning...\nUP Hosts Found: {len(UP_HOSTS)}")

    await process.wait()

    # After scan completes
    keyboard = [
        [InlineKeyboardButton("View UP Hosts", callback_data="view_up_hosts")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await message.edit_text(f"Scan Completed!\nUP Hosts: {len(UP_HOSTS)}", reply_markup=reply_markup)

    # Post to channel
    if UP_HOSTS:
        hosts_text = "\n".join(UP_HOSTS)
        await context.bot.send_message(chat_id=CHANNEL_ID, text=f"Scan Results:\n{hosts_text}")

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == "view_up_hosts":
        if UP_HOSTS:
            hosts_text = "\n".join(UP_HOSTS)
            await query.edit_message_text(f"UP Hosts:\n{hosts_text}")
        else:
            await query.edit_message_text("No UP Hosts found.")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CallbackQueryHandler(button))

    app.run_webhook(
        listen="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        webhook_path=f"/webhook/{BOT_TOKEN}",
        webhook_url=f"https://cctv3.koyeb.app/webhook/{BOT_TOKEN}"
    )

if __name__ == "__main__":
    import os
    main()
