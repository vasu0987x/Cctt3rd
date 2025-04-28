import os
import asyncio
from aiohttp import web
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters

# Bot Token aur Channel ID
BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"
CHANNEL_ID = -1002522049841
APP_NAME = "cctv3"

WEBHOOK_PATH = f"/webhook/{BOT_TOKEN}"
WEBHOOK_URL = f"https://{APP_NAME}.koyeb.app{WEBHOOK_PATH}"

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip_range = update.message.text.strip()

    if not ("/" in ip_range and "." in ip_range):
        await update.message.reply_text("Please send a valid IP range like 192.168.1.0/24")
        return

    await update.message.reply_text(f"Scanning `{ip_range}`... please wait...", parse_mode="Markdown")

    proc = await asyncio.create_subprocess_shell(
        f"nmap -v -sn {ip_range}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    result = stdout.decode() or stderr.decode()
    if not result:
        result = "No output received."

    if len(result) > 4000:
        result = result[:4000] + "\n\n[Output truncated]"

    await update.message.reply_text(f"Scan Result:\n\n{result}")
    await context.bot.send_message(chat_id=CHANNEL_ID, text=f"Scan on {ip_range} finished!\n\n{result}")

async def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Aiohttp server bana rahe
    async def webhook_handler(request):
        data = await request.json()
        update = Update.de_json(data, app.bot)
        await app.process_update(update)
        return web.Response()

    app.webhook_server = web.Application()
    app.webhook_server.router.add_post(WEBHOOK_PATH, webhook_handler)

    # Set webhook URL on Telegram
    await app.bot.set_webhook(WEBHOOK_URL)

    runner = web.AppRunner(app.webhook_server)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", int(os.environ.get("PORT", 8080)))
    await site.start()

    print("Bot started with webhook.")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
    
