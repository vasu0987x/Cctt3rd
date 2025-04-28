import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = os.getenv("8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8")
KOYEB_APP_NAME = os.getenv("KOYEB_APP_NAME")

WEBHOOK_PATH = f"/webhook/{BOT_TOKEN}"
WEBHOOK_URL = f"https://{KOYEB_APP_NAME}.koyeb.app{WEBHOOK_PATH}"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Bot is running on webhook!")

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Scan command received!")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))

    app.run_webhook(
        listen="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        webhook_path=WEBHOOK_PATH,
        webhook_url=WEBHOOK_URL
    )

if __name__ == "__main__":
    main()
