import asyncio
import subprocess
from aiohttp import web
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

BOT_TOKEN = '8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8'
PORT = 8080

user_data = {}

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

# Command: /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Welcome!\nPlease send the IP range to scan.\nExample: 192.168.1.0/24"
    )

# Function to scan network
async def scan_network(ip_range):
    try:
        # Run nmap scan
        proc = await asyncio.create_subprocess_exec(
            'nmap', '-sn', '-n', ip_range,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if stderr:
            return None, stderr.decode()

        hosts = []
        lines = stdout.decode().split('\n')
        current_host = {}

        for line in lines:
            if line.startswith("Nmap scan report for"):
                ip = line.split()[-1]
                current_host = {"ip": ip}
            elif "MAC Address" in line:
                mac = line.split("MAC Address:")[1].split('(')[0].strip()
                current_host["mac"] = mac
            if current_host and 'ip' in current_host:
                hosts.append(current_host)
                current_host = {}

        return hosts, None

    except Exception as e:
        return None, str(e)

# Message Handler (user sends IP range)
async def get_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip_range = update.message.text.strip()
    await update.message.reply_text(f"Scanning {ip_range}...\nPlease wait...")

    hosts, error = await scan_network(ip_range)

    if error:
        await update.message.reply_text(f"Error during scan: {error}")
        return

    if not hosts:
        await update.message.reply_text("No live hosts found.")
        return

    # Save scan data
    user_data[update.effective_user.id] = hosts

    # Create inline buttons
    buttons = [
        [InlineKeyboardButton(host['ip'], callback_data=host['ip'])]
        for host in hosts
    ]
    reply_markup = InlineKeyboardMarkup(buttons)

    await update.message.reply_text(
        "Live hosts found:",
        reply_markup=reply_markup
    )

# Button Handler (user clicks a host)
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    selected_ip = query.data

    hosts = user_data.get(user_id, [])

    for host in hosts:
        if host['ip'] == selected_ip:
            details = f"IP Address: {host['ip']}\n"
            details += f"MAC Address: {host.get('mac', 'N/A')}\n"
            await query.edit_message_text(details)
            return

    await query.edit_message_text("Host information not found.")

# Main function
async def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, get_ip))
    app.add_handler(CallbackQueryHandler(button_handler))

    await app.initialize()

    web_task = asyncio.create_task(run_web_server())
    bot_task = asyncio.create_task(app.start())
    polling_task = asyncio.create_task(app.updater.start_polling())

    try:
        await asyncio.gather(web_task, bot_task, polling_task)
    except asyncio.CancelledError:
        print("Tasks cancelled, shutting down cleanly...")

    await app.updater.stop()
    await app.stop()
    await app.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
                
