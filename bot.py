import subprocess
import re
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = "8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8"  # <-- Yahan apna bot token daalo

def scan_network(subnet):
    result = subprocess.run(["nmap", "-sn", subnet], capture_output=True, text=True)
    return result.stdout

def get_alive_hosts(nmap_output):
    alive_hosts = []
    lines = nmap_output.splitlines()
    for i in range(len(lines)):
        if "Nmap scan report for" in lines[i]:
            ip_match = re.search(r"Nmap scan report for (.+)", lines[i])
            if ip_match:
                ip = ip_match.group(1)
                if i+1 < len(lines) and "Host is up" in lines[i+1]:
                    alive_hosts.append(ip)
    return alive_hosts

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Please provide a subnet/IP. Example: /scan 192.168.1.0/24")
        return

    subnet = context.args[0]
    await update.message.reply_text(f"Scanning {subnet}... Please wait.")

    output = scan_network(subnet)
    alive_hosts = get_alive_hosts(output)

    if alive_hosts:
        message = "Alive hosts:\n" + "\n".join(alive_hosts)
    else:
        message = "No alive hosts found."

    await update.message.reply_text(message)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Send /scan <subnet> to scan network.")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_command))

    print("Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
    
