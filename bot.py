# main.py

import subprocess
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

BOT_TOKEN = '8159511483:AAF7WOtZegkLAzrr2uIYXlXU8crlerWHPJ8'

# Dictionary to store user scans
user_scans = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome! Please send the IP range to scan.\nExample: 192.168.1.0/24")

async def get_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    ip_range = update.message.text.strip()

    await update.message.reply_text(f"Starting scan on {ip_range}...")

    # Start nmap scan asynchronously
    await scan_network(ip_range, update, context, user_id)

async def scan_network(ip_range, update, context, user_id):
    try:
        # Run nmap ping scan
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

        # Save scan results
        user_scans[user_id] = hosts

        # Build buttons
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
        # Try to fetch MAC address using ARP
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

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, get_ip))
    app.add_handler(CallbackQueryHandler(button_handler))

    print("Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
    
