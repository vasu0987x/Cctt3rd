# Python ka lightweight latest version
FROM python:3.11-slim  

# Working directory set kar rahe
WORKDIR /app  

# Sab files container ke andar copy karenge
COPY . .  

# System update aur nmap install karenge
RUN apt update && apt install -y nmap  

# Telegram bot ke liye required packages install karenge
RUN pip install --no-cache-dir "python-telegram-bot[webhooks]" aiohttp  

# Port expose kar rahe webhook ke liye
EXPOSE 8080  

# Container start hote hi bot chalega
CMD ["python", "bot.py"]  
