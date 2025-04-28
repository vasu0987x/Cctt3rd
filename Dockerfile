FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN apt update && apt install -y nmap

RUN pip install --no-cache-dir "python-telegram-bot[webhooks]==20.3"

CMD ["python", "bot.py"]
