FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN apt update && apt install -y nmap && apt clean

RUN pip install --no-cache-dir python-telegram-bot==20.3

ENV PORT=8080

CMD ["python", "bot.py"]
