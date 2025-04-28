# Python 3.11 slim image le rahe hain
FROM python:3.11-slim

# App ka kaam /app folder ke andar hoga
WORKDIR /app

# Saare local files copy kar lenge container me
COPY . .

# Jo requirements.txt me likha hai usko install karenge
RUN pip install --no-cache-dir -r requirements.txt

# Bot ko run karenge
CMD ["python", "bot.py"]
