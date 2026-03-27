# Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Установим зависимости (укажи свои версии в requirements.txt)
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
 && python -m pip install --no-cache-dir -r /app/requirements.txt

# Копируем код (если хочешь монтировать локально, можно убрать COPY)
COPY . /app

# Запуск (можно переопределить в docker-compose)
CMD ["python3", "bot_api.py"]
