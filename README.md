# Dockerfile
# Используем официальный образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Устанавливаем переменные окружения, чтобы Python выводил все сразу
ENV PYTHONUNBUFFERED 1

# Копируем файл с зависимостями
COPY requirements.txt .

# Устанавливаем зависимости
# --no-cache-dir уменьшает размер образа
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все остальные файлы проекта в контейнер
COPY . .

# Указываем, какой порт будет слушать приложение
EXPOSE 8080

# Команда для запуска Uvicorn сервера
# --host 0.0.0.0 делает сервер доступным извне контейнера
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]

