# WatchMyBacklogDude

WatchMyBacklogDude — это демонстрационный инструмент на FastAPI для анализа системных логов macOS в реальном времени. 
Приложение использует Retrieval Augmented Generation (RAG) на базе SentenceTransformer — векторная база знакомых паттернов атак, а также проверяет пути к файлам через VirusTotal и делает краткий анализ при помощи OpenAI. 
Результаты отображаются в веб-интерфейсе через WebSocket.

## Состав репозитория
- **api/** — исходный код FastAPI приложения
- **static/** и **templates/** — файлы веб-интерфейса
- **create_attack_vectors.py** — скрипт для генерации векторной базы
- **main_processor.py** — пример скрипта для потоковой обработки логов
- **docker-compose.yml** — окружение с Prometheus и Grafana
- **Dockerfile** — образ для запуска приложения
- **requirements.txt** — зависимости Python

## Быстрый старт с Docker Compose
1. Установите [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Скопируйте файл `.env.example` в `.env` и заполните `VIRUSTOTAL_API_KEY`, `OPENAI_API_KEY`, `SECRET_KEY`, `LOGIN_EMAIL` и `LOGIN_PASSWORD`.
3. Запустите:
```bash
docker compose up --build
```
4. Перейдите на `http://localhost:8080` для интерфейса приложения.
5. Метрики Prometheus доступны на `http://localhost:4200`, Grafana — `http://localhost:4201`.

## Локальная установка (без Docker)
1. Убедитесь, что установлен Python 3.11.
2. Создайте виртуальное окружение и установите зависимости:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
3. Сгенерируйте файлы базы векторов:
```bash
python create_attack_vectors.py
```
4. Запустите приложение:
```bash
uvicorn api.main:app --reload
```

## Особенности macOS
Для работы `log stream` требуется повышенные привилегии. В Docker Compose уже прописаны необходимые параметры (`cap_add` и `SYS_ADMIN`). При локальном запуске убедитесь, что у пользователя есть права на чтение системных логов.

### Apple Silicon (M1, M2, M3, M4)
На компьютерах с чипами Apple Silicon Docker использует виртуализацию на базе `qemu`. Файлы образов собираются под архитектуру `arm64`. В `docker-compose.yml` никаких дополнительных настроек не требуется.

### Intel-based Mac
На Intel Mac приложение также работает из контейнера. Если параллельно используются образы под `arm64` и `amd64`, Docker автоматически скачает корректные образы для каждой архитектуры.

## Состояние проекта
Проект носит демонстрационный характер и не готов для использования в production. Все ключи и учётные данные передаются через `.env` файл. Для доступа предусмотрен простой интерфейс авторизации на сессиях.

