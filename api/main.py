# api/main.py
import asyncio
import subprocess
import os
import re
import json
import requests
from typing import List, Dict

import faiss
import numpy as np
from dotenv import load_dotenv
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from openai import AsyncOpenAI
from sentence_transformers import SentenceTransformer
from prometheus_client import Counter, start_http_server, Gauge

# --- 0. Инициализация и конфигурация ---
print("Инициализация приложения...")
load_dotenv()

# Загрузка ключей API
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not VIRUSTOTAL_API_KEY or not OPENAI_API_KEY:
    print("ВНИМАНИЕ: Ключи API для VirusTotal и/или OpenAI не найдены в .env файле.")

# Инициализация OpenAI клиента
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# --- 1. Настройка FastAPI и статических файлов ---
app = FastAPI(title="WatchMyBacklogDude Security Analyzer")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- 2. Менеджер WebSocket-соединений ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

# --- 3. Настройка моделей AI и базы векторов (RAG) ---
print("Загрузка AI моделей и базы векторов...")
# Обертка в try-except на случай, если скрипт `create_attack_vectors.py` не был запущен
try:
    model = SentenceTransformer('all-MiniLM-L6-v2')
    index = faiss.read_index("data/attack_vectors.index")
    with open("data/attack_patterns.txt", "r") as f:
        known_attack_patterns = [line.strip() for line in f.readlines()]
    print("Модели и векторы успешно загружены.")
    RAG_ENABLED = True
except FileNotFoundError:
    print("ВНИМАНИЕ: Файлы для RAG (attack_vectors.index, attack_patterns.txt) не найдены. RAG будет отключен.")
    RAG_ENABLED = False

# --- 4. Настройка метрик Prometheus ---
print("Запуск сервера метрик Prometheus на порту 8001...")
start_http_server(8001)
LOGS_PROCESSED = Counter('logs_processed_total', 'Всего обработано логов')
SUSPICIOUS_LOGS_FOUND = Counter('suspicious_logs_total', 'Найдено подозрительных логов', ['source'])
CURRENT_WEBSOCKETS = Gauge('current_websocket_connections', 'Текущее количество WebSocket соединений')

# --- 5. Функции анализа логов ---
def find_file_path(log_line: str) -> List[str]:
    # Регулярное выражение для поиска путей к файлам в стиле macOS
    return re.findall(r' (/[^/ ]*)+/([^/ ]*)', log_line)

async def check_virustotal(file_path: str) -> Dict:
    # Функция для проверки файла через VirusTotal API (использует API v3 для файлов)
    # Для реального использования нужно сначала получить SHA256 хэш файла.
    # Здесь мы делаем мок-запрос для демонстрации.
    print(f"VT Check: {file_path}")
    SUSPICIOUS_LOGS_FOUND.labels('virustotal_check').inc()
    # url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    # headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    # async with httpx.AsyncClient() as client:
    #     response = await client.get(url, headers=headers)
    #     return response.json()
    await asyncio.sleep(1) # Имитация сетевого запроса
    return {"status": "mock_vt_check", "positives": 0, "path": file_path}

async def analyze_with_openai(log_line: str) -> str:
    print(f"OpenAI Analysis: {log_line[:80]}...")
    SUSPICIOUS_LOGS_FOUND.labels('openai').inc()
    try:
        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini", # Используем быструю и дешевую модель
            messages=[
                {"role": "system", "content": "You are a macOS cybersecurity analyst. Analyze the provided log entry for potential threats. Be concise. Start with a one-word risk assessment (e.g., 'Critical,', 'Warning,', 'Info,'). Then, provide a one-sentence explanation."},
                {"role": "user", "content": log_line}
            ],
            max_tokens=80,
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Ошибка при анализе OpenAI: {e}")
        return "OpenAI analysis failed."

# --- 6. Основной обработчик логов ---
async def process_log_stream():
    """Запускает 'log stream' и асинхронно обрабатывает его вывод."""
    print("Запуск 'log stream' для сбора системных логов macOS...")
    command = ["log", "stream", "--style", "json", "--predicate", 'subsystem != "com.apple.TimeMachine"']
    
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    while True:
        line = await process.stdout.readline()
        if not line:
            await asyncio.sleep(0.1)
            continue
        
        LOGS_PROCESSED.inc()
        log_entry_str = line.decode('utf-8').strip()
        
        try:
            log_json = json.loads(log_entry_str)
            message = log_json.get("eventMessage", "")
            process_name = log_json.get("process", "")
            
            # --- Быстрый фильтр по ключевым словам ---
            suspicious_keywords = ['fail', 'error', 'denied', 'sudo', 'auth', 'critical', 'unauthorized']
            if not any(keyword in message.lower() for keyword in suspicious_keywords):
                continue
            
            analysis_result = {
                "log": message,
                "process": process_name,
                "timestamp": log_json.get("timestamp"),
                "analyses": []
            }

            # --- RAG Анализ ---
            if RAG_ENABLED:
                log_vector = model.encode([message])
                D, I = index.search(log_vector, k=1)
                # Порог схожести. Чем меньше значение, тем больше схожесть.
                if D[0][0] < 1.0:
                    matched_pattern = known_attack_patterns[I[0][0]]
                    analysis_result["analyses"].append({
                        "source": "RAG",
                        "level": "warning",
                        "details": f"Похоже на известный паттерн: '{matched_pattern}' (Схожесть: {D[0][0]:.2f})"
                    })
                    SUSPICIOUS_LOGS_FOUND.labels('rag').inc()

            # --- Анализ путей к файлам ---
            paths = find_file_path(message)
            if paths:
                for path_tuple in paths:
                    full_path = "".join(path_tuple)
                    vt_res = await check_virustotal(full_path)
                    analysis_result["analyses"].append({
                        "source": "VirusTotal",
                        "level": "critical" if vt_res.get("positives", 0) > 0 else "info",
                        "details": f"Проверка файла {full_path}. Результат: {vt_res}"
                    })

            # --- Анализ через OpenAI (если не было точного совпадения с RAG) ---
            if not any(a['source'] == 'RAG' for a in analysis_result['analyses']):
                 openai_res = await analyze_with_openai(message)
                 level = "info"
                 if "critical" in openai_res.lower(): level = "critical"
                 elif "warning" in openai_res.lower(): level = "warning"
                 analysis_result["analyses"].append({
                        "source": "OpenAI",
                        "level": level,
                        "details": openai_res
                    })

            if analysis_result["analyses"]:
                 await manager.broadcast(analysis_result)

        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            # Игнорируем строки, которые не являются валидным JSON
            pass
        except Exception as e:
            print(f"Непредвиденная ошибка в цикле обработки лога: {e}")

# --- 7. Запуск и конечные точки API ---
@app.on_event("startup")
async def startup_event():
    # Запускаем обработчик логов в фоновой задаче
    asyncio.create_task(process_log_stream())

@app.get("/")
async def get_home(request: Request):
    # Здесь должна быть логика проверки аутентификации.
    # Для мокапа просто отдаем страницу.
    return templates.TemplateResponse("index.html", {"request": request})
    
@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    CURRENT_WEBSOCKETS.inc()
    print(f"Новое WebSocket соединение. Всего: {len(manager.active_connections)}")
    try:
        while True:
            # Просто держим соединение открытым
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        CURRENT_WEBSOCKETS.dec()
        print(f"WebSocket соединение закрыто. Осталось: {len(manager.active_connections)}")

# Для аутентификации мы бы добавили роутеры из fastapi-users.
# Например: app.include_router(fastapi_users.get_auth_router(auth_backend), ...)
# Но для мокапа, чтобы не усложнять, мы опустим реальную реализацию.
