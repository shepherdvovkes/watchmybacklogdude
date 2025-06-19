import subprocess
import os
import re
import time
import requests
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from dotenv import load_dotenv
from openai import OpenAI
from prometheus_client import start_http_server, Counter

# --- Инициализация ---
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Проверка наличия ключей
if not VIRUSTOTAL_API_KEY or not OPENAI_API_KEY:
    raise ValueError("API keys for VirusTotal and OpenAI must be set in .env file")

# Метрики Prometheus
PROCESSED_LOGS = Counter('logs_processed_total', 'Total number of logs processed')
SUSPICIOUS_LOGS = Counter('logs_suspicious_total', 'Total number of suspicious logs found')
VT_CHECKS = Counter('virustotal_checks_total', 'Total number of VirusTotal checks')
OPENAI_ANALYSIS = Counter('openai_analysis_total', 'Total number of OpenAI analyses')

# Загрузка AI моделей и векторов
print("Loading models and vector database...")
model = SentenceTransformer('all-MiniLM-L6-v2')
index = faiss.read_index("attack_vectors.index")
with open("attack_patterns.txt", "r") as f:
    known_attack_patterns = [line.strip() for line in f.readlines()]
openai_client = OpenAI(api_key=OPENAI_API_KEY)
print("Initialization complete.")

# --- Функции анализа ---

def find_file_paths(log_line):
    # Ищет пути к файлам в стиле macOS
    return re.findall(r'(/[^/ ]*)+/(([^/ ]*)+)', log_line)

def check_with_virustotal(file_path):
    """Отправляет хэш файла или сам файл в VirusTotal."""
    # В реальном приложении нужно вычислить хэш файла (sha256)
    # Здесь для примера просто используем API для получения отчета по пути (гипотетически)
    # Реальный API VT работает с хэшами или загрузкой файлов.
    VT_CHECKS.inc()
    print(f"Checking file {file_path} with VirusTotal...")
    # ... логика запроса к VT API ...
    # url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    # headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    # response = requests.get(url, headers=headers)
    # return response.json()
    return {"status": "mock", "positives": 0} # Mock response

def analyze_with_openai(log_line):
    """Анализирует лог с помощью OpenAI."""
    OPENAI_ANALYSIS.inc()
    print(f"Analyzing with OpenAI: {log_line}")
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o", # или gpt-4-turbo
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst. Analyze the following macOS log entry for potential threats, vulnerabilities, or misconfigurations. Provide a brief, one-sentence summary of the risk."},
                {"role": "user", "content": log_line}
            ],
            max_tokens=100
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error analyzing with OpenAI: {e}"


def process_log_line(log_line):
    """Основная логика обработки одной строки лога."""
    PROCESSED_LOGS.inc()
    
    # 1. Быстрый поиск по ключевым словам (дополнить)
    suspicious_keywords = ['failed', 'error', 'denied', 'sudo', 'ssh', 'critical']
    is_suspicious = any(keyword in log_line.lower() for keyword in suspicious_keywords)

    if not is_suspicious:
        return None # Пропускаем неинтересные логи

    SUSPICIOUS_LOGS.inc()
    analysis_result = {"original_log": log_line, "analyses": []}

    # 2. Поиск файловых путей и проверка в VT
    file_paths = find_file_paths(log_line)
    for path_tuple in file_paths:
        full_path = "".join(path_tuple)
        if os.path.exists(full_path): # Проверяем, существует ли файл
             vt_result = check_with_virustotal(full_path)
             analysis_result["analyses"].append({"source": "VirusTotal", "details": vt_result, "target": full_path})

    # 3. Векторный поиск (RAG - Retrieval)
    log_vector = model.encode([log_line])
    D, I = index.search(log_vector, k=1) # Ищем 1 самый похожий вектор
    
    similarity_threshold = 1.0 # Порог схожести (нужно тюнить)
    
    if D[0][0] < similarity_threshold:
        # Найден похожий известный паттерн
        matched_pattern = known_attack_patterns[I[0][0]]
        analysis_result["analyses"].append({
            "source": "Internal RAG", 
            "details": f"Log is similar to a known pattern: '{matched_pattern}'",
            "similarity": float(D[0][0])
        })
    else:
        # 4. Если не нашли в своей базе -> OpenAI
        openai_summary = analyze_with_openai(log_line)
        analysis_result["analyses"].append({"source": "OpenAI", "details": openai_summary})

    # Этот результат нужно отправить в веб-интерфейс через WebSocket
    print(f"\n[SUSPICIOUS ACTIVITY DETECTED]\n{analysis_result}\n")
    return analysis_result


# --- Основной цикл ---

def main():
    """Запускает 'log stream' и обрабатывает его вывод."""
    # Запускаем сервер метрик для Prometheus
    start_http_server(8000)
    print("Prometheus metrics server started on http://localhost:8000")

    # Команда для получения логов
    # --predicate 'subsystem == "com.apple.securityd"' можно использовать для фильтрации
    command = ["log", "stream", "--style", "json"] 
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print("Starting to stream logs from macOS...")
    try:
        while True:
            line = process.stdout.readline()
            if not line:
                break
            # Здесь мы бы отправляли `line` в FastAPI бэкенд
            process_log_line(line.strip())

    except KeyboardInterrupt:
        print("Stopping log processor...")
    finally:
        process.terminate()

if __name__ == "__main__":
    main()