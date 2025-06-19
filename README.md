# WatchMyBacklogDude

WatchMyBacklogDude — комплексная система для сбора, анализа и визуализации системных логов macOS в реальном времени. 
Она использует Retrieval Augmented Generation (RAG) и внешние API (VirusTotal, OpenAI), а также стек мониторинга Prometheus + Grafana.
Результаты отображаются в веб‑интерфейсе через WebSocket.

## Состав репозитория
- **api/** — исходный код FastAPI приложения
- **static/** и **templates/** — файлы веб-интерфейса
- **create_attack_vectors.py** — скрипт для генерации векторной базы
- **main_processor.py** — пример скрипта для потоковой обработки логов
- **docker-compose.yml** — окружение с Prometheus и Grafana
- **Dockerfile** — образ для запуска приложения
- **requirements.txt** — зависимости Python

## Предварительные требования
- Установленный и запущенный Docker Desktop
- Python 3.10 или 3.11 (PyTorch не имеет стабильных сборок для 3.12)

3. Перейдите на `http://localhost:8080` для интерфейса приложения.
4. Метрики Prometheus доступны на `http://localhost:4200`, Grafana — `http://localhost:4201`.

## Локальная установка (без Docker)
1. Убедитесь, что установлен Python 3.10 или 3.11 и создайте виртуальное окружение:
```bash
python3.11 -m venv venv
source venv/bin/activate
```
2. Установите PyTorch вручную (см. ниже) и затем остальные зависимости:
```bash
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

### Установка PyTorch на macOS
1. Обновите pip и попробуйте стандартную установку:
```bash
pip install --upgrade pip
pip install torch torchvision torchaudio
```
2. Если возникают ошибки, используйте Miniconda:
```bash
brew install miniconda
conda init zsh  # или bash/fish
exec $SHELL
conda create -n watchmybacklog python=3.11
conda activate watchmybacklog
conda install pytorch torchvision torchaudio -c pytorch
```
3. Проверьте установку:
```bash
python -c "import torch; print(f'PyTorch version: {torch.__version__}')"
```

## Особенности macOS
Для работы `log stream` требуется повышенные привилегии. В Docker Compose уже прописаны необходимые параметры (`cap_add` и `SYS_ADMIN`). При локальном запуске убедитесь, что у пользователя есть права на чтение системных логов.

### Apple Silicon (M1, M2, M3, M4)
На компьютерах с чипами Apple Silicon Docker использует виртуализацию на базе `qemu`. Файлы образов собираются под архитектуру `arm64`. В `docker-compose.yml` никаких дополнительных настроек не требуется.

### Intel-based Mac
На Intel Mac приложение также работает из контейнера. Если параллельно используются образы под `arm64` и `amd64`, Docker автоматически скачает корректные образы для каждой архитектуры.

## Состояние проекта
Проект носит демонстрационный характер и не готов для использования в production. Все ключи и учётные данные передаются через `.env` файл. Для доступа предусмотрен простой интерфейс авторизации на сессиях.

## Интеграция с GitHub по SSH-ключу
1. Создайте ключ, если его ещё нет:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/watchmybacklogdude -C "your_email@example.com"
```
2. Добавьте публичную часть ключа в настройках GitHub.
3. Запишите конфигурацию в `~/.ssh/config`:
```ssh
Host github.com-watchmybacklogdude
    HostName github.com
    User git
    IdentityFile ~/.ssh/watchmybacklogdude
    IdentitiesOnly yes
```
4. Привяжите локальный репозиторий к удалённому:
```bash
git remote add origin git@github.com-watchmybacklogdude:shepherdvovkes/watchmybacklogdude.git
git push -u origin main
```

