# Remote Access Tool

Инструмент удалённого доступа через relay-сервер (два серых IP).
Протокол: TCP (локально) + WebSocket → relay (onrender.com).

---

## Возможности

| Модуль            | Что умеет                                                        |
|-------------------|------------------------------------------------------------------|
| **Shell**         | Выполнение команд, stdout/stderr, рабочая папка                  |
| **Файлы**         | Загрузка, скачивание, листинг, удаление, mkdir, rename, zip      |
| **Скриншот**      | Одиночный снимок + стрим экрана (до 15 fps)                      |
| **Процессы**      | Список всех процессов, завершение по PID (normal / force)        |
| **Мышь**          | move, click, double-click, scroll, drag & drop                   |
| **Клавиатура**    | key_press, hotkey (ctrl+c и т.д.), type_text (unicode)           |
| **Буфер обмена**  | Получить / установить clipboard                                  |
| **Системная инфо**| OS, CPU, RAM, Disk                                               |
| **Веб-интерфейс** | Полная панель управления в браузере (Flask, на relay)            |

---

## Структура проекта

```
remote_tool/
├── server/
│   ├── main.py          ← точка запуска агента
│   ├── handler.py       ← обработчик команд
│   ├── relay_agent.py   ← WebSocket-мост к relay
│   └── web.py           ← Flask веб-интерфейс (используется relay)
├── relay/
│   ├── main.py          ← relay-сервер (деплоится на render.com)
│   ├── web.py           ← веб-интерфейс оператора
│   ├── agent_ws.py      ← обработчик WS-соединений агентов
│   ├── conn.py          ← управление соединениями
│   ├── registry.py      ← реестр агентов
│   └── render.yaml      ← конфигурация Render.com
├── client/
│   └── agent.py         ← Python API (все методы)
├── common/
│   ├── protocol.py      ← протокол сообщений
│   └── crypto.py        ← SSL, хэши паролей
├── templates/
│   ├── index.html       ← веб-интерфейс оператора
│   ├── agent.html       ← страница агента
│   └── login.html       ← страница входа
└── requirements.txt
```

---

## Установка

```bash
pip install -r requirements.txt

# Для скриншотов на Linux:
sudo apt install python3-tk python3-dev scrot
```

---

## Запуск агента

```bash
python -m server.main --port 9999 --password МойПароль12symbols \
    --relay https://your-relay.onrender.com --agent-id MyPC
```

Параметры:
- `--port` — локальный TCP-порт (по умолчанию 9999)
- `--password` — пароль (минимум 12 символов)
- `--relay` — URL relay-сервера на render.com
- `--agent-id` — уникальный ID агента (по умолчанию hostname)
- `--agent-label` — человекочитаемое имя (по умолчанию = agent-id)

Оператор открывает веб-интерфейс по адресу relay-сервера в браузере.

---

## Relay-сервер (render.com)

Деплоится из папки `relay/` через `render.yaml`.
Переменные окружения на Render:
- `OPERATOR_PASSWORD` — пароль для входа оператора

---

## Безопасность

- Пароль передаётся и хранится как **bcrypt-хэш**
- Локальный TCP без SSL (только localhost)
- Внешний трафик через **WSS** (WebSocket Secure)
- Rate limiting на странице входа

---

## ⚠️ Важно

Используйте только для администрирования **собственной инфраструктуры**.
