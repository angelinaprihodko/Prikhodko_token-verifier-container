#!/bin/bash
echo " РАЗВЁРТЫВАНИЕ КОНТЕЙНЕРА ВЕРИФИКАЦИИ"

# 1. Установка зависимостей
echo "[1/5] Установка зависимостей..."
pip install django sympy matplotlib numpy django-sslserver

# 2. Миграция базы данных
echo "[2/5] Применение миграций..."
python manage.py migrate

# 3. Сбор статических файлов
echo "[3/5] Сбор статических файлов..."
python manage.py collectstatic --noinput 2>/dev/null || echo "   Пропущено"

# 4. Создание папок при необходимости
echo "[4/5] Проверка структуры проекта..."
mkdir -p verifier/templates

# 5. Запуск HTTPS-сервера
echo "[5/5] Запуск HTTPS-сервера..."
echo ""
echo " РАЗВЁРТЫВАНИЕ ЗАВЕРШЕНО"
echo " Сервер запущен на https://0.0.0.0:443"
python manage.py runsslserver 0.0.0.0:443