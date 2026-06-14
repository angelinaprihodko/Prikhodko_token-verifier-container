FROM python:3.11-slim

WORKDIR /workspace

# Зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Миграции и сбор статики
RUN python manage.py migrate --noinput
RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 8001

CMD ["python", "manage.py", "runserver", "0.0.0.0:8001"]