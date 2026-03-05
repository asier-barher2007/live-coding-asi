# backend/Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Instalar gcc (necesario para compilar bcrypt)
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar solo los archivos Python (NO la carpeta data/)
COPY app.py .
COPY seed.py .

# Crear carpeta de datos para SQLite
RUN mkdir -p /app/data

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=3000
ENV PYTHONUNBUFFERED=1

EXPOSE 3000

CMD ["flask", "run"]