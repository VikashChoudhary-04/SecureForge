FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SECURECOMMERCE_HOST=0.0.0.0
ENV SECURECOMMERCE_PORT=5000

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY run.py .

RUN mkdir -p /app/instance /app/uploads

EXPOSE 5000

CMD ["python", "run.py"]
