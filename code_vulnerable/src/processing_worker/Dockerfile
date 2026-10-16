FROM python:3.10-slim

WORKDIR /app

COPY external_packages /app/external_packages

RUN pip install --no-cache-dir /app/external_packages/chat_formatter

COPY src/processing_worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/processing_worker/ .

EXPOSE 8002
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]