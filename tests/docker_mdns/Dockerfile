FROM python:3.11-slim

RUN pip install --no-cache-dir zeroconf

WORKDIR /app
COPY responder.py /app/responder.py
RUN chmod +x /app/responder.py

CMD ["python", "/app/responder.py"]

