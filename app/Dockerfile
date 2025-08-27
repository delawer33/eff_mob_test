FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /code

COPY requirements.txt .

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir -r requirements.txt

COPY ./app /code/app


FROM python:3.12-slim

WORKDIR /code

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /code /code

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/code/app \
    PYTHONUNBUFFERED=1

# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
