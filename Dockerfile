# 本番イメージ。Cloud Run に載せる。
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 依存だけ先に入れる。コードを変えても依存の層は再利用される
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Cloud Run は PORT を渡してくる
ENV PORT=8080
EXPOSE 8080
CMD exec uvicorn drive_qr_sign.main:app --host 0.0.0.0 --port ${PORT}
