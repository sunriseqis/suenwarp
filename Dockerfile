# syntax=docker/dockerfile:1

FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app

RUN useradd -m -u 1000 warp && mkdir -p /data && chown warp:warp /data

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=web /web/dist ./static

ENV WARPSUB_DATA_DIR="/data" \
    WARPSUB_STATIC_DIR="/app/static" \
    WARPSUB_CONFIG="/data/config.yaml" \
    TZ="Asia/Shanghai"

USER warp
VOLUME ["/data"]
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
