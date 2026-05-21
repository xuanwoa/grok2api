FROM ghcr.io/chenyme/grok2api:latest

ENV SERVER_HOST=0.0.0.0 \
    SERVER_PORT=7860 \
    SERVER_WORKERS=1 \
    DATA_DIR=/data \
    ACCOUNT_STORAGE=local \
    ACCOUNT_LOCAL_PATH=/data/accounts.db \
    LOG_FILE_ENABLED=false \
    LOG_DIR=/tmp/logs

EXPOSE 7860
