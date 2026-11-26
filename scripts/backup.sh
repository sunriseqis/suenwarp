#!/bin/sh
# 备份 warp-sub 的运行数据（账号密钥 + 扫描结果 + 历史）。
# 用法: ./scripts/backup.sh [数据目录] [备份目录] [保留份数]
set -eu

DATA_DIR="${1:-./data}"
BACKUP_DIR="${2:-./backups}"
KEEP="${3:-14}"

if [ ! -d "$DATA_DIR" ]; then
  echo "数据目录不存在: $DATA_DIR" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="$BACKUP_DIR/warp-sub-$STAMP.tar.gz"

# 账号文件含私钥，备份必须是 600
umask 077
tar -czf "$ARCHIVE" -C "$(dirname "$DATA_DIR")" "$(basename "$DATA_DIR")"

# 只保留最近 N 份
ls -1t "$BACKUP_DIR"/warp-sub-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old"
done

echo "已备份到 $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"
