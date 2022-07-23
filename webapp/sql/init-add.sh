#!/bin/sh

set -ex
cd `dirname $0`

ISUCON_DB_HOST=${ISUCON_DB_HOST:-127.0.0.1}
ISUCON_DB_PORT=${ISUCON_DB_PORT:-3306}
ISUCON_DB_USER=${ISUCON_DB_USER:-isucon}
ISUCON_DB_PASSWORD=${ISUCON_DB_PASSWORD:-isucon}
ISUCON_DB_NAME=${ISUCON_DB_NAME:-isuports}

# 追加テーブル
mysql -u"$ISUCON_DB_USER" \
		-p"$ISUCON_DB_PASSWORD" \
		--host "$ISUCON_DB_HOST" \
		--port "$ISUCON_DB_PORT" \
		"$ISUCON_DB_NAME" < karaage2.sql

# 追加初期データ
for sql in $(ls ../../initial_data_mysql/work/bulk | grep '.sql'); do
    echo $sql
	mysql -u"$ISUCON_DB_USER" \
			-p"$ISUCON_DB_PASSWORD" \
			--host "$ISUCON_DB_HOST" \
			--port "$ISUCON_DB_PORT" \
			"$ISUCON_DB_NAME" < ../../initial_data_mysql/work/bulk/$sql
done

