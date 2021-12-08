#!/bin/bash -ue

# 通常使用はこのファイルをコピペするなり設定を書き換えるなりで処理すること

export SETTING_URL=http://localhost/deploy/php-deploy-receiver.php
export SETTING_ACCESS_KEY=password
export SETTING_AUTH_HEADER_NAME=DEPLOY
export SETTING_ARCHIVE_FILE_NAME=public_html.zip
export SETTING_SPLIT_SIZE=10MB

# はい実行！
$(cd $(dirname $0); pwd)/send-core.sh
