<?php

declare(strict_types=1);

function getConfig()
{
	return [
		// ☆展開ディレクトリ(事故が怖いのでフルパスで！)
		'PUBLIC_DIR_PATH' => '/home/user/public_html',
		// ☆トークン発行に使用するアクセスキー
		'ACCESS_KEY' => '',
		// トークンの有効期限
		'TOKEN_EXPIRATION' => 'PT1H',
		// ☆アクセストークンヘッダ(HTTP_はApache依存なのに注意)
		'AUTH_HEADER' => 'HTTP_DEPLOY',
		// ☆配置サーバー(apache, それ以外)。apache なら .htaccess 補正をめっちゃ頑張る
		'SERVER' => 'apache',
		// 鍵作成設定: null でいいけど xampp でやる場合なんかは 'config' => 'C:\\xampp\\....openssl\\openssl.cnf' しておくのが無難
		'OPENSSL' => null,
	];
}
