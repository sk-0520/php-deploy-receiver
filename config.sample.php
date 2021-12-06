<?php

declare(strict_types=1);

function getConfig()
{
	return [
		// ☆展開ディレクトリ(事故が怖いのでフルパスで！)
		'PUBLIC_DIR_PATH' => '/home/user/public_html',
		// ☆トークン発行に使用するアクセスキー
		'ACCESS_KEY' => '',
		// 暗号化: openssl_encrypt/openssl_decrypt で使用する
		'CRYPT' => [
			'ALGORITHM' => 'aes-256-cbc',
			// ☆暗号キー
			'KEY' => '',
			// ☆IV: bin2hex(openssl_random_pseudo_bytes(16)) でつくる
			'IV' => '',
			'OPTIONS' => OPENSSL_RAW_DATA,
		]
	];
}
