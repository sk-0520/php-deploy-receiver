<?php

	$key_pair = openssl_pkey_new([
			'config' => 'C:\\Applications\\xampp\\xampp-portable-win32-7.1.1-0-VC14\\xampp\\php\\extras\\openssl\\openssl.cnf'
		]);
	openssl_pkey_export($key_pair, $self_private_key);
	$details = openssl_pkey_get_details($key_pair);
	$self_public_key = $details['key'];

	echo $self_private_key;
	echo "<br/>";
	echo $self_public_key;

