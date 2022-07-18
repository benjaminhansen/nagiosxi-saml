<?php

$keys = openssl_pkey_new(array("private_key_bits" => 4096, "private_key_type" => OPENSSL_KEYTYPE_RSA));
$public_key_pem = openssl_pkey_get_details($keys)['key'];
openssl_pkey_export($keys, $private_key_pem);

$public_key_pem_raw= str_replace (array("-----BEGIN PUBLIC KEY-----","-----END PUBLIC KEY-----","\r\n", "\n", "\r"), '', $public_key_pem);
$private_key_pem_raw= str_replace (array("-----BEGIN PRIVATE KEY-----","-----END PRIVATE KEY-----","\r\n", "\n", "\r"), '', $private_key_pem);

echo json_encode([
    'private_key' => $private_key_pem_raw,
    'public_key' => $public_key_pem_raw
]);
