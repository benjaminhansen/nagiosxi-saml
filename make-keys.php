<?php

// generate a new RSA key pair
$keys = openssl_pkey_new([
    'private_key_bits' => 4096,
    'private_key_type' => OPENSSL_KEYTYPE_RSA
]);

// export the keys to PEM format
$public_key_pem = openssl_pkey_get_details($keys)['key'];
openssl_pkey_export($keys, $private_key_pem);

// clean up the PEM format by removing unnecessary characters
$public_key_pem_raw = str_replace([
    '-----BEGIN PUBLIC KEY-----',
    '-----END PUBLIC KEY-----',
    '\r\n',
    '\n',
    '\r',
], '', $public_key_pem);

// also clean up the private key PEM format
$private_key_pem_raw = str_replace([
    '-----BEGIN PRIVATE KEY-----',
    '-----END PRIVATE KEY-----',
    '\r\n',
    '\n',
    '\r',
], '', $private_key_pem);

// return the keys as a JSON response
echo json_encode([
    'private_key' => $private_key_pem_raw,
    'public_key' => $public_key_pem_raw
]);
