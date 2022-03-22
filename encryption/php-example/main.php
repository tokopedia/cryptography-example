<?php
require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\AES;

$key = "tokopedia1234567";
$payload = '{"hello": "world"}';
$pubKey = file_get_contents('../key/pub.pem');
$privKey = file_get_contents('../key/priv.pem');

echo "=== Testing Encrypt Payload ===" . PHP_EOL;
echo "plain payload : $payload" . PHP_EOL;

$encryptedPayload = encrypt_payload($payload, $key);
echo "encrypted payload : $encryptedPayload" . PHP_EOL;

$decryptedPayload = decrypt_payload($encryptedPayload, $key);
echo "decrypted payload : $decryptedPayload". PHP_EOL . PHP_EOL . PHP_EOL;

echo "=== Testing Encrypt Key ===" . PHP_EOL;
echo "plain key : $key" . PHP_EOL;

$encryptedKey = encrypt_key($key, $pubKey);
echo "encrypted key : $encryptedKey" . PHP_EOL;

$decryptedKey = decrypt_key($encryptedKey, $privKey);
echo "decrypted key : $decryptedKey". PHP_EOL;

function encrypt_payload($payload, $key) {
    $nonce = Random::string(12);

    $cipher = new AES('gcm');
    $cipher->setKey($key);
    $cipher->setNonce($nonce);

    $ciphertext = $cipher->encrypt($payload) . $cipher->getTag() . $nonce;
    return base64_encode($ciphertext);
}

function decrypt_payload($payload, $key) {
    $decoded = base64_decode($payload);

    $nonce = substr($decoded, -12);
    $decoded = substr($decoded, 0, -12);

    $tag = substr($decoded, -16);
    $decoded = substr($decoded, 0, -16);

    $cipher = new AES('gcm');
    $cipher->setKey($key);
    $cipher->setNonce($nonce);
    $cipher->setTag($tag);

    return $cipher->decrypt($decoded);
}

function encrypt_key($key, $public_key) {
    $rsa = PublicKeyLoader::load($public_key);
    return base64_encode($rsa->encrypt($key));
}

function decrypt_key($key, $private_key) {
    $rsa = PublicKeyLoader::load($private_key);
    return $rsa->decrypt(base64_decode($key));
}
