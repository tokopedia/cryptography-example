<?php
require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Crypt\RSA;

$privKey = file_get_contents('../key/priv.pem');
$pubKey = file_get_contents('../key/pub.pem');
$priv = RSA::loadPrivateKey($privKey) // private key
    ->withHash('sha256'); // hash algorithm
// $priv = $priv->withPadding(RSA::SIGNATURE_PKCS1); // Add this code to change the padding to PKCS1, By default, the padding is RSA::SIGNATURE_PS


$plaintext = 'test';

$keySize = $priv->getLength() / 8; // key length in byte
$hashed = hash('sha256', $plaintext, true); // hash with sha256 
$hashLength = strlen($hashed); // length of hash 
$saltLength = $keySize - 2 - $hashLength; // length of salt
$priv = $priv->withSaltLength($saltLength);

$signature = $priv->sign($plaintext);
$base64sign = base64_encode($signature);
echo $base64sign;

$pub = RSA::loadPublicKey($pubKey);
$keySize = $pub->getLength() / 8; // key length in byte
$hashed = hash('sha256', $plaintext, true); // hash with sha256
$hashLength = strlen(($hashed)); // length of hash
$saltLength = $keySize - 2 - $hashLength; // length of salt
$pub = $pub->withSaltLength($saltLength);
// $pub = $pub->withPadding(RSA::SIGNATURE_PKCS1); // Add this code to change the padding to PKCS1, By default, the padding is RSA::SIGNATURE_PS

$verify = $pub->verify($plaintext, $signature);

echo "\n";
echo $verify ? 'verified' : 'unverified';
