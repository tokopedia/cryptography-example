<?php
require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Crypt\RSA;
$privKey = file_get_contents('../key/priv.pem');
$pubKey = file_get_contents('../key/pub.pem');
$priv = RSA::loadPrivateKey($privKey); // private key

$plaintext = 'test';
$signature = $priv->sign($plaintext);
$base64sign = base64_encode($signature);

echo $base64sign;

$pub = RSA::loadPublicKey($pubKey);
$verify = $pub->verify($plaintext, $signature);

echo "\n";
echo $verify ? 'verified' : 'unverified';
?>