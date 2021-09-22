var crypto = require("crypto");
var fs = require("fs");
var ALGORITHM = "sha256"; // Accepted: any result of crypto.getHashes(), check doc dor other options
var SIGNATURE_FORMAT = "base64"; // Accepted: hex, latin1, base64

function getPublicKey() {
  var pubKey = fs.readFileSync("../key/pub.pem", "utf8");
  console.log("\n>>> Public key: \n\n" + pubKey);

  return pubKey;
}

function getPrivateKey() {
  var privKey = fs.readFileSync("../key/priv.pem", "utf8");
  console.log(">>> Private key: \n\n" + privKey);

  return privKey;
}

function getSignatureToVerify(data) {
  var privateKey = getPrivateKey();
  var sign = crypto.createSign(ALGORITHM);
  sign.update(data);
  var signature = sign.sign(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    SIGNATURE_FORMAT
  );

  console.log(">>> Signature:\n\n" + signature);

  return signature;
}

var publicKey = getPublicKey();
var verify = crypto.createVerify(ALGORITHM);
var data = "{}";
var signature = getSignatureToVerify(data);

console.log("\n>>> Message:\n\n" + data);

verify.update(data);

var verification = verify.verify(
  {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  },
  signature,
  SIGNATURE_FORMAT
);

console.log(
  "\n>>> Verification result: " + verification.toString().toUpperCase()
);
