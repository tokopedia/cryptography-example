const crypto = require('crypto');
const fs = require("fs");
//Key is 12byte
const iv = crypto.randomBytes(12);
//key is 16byte
var key = "tokopedia1234567";
var keyBytes = Buffer.from(key)
var message = '{"hello": "world"}';
//Public & private key
//example -----BEGIN PUBLIC KEY-----
const pubKey = fs.readFileSync("/Users/brigita.dewi/Workspace/Encryption/encryption/key/pub.pem", "utf8");
//example -----BEGIN RSA PRIVATE KEY-----
const privKey = fs.readFileSync("/Users/brigita.dewi/Workspace/Encryption/encryption/key/priv.pem", "utf8");


//encryptedPayload
var encryptedText = encrypt(key,message);
console.log("encryptedPayload     : ", encryptedText.toString('base64'));

//encryptedKey
var encryptedKey = encryptKey(pubKey,keyBytes);
console.log("encypted key         : ", encryptedKey.toString("base64"))

//decryptedKey
var decryptedKey = decryptKey(privKey,encryptedKey.toString("base64"));
console.log("decrypted key        : ", decryptedKey.toString())

//decryptedPayload
var decryptedText = decrypt(decryptedKey.toString(),encryptedText);
console.log("decryptedTextPayload : ",decryptedText); 
 

//AES GCM encryption
function encrypt(key,text) {
    var message = Buffer.from(text, 'utf8');
    let cipher = crypto.createCipheriv('aes-128-gcm',key, iv);
    let encryptedToText = cipher.update(message);

    let encrypted = Buffer.concat([
        encryptedToText, 
        cipher.final(),
        cipher.getAuthTag(), //16byte
        iv
        ]); 

    return encrypted.toString('base64');
}

function decrypt(key,text) { 
    
    let encryptedText = Buffer.from(text, 'base64');
    let iv = encryptedText.slice(encryptedText.byteLength - 12, encryptedText.byteLength);

    let decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
    //16-> tag , 12->iv
    let decrypted = decipher.update(encryptedText.slice(0, encryptedText.byteLength - 16 - 12));

    decrypted = Buffer.concat([decrypted]);
    return decrypted.toString();
}

//RSA OAEP encryption
function encryptKey(key,textBytes) { 
    const encryptedData = crypto.publicEncrypt(
        {
            key: key,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        textBytes
    )
    return encryptedData
}

function decryptKey(key,text) { 
    const decryptedData = crypto.privateDecrypt(
        {
            key: key,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(text, "base64")
    )
    return decryptedData
}
 
 


 