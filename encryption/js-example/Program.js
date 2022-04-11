const crypto = require('crypto');
const fs = require("fs");


console.log("Example Encryption & Decryption on Javascript")
main();


function main() {

    
    // Key is 32 byte
    let key = "RX9SflncVGx0dZE6qdL3xlfVumWtKmju";
    let keyBytes = Buffer.from(key)
    let message = '{"hello": "world"}';
    // Public & private key
    // Example -----BEGIN PUBLIC KEY-----
    const pubKey = fs.readFileSync("../key/pub.pem", "utf8");
    // Example -----BEGIN RSA PRIVATE KEY-----
    const privKey = fs.readFileSync("../key/priv.pem", "utf8");


    // Encrypted Payload
    let encryptedText = encrypt(key,message);
    console.log("encryptedPayload     : ", encryptedText.toString('base64'));

    // Encrypted Key
    let encryptedKey = encryptKey(pubKey,keyBytes);
    console.log("encypted key         : ", encryptedKey.toString("base64"))

    // Decrypted Key
    let decryptedKey = decryptKey(privKey,encryptedKey.toString("base64"));
    console.log("decrypted key        : ", decryptedKey.toString())

    // Decrypted Payload
    let decryptedText = decrypt(decryptedKey.toString(),encryptedText);
    console.log("decryptedTextPayload : ",decryptedText); 
}

// AES GCM encryption
function encrypt(key,text) {
    // iv/nonce is 12 byte
    const iv = crypto.randomBytes(12);
    let message = Buffer.from(text, 'utf8');
    let cipher = crypto.createCipheriv('aes-256-gcm',key, iv);
    let encryptedToText = cipher.update(message);

    let encrypted = Buffer.concat([
        encryptedToText, 
        cipher.final(),
        // tag is 16 byte
        cipher.getAuthTag(), 
        iv
        ]); 

    return encrypted.toString('base64');
}

function decrypt(key,text) { 
    
    let encryptedText = Buffer.from(text, 'base64');
    let iv = encryptedText.slice(encryptedText.byteLength - 12, encryptedText.byteLength);

    let decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    // 16-> tag , 12->iv
    let decrypted = decipher.update(encryptedText.slice(0, encryptedText.byteLength - 16 - 12));

    decrypted = Buffer.concat([decrypted]);
    return decrypted.toString();
}

// RSA OAEP encryption
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
 
 


 