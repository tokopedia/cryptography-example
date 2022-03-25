## PREREQUISITE

### PHP 
There are 2 encryption on this example
- Encrypt/Decrypt key: using RSA encryption
- Encrypt/Decrypt payload: using AES GCM encryption

### C#
There are 2 encryption on this example
- Encrypt/Decrypt key: using RSA OAEP 256 encryption
- Encrypt/Decrypt payload: using AES GCM encryption
- Min require : .NET Core

### Generate RSA Key Pair
Create a `key` directory int root folder
    
    mkdir key
    cd key
Generate 2048 bit RSA Key

    openssl genrsa -des3 -out private.pem 2048
Export the RSA Private Key

    openssl rsa -in private.pem -out priv.pem -outform PEM
Export the RSA Public Key

    openssl rsa -in private.pem -outform PEM -pubout -out pub.pem
Remove the RSA Key

    rm private.pem


## HOW TO RUN
### PHP 
``` bash
cd php-example
composer install 
php main.php  
```

### C# 
``` bash
cd c\#-example/Encryption/
dotnet run 
```
