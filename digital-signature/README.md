## PREREQUISITE
### Generate RSA Key Pair
    This is how to generate the key pair:
    will be added later
### Create Key Directory
Create a `key` directory int root folder
<br>

``` bash
mkdir key
touch key/priv.pem
touch key/pub.pem
```

copy all the generated key pair to the `key` directory
<br>
<br>

## HOW TO RUN
### C#
``` bash
cd c\#-example
dotnet run
```

### GO
``` bash
go run ./go-example/main.go
```

### PHP 
``` bash
cd php-example
composer install 
php main.php  
```

### Javascript
```bash
cd js-example
npm install
node .
```

### JAVA
```bash
cd java-example
mvn install
mvn exec:java -Dexec.mainClass="com.java.example.pkcs"
```

### PYTHON
```bash
cd python-example
pip3 install -r requirements.txt
python3 digital-signature.py
```

