# For run code
1) npm install
2) npx ts-node hybrid-encryption.ts

# การทำงานของ Code 
- การส่งข้อมูลไปยัง server ให้ปลอดภัยเราจะใช้ Keypair คือ การที่เข้ารหัสต้นทางด้วย public key และ จะถอดได้ต้องมี private key ที่เป็นคู่กัน แต่การจะเข้ารหัสข้อมูลขนาดใหญ่ด้วย keypair ใช้เวลานานและข้อมูลใหญ่มาก จึงจะผสมการเข้ารหัสแบบ AES (Advanced Encryption Standard) ที่ทำได้ไวและไม่ซับซ้อนเป็นการเข้ารหัสและถอดรหัสด้วย key เดียว
    1) เราจะเข้า ข้อมูลด้วย AES key ซึ่่งปลายทางจะไม่มีคียร์นี้เราจะต้องส่งไปด้วย แต่ การส่งไปตรงๆก็จะแอบดักละเปิดดูข้อมูลได้
    2) เราจะเข้ารหัส key AES ด้วย public key หรือ RSA เนื่องจาก key มีขนาดไม่ใหญ่ทำให้ทำได้ และ การจะเปิด AES Key ได้ก็ต้องมี private key เท่านั้นซึ่งอยู่ที่ระบบ server

- ฝั่ง Server จะเข้า decrypt AES key โดยใช้ private key ที่ตัวเองมี และใช้ AES decrypt data  อีกทีนึง

# Code แบ่งเป็น 3 ส่วร
1) สร้าง RSA keypair และ AES key
``` typescript
const pki = forge.pki;
const random = forge.random;
const aes = forge.cipher;
const pki = forge.pki;
const serverKeypair = pki.rsa.generateKeyPair(2048);
```

2) ฝั่ง Client จะเข้ารหัสข้อมูลด้วย AES key และส่งไปยัง Server และเข้ารหัส AES key ด้วย public key ของ server

``` typescript
function EncyptTextFromClient(filePath: string): ClientReq {
    console.log('🔐 Encrypting data on client side...');
    // Generate a random AES key (128-bit)
    const aesKey = random.getBytesSync(16); // 16 bytes = 128 bits
    console.log('✅ Generated AES key:');
    const iv = random.getBytesSync(16);     // AES IV

    // Encrypt data with AES key
    const plaintext: string = fs.readFileSync(filePath, 'utf8');
    console.log('🔐 PlainText:', plaintext);

    // encrypt data with AES key
    const cipher = aes.createCipher('AES-CBC', aesKey);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
    cipher.finish();
    const encryptedData = cipher.output.getBytes(); // binary
    console.log('✅ Encrypted data:');

    // Encrypt AES key with server's RSA public key
    const encryptedAESKey = serverKeypair.publicKey.encrypt(aesKey, 'RSAES-PKCS1-V1_5');
    const encryptIV = serverKeypair.publicKey.encrypt(iv, 'RSAES-PKCS1-V1_5');
    console.log('✅ Encrypted AES key:');

    console.log({
        encyptedAESKey:forge.util.encode64(encryptedAESKey),
        encryptedData: forge.util.encode64 (encryptedData),
    })

    const request: ClientReq = {
        encyptedAESKey: encryptedAESKey,
        encryptedData: encryptedData,
        iv: encryptIV
    }
    return  request;
}
```

3) ฝั่ง Server จะถอดรหัส AES key ด้วย private key และถอดรหัสข้อมูลด้วย AES key
``` typescript
function serverDecrypt(request: ClientReq){
    console.log('🔐 Decrypting AES key and data on server side...');
    //  เนื่องจากไม่ได้ส่งมาเป็น base64 log ตรงๆมันจะ งง
    console.log({
        encyptedAESKey: forge.util.encode64(request.encyptedAESKey),
        encryptedData: forge.util.encode64(request.encryptedData),
    })
   const decryptedAESKey = serverKeypair.privateKey.decrypt(request.encyptedAESKey, 'RSAES-PKCS1-V1_5');
   const decipherAESKeyIV = serverKeypair.privateKey.decrypt(request.iv, 'RSAES-PKCS1-V1_5');
   const data = request.encryptedData;

    // Decrypt data with decrypted AES key
    const decipher = aes.createDecipher('AES-CBC', decryptedAESKey);
    decipher.start({iv: decipherAESKeyIV});
    decipher.update(forge.util.createBuffer(data));
    const success = decipher.finish();

    const decryptedMessage = decipher.output.toString();

    console.log('✅ Decrypted:', decryptedMessage);

}
```
