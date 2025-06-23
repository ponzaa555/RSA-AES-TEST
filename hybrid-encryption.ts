import forge from 'node-forge';
import * as fs from 'fs';

const pki = forge.pki;
const random = forge.random;
const aes = forge.cipher;

type ClientReq = {
    encyptedAESKey: string; // Encrypted AES key
    encryptedData: string; // Encrypted data
    iv : string;
}
// ===== 1. Generate RSA key pair (server side) =====
const serverKeypair = pki.rsa.generateKeyPair(2048);


function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

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
// ===== 3. Receiver side =====
// Decrypt AES key with RSA private key


async function main() {
    const filePath = 'message.txt'; // Path to the file to encrypt
    const request = EncyptTextFromClient(filePath);
    console.log();
    console.log('⏳ Simulating delay...');
    await delay(2000); // wait 2 seconds
    console.log();

    serverDecrypt(request);
}

main()