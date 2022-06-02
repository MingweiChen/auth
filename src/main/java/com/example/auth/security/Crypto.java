package com.example.auth.security;

import javax.crypto.Cipher;
import java.security.spec.KeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.AlgorithmParameters;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;
public class Crypto {
    Cipher decipher;

    final byte[] SALT = new String("12345678").getBytes();
    final String PASS_PHRASE = "test";
    final int ITERATION_COUNT = 1024;
    final int STRENGTH = 256;
    SecretKey key;
    byte[] iv;

    public Crypto() {
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(PASS_PHRASE.toCharArray(), SALT, ITERATION_COUNT, STRENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            key = new SecretKeySpec(tmp.getEncoded(), "AES");
            decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (Exception e) {
            // Log if required.
        }
}

    public String encrypt(String data) throws Exception {
        decipher.init(Cipher.ENCRYPT_MODE, key);
        AlgorithmParameters params = decipher.getParameters();
        iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] utf8EncryptedData = decipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(utf8EncryptedData);
    }

    public String decrypt(String base64EncryptedData)  throws Exception {
        decipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decryptedData = Base64.getDecoder().decode(base64EncryptedData);
        byte[] utf8 = decipher.doFinal(decryptedData);
        return new String(utf8, "UTF8");
    }
}
