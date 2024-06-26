/*
 * This source file was generated by the Gradle 'init' task
 */
package org.example;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import org.conscrypt.Conscrypt;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;

public class DemoTinkCryptor {

    static {
        try {
            // Java で AES-GCM-SIV を使うためには、JCE に Conscrypt を追加する必要がある
            // @see https://developers.google.com/tink/supported-key-types
            Conscrypt.checkAvailability();
            Security.addProvider(Conscrypt.newProvider());
            AeadConfig.register();
        } catch (Exception t) {
            throw new IllegalStateException("Conscrypt provider is required but not available", t);
        }
    }

    final KeysetHandle keysetHandle;

    public DemoTinkCryptor(KeysetHandle keysetHandle) {
        this.keysetHandle = keysetHandle;
    }

    public String encrypt(String plainText, String aad) {
        try {
            Aead aead = keysetHandle.getPrimitive(Aead.class);
            byte[] encrypted = aead.encrypt(
                    plainText.getBytes(StandardCharsets.UTF_8),
                    aad.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new DemoTinkOperationException("Encryption failed. ", e);
        }
    }

    public String decrypt(String encryptedText, String aad) {
        try {
            Aead aead = keysetHandle.getPrimitive(Aead.class);
            byte[] decryptedByte = aead.decrypt(
                    Base64.getUrlDecoder().decode(encryptedText),
                    aad.getBytes(StandardCharsets.UTF_8));
            return new String(decryptedByte, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new DemoTinkOperationException("Decryption failed.", e);
        }
    }

    public static class DemoTinkOperationException extends RuntimeException {
        public DemoTinkOperationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
