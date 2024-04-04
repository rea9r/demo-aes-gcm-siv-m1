package org.example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.conscrypt.Conscrypt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AesGcmSivKeyManager;

class DemoTinkCryptorTest {
    private DemoTinkCryptor cryptor;

    @BeforeEach
    void init() throws GeneralSecurityException, IOException {
        String demoKeysetJsonStr = """
                {
                  "primaryKeyId": 2110507095,
                  "key": [
                    {
                      "keyData": {
                        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
                        "value": "GiDPCYyIraH83IrN7PRvd4xUfSI4hE937/1n0govi4t3jg==",
                        "keyMaterialType": "SYMMETRIC"
                      },
                      "status": "ENABLED",
                      "keyId": 2110507095,
                      "outputPrefixType": "TINK"
                    }
                  ]
                }
                """;
        KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withString(demoKeysetJsonStr));
        cryptor = new DemoTinkCryptor(keysetHandle);
    }

    @Test
    void generateKeySetAndSerialize() throws Exception {
        /*
         * キーを生成してシリアライズする際に使ったコードを残す
         */
        // Java で AES-GCM-SIV を使うためには、JCE に Conscrypt を追加する必要がある
        // @see https://developers.google.com/tink/supported-key-types
        Conscrypt.checkAvailability();
        Security.addProvider(Conscrypt.newProvider());
        AeadConfig.register();

        KeysetHandle keysetHandle = KeysetHandle.generateNew(AesGcmSivKeyManager.aes256GcmSivTemplate());
        String serializedKeyset = TinkJsonProtoKeysetFormat.serializeKeyset(keysetHandle,
                                                                            InsecureSecretKeyAccess.get());
        System.out.println("serializedKeyset: " + serializedKeyset);
    }

    @Test
    void testEncryptDecrypt() {
        final String original = "This is original text!";

        String encryptedText = cryptor.encrypt(original, "additionalData");
        assertNotEquals(original, encryptedText);

        String decryptedText = cryptor.decrypt(encryptedText, "additionalData");
        assertEquals(original, decryptedText);
    }
}
