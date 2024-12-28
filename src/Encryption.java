// Encryption.java

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.concurrent.ThreadLocalRandom;

public class Encryption {

    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 128;
    private static final int SALT_SIZE = 16;
    private static final int ITERATIONS = 1_000_000;
    private static final int PADDING_MIN = 10;
    private static final int PADDING_MAX = 50;

    public record EncryptedData(byte[] salt, byte[] iv, byte[] ciphertext) {}

    private final SecureRandom secureRandom;

    public Encryption() {
        this.secureRandom = new SecureRandom();
    }

    public EncryptedData encrypt(String password, byte[] data) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        secureRandom.nextBytes(salt);
        SecretKey key = deriveKey(password.toCharArray(), salt);
        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(data);
        return new EncryptedData(salt, iv, ciphertext);
    }

    private SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public byte[] getRandomPadding() {
        int paddingSize = ThreadLocalRandom.current().nextInt(PADDING_MIN, PADDING_MAX + 1);
        byte[] padding = new byte[paddingSize];
        secureRandom.nextBytes(padding);
        return padding;
    }
}
