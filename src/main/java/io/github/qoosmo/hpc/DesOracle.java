package io.github.qoosmo.hpc;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Deterministic DES encryption oracle for the deliberately reduced-keyspace
 * experiments in this repository.
 *
 * <p>This class is for historical/reproducibility experiments only. DES is
 * obsolete and must not be used for security-sensitive applications.
 *
 * <p>A cipher instance is cached per thread so benchmark loops do not repeatedly
 * pay provider lookup/instance-construction cost. Each encryption still
 * reinitializes the cipher with the state-derived key.
 */
public final class DesOracle {
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    private final ReducedDesKeySpace keySpace;
    private final byte[] plaintext;
    private final ThreadLocal<Cipher> ciphers =
            ThreadLocal.withInitial(DesOracle::newCipher);

    public DesOracle(ReducedDesKeySpace keySpace, byte[] plaintext) {
        if (keySpace == null) {
            throw new NullPointerException("keySpace");
        }
        if (plaintext == null) {
            throw new NullPointerException("plaintext");
        }
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("plaintext must not be empty");
        }
        this.keySpace = keySpace;
        this.plaintext = plaintext.clone();
    }

    public byte[] encryptState(long state) {
        return encrypt(keySpace.toKey(state));
    }

    public boolean matches(long state, byte[] expectedCiphertext) {
        if (expectedCiphertext == null) {
            throw new NullPointerException("expectedCiphertext");
        }
        return Arrays.equals(encryptState(state), expectedCiphertext);
    }

    public byte[] plaintext() {
        return plaintext.clone();
    }

    private byte[] encrypt(SecretKey key) {
        try {
            Cipher cipher = ciphers.get();
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("DES provider is unavailable", e);
        }
    }

    private static Cipher newCipher() {
        try {
            return Cipher.getInstance(TRANSFORMATION);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("DES provider is unavailable", e);
        }
    }
}
