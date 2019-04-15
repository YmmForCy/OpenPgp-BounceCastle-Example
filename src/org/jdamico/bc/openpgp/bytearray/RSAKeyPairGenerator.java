package org.jdamico.bc.openpgp.bytearray;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
 * <p>
 * usage: RSAKeyPairGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are placed
 * in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class RSAKeyPairGenerator {

    public List<byte[]> generatorKeyPair(
            PublicKey publicKey,
            PrivateKey privateKey,
            String identity,
            char[] passPhrase)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {

        //PGPPublicKey
        PGPPublicKey a = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey, new Date()));
        RSAPrivateCrtKey rsK = (RSAPrivateCrtKey) privateKey;
        RSASecretBCPGKey privPk = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
        //PGPPrivateKey
        PGPPrivateKey b = new PGPPrivateKey(a.getKeyID(), a.getPublicKeyPacket(), privPk);

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyPair keyPair = new PGPKeyPair(a, b);
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        PGPPublicKey key = secretKey.getPublicKey();

        List<byte[]> keys = new ArrayList<>(2);
        keys.add(secretKey.getEncoded());
        keys.add(key.getEncoded());
        return keys;
    }


}
