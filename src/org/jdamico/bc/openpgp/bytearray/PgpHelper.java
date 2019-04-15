package org.jdamico.bc.openpgp.bytearray;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

/**
 * Taken from org.bouncycastle.openpgp.examples
 *
 * @author seamans
 * @author jdamico <damico@dcon.com.br>
 */
public class PgpHelper {

    private static PgpHelper INSTANCE = null;

    public static PgpHelper getInstance() {

        if (INSTANCE == null) INSTANCE = new PgpHelper();
        return INSTANCE;
    }

    private PgpHelper() {
    }

    public PGPPublicKey readPublicKey(byte[] encoding) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(encoding);
        PGPPublicKey key = null;
        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = kIt.next();

                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }

        return key;
    }

    /**
     * Load a secret key ring collection from keyIn and find the secret key corresponding to
     * keyID if it exists.
     *
     * @param encoding a key ring collection.
     * @param keyID keyID we want.
     * @param pass  passphrase to decrypt secret key with.
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public PGPPrivateKey findSecretKey(byte[] encoding, long keyID, char[] pass)
            throws IOException, PGPException, NoSuchProviderException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(encoding);

        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        PBESecretKeyDecryptor a = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(pass);

        return pgpSecKey.extractPrivateKey(a);
    }

    /**
     * decrypt the passed in message stream
     * @param in 加密后的文件
     * @param out 解密后的文件
     * @param keyIn PGP私钥
     * @param passwd 密码
     * @throws Exception
     */
    /*@SuppressWarnings("unchecked")
    public void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        in = PGPUtil.getDecoderStream(in);
        PGPObjectFactory pgpF = new PGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = it.next();
            sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        //解密
        PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").setContentProvider("BC").build(sKey);

        InputStream clear = pbe.getDataStream(b);

        PGPObjectFactory plainFact = new PGPObjectFactory(clear);

        Object message = plainFact.nextObject();

        //解压
        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());

            message = pgpFact.nextObject();
        }

        String str = "";
        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            int ch;
            byte[] buf = new byte[1024];
            while ((ch = unc.read(buf)) != -1) {
                out.write(buf, 0, ch);
                str += new String(buf, 0, ch);
            }
            System.err.println(str);
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }*/

    /**
     *
     *  1 用伪随机数生成器生成会话密钥
     *  2 用公钥密码加密会话密钥
     *  3 压缩消息
     *  4 使用对称密码对压缩的消息进行加密，这里使用的密钥是步骤1中生成的会话密钥。
     *  5 将加密的会话密钥（步骤2）与加密的消息（步骤4）拼合起来。
     *  6 将步骤5的结果转换为文本数据，转换后的结果就是报文数据。
     *
     * @param out 加密后的文件 -- ByteArrayOutputStream
     * @param fileName 要加密的文件
     * @param encKey PGP公钥
     * @param armor
     * @param withIntegrityCheck 完整性
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    /*public void encryptFile(OutputStream out, String fileName,
                            PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {
        Security.addProvider(new BouncyCastleProvider());

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);
        // 压缩消息
        PGPUtil.writeFileToLiteralData(comData.open(bOut),
                PGPLiteralData.BINARY, new File(fileName));

        comData.close();

        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        cPk.addMethod(d);

        byte[] bytes = bOut.toByteArray();
        //会话秘钥使用公钥加密、会话秘钥加密压缩的消息、组合
        OutputStream cOut = cPk.open(out, bytes.length);
        //写出到加密文件
        cOut.write(bytes);

        cOut.close();

        out.close();
    }*/


    /*public byte[] inputStreamToByteArray(InputStream is) throws IOException {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;
        byte[] data = new byte[1024];

        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();

        return buffer.toByteArray();
    }*/


    /**
     * verify the signature in in against content.
     */
    public boolean verifySignature(
            byte[] content,
            byte[] b,
            byte[] pubKey)
            throws GeneralSecurityException, IOException, PGPException {
        //in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpFact = new PGPObjectFactory(b);
        PGPSignatureList p3 = null;

        Object o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;

            pgpFact = new PGPObjectFactory(c1.getDataStream());

            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else {
            p3 = (PGPSignatureList) o;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(pubKey);

        PGPSignature sig = p3.get(0);
        PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), key);
        sig.update(content);
        if (sig.verify()) {
            System.out.println("signature verified.");
            return true;
        } else {
            System.out.println("signature verification failed.");
            return false;
        }
    }

    /*public PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input));

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }*/

    public PGPSecretKey readSecretKey(byte[] priKey) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(priKey);

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    public byte[] createSignature(
            byte[] content,
            byte[] priKey,
            char[] pass,
            boolean armor)
            throws GeneralSecurityException, IOException, PGPException {


        PGPSecretKey pgpSecKey = readSecretKey(priKey);
        PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider()).build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider(new BouncyCastleProvider()));


        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(byteOut);


        BCPGOutputStream bOut = new BCPGOutputStream(byteOut);

        sGen.update(content);

        aOut.endClearText();

        sGen.generate().encode(bOut);

        if (armor) {
            aOut.close();
        }

        bOut.close();
        return byteOut.toByteArray();
    }

}