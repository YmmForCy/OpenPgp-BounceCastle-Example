package org.jdamico.bc.openpgp.bytearray_methodRef;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

public class InterlinkEncryptor {
    public byte[] encrypt(byte[] in,byte[] enc_data, CertStore cs) throws NoSuchProviderException, IOException, PGPException {
        ByteArrayOutputStream cypherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        Security.addProvider(new BouncyCastleProvider());

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);
        // 压缩消息，将content写入bOut
        PGPUtilPer.writeFileToLiteralDataPer(comData.open(bOut),
                PGPLiteralData.BINARY, in);

        comData.close();

        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(PgpHelper.getInstance().readPublicKey(cs.getPgpPubKey())).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        cPk.addMethod(d);

        byte[] bytes = bOut.toByteArray();
        //会话秘钥使用公钥加密、会话秘钥加密压缩的消息、组合
        OutputStream cOut = cPk.open(cypherOut, bytes.length);
        //写出到加密文件
        cOut.write(bytes);
        System.out.println("流关闭前：" + cypherOut.toByteArray().length); // 177
        cOut.close();
        cypherOut.close();
        bOut.close();

        enc_data = cypherOut.toByteArray();
        return enc_data;
    }

    public byte[] decrypt(byte[] in, byte[] dec_data, CertStore cs) throws Exception {
        ByteArrayOutputStream decPlainTextOut = new ByteArrayOutputStream();

        Security.addProvider(new BouncyCastleProvider());
        // 读取加密的内容
        //ByteArrayInputStream in = new ByteArrayInputStream(cypherOut.toByteArray());
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
            sKey = PgpHelper.getInstance().findSecretKey(cs.getPgpPriKey(), pbe.getKeyID(), "idpass".toCharArray());
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
                decPlainTextOut.write(buf, 0, ch);
                str += new String(buf, 0, ch);
            }
            System.err.println("解密后的数据：" + str);
            dec_data = decPlainTextOut.toByteArray();
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
        return dec_data;
    }

    public byte[] sign(byte[] in, byte[] signdata, CertStore cs) throws Exception {
        signdata = PgpHelper.getInstance().createSignature(in, cs.getPgpPriKey(), "idpass".toCharArray(), true);
        return signdata;
    }

    public boolean isValid(byte[] in, byte[] signdata, CertStore cs) throws PGPException, GeneralSecurityException, IOException {
        return PgpHelper.getInstance().verifySignature(in, signdata, cs.getPgpPubKey());
    }
}
