package org.jdamico.bc.openpgp.bytearray;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.Test;

import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;


public class TestBCOpenPGP {

    private boolean isArmored = false;
    private String id = "id";
    private String passwd = "idpass";
    private boolean integrityCheck = true;

    private byte[] priKey;
    private byte[] pubKey;

    //要加密的内容
    /*public String content = "abc dsadas打击打击史莱克  \n" +
            "dasdasjdkjlas\n" +
            "djasdjlakjdkl就撒肯德基卡机的垃圾堆克拉斯 x2011";*/
    public String content = "abc";
    //加密后的内容，保存在cypherOut
    ByteArrayOutputStream cypherOut = new ByteArrayOutputStream();
    //解密后的内容，保存在decPlainTextOut
    ByteArrayOutputStream decPlainTextOut = new ByteArrayOutputStream();
    //签名
    ByteArrayOutputStream signOut = new ByteArrayOutputStream();

    @Test
    public void genKeyPair() throws Exception {

        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

        // 添加BouncyCastleProvider，是一种用于 Java 平台的开放源码的轻量级密码术包，它支持大量的密码术算法
        Security.addProvider(new BouncyCastleProvider());

        // 获取KeyPairGenerator，算法名称：RSA、Provider：BC = BouncyCastleProvider
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        // 初始化秘钥长度
        kpg.initialize(1024);

        // 生成秘钥对
        KeyPair kp = kpg.generateKeyPair();

        // 生成PGP秘钥对 （公钥目录、私钥目录、公钥、私钥、id、passwd、isArmored）
        List<byte[]> keys = rkpg.generatorKeyPair(kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray());

        priKey = keys.get(0);
        pubKey = keys.get(1);
        System.out.println(Base64.getEncoder().encodeToString(priKey));
        String s = Base64.getEncoder().encodeToString(priKey);
        byte[] decode = Base64.getDecoder().decode(s);
        System.out.println(Arrays.equals(priKey, decode));
        System.out.println("prikey length: " + priKey.length);
        System.out.println("pubkey length: " + pubKey.length);

        encrypt();
        System.out.println("cypherOut length: " + cypherOut.toByteArray().length);

        decrypt();

        sign();
        System.out.println(isValid());

        cypherOut.close();
        decPlainTextOut.close();
        signOut.close();
    }

    public void encrypt() throws NoSuchProviderException, IOException, PGPException {

        Security.addProvider(new BouncyCastleProvider());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);
        // 压缩消息，将content写入bOut
        PGPUtilPer.writeFileToLiteralDataPer(comData.open(bOut),
                PGPLiteralData.BINARY, "abc".getBytes());

        comData.close();

        JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_128).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC");

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

        //System.out.println(pubKey.length);
        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(PgpHelper.getInstance().readPublicKey(pubKey)).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        cPk.addMethod(d);

        byte[] bytes = bOut.toByteArray();
        //会话秘钥使用公钥加密、会话秘钥加密压缩的消息、组合
        OutputStream cOut = cPk.open(cypherOut, bytes.length);
        //写出到加密文件
        cOut.write(bytes);
        //System.out.println(cypherOut.toByteArray().length); 177
        //System.out.println(cypherOut.size()); 177
        cOut.flush();
        //System.out.println(cypherOut.size()); 177
        cOut.close();
        //System.out.println(cypherOut.size()); 214
    }

    public void decrypt() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // 读取加密的内容
        ByteArrayInputStream in = new ByteArrayInputStream(cypherOut.toByteArray());
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
            sKey = PgpHelper.getInstance().findSecretKey(priKey, pbe.getKeyID(), passwd.toCharArray());
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
    }

    public void sign() throws Exception {
        byte[] sig = PgpHelper.getInstance().createSignature(content.getBytes(), priKey, passwd.toCharArray(), true);
        signOut.write(sig);
    }

    public boolean isValid() throws PGPException, GeneralSecurityException, IOException {
        return PgpHelper.getInstance().verifySignature(content.getBytes(), signOut.toByteArray(), pubKey);
    }

}
