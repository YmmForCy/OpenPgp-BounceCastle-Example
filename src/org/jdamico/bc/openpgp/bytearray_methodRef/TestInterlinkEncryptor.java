package org.jdamico.bc.openpgp.bytearray_methodRef;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.List;

public class TestInterlinkEncryptor {
    public static void main(String[] args) throws Exception {
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
        List<byte[]> keys = rkpg.generatorKeyPair(kp.getPublic(), kp.getPrivate(), "id", "idpass".toCharArray());

        CertStore cs = new CertStore();
        cs.setPgpPriKey(keys.get(0));
        cs.setPgpPubKey(keys.get(1));
        System.out.println("prikey length: " + cs.getPgpPriKey().length);
        System.out.println("pubkey length: " + cs.getPgpPubKey().length);

        InterlinkEncryptor interlinkEncryptor = new InterlinkEncryptor();

        //加密
        byte[] enc_data = null;
        enc_data = interlinkEncryptor.encrypt("abc".getBytes(),enc_data, cs);
        System.out.println("cypherOut length: " + enc_data.length);
        //解密
        byte[] dec_data = null;
        dec_data = interlinkEncryptor.decrypt(enc_data, dec_data, cs);
        //签名
        byte[] signdata = null;
        signdata = interlinkEncryptor.sign("abc".getBytes(), signdata, cs);
        //解签
        boolean flag = false;
        flag = interlinkEncryptor.isValid("abc".getBytes(), signdata, cs);
    }

    /*@Test
    public void test() throws Exception {
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
        List<byte[]> keys = rkpg.generatorKeyPair(kp.getPublic(), kp.getPrivate(), "id", "idpass".toCharArray());

        CertStore cs = new CertStore();
        cs.setPgpPriKey(keys.get(0));
        cs.setPgpPubKey(keys.get(1));
        System.out.println("prikey length: " + cs.getPgpPriKey().length);
        System.out.println("pubkey length: " + cs.getPgpPubKey().length);

        encrypt(keys.get(1));
    }

    public void encrypt(byte[] pubKey) throws NoSuchProviderException, IOException, PGPException {
        ByteArrayOutputStream cypherOut = new ByteArrayOutputStream();

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

        JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(PgpHelper.getInstance().readPublicKey(pubKey)).setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

        cPk.addMethod(d);

        byte[] bytes = bOut.toByteArray();
        //会话秘钥使用公钥加密、会话秘钥加密压缩的消息、组合
        OutputStream cOut = cPk.open(cypherOut, bytes.length);
        //写出到加密文件
        cOut.write(bytes);
        System.out.println(cypherOut.toByteArray().length); //177

        cypherOut.flush();
        cOut.close();
        System.out.println(cypherOut.toByteArray().length); //214
    }*/
}
