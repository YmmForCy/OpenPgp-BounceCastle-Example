package org.jdamico.bc.openpgp.tests;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.jdamico.bc.openpgp.utils.PgpHelper;
import org.jdamico.bc.openpgp.utils.RSAKeyPairGenerator;
import org.junit.Test;


public class TestBCOpenPGP {

    private boolean isArmored = false;
    private String id = "damico";
    private String passwd = "******";
    private boolean integrityCheck = true; // 完整性检查


    private String pubKeyFile = "/Users/chenyu/Desktop/PGP/pub.dat";
    private String privKeyFile = "/Users/chenyu/Desktop/PGP/secret.dat";

    private String plainTextFile = "/Users/chenyu/Desktop/PGP/plain-text.txt"; // create a text file to be encripted, before run the tests
    private String cipherTextFile = "/Users/chenyu/Desktop/PGP/cypher-text.txt"; // 加密文件
    private String decPlainTextFile = "/Users/chenyu/Desktop/PGP/dec-plain-text.txt"; // 解密后的文件
    private String signatureFile = "/Users/chenyu/Desktop/PGP/signature.txt"; //签名文件

    @Test
    public void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

        // 添加BouncyCastleProvider，是一种用于 Java 平台的开放源码的轻量级密码术包，它支持大量的密码术算法
        Security.addProvider(new BouncyCastleProvider());

        // 获取KeyPairGenerator，算法名称：RSA、Provider：BC = BouncyCastleProvider
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        // 初始化秘钥长度
        kpg.initialize(1024);

        // 生成秘钥对
        KeyPair kp = kpg.generateKeyPair();

        FileOutputStream out1 = new FileOutputStream(privKeyFile);
        FileOutputStream out2 = new FileOutputStream(pubKeyFile);

        // 导出秘钥对 （公钥目录、私钥目录、公钥、私钥、id、passwd、isArmored）
        rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);
    }

    @Test
    public void encrypt() throws NoSuchProviderException, IOException, PGPException {
        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
        PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();
    }

    @Test
    public void decrypt() throws Exception {

        FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }

    @Test
    public void signAndVerify() throws Exception {
        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileInputStream plainTextInput = new FileInputStream(plainTextFile);
        FileOutputStream signatureOut = new FileOutputStream(signatureFile);

        byte[] bIn = PgpHelper.getInstance().inputStreamToByteArray(plainTextInput);
        byte[] sig = PgpHelper.getInstance().createSignature(plainTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);
        PgpHelper.getInstance().verifySignature(plainTextFile, sig, pubKeyIs);
    }

}
