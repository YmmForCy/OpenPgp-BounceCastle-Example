package org.jdamico.bc.openpgp.bytearray_methodRef;

public class CertStore {
    byte[] pgpPriKey = null;
    byte[] pgpPubKey = null;

    public byte[] getPgpPriKey() {
        return pgpPriKey;
    }

    public void setPgpPriKey(byte[] pgpPriKey) {
        this.pgpPriKey = pgpPriKey;
    }

    public byte[] getPgpPubKey() {
        return pgpPubKey;
    }

    public void setPgpPubKey(byte[] pgpPubKey) {
        this.pgpPubKey = pgpPubKey;
    }
}
