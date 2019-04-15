package org.jdamico.bc.openpgp.bytearray;

import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

/**
 * Basic utility class
 */
public class PGPUtilPer extends PGPUtil {

    public static void writeFileToLiteralDataPer(
            OutputStream out,
            char fileType,
            byte[] content)
            throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, "plain-text.txt", content.length, new Date(System.currentTimeMillis()));
        pipeFileContentsPer(content, pOut);
    }

    private static void pipeFileContentsPer(byte[] content, OutputStream pOut) throws IOException {
        pOut.write(content);
        pOut.close();
    }
}
