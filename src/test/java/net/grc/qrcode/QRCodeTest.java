package net.grc.qrcode;

import com.google.zxing.WriterException;
import org.junit.Test;

public class QRCodeTest {
    @Test
    public void testBlobQRC() throws WriterException {
        byte[] data = new byte[256];
        for(int i = 0; i < data.length; i++) {
            data[i] = (byte)i;
        }

        QRCode.createQRCode(data,300,300);
    }
}
