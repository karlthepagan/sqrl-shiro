package net.grc.qrcode;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import java.awt.image.BufferedImage;

public class QRCode {
    public static BufferedImage createQRCode(byte[] byteData, int width, int height) {
        char[] data = new char[byteData.length];
        for(int i = data.length-1; i >= 0; i--) {
            data[i] = (char)(0xFF & byteData[i]); // flip signed to unsigned
        }

        QRCodeWriter writer = new QRCodeWriter();
        try {
            // default encoding is full-width bytes
            BitMatrix bitMatrix = writer.encode(new String(data), BarcodeFormat.QR_CODE, width, height);
            BufferedImage image = toBufferedImage(bitMatrix);
            return image;
        } catch( WriterException e ) {
            e.printStackTrace(); // TODO re-throw
        }
        return null;
    }

    public static BufferedImage createQRCode(String stringData, int width, int height) {
        QRCodeWriter writer = new QRCodeWriter();
        try {
            BitMatrix bitMatrix = writer.encode(stringData, BarcodeFormat.QR_CODE, width, height);
            BufferedImage image = toBufferedImage(bitMatrix);
            return image;
        } catch( WriterException e ) {
            e.printStackTrace(); // TODO re-throw
        }
        return null;
    }

    public static BufferedImage toBufferedImage(BitMatrix matrix) {
        int h = matrix.getHeight();
        int w = matrix.getWidth();
        BufferedImage image = new BufferedImage(w, h, 1);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                image.setRGB(x, y,
                        matrix.get(x, y) ? 0xff000000 : 0xffffffff);
            }
        }
        return image;
    }
}
