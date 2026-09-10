package com.enigma.securechat.qr

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

object QrCodeGenerator {
    fun generate(
        content: String,
        sizePx: Int,
        foreground: Int,
        background: Int,
        centerLogo: Bitmap? = null,
    ): Bitmap {
        require(sizePx >= 128) { "QR size must be at least 128px" }
        val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H)
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        for (x in 0 until sizePx) {
            for (y in 0 until sizePx) {
                bitmap.setPixel(x, y, if (matrix[x, y]) foreground else background)
            }
        }
        if (centerLogo != null) {
            drawCenterLogo(bitmap, centerLogo, background)
        }
        return bitmap
    }

    private fun drawCenterLogo(target: Bitmap, logo: Bitmap, background: Int) {
        val canvas = Canvas(target)
        val side = target.width / 5
        val left = (target.width - side) / 2
        val top = (target.height - side) / 2
        val bounds = Rect(left, top, left + side, top + side)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        paint.color = background
        canvas.drawRect(bounds, paint)
        canvas.drawBitmap(logo, null, bounds, paint)
    }
}
