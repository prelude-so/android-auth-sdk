package so.prelude.android.session.dpop

/**
 * Convert a DER-encoded ECDSA signature into JWS raw `r || s` form.
 *
 * DER layout: `SEQUENCE(0x30) len INTEGER(0x02) lenR r INTEGER(0x02) lenS s`.
 * DER INTEGERs are signed, so a leading `0x00` may pad an MSB-set
 * value. Each component is left-padded to [coordinateBytes] (32 for
 * P-256, 48 for P-384, …).
 */
internal fun derToRawEcdsa(der: ByteArray, coordinateBytes: Int): ByteArray {
    val cursor = DerCursor(der)
    if (cursor.readByte() != 0x30.toByte()) throw DPoPKeyStoreError.MalformedSignature()
    val sequenceLength = cursor.readDerLength()
    if (cursor.remaining() < sequenceLength) throw DPoPKeyStoreError.MalformedSignature()
    val r = cursor.readDerInteger(maxBytes = coordinateBytes)
    val s = cursor.readDerInteger(maxBytes = coordinateBytes)
    return leftPad(r, coordinateBytes) + leftPad(s, coordinateBytes)
}

private fun leftPad(bytes: ByteArray, length: Int): ByteArray {
    if (bytes.size >= length) return bytes
    return ByteArray(length).also { bytes.copyInto(it, destinationOffset = length - bytes.size) }
}

private class DerCursor(private val bytes: ByteArray) {
    private var index = 0
    fun remaining(): Int = bytes.size - index

    fun readByte(): Byte {
        if (index >= bytes.size) throw DPoPKeyStoreError.MalformedSignature()
        return bytes[index++]
    }

    fun readDerLength(): Int {
        if (index >= bytes.size) throw DPoPKeyStoreError.MalformedSignature()
        val first = bytes[index].toInt() and 0xFF
        index += 1
        if (first < 0x80) return first
        val numLengthBytes = first and 0x7F
        if (numLengthBytes !in 1..2 || bytes.size - index < numLengthBytes) {
            throw DPoPKeyStoreError.MalformedSignature()
        }
        var length = 0
        for (offset in 0 until numLengthBytes) {
            length = (length shl 8) or (bytes[index + offset].toInt() and 0xFF)
        }
        index += numLengthBytes
        return length
    }

    fun readDerInteger(maxBytes: Int): ByteArray {
        if (index >= bytes.size || bytes[index] != 0x02.toByte()) {
            throw DPoPKeyStoreError.MalformedSignature()
        }
        index += 1
        val length = readDerLength()
        if (bytes.size - index < length) throw DPoPKeyStoreError.MalformedSignature()
        var value = bytes.copyOfRange(index, index + length)
        index += length
        if (value.isNotEmpty() && value[0] == 0x00.toByte() && value.size > 1) {
            value = value.copyOfRange(1, value.size)
        }
        if (value.size > maxBytes) throw DPoPKeyStoreError.MalformedSignature()
        return value
    }
}
