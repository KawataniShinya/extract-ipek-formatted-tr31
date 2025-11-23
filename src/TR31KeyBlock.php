<?php

class TR31KeyBlock
{
    private const MAC_LEN = 4;
    private const HEADER_LEN = 16;
    private const ALGORITHM = 'DES-EDE3';
    private const TRANSFORMATION = 'DES-EDE3-CBC';

    private string $header;
    private string $encryptedKey;
    private string $mac;
    private ?string $plainKey = null;
    private string $version;

    private string $KBPK; // Key Block Public Key
    private string $KBEK; // Key Block Encryption Key
    private string $KBMK; // Key Block MAC Key

    /**
     * Returns the plain key after decryption.
     *
     * @return string|null The decrypted plain key or null if decryption failed.
     */
    public function getPlainKey(): ?string
    {
        return $this->plainKey;
    }

    /**
     * Decrypts the TR-31 key block and extracts IPEK.
     * MAC verification is performed only for version A.
     *
     * @param string $keyBlock The TR-31 key block in hexadecimal format.
     * @param string $kbpk     The Key Block Public Key in hexadecimal format.
     *
     * @return bool True if IPEK extraction is successful, otherwise false.
     */
    public function decryptKeyBlock(string $keyBlock, string $kbpk): bool
    {
        // Validate the key block format
        // TR-31 key block version can be 'A', 'B', or 'D' (first character indicates version)
        if ($keyBlock === '' || $kbpk === '' || strlen($keyBlock) < self::HEADER_LEN + self::MAC_LEN * 2 + 16 || !preg_match('/^[ABD]/', $keyBlock)) {
            return false;
        }

        $this->version = $keyBlock[0];
        $this->header = substr($keyBlock, 0, self::HEADER_LEN);
        $this->createKeySpec($kbpk);

        $keyString = substr($keyBlock, self::HEADER_LEN, strlen($keyBlock) - self::HEADER_LEN - self::MAC_LEN * 2);
        $this->encryptedKey = hex2bin($keyString);
        $this->mac = hex2bin(substr($keyBlock, strlen($keyBlock) - self::MAC_LEN * 2));

        // Decrypt the key block. If decryption fails, return false.
        $this->plainKey = $this->decryptKeyBlockInternal();
        if ($this->plainKey === null) {
            return false;
        }

        // IPEK extraction succeeded (MAC verification is separate)
        return true;
    }

    /**
     * Returns the version of the TR-31 key block.
     *
     * @return string The version character ('A', 'B', or 'D').
     */
    public function getVersion(): string
    {
        return $this->version;
    }

    /**
     * Verifies the MAC for the TR-31 key block.
     * Only version A supports MAC verification.
     *
     * @return bool|null True if MAC is valid, false if invalid, null if verification is not applicable (version B or D).
     */
    public function verifyMAC(): ?bool
    {
        // MAC verification is only supported for version A
        if ($this->version !== 'A') {
            return null;
        }

        $calculatedMAC = $this->calcMAC();
        if ($calculatedMAC === null) {
            return false;
        }

        return $this->mac === $calculatedMAC;
    }

    /**
     * Creates the Key Block Public Key (KBPK), Key Block Encryption Key (KBEK), and Key Block MAC Key (KBMK).
     *
     * @param string $kbpk The Key Block Public Key in hexadecimal format.
     *
     * @return void
     */
    private function createKeySpec(string $kbpk): void
    {
        $this->KBPK = $this->getTripleLengthKey(hex2bin($kbpk));
        $kbpkBytes = $this->KBPK;

        $kbekBytes = $kbpkBytes ^ $this->repeat(chr(0x45), strlen($kbpkBytes)); // 'E' == 0x45
        $this->KBEK = $this->getTripleLengthKey($kbekBytes);

        $kbmkBytes = $kbpkBytes ^ $this->repeat(chr(0x4D), strlen($kbpkBytes)); // 'M' == 0x4D
        $this->KBMK = $this->getTripleLengthKey($kbmkBytes);
    }

    /**
     * Decrypts the TR-31 key block using the KBEK.
     *
     * @return string|null The decrypted plain key or null if decryption fails.
     */
    private function decryptKeyBlockInternal(): ?string
    {
        try {
            $iv = substr($this->header, 0, 8);
            $cipher = openssl_decrypt($this->encryptedKey, self::TRANSFORMATION, $this->KBEK, OPENSSL_NO_PADDING, $iv);
            if ($cipher === false) {
                return null;
            }

            $result = $cipher;
            $keyBitsLength = hexdec(bin2hex(substr($result, 0, 2)));

            return substr($result, 2, (int)($keyBitsLength / 8));
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Calculates the MAC for the TR-31 key block.
     *
     * @return string|null The calculated MAC or null if an error occurs.
     */
    private function calcMAC(): ?string
    {
        try {
            $data = $this->header . $this->encryptedKey;
            $iv = str_repeat(chr(0), 8);
            $cipher = openssl_encrypt($data, self::TRANSFORMATION, $this->KBMK, OPENSSL_NO_PADDING, $iv);
            if ($cipher === false) {
                return null;
            }

            $result = $cipher;

            return substr($result, -8, self::MAC_LEN);
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Converts a key to a triple-length key.
     *
     * @param string $key The original key in binary format.
     *
     * @return string The triple-length key in binary format.
     */
    private function getTripleLengthKey(string $key): string
    {
        $tdesKey = substr($key, 0, 16) . substr($key, 0, 8);

        return $tdesKey;
    }

    /**
     * Repeats a string for a specified number of times.
     *
     * @param string $s The string to repeat.
     * @param int    $n The number of times to repeat the string.
     *
     * @return string The repeated string.
     */
    private function repeat(string $s, int $n): string
    {
        return str_repeat($s, $n);
    }
}
