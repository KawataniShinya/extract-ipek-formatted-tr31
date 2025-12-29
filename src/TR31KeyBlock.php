<?php

class TR31KeyBlock
{
    private const MAC_LEN_A = 4; // バージョンAのMAC長（バイト）
    private const MAC_LEN_B = 8; // バージョンBのMAC長（バイト）
    private const HEADER_LEN = 16;
    private const TRANSFORMATION = 'DES-EDE3-CBC';

    private string $header;
    private string $encryptedKey;
    private string $mac;
    private ?string $plainKey = null;
    private ?string $plainKeyBlock = null; // 復号化された鍵ブロック全体（鍵長情報 + 鍵本体）
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
     * Returns the MAC length in bytes based on the version.
     *
     * @param string $version The TR-31 key block version ('A', 'B', or 'D').
     *
     * @return int The MAC length in bytes.
     */
    private function getMacLen(string $version): int
    {
        return $version === 'A' ? self::MAC_LEN_A : self::MAC_LEN_B;
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
        if ($keyBlock === '' || $kbpk === '' || !preg_match('/^[ABD]/', $keyBlock)) {
            return false;
        }

        $this->version = $keyBlock[0];
        $macLen = $this->getMacLen($this->version);
        $macLenHexChars = $macLen * 2; // バイト数を16進文字数に変換

        // 最小長の検証（ヘッダー + 最小鍵長 + MAC）
        if (strlen($keyBlock) < self::HEADER_LEN + 16 + $macLenHexChars) {
            return false;
        }

        $this->header = substr($keyBlock, 0, self::HEADER_LEN);
        $this->createKeySpec($kbpk);

        $keyString = substr($keyBlock, self::HEADER_LEN, strlen($keyBlock) - self::HEADER_LEN - $macLenHexChars);
        $this->encryptedKey = hex2bin($keyString);
        $this->mac = hex2bin(substr($keyBlock, strlen($keyBlock) - $macLenHexChars));

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
     *
     * @return bool|null True if MAC is valid, false if invalid, null if verification is not applicable (version D).
     */
    public function verifyMAC(): ?bool
    {
        // バージョンDはMAC検証をサポートしていない
        if ($this->version === 'D') {
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

        if ($this->version === 'A') {
            // バージョンA: XORバリアント（E/M）
            $kbpkBytes = $this->KBPK;

            $kbekBytes = $kbpkBytes ^ $this->repeat(chr(0x45), strlen($kbpkBytes)); // 'E' == 0x45
            $this->KBEK = $this->getTripleLengthKey($kbekBytes);

            $kbmkBytes = $kbpkBytes ^ $this->repeat(chr(0x4D), strlen($kbpkBytes)); // 'M' == 0x4D
            $this->KBMK = $this->getTripleLengthKey($kbmkBytes);
        } else {
            // バージョンB: TDES-CMAC KDF（固定入力8バイト×カウンタ2回 → 16バイト生成）
            // KBEK: tdesCmac(kbpk, [0x01, 0, 0, 0, 0, 0, 0, 0x80]) + tdesCmac(kbpk, [0x02, 0, 0, 0, 0, 0, 0, 0x80])
            $kbek1 = $this->tdesCmac($this->KBPK, pack('C*', 0x01, 0, 0, 0, 0, 0, 0, 0x80));
            $kbek2 = $this->tdesCmac($this->KBPK, pack('C*', 0x02, 0, 0, 0, 0, 0, 0, 0x80));
            $kbekBytes = $kbek1 . $kbek2;
            $this->KBEK = $this->getTripleLengthKey($kbekBytes);

            // KBMK: tdesCmac(kbpk, [0x01, 0, 0x01, 0, 0, 0, 0, 0x80]) + tdesCmac(kbpk, [0x02, 0, 0x01, 0, 0, 0, 0, 0x80])
            $kbmk1 = $this->tdesCmac($this->KBPK, pack('C*', 0x01, 0, 0x01, 0, 0, 0, 0, 0x80));
            $kbmk2 = $this->tdesCmac($this->KBPK, pack('C*', 0x02, 0, 0x01, 0, 0, 0, 0, 0x80));
            $kbmkBytes = $kbmk1 . $kbmk2;
            $this->KBMK = $this->getTripleLengthKey($kbmkBytes);
        }
    }

    /**
     * Decrypts the TR-31 key block using the KBEK.
     *
     * @return string|null The decrypted plain key or null if decryption fails.
     */
    private function decryptKeyBlockInternal(): ?string
    {
        try {
            // バージョンA: ヘッダーの最初の8バイトをIVとして使用
            // バージョンB: 認証子（MAC等）のバイト列（8バイト）をIVとして使用
            if ($this->version === 'A') {
                $iv = substr($this->header, 0, 8);
            } else {
                // バージョンBの場合、MACの8バイトをIVとして使用
                $iv = substr($this->mac, 0, 8);
            }

            $cipher = openssl_decrypt($this->encryptedKey, self::TRANSFORMATION, $this->KBEK, OPENSSL_NO_PADDING, $iv);
            if ($cipher === false) {
                return null;
            }

            // 復号化された鍵ブロック全体を保存（バージョンBのMAC計算で使用）
            $this->plainKeyBlock = $cipher;

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
            if ($this->version === 'B') {
                // バージョンB: header + plainKeyBlock をTDES-CMACで計算
                if ($this->plainKeyBlock === null) {
                    return null;
                }
                $data = $this->header . $this->plainKeyBlock;
                return $this->tdesCmac($this->KBMK, $data);
            } else {
                // バージョンA: header + encryptedKey をCBC暗号化し、最後の8バイトからMAC長分を取得
                $data = $this->header . $this->encryptedKey;
                // データを8バイトの倍数にパディング
                $paddedData = $this->padNoPadData($data);
                $iv = str_repeat(chr(0), 8);
                $cipher = openssl_encrypt($paddedData, self::TRANSFORMATION, $this->KBMK, OPENSSL_NO_PADDING, $iv);
                if ($cipher === false) {
                    return null;
                }

                $result = $cipher;
                $macLen = $this->getMacLen($this->version);

                // 最後の8バイトからMAC長分を取得
                return substr($result, -8, $macLen);
            }
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

    /**
     * Calculates TDES-CMAC (Cipher-based Message Authentication Code).
     *
     * @param string $key The triple-length DES key in binary format.
     * @param string $msg The message to authenticate.
     *
     * @return string The 8-byte CMAC result.
     */
    private function tdesCmac(string $key, string $msg): string
    {
        $blockSize = 8;

        // Step 1: Compute L = E_K(0)
        $zeroBlock = str_repeat(chr(0), $blockSize);
        $L = openssl_encrypt($zeroBlock, 'DES-EDE3-ECB', $key, OPENSSL_NO_PADDING);
        if ($L === false) {
            return '';
        }
        $L = substr($L, 0, $blockSize);

        // Step 2: Generate subkeys K1 and K2
        $K1 = $this->generateSubkey($L);
        $K2 = $this->generateSubkey($K1);

        // Step 3: Process message blocks
        $n = max(1, (int)ceil(strlen($msg) / $blockSize));
        $lastComplete = (strlen($msg) > 0 && strlen($msg) % $blockSize === 0);

        $X = str_repeat(chr(0), $blockSize);
        for ($i = 0; $i < $n - 1; $i++) {
            $m = substr($msg, $i * $blockSize, $blockSize);
            $X = openssl_encrypt($this->xor($X, $m), 'DES-EDE3-ECB', $key, OPENSSL_NO_PADDING);
            if ($X === false) {
                return '';
            }
            $X = substr($X, 0, $blockSize);
        }

        // Step 4: Process last block
        $last = '';
        if ($lastComplete) {
            $lastBlock = substr($msg, ($n - 1) * $blockSize, $blockSize);
            $last = $this->xor($lastBlock, $K1);
        } else {
            $buf = str_repeat(chr(0), $blockSize);
            if (strlen($msg) > 0) {
                $rem = strlen($msg) % $blockSize;
                $lastBlock = substr($msg, ($n - 1) * $blockSize, $rem);
                for ($j = 0; $j < $rem; $j++) {
                    $buf[$j] = $lastBlock[$j];
                }
                $buf[$rem] = chr(0x80);
            } else {
                $buf[0] = chr(0x80);
            }
            $last = $this->xor($buf, $K2);
        }

        // Step 5: Final encryption
        $result = openssl_encrypt($this->xor($X, $last), 'DES-EDE3-ECB', $key, OPENSSL_NO_PADDING);
        if ($result === false) {
            return '';
        }

        return substr($result, 0, $blockSize);
    }

    /**
     * Generates a subkey for CMAC.
     *
     * @param string $input The input block.
     *
     * @return string The generated subkey.
     */
    private function generateSubkey(string $input): string
    {
        $shifted = $this->leftShiftOneBit($input);
        $Rb = pack('C*', 0, 0, 0, 0, 0, 0, 0, 0x1B);

        // Check if MSB is set
        if ((ord($input[0]) & 0x80) !== 0) {
            return $this->xor($shifted, $Rb);
        }

        return $shifted;
    }

    /**
     * Performs a left shift by one bit.
     *
     * @param string $input The input block.
     *
     * @return string The shifted block.
     */
    private function leftShiftOneBit(string $input): string
    {
        $out = '';
        $carry = 0;
        for ($i = strlen($input) - 1; $i >= 0; $i--) {
            $b = ord($input[$i]) & 0xFF;
            $v = ($b << 1) | $carry;
            $out = chr($v & 0xFF) . $out;
            $carry = ($v >> 8) & 0x01;
        }

        return $out;
    }

    /**
     * Performs XOR operation on two byte arrays.
     *
     * @param string $a The first byte array.
     * @param string $b The second byte array.
     *
     * @return string The XOR result.
     */
    private function xor(string $a, string $b): string
    {
        $out = '';
        $len = strlen($a);
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i % strlen($b)]));
        }

        return $out;
    }

    /**
     * Pads data to a multiple of 8 bytes (block size) for NoPadding mode.
     *
     * @param string $data The data to pad.
     *
     * @return string The padded data.
     */
    private function padNoPadData(string $data): string
    {
        $blockSize = 8;
        $rem = strlen($data) % $blockSize;
        if ($rem === 0) {
            return $data;
        }

        return $data . str_repeat(chr(0), $blockSize - $rem);
    }
}
