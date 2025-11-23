<?php

class RKIEncryptedParametersValidator
{
    /**
     * 復号化されたTMK文字列を返却
     *
     * @param string $rsaPrivateKeyPem   RSA秘密鍵のPEM形式文字列。TMKの復号化に使用。
     * @param string $passphrase         暗号化秘密鍵のパスフレーズ。
     * @param string $encryptedTMKBase64 RSA公開鍵で暗号化され、Base64エンコードされたTMK文字列
     *
     * @return string|null 復号化されたTMK（16進数文字列）。失敗時はnull。
     */
    public function getDecryptedTMK(string $rsaPrivateKeyPem, string $passphrase, string $encryptedTMKBase64): ?string
    {
        try {
            // RSA秘密鍵を取得
            $privateKey = openssl_get_privatekey($rsaPrivateKeyPem, $passphrase);
            if ($privateKey === false) {
                throw new Exception('秘密鍵の取得に失敗しました。');
            }

            // 暗号化されたTMKをBase64デコードして復号化
            $encryptedTmk = base64_decode($encryptedTMKBase64);
            if ($encryptedTmk === false) {
                throw new Exception('Base64デコードに失敗しました。');
            }

            // 暗号化されたTMKを復号化
            $decryptedTmk = '';
            if (!openssl_private_decrypt($encryptedTmk, $decryptedTmk, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
                throw new Exception('TMKの復号化に失敗しました。');
            }

            return bin2hex($decryptedTmk);
        } catch (Exception $ex) {
            error_log($ex->getMessage());
            return null;
        }
    }

    /**
     * 復号化されたTMKからIPEK文字列を取得
     *
     * @param string $tmkStr     復号化されたTMK（16進数文字列）。先頭の00008000はデフォルトのstring-to-keyパラメータ。
     * @param string $tr31String TR31文字列 RKIで使用するデータの場合にはA0072から始まる(0072の部分はLength)
     *
     * @return array|null ['ipek' => string, 'macVerified' => bool|null, 'version' => string] 失敗時はnull。
     *                    macVerified: true=検証成功, false=検証失敗, null=検証不要（バージョンB/D）
     */
    public function getIPEKFromTMK(string $tmkStr, string $tr31String): ?array
    {
        try {
            // 文字列化TMKのValidation
            if (!str_starts_with($tmkStr, '00008000')) { // Default string-to-key parameters
                return null;
            }

            // Validation & Decrypt TR31 Key Block
            $kbpk = substr($tmkStr, 8);
            $kb = new TR31KeyBlock();

            // キーブロックをTMKで復号化（MAC検証は分離）
            if ($kb->decryptKeyBlock($tr31String, $kbpk)) {
                $ipek = bin2hex($kb->getPlainKey());
                $version = $kb->getVersion();
                $macVerified = $kb->verifyMAC();

                return [
                    'ipek' => $ipek,
                    'macVerified' => $macVerified,
                    'version' => $version,
                ];
            }
        } catch (Exception $ex) {
            error_log($ex->getMessage());
        }

        return null;
    }

    /**
     * 検証したIPEK文字列を返却（後方互換性のため残す）
     *
     * @param string $rsaPrivateKeyPem   RSA秘密鍵のPEM形式文字列。TMKの復号化に使用。
     * @param string $passphrase         暗号化秘密鍵のパスフレーズ。
     * @param string $encryptedTMKBase64 RSA公開鍵で暗号化され、Base64エンコードされたTMK文字列
     * @param string $tr31String         TR31文字列 RKIで使用するデータの場合にはA0072から始まる(0072の部分はLength)
     *
     * @return string|null IPEK文字列（後方互換性のため、IPEKのみ返却）
     */
    public function getIPEKWithValidation(string $rsaPrivateKeyPem, string $passphrase, string $encryptedTMKBase64, string $tr31String): ?string
    {
        $tmkStr = $this->getDecryptedTMK($rsaPrivateKeyPem, $passphrase, $encryptedTMKBase64);
        if ($tmkStr === null) {
            return null;
        }

        $result = $this->getIPEKFromTMK($tmkStr, $tr31String);
        return $result !== null ? $result['ipek'] : null;
    }

    /**
     * HEX STR -> Bytes
     */
    private function hexStringToBytes($str): false|string
    {
        return hex2bin($str);
    }
}
