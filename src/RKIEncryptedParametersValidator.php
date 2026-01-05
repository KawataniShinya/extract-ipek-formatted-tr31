<?php

class RKIEncryptedParametersValidator
{
    /**
     * 復号化されたTMK文字列を返却
     *
     * @param string $rsaPrivateKeyPem   RSA秘密鍵のPEM形式文字列。TMKの復号化に使用。
     * @param string $passphrase         暗号化秘密鍵のパスフレーズ。
     * @param string $encryptedTMK        RSA公開鍵で暗号化されたTMK文字列（Base64またはHEX形式）
     * @param string $format             エンコード形式。'base64' または 'hex'（デフォルト: 'base64'）
     *
     * @return string|null 復号化されたTMK（16進数文字列）。失敗時はnull。
     */
    public function getDecryptedTMK(string $rsaPrivateKeyPem, string $passphrase, string $encryptedTMK, string $format = 'base64'): ?string
    {
        try {
            // RSA秘密鍵を取得
            $privateKey = openssl_get_privatekey($rsaPrivateKeyPem, $passphrase);
            if ($privateKey === false) {
                throw new Exception('秘密鍵の取得に失敗しました。');
            }

            // エンコード形式に応じて処理
            $encryptedTmk = null;
            if ($format === 'hex') {
                // HEX形式の場合: HEX文字列をバイナリに変換
                $encryptedTmk = hex2bin($encryptedTMK);
                if ($encryptedTmk === false) {
                    throw new Exception('HEX文字列の変換に失敗しました。');
                }
            } else {
                // Base64形式の場合（デフォルト）: Base64デコード
                $encryptedTmk = base64_decode($encryptedTMK, true);
                if ($encryptedTmk === false) {
                    throw new Exception('Base64デコードに失敗しました。');
                }
            }

            // 暗号化されたTMKを復号化
            // まずSHA-256で復号化を試みる
            $decryptedTmk = $this->decryptWithOAEP($encryptedTmk, $privateKey, 'sha256', $rsaPrivateKeyPem, $passphrase);
            
            // SHA-256で失敗した場合、SHA-1で復号化を試みる（フォールバック）
            if ($decryptedTmk === false) {
                $decryptedTmk = $this->decryptWithOAEP($encryptedTmk, $privateKey, 'sha1', $rsaPrivateKeyPem, $passphrase);
                if ($decryptedTmk === false) {
                    throw new Exception('TMKの復号化に失敗しました（SHA-256とSHA-1の両方で失敗）。');
                }
            }

            $decryptedTmkHex = bin2hex($decryptedTmk);
            
            // HEX形式の場合、復号化結果に00008000プレフィックスが付いていない可能性がある
            // 00008000プレフィックスがない場合は追加する
            if ($format === 'hex' && !str_starts_with($decryptedTmkHex, '00008000')) {
                $decryptedTmkHex = '00008000' . $decryptedTmkHex;
            }

            return $decryptedTmkHex;
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
     * @param string $encryptedTMK        RSA公開鍵で暗号化されたTMK文字列（Base64またはHEX形式）
     * @param string $tr31String         TR31文字列 RKIで使用するデータの場合にはA0072から始まる(0072の部分はLength)
     * @param string $format             エンコード形式。'base64' または 'hex'（デフォルト: 'base64'）
     *
     * @return string|null IPEK文字列（後方互換性のため、IPEKのみ返却）
     */
    public function getIPEKWithValidation(string $rsaPrivateKeyPem, string $passphrase, string $encryptedTMK, string $tr31String, string $format = 'base64'): ?string
    {
        $tmkStr = $this->getDecryptedTMK($rsaPrivateKeyPem, $passphrase, $encryptedTMK, $format);
        if ($tmkStr === null) {
            return null;
        }

        $result = $this->getIPEKFromTMK($tmkStr, $tr31String);
        return $result !== null ? $result['ipek'] : null;
    }

    /**
     * OAEPパディングモードで復号化
     *
     * @param string $encryptedData 暗号化されたデータ
     * @param resource|OpenSSLAsymmetricKey $privateKey 秘密鍵リソース
     * @param string $hashAlgorithm ハッシュアルゴリズム（'sha1' または 'sha256'）
     * @param string $rsaPrivateKeyPem RSA秘密鍵のPEM形式文字列
     * @param string $passphrase 暗号化秘密鍵のパスフレーズ
     * @return string|false 復号化されたデータ、失敗時はfalse
     */
    private function decryptWithOAEP(string $encryptedData, $privateKey, string $hashAlgorithm, string $rsaPrivateKeyPem, string $passphrase): string|false
    {
        // openssl_pkey_decryptが利用可能な場合は使用
        if (function_exists('openssl_pkey_decrypt')) {
            $options = [];

            // SHA-256の場合は明示的に指定
            if ($hashAlgorithm === 'sha256') {
                $options['rsa_oaep_md'] = 'sha256';
                $options['rsa_mgf1_md'] = 'sha256';
            }
            // SHA-1の場合はデフォルトなので指定不要

            // openssl_pkey_decryptの第3引数はpadding、第4引数はoptions
            $decrypted = @openssl_pkey_decrypt($encryptedData, $privateKey, OPENSSL_PKCS1_OAEP_PADDING, $options);
            if ($decrypted !== false) {
                return $decrypted;
            }
        }

        // openssl_pkey_decryptが利用できない場合、または失敗した場合
        // openssl_private_decryptを使用（SHA-1のみ対応）
        if ($hashAlgorithm === 'sha1') {
            $decrypted = '';
            if (@openssl_private_decrypt($encryptedData, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
                return $decrypted;
            }
        }

        // SHA-256でopenssl_pkey_decryptが利用できない場合は、opensslコマンドを使用
        if ($hashAlgorithm === 'sha256') {
            return $this->decryptWithOpenSSLCommand($encryptedData, $rsaPrivateKeyPem, $passphrase);
        }

        return false;
    }

    /**
     * opensslコマンドを使用してSHA-256で復号化
     *
     * @param string $encryptedData 暗号化されたデータ（バイナリ）
     * @param string $rsaPrivateKeyPem RSA秘密鍵のPEM形式文字列
     * @param string $passphrase 暗号化秘密鍵のパスフレーズ
     * @return string|false 復号化されたデータ、失敗時はfalse
     */
    private function decryptWithOpenSSLCommand(string $encryptedData, string $rsaPrivateKeyPem, string $passphrase): string|false
    {
        // 一時ファイルを作成
        $tempKeyFile = tempnam(sys_get_temp_dir(), 'openssl_key_');
        $tempDataFile = tempnam(sys_get_temp_dir(), 'openssl_data_');

        if ($tempKeyFile === false || $tempDataFile === false) {
            return false;
        }

        try {
            // 秘密鍵をPEM形式で一時ファイルに書き込み
            if (file_put_contents($tempKeyFile, $rsaPrivateKeyPem) === false) {
                return false;
            }

            // 暗号化データを一時ファイルに書き込み
            if (file_put_contents($tempDataFile, $encryptedData) === false) {
                return false;
            }

            // opensslコマンドを実行
            $command = sprintf(
                'openssl pkeyutl -decrypt -inkey %s -passin pass:%s -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in %s 2>/dev/null',
                escapeshellarg($tempKeyFile),
                escapeshellarg($passphrase),
                escapeshellarg($tempDataFile)
            );

            $output = shell_exec($command);
            if ($output === null || $output === false) {
                return false;
            }

            return $output;
        } finally {
            // 一時ファイルを削除
            @unlink($tempKeyFile);
            @unlink($tempDataFile);
        }
    }

    /**
     * HEX STR -> Bytes
     */
    private function hexStringToBytes($str): false|string
    {
        return hex2bin($str);
    }
}
