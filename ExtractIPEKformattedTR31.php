<?php

require_once __DIR__ . '/src/TR31KeyBlock.php';
require_once __DIR__ . '/src/RKIEncryptedParametersValidator.php';

// コマンドライン引数を取得
if ($argc !== 5 && $argc !== 6) {
    echo "Usage: php ExtractIPEKformattedTR31.php <rsaPrivateKeyPemPath> <passphrase> <encryptedTMK> <tr31String> [format]\n";
    echo "  format: 'base64' (default) or 'hex'\n";
    exit(1);
}

$rsaPrivateKeyPemPath = $argv[1];
$passphrase = $argv[2];
$encryptedTMK = $argv[3];
$tr31String = $argv[4];
$format = $argc === 6 ? $argv[5] : 'base64';

// 形式の検証
if ($format !== 'base64' && $format !== 'hex') {
    echo "Error: format must be 'base64' or 'hex'.\n";
    exit(1);
}

// RSA秘密鍵のPEM形式文字列をファイルから取得
$rsaPrivateKeyPem = file_get_contents($rsaPrivateKeyPemPath);
if ($rsaPrivateKeyPem === false) {
    echo "Failed to read the private key PEM file.\n";
    exit(1);
}

$validator = new RKIEncryptedParametersValidator();

// TMKを復号化
$tmkStr = $validator->getDecryptedTMK(
    $rsaPrivateKeyPem,
    $passphrase,
    $encryptedTMK,
    $format
);

if ($tmkStr === null) {
    echo "TMK decryption failed.\n";
    exit(1);
}

echo "=== RESULT ===" . PHP_EOL;

// 復号化されたTMKを出力
echo "Decrypted TMK: $tmkStr (leading 00008000 indicates default string-to-key parameters)\n";

// IPEKを取得
// TR-31鍵ブロックのプレフィックス"R"を除く（Rで始まる場合のみ）
$tr31KeyBlock = (str_starts_with($tr31String, 'R')) ? substr($tr31String, 1) : $tr31String;
$result = $validator->getIPEKFromTMK(
    $tmkStr,
    $tr31KeyBlock
);

if ($result === null) {
    echo "IPEK extraction failed.\n";
    exit(1);
}

// IPEKを出力
echo "Valid IPEK: {$result['ipek']}\n";

// MAC検証結果を出力（検証可能バージョンのみ）
if ($result['macVerified'] !== null) {
    echo "MAC Verification: " . ($result['macVerified'] ? "PASSED" : "FAILED") . " (Version {$result['version']})\n";
} else {
    echo "MAC Verification: Not applicable (Version {$result['version']})\n";
}
