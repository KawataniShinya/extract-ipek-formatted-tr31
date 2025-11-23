<?php

require_once __DIR__ . '/src/TR31KeyBlock.php';
require_once __DIR__ . '/src/RKIEncryptedParametersValidator.php';

// コマンドライン引数を取得
if ($argc !== 5) {
    echo "Usage: php ExtractIPEKformattedTR31.php <rsaPrivateKeyPemPath> <passphrase> <encryptedTMKBase64> <tr31String>\n";
    exit(1);
}

$rsaPrivateKeyPemPath = $argv[1];
$passphrase = $argv[2];
$encryptedTMKBase64 = $argv[3];
$tr31String = $argv[4];

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
    $encryptedTMKBase64
);

if ($tmkStr === null) {
    echo "TMK decryption failed.\n";
    exit(1);
}

echo "=== RESULT ===" . PHP_EOL;

// 復号化されたTMKを出力
echo "Decrypted TMK: $tmkStr (leading 00008000 indicates default string-to-key parameters)\n";

// IPEKを取得
$result = $validator->getIPEKFromTMK(
    $tmkStr,
    substr($tr31String, 1) // TR-31鍵ブロックのプレフィックス"R"を除く
);

if ($result === null) {
    echo "IPEK extraction failed.\n";
    exit(1);
}

// IPEKを出力
echo "Valid IPEK: {$result['ipek']}\n";

// MAC検証結果を出力（バージョンAのみ）
if ($result['macVerified'] !== null) {
    echo "MAC Verification: " . ($result['macVerified'] ? "PASSED" : "FAILED") . " (Version {$result['version']})\n";
} else {
    echo "MAC Verification: Not applicable (Version {$result['version']})\n";
}
