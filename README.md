# ExtractIPEKformattedTR31

RSA暗号化されたTMK（Terminal Master Key）を復号化し、TR-31キーブロックからIPEK（Initial PIN Encryption Key）を抽出するツールです。

## 概要

このツールは以下の2つの主要な処理を実行します：

1. **TMKの復号化**: RSA公開鍵で暗号化され、Base64エンコードされたTMKを、RSA秘密鍵を使用して復号化します。
2. **IPEKの取得**: 復号化されたTMKからKBPK（Key Block Public Key）を抽出し、TR-31キーブロックを復号化してIPEKを取得します。
3. **MAC検証**（補足情報）: TR-31キーブロックのバージョンAの場合のみ、MAC検証を実行し、結果を補足情報として表示します。バージョンB/DではMAC検証は不要です。

## ディレクトリ構造

```
ExtractIPEKformattedTR31/
├── README.md
├── ExtractIPEKformattedTR31.php            # メインスクリプト
├── key/
│   ├── private_key.pem        # RSA秘密鍵（例）
│   └── public_key.pem         # RSA公開鍵（例）
└── src/
    ├── RKIEncryptedParametersValidator.php  # TMK復号化・IPEK抽出処理
    └── TR31KeyBlock.php                      # TR-31キーブロック復号化処理
```

## 処理概要

### 1. TMKの復号化

1. RSA秘密鍵ファイルを読み込み
2. Base64エンコードされた暗号化TMKをデコード
3. RSA秘密鍵とOAEPパディングを使用してTMKを復号化
4. 復号化されたTMKを16進数文字列として返却

**復号化されたTMKの形式**:
- 先頭の `00008000` はデフォルトのstring-to-keyパラメータを示します
- その後の部分がKBPK（Key Block Public Key）として使用されます

**opensslコマンドでの同等処理**:

TMKの復号化は、以下のopensslコマンドと同等の処理です：

```bash
echo "<encryptedTMKBase64>" | base64 -d | openssl pkeyutl -decrypt -inkey <private_key.pem> -passin pass:<passphrase> -pkeyopt rsa_padding_mode:oaep | xxd -p -c 256
```

例：
```bash
echo "LlgTff+W6B0f23pJr7ATABVM/anuv5bFfBFys1EFEhbtA0cserRHlrqmgeEnXmayPLgJ24TLyzMi1wituHx6Tl6in3HG8HJp64ZVaOe1pbKh44BnxtuD06qFGPSAGNE084DAPjQ2GnJMX0HUS2jwhs7YH44WZDOlcyUAywfCrEv6uKg5LKAuPTDTVgeKydVP+dD7Zq//lg/mUtjcvO+QgxfVBgS/Efs85kO56pbfvabXrlFxVF4rrt/8S6lLOzAU8cPpnlqBZ00ksA40+QCpoVWSFpFq9HjSqQgIYBgit+lEIhWAYsy+JIuDTitU/rhTVHOcFZu2ZMRXeLt1tWTdGQ==" | base64 -d | openssl pkeyutl -decrypt -inkey ../../private_key.pem -passin pass:password -pkeyopt rsa_padding_mode:oaep | xxd -p -c 256
```

このコマンドは以下の処理を実行します：
1. **Base64デコード**: `base64 -d` で暗号化データをバイナリに変換
2. **RSA復号化**: `openssl pkeyutl -decrypt` で復号化
   - `-inkey`: 秘密鍵ファイル
   - `-passin pass:password`: パスフレーズ
   - `-pkeyopt rsa_padding_mode:oaep`: OAEPパディング（PHPコードの `OPENSSL_PKCS1_OAEP_PADDING` に対応）
3. **16進数表示**: `xxd -p -c 256` で16進数文字列として出力（PHPコードの `bin2hex()` に対応）

### 2. IPEKの取得（KBPKからIPEKへの変換）

1. **KBPKの準備**: 復号化されたTMKから先頭の `00008000` を除いた部分をKBPKとして抽出
2. **KBEK/KBMKの生成**:
   - KBPKを3DESキー（24バイト）に変換
   - KBEK = KBPK XOR (0x45を繰り返し) を3DESキーに変換
   - KBMK = KBPK XOR (0x4Dを繰り返し) を3DESキーに変換
3. **TR-31キーブロックの解析**:
   - バージョン情報（先頭1文字: 'A', 'B', または 'D'）
   - ヘッダー（16バイト、先頭8バイトがIV）
   - 暗号化キー（ヘッダーとMACの間）
   - MAC（最後の4バイト）
4. **キーの復号化**:
   - KBEKとIVを使用して3DES-CBCモードで復号化
   - 復号結果の最初の2バイトからキー長を取得
   - 3バイト目以降からIPEKを抽出
5. **MAC検証**（バージョンAのみ）:
   - バージョンAの場合のみ、KBMKを使用してMACを計算
   - 計算したMACとキーブロック内のMACが一致するか検証
   - バージョンB/DではMAC検証は実行されません
6. **IPEKの返却**: IPEK（16進数文字列）を返却（MAC検証の結果に関係なく返却）

## 使用方法

### コマンド形式

```bash
php ExtractIPEKformattedTR31.php <rsaPrivateKeyPemPath> <passphrase> <encryptedTMKBase64> <tr31String>
```

### パラメータ

| パラメータ | 説明 | 例 |
|-----------|------|-----|
| `rsaPrivateKeyPemPath` | RSA秘密鍵のPEMファイルパス（相対パスまたは絶対パス） | `./key/private_key.pem` |
| `passphrase` | 秘密鍵のパスフレーズ | `password` |
| `encryptedTMKBase64` | RSA公開鍵で暗号化され、Base64エンコードされたTMK文字列 | `LlgTff+W6B0f...` |
| `tr31String` | TR-31キーブロック文字列（先頭に"R"が付く形式） | `RA0072B1TN00S0000...` |

## コマンド例

### 例1: バージョンAのTR-31キーブロック（MAC検証あり）

```bash
cd tools/ExtractIPEKformattedTR31
php ExtractIPEKformattedTR31.php "./key/private_key.pem" password "LlgTff+W6B0f23pJr7ATABVM/anuv5bFfBFys1EFEhbtA0cserRHlrqmgeEnXmayPLgJ24TLyzMi1wituHx6Tl6in3HG8HJp64ZVaOe1pbKh44BnxtuD06qFGPSAGNE084DAPjQ2GnJMX0HUS2jwhs7YH44WZDOlcyUAywfCrEv6uKg5LKAuPTDTVgeKydVP+dD7Zq//lg/mUtjcvO+QgxfVBgS/Efs85kO56pbfvabXrlFxVF4rrt/8S6lLOzAU8cPpnlqBZ00ksA40+QCpoVWSFpFq9HjSqQgIYBgit+lEIhWAYsy+JIuDTitU/rhTVHOcFZu2ZMRXeLt1tWTdGQ==" RA0072B1TN00S00006D2F59B60F3BCCAC8A869370685F00EBF3AD3865414CFAAC77412898
```

### 例2: バージョンBのTR-31キーブロック（MAC検証不要）

```bash
cd tools/ExtractIPEKformattedTR31
php ExtractIPEKformattedTR31.php "./key/private_key.pem" password "bhi7H2BHqIAa0hlPUiCqfpOozxkuvbh2CSOx1tCZV3j+TjQpaJf5kLa0EmoUcrqrZw2WFq2xIKmb0byYz0gr2bQCvTu6F7HQbPrVtvvKA7DSwDM7nglZCuypq9CJR+oV/yGu0U6BGXxiOS0+ekMJkbtgnoXn6QAhpBjvdMHWWAOMYf/z67VDedZShrvQDIlm7xEFiUykKysF76JBQMtfp6dQAa+TuaJQc9BIpgahq1pOAvqn5rzkduY/rnpwgYuktKaYg1vUZHyqxtNixM2In7ICdkzcUMrn0+MwNi3Qtg2Th1DVuTQAzD8ybaS/c4BMLwG7Tpusj6Wy7kLQ5UVuHQ==" RB0080B1TN00N000049E1F5AD028AC01B3DC89BE13E91198EA640BA387B1510B12AF31935
```

## 想定結果

### バージョンAの正常終了時の出力（MAC検証あり）

```
=== RESULT ===
Decrypted TMK: 0000800062c776ba57576dfdd60146ea1fdaae6e (leading 00008000 indicates default string-to-key parameters)
Valid IPEK: 8b931e0e0b1e5dcfdc2d31e0f9ed0281
MAC Verification: PASSED (Version A)
```

### バージョンBの正常終了時の出力（MAC検証不要）

```
=== RESULT ===
Decrypted TMK: 000080004a9b2feccd3ba7b0e34a194a7a9e8640 (leading 00008000 indicates default string-to-key parameters)
Valid IPEK: f1d5812771552c5a349db7ff4d90ea7d979a0cbe863c
MAC Verification: Not applicable (Version B)
```

### 出力の説明

- **Decrypted TMK**: 復号化されたTMK（16進数文字列）
  - 先頭の `00008000` はデフォルトのstring-to-keyパラメータを示します
  - その後の部分（例: `62c776ba57576dfdd60146ea1fdaae6e`）がKBPKとして使用されます
- **Valid IPEK**: 取得されたIPEK（16進数文字列）
  - MAC検証の結果に関係なく返却されます
- **MAC Verification**: MAC検証結果（補足情報）
  - **バージョンA**: `PASSED`（検証成功）または `FAILED`（検証失敗）
  - **バージョンB/D**: `Not applicable`（検証不要）

### エラー時の出力

#### 秘密鍵ファイルの読み込み失敗

```
Failed to read the private key PEM file.
```

#### TMK復号化失敗

```
TMK decryption failed.
```

#### IPEK取得失敗

```
=== RESULT ===
Decrypted TMK: 0000800062c776ba57576dfdd60146ea1fdaae6e (leading 00008000 indicates default string-to-key parameters)
IPEK extraction failed.
```

## 技術詳細

### 使用されている暗号化方式

- **RSA暗号化**: TMKの暗号化に使用（OAEPパディング）
- **3DES (Triple DES)**: TR-31キーブロックの復号化に使用（CBCモード）
- **TR-31標準**: ANSI X9.24-1に基づくキーブロック形式

### キー導出方式

- **KBEK (Key Block Encryption Key)**: KBPK XOR 0x45（'E'）から導出
- **KBMK (Key Block MAC Key)**: KBPK XOR 0x4D（'M'）から導出

## 注意事項

1. 秘密鍵ファイルとパスフレーズは適切に管理してください
2. TR-31キーブロック文字列の先頭の"R"は自動的に除去されます
3. 復号化されたTMKの先頭が `00008000` でない場合、IPEKの取得は失敗します
4. **MAC検証とIPEK取得は分離されています**
   - IPEK取得はMAC検証の結果に関係なく実行されます
   - MAC検証はバージョンAの場合のみ実行され、結果は補足情報として表示されます
   - バージョンB/DではMAC検証は実行されません
5. サポートされているTR-31キーブロックのバージョンは 'A', 'B', 'D' です
