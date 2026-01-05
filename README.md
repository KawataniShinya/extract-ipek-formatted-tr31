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
php ExtractIPEKformattedTR31.php <rsaPrivateKeyPemPath> <passphrase> <encryptedTMK> <tr31String> [format]
```

### パラメータ

| パラメータ | 説明 | 例 |
|-----------|------|-----|
| `rsaPrivateKeyPemPath` | RSA秘密鍵のPEMファイルパス（相対パスまたは絶対パス） | `./key/private_key.pem` |
| `passphrase` | 秘密鍵のパスフレーズ | `password` |
| `encryptedTMK` | RSA公開鍵で暗号化されたTMK文字列（Base64またはHEX形式） | `LlgTff+W6B0f...` (Base64) または `2e58137dff96e81d...` (HEX) |
| `tr31String` | TR-31キーブロック文字列（先頭に"R"が付く形式） | `RA0072B1TN00S0000...` |
| `format` | エンコード形式（オプショナル、デフォルト: `base64`） | `base64` または `hex` |

> **注意**: `format`パラメータを指定しない場合、デフォルトで`base64`として処理されます。HEX形式のTMKを使用する場合は、`format`に`hex`を指定してください。

## コマンド例

### 例1: 暗号化TMKのパディングモードがSHA-1でBase64エンコードされており、TR-31キーブロックがバージョンAの場合。

```bash
cd tools/ExtractIPEKformattedTR31
php ExtractIPEKformattedTR31.php "./key/private_key.pem" password "LlgTff+W6B0f23pJr7ATABVM/anuv5bFfBFys1EFEhbtA0cserRHlrqmgeEnXmayPLgJ24TLyzMi1wituHx6Tl6in3HG8HJp64ZVaOe1pbKh44BnxtuD06qFGPSAGNE084DAPjQ2GnJMX0HUS2jwhs7YH44WZDOlcyUAywfCrEv6uKg5LKAuPTDTVgeKydVP+dD7Zq//lg/mUtjcvO+QgxfVBgS/Efs85kO56pbfvabXrlFxVF4rrt/8S6lLOzAU8cPpnlqBZ00ksA40+QCpoVWSFpFq9HjSqQgIYBgit+lEIhWAYsy+JIuDTitU/rhTVHOcFZu2ZMRXeLt1tWTdGQ==" RA0072B1TN00S00006D2F59B60F3BCCAC8A869370685F00EBF3AD3865414CFAAC77412898
```

### 例2: 暗号化TMKのパディングモードがSHA-1でBase64エンコードされており、TR-31キーブロックがバージョンBの場合。

```bash
cd tools/ExtractIPEKformattedTR31
php ExtractIPEKformattedTR31.php "./key/private_key.pem" password "Y3a/YaG1IXfoKqFmQrf9XVOxDAYNygEEEmzShKCmMrgPjF7TC8f6z1d9ohTtXOF3xYRYPNxRGun2J9t9bbqedzO2xSu6JyaBjHE1kHXSByoRkj5bLAW6JXy+nj+xRUEVCL+efeNanGk0GfmZMNj/8lAZ+F8ITw5CL1GhRN+q+BfujdFROtM1UlWoqlXsKYTe+k8t/v4goRkLsXGdRC/x+kZgNZzR/UNWmrH9Fe61nuVkMSI6fk0JoMQd9yD4LQa+VoiPtC+P5hFfWn+SRWM6mVqF5xwX2XuHplUXXlBZrsj67ivWm18OcueDnpy5CsYj7PnVlO4ysZKZ8uv5mW6xJg==" RB0080B1TN00N00005D94BB551567F53FD0937E7183971B9353DDFB880708383DE53735D2A1D246EA
```

### 例3: 暗号化TMKのパディングモードがSHA-256でBase64エンコードされており、TR-31キーブロックがバージョンBの場合。(APCで生成した場合)

```bash
cd tools/ExtractIPEKformattedTR31
php ExtractIPEKformattedTR31.php "./key/private_key_apc.pem" password "0b63226064b65428d960b178a1e8aeb435d055aaf8681149dc78518de522284726dec2916185f06e3e608780ed1d8d8fba266dd6e1245ec173d988071818bda894a21c90971d81b882e41b95b3e167de78784be2ae11fede9ebf1940a3f56f3af652d3b8536bfbcfce90d05ac95769cfe17cd7a5dbfdc6b2e102ed5a36b57c89b6a4e6ae52ec136d9c710078a4c61d8f3baa09be96e72d0c5fac57e53fc03ff6d14fd435aa49021e51b5df40dbbaee70fc80e563d1101d010c8936620a8936717b8315d5a227d81a3a2f5d42c74e5a1348b746664282f5773fee621e43f9b9b47fc515904bb305aa94ffea80b01f148cc89e1328e46c352b00cb2d9d90bb607a" B0096B1TX00S0000FAADEE5B7F5BDEA7788A9A15F76FB3B42AB8E59F7DF8E4C2327ECE108C5D0068B0B3A3EDFA4AA909 hex
```

## 想定結果

### バージョンA,Bの正常終了時の出力（MAC検証あり）

```
=== RESULT ===
Decrypted TMK: 0000800062c776ba57576dfdd60146ea1fdaae6e (leading 00008000 indicates default string-to-key parameters)
Valid IPEK: 8b931e0e0b1e5dcfdc2d31e0f9ed0281
MAC Verification: PASSED (Version A)
```

### バージョンDの正常終了時の出力想定（MAC検証不要）

```
=== RESULT ===
...
MAC Verification: Not applicable (Version D)
```

### 出力の説明

- **Decrypted TMK**: 復号化されたTMK（16進数文字列）
  - 先頭の `00008000` はデフォルトのstring-to-keyパラメータを示します。(ただしAPC出力のTMKには付加されていません。)
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

### TR-31鍵ブロックのバージョンによる違い

TR-31鍵ブロックには複数のバージョン（'A', 'B', 'D'など）があり、バージョンによって以下のロジックが異なります：

#### バージョンA

- **MAC長**: 4バイト
- **IV（初期化ベクトル）**: ヘッダーの最初の8バイト
- **KBEK/KBMK導出方式**: XORバリアント方式
  - KBEK = KBPK XOR (0x45を繰り返し) を3DESキーに変換
  - KBMK = KBPK XOR (0x4Dを繰り返し) を3DESキーに変換
- **MAC検証方式**: CBC暗号化方式
  - データ: `header + encryptedKey`
  - 3DES-CBCで暗号化し、最後の8バイトから4バイト（MAC長）を取得

#### バージョンB

- **MAC長**: 8バイト
- **IV（初期化ベクトル）**: MACの8バイト
- **KBEK/KBMK導出方式**: TDES-CMAC KDF（Key Derivation Function）
  - 固定入力8バイト × カウンタ2回 → 16バイト生成
  - KBEK = `tdesCmac(KBPK, [0x01, 0, 0, 0, 0, 0, 0, 0x80]) + tdesCmac(KBPK, [0x02, 0, 0, 0, 0, 0, 0, 0x80])`
  - KBMK = `tdesCmac(KBPK, [0x01, 0, 0x01, 0, 0, 0, 0, 0x80]) + tdesCmac(KBPK, [0x02, 0, 0x01, 0, 0, 0, 0, 0x80])`
  - 各結果を連結して16バイトとし、3DESキーに変換
- **MAC検証方式**: TDES-CMAC方式
  - データ: `header + plainKeyBlock`（復号化された鍵ブロック全体）
  - TDES-CMACで計算し、8バイトのMACを生成

#### バージョンD

- MAC検証はサポートされていません（検証不要）

### キー導出方式（バージョン別）

#### バージョンA: XORバリアント方式

- **KBEK (Key Block Encryption Key)**: KBPK XOR 0x45（'E'）から導出
- **KBMK (Key Block MAC Key)**: KBPK XOR 0x4D（'M'）から導出

#### バージョンB: TDES-CMAC KDF方式

- **KBEK (Key Block Encryption Key)**: TDES-CMAC KDFを使用
  - カウンタ1: `tdesCmac(KBPK, [0x01, 0, 0, 0, 0, 0, 0, 0x80])` → 8バイト
  - カウンタ2: `tdesCmac(KBPK, [0x02, 0, 0, 0, 0, 0, 0, 0x80])` → 8バイト
  - 連結して16バイトとし、3DESキーに変換
- **KBMK (Key Block MAC Key)**: TDES-CMAC KDFを使用
  - カウンタ1: `tdesCmac(KBPK, [0x01, 0, 0x01, 0, 0, 0, 0, 0x80])` → 8バイト
  - カウンタ2: `tdesCmac(KBPK, [0x02, 0, 0x01, 0, 0, 0, 0, 0x80])` → 8バイト
  - 連結して16バイトとし、3DESキーに変換

### TDES-CMACについて

TDES-CMAC（Triple DES Cipher-based Message Authentication Code）は、バージョンBのKBEK/KBMK導出とMAC検証で使用される認証コード生成方式です。

1. **Lの計算**: ゼロブロック（8バイト）をTDES-ECBで暗号化
2. **サブキー生成**: LからK1、K1からK2を生成（1ビット左シフトと条件付きXOR）
3. **メッセージ処理**: メッセージを8バイトブロック単位で処理
4. **最終ブロック処理**: 最後のブロックにパディング（必要に応じて）とサブキーを適用
5. **MAC生成**: 最終的なXOR結果をTDES-ECBで暗号化してMACを生成

## 注意事項

1. 秘密鍵ファイルとパスフレーズは適切に管理してください
2. TR-31キーブロック文字列の先頭の"R"は自動的に除去されます
3. 復号化されたTMKの先頭が `00008000` でない場合、IPEKの取得は失敗します
4. **MAC検証とIPEK取得は分離されています**
   - IPEK取得はMAC検証の結果に関係なく実行されます
   - MAC検証はバージョンAの場合のみ実行され、結果は補足情報として表示されます
   - バージョンB/DではMAC検証は実行されません
5. サポートされているTR-31キーブロックのバージョンは 'A', 'B', 'D' です
