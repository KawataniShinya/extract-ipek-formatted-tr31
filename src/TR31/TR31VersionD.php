<?php

namespace ExtractIpekFormattedTR31\TR31;

use ExtractIpekFormattedTR31\TR31KeyBlock;

class TR31VersionD extends TR31KeyBlock
{
    public function getVersion(): string
    {
        return 'D';
    }

    protected function getMacLen(): int
    {
        return 16;
    }

    protected function isImplemented(): bool
    {
        return true;
    }

    protected function supportsMacVerification(): bool
    {
        return true;
    }

    protected function normalizeKbpkByVersion(string $kbpkBytes): string
    {
        $len = strlen($kbpkBytes);
        if ($len !== 16 && $len !== 24 && $len !== 32) {
            throw new \InvalidArgumentException('Version D requires AES-128/192/256 KBPK.');
        }

        return $kbpkBytes;
    }

    protected function getDecryptTransformation(): string
    {
        return match (strlen($this->KBEK)) {
            16 => 'aes-128-cbc',
            24 => 'aes-192-cbc',
            32 => 'aes-256-cbc',
            default => throw new \InvalidArgumentException('Unsupported AES key length.'),
        };
    }

    protected function deriveKeysByVersion(string $kbpk): array
    {
        $k2 = $this->generateSubkeys($kbpk)[1];

        $keyInfo = match (strlen($kbpk)) {
            16 => ['algo' => [0x00, 0x02], 'len' => [0x00, 0x80], 'calls' => [1]],
            24 => ['algo' => [0x00, 0x03], 'len' => [0x00, 0xC0], 'calls' => [1, 2]],
            32 => ['algo' => [0x00, 0x04], 'len' => [0x01, 0x00], 'calls' => [1, 2]],
            default => throw new \InvalidArgumentException('Unsupported AES key length.'),
        };

        $kbek = '';
        $kbmk = '';
        foreach ($keyInfo['calls'] as $counter) {
            $base = pack(
                'C*',
                $counter,
                0x00, 0x00, // usage: encryption
                0x00,
                $keyInfo['algo'][0], $keyInfo['algo'][1],
                $keyInfo['len'][0], $keyInfo['len'][1],
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            );
            $kbek .= $this->encryptAesEcb($kbpk, $this->xor($base, $k2));

            $base = pack(
                'C*',
                $counter,
                0x00, 0x01, // usage: mac
                0x00,
                $keyInfo['algo'][0], $keyInfo['algo'][1],
                $keyInfo['len'][0], $keyInfo['len'][1],
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            );
            $kbmk .= $this->encryptAesEcb($kbpk, $this->xor($base, $k2));
        }

        return [
            substr($kbek, 0, strlen($kbpk)),
            substr($kbmk, 0, strlen($kbpk)),
        ];
    }

    protected function getDecryptIvByVersion(string $header, string $mac): string
    {
        return substr($mac, 0, 16);
    }

    protected function calculateMacByVersion(): ?string
    {
        if ($this->plainKeyBlock === null) {
            return null;
        }

        return $this->aesCmac($this->KBMK, $this->getAuthenticatedDataPrefix() . $this->plainKeyBlock);
    }

    private function aesCmac(string $key, string $msg): string
    {
        $blockSize = 16;
        [$k1, $k2] = $this->generateSubkeys($key);

        $n = max(1, (int) ceil(strlen($msg) / $blockSize));
        $lastComplete = (strlen($msg) > 0 && strlen($msg) % $blockSize === 0);

        $x = str_repeat(chr(0), $blockSize);
        for ($i = 0; $i < $n - 1; $i++) {
            $m = substr($msg, $i * $blockSize, $blockSize);
            $x = $this->encryptAesEcb($key, $this->xor($x, $m));
        }

        if ($lastComplete) {
            $lastBlock = substr($msg, ($n - 1) * $blockSize, $blockSize);
            $last = $this->xor($lastBlock, $k1);
        } else {
            $remainder = strlen($msg) % $blockSize;
            $buf = str_repeat(chr(0), $blockSize);
            if ($remainder > 0) {
                $tail = substr($msg, ($n - 1) * $blockSize, $remainder);
                for ($j = 0; $j < $remainder; $j++) {
                    $buf[$j] = $tail[$j];
                }
            }
            $buf[$remainder] = chr(0x80);
            $last = $this->xor($buf, $k2);
        }

        return $this->encryptAesEcb($key, $this->xor($x, $last));
    }

    private function generateSubkeys(string $key): array
    {
        $zero = str_repeat(chr(0), 16);
        $l = $this->encryptAesEcb($key, $zero);

        $rb = str_repeat(chr(0), 15) . chr(0x87);

        $k1 = $this->leftShiftOneBit($l);
        if ((ord($l[0]) & 0x80) !== 0) {
            $k1 = $this->xor($k1, $rb);
        }

        $k2 = $this->leftShiftOneBit($k1);
        if ((ord($k1[0]) & 0x80) !== 0) {
            $k2 = $this->xor($k2, $rb);
        }

        return [$k1, $k2];
    }

    private function encryptAesEcb(string $key, string $data): string
    {
        $algo = match (strlen($key)) {
            16 => 'aes-128-ecb',
            24 => 'aes-192-ecb',
            32 => 'aes-256-ecb',
            default => throw new \InvalidArgumentException('Unsupported AES key length.'),
        };

        $out = openssl_encrypt($data, $algo, $key, OPENSSL_NO_PADDING);
        if ($out === false) {
            throw new \RuntimeException('AES ECB encryption failed.');
        }

        return $out;
    }

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

    private function xor(string $a, string $b): string
    {
        $len = strlen($a);
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i]));
        }

        return $out;
    }
}
