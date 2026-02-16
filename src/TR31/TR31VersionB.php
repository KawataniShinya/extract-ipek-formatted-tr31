<?php

namespace ExtractIpekFormattedTR31\TR31;

use ExtractIpekFormattedTR31\TR31KeyBlock;

class TR31VersionB extends TR31KeyBlock
{
    public function getVersion(): string
    {
        return 'B';
    }

    protected function getMacLen(): int
    {
        return 8;
    }

    protected function isImplemented(): bool
    {
        return true;
    }

    protected function supportsMacVerification(): bool
    {
        return true;
    }

    protected function deriveKeysByVersion(string $kbpk): array
    {
        $kbek1 = $this->tdesCmac($kbpk, pack('C*', 0x01, 0, 0, 0, 0, 0, 0, 0x80));
        $kbek2 = $this->tdesCmac($kbpk, pack('C*', 0x02, 0, 0, 0, 0, 0, 0, 0x80));
        $kbmk1 = $this->tdesCmac($kbpk, pack('C*', 0x01, 0, 0x01, 0, 0, 0, 0, 0x80));
        $kbmk2 = $this->tdesCmac($kbpk, pack('C*', 0x02, 0, 0x01, 0, 0, 0, 0, 0x80));

        return [
            substr($kbek1 . $kbek2, 0, 16) . substr($kbek1 . $kbek2, 0, 8),
            substr($kbmk1 . $kbmk2, 0, 16) . substr($kbmk1 . $kbmk2, 0, 8),
        ];
    }

    protected function getDecryptIvByVersion(string $header, string $mac): string
    {
        return substr($mac, 0, 8);
    }

    protected function calculateMacByVersion(): ?string
    {
        if ($this->plainKeyBlock === null) {
            return null;
        }

        return $this->tdesCmac($this->KBMK, $this->header . $this->plainKeyBlock);
    }

    protected function tdesCmac(string $key, string $msg): string
    {
        $blockSize = 8;

        $zeroBlock = str_repeat(chr(0), $blockSize);
        $L = openssl_encrypt($zeroBlock, 'DES-EDE3-ECB', $key, OPENSSL_NO_PADDING);
        if ($L === false) {
            return '';
        }
        $L = substr($L, 0, $blockSize);

        $K1 = $this->generateSubkey($L);
        $K2 = $this->generateSubkey($K1);

        $n = max(1, (int) ceil(strlen($msg) / $blockSize));
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

        $result = openssl_encrypt($this->xor($X, $last), 'DES-EDE3-ECB', $key, OPENSSL_NO_PADDING);
        if ($result === false) {
            return '';
        }

        return substr($result, 0, $blockSize);
    }

    private function generateSubkey(string $input): string
    {
        $shifted = $this->leftShiftOneBit($input);
        $Rb = pack('C*', 0, 0, 0, 0, 0, 0, 0, 0x1B);

        if ((ord($input[0]) & 0x80) !== 0) {
            return $this->xor($shifted, $Rb);
        }

        return $shifted;
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
        $out = '';
        $len = strlen($a);
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($a[$i]) ^ ord($b[$i % strlen($b)]));
        }

        return $out;
    }
}
