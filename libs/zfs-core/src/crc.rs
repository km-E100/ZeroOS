//! 磁盘结构校验用的 CRC-32（IEEE 802.3，反射位序，无表实现）。
//! 用于超级块副本、日志区域头与日志记录的一致性校验。

/// 计算 CRC-32（初值 0xFFFF_FFFF，最终异或 0xFFFF_FFFF）。
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // 标准测试向量（与 Python zlib.crc32 校验一致）
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"ZFS00   "), 0xCBA8_08D0);
    }

    #[test]
    fn detects_corruption() {
        let a = crc32(b"hello zero fs journal record");
        let mut data = b"hello zero fs journal record".to_vec();
        data[10] ^= 0x01;
        assert_ne!(a, crc32(&data));
    }
}
