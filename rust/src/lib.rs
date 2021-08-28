use sha1::{Digest, Sha1};

const SHA1_BLOCK_SIZE_BYTES: usize = 64;
//const SHA1_RESULT_SIZE_BYTES: usize = 20;

fn prepare_key(key: &str) -> Vec<u8> {
    if key.len() > SHA1_BLOCK_SIZE_BYTES {
        let mut hasher = Sha1::default();
        hasher.update(key);
        let r = hasher.finalize();
        r.as_slice().to_vec()
    } else if key.len() == SHA1_BLOCK_SIZE_BYTES {
        key.as_bytes().to_vec()
    } else {
        let mut result = key.as_bytes().to_vec();
        while result.len() < SHA1_BLOCK_SIZE_BYTES {
            result.push(0);
        }
        result
    }
}

fn pad(processed_key: &[u8], padding: u8) -> Vec<u8> {
    let mut result = Vec::new();
    for b in processed_key {
        result.push(b ^ padding);
    }
    result
}

pub fn hmac_sha1(key: &str, message: &str) -> Vec<u8> {
    let key = prepare_key(key);
    let outer_key_pad = pad(&key, 0x5c);
    let inner_key_pad = pad(&key, 0x36);

    let mut hasher = Sha1::default();
    hasher.update(inner_key_pad);
    hasher.update(message);
    let inner_hashed = hasher.finalize();

    let mut hasher = Sha1::default();
    hasher.update(outer_key_pad);
    hasher.update(inner_hashed);
    let r = hasher.finalize();
    r.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha1() {
        let r = hmac_sha1("$3cr3tP4$$", "0");
        assert_eq!(&hex(&r), "5d1014482edb0afb42101d8d4b5ff9bb5340a683");
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;

        let mut buf = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(buf, "{:02x}", b).unwrap();
        }
        buf
    }
}
