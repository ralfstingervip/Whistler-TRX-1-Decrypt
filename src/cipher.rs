use crate::pe::KEY_LEN;

/// Keystream bytes the updater throws away after the key schedule.
pub const DROP: usize = 256;

pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// The updater indexes the key with `i & (len - 1)`. For its 64-byte key that
    /// is the same as `i % len`.
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (n, v) in s.iter_mut().enumerate() {
            *v = n as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let t = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[t as usize]
    }

    pub fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.next();
        }
    }

    /// One continuous keystream. The updater's 64-byte chunks do not re-key.
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            *b ^= self.next();
        }
    }
}

/// The RC4 key is the salt XOR the static key. The updater XORs a stack copy.
pub fn session_key(salt: &[u8], static_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    for (k, (a, b)) in key.iter_mut().zip(salt.iter().zip(static_key)) {
        *k = a ^ b;
    }
    key
}

/// Removes the updater's cipher. `payload` is salt then image.
pub fn decrypt(payload: &[u8], static_key: &[u8; KEY_LEN]) -> Vec<u8> {
    let (salt, image) = payload.split_at(KEY_LEN);
    let mut rc4 = Rc4::new(&session_key(salt, static_key));
    rc4.skip(DROP);
    let mut out = image.to_vec();
    rc4.apply(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystream(key: &[u8], skip: usize, n: usize) -> Vec<u8> {
        let mut rc4 = Rc4::new(key);
        rc4.skip(skip);
        let mut out = vec![0u8; n];
        rc4.apply(&mut out);
        out
    }

    #[test]
    fn rfc6229_forty_bit_key() {
        let key = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(
            keystream(&key, 0, 16),
            [
                0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a,
                0x11, 0x18, 0xa8
            ]
        );
        assert_eq!(
            keystream(&key, DROP, 16),
            [
                0x1c, 0xfc, 0xf6, 0x2b, 0x03, 0xed, 0xdb, 0x64, 0x1d, 0x77, 0xdf, 0xcf, 0x7f,
                0x8d, 0x8c, 0x93
            ]
        );
    }

    #[test]
    fn plaintext_vector() {
        let mut data = *b"Plaintext";
        Rc4::new(b"Key").apply(&mut data);
        assert_eq!(data, [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
    }

    #[test]
    fn drop_continues_the_same_stream() {
        let key = [0x5Au8; KEY_LEN];
        let full = keystream(&key, 0, DROP + 100);
        assert_eq!(keystream(&key, DROP, 100), full[DROP..]);
    }

    #[test]
    fn decrypt_is_salted_drop256() {
        let static_key = [0x33u8; KEY_LEN];
        let mut payload = vec![0x11u8; KEY_LEN];
        payload.extend_from_slice(&[0u8; 32]);
        // Salt 0x11 XOR key 0x33 = 0x22 in every key byte.
        assert_eq!(decrypt(&payload, &static_key), keystream(&[0x22; KEY_LEN], DROP, 32));
    }
}
