use chacha20poly1305::{
    aead::{
        bytes::{BufMut, BytesMut},
        AeadInPlace, KeyInit,
    },
    Key, XChaCha8Poly1305, XNonce,
};
use nanorand::{BufferedRng, ChaCha8, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const XNONCE_LENGTH: usize = 24;
pub const TAG_LENGTH: usize = 16;

pub struct EncryptedMem<const N: usize> {
    ciphertext: ZeroizeBytesArray<N>,
    xnonce: XNonce,
}

impl<const N: usize> EncryptedMem<N> {
    pub fn new() -> Self {
        let mut nonce_buffer = [0u8; XNONCE_LENGTH];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut nonce_buffer);

        let outcome = EncryptedMem {
            ciphertext: ZeroizeBytesArray::with_additional_capacity(16),
            xnonce: *XNonce::from_slice(&nonce_buffer), //TODO check if this is zeroed out,
        };

        nonce_buffer[..].copy_from_slice(&[0u8; XNONCE_LENGTH]);

        outcome
    }

    pub fn new_with_added_capacity(capacity: usize) -> Self {
        let mut nonce_buffer = [0u8; XNONCE_LENGTH];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut nonce_buffer);

        let outcome = EncryptedMem {
            ciphertext: ZeroizeBytesArray::with_additional_capacity(capacity),
            xnonce: *XNonce::from_slice(&nonce_buffer), //TODO check if this is zeroed out,
        };

        nonce_buffer[..].copy_from_slice(&[0u8; XNONCE_LENGTH]);

        outcome
    }

    pub fn ciphertext(&self) -> &ZeroizeBytesArray<N> {
        &self.ciphertext
    }

    pub fn encrypt(&mut self, plaintext: &ZeroizeArray<N>, key: &Key) -> &mut Self {
        let cipher = XChaCha8Poly1305::new(&key);

        let mut buffer = BytesMut::with_capacity(N + TAG_LENGTH); // Note: buffer needs 16-bytes overhead for auth tag
        buffer.extend_from_slice(plaintext.expose_borrowed());
        // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
        cipher
            .encrypt_in_place(&self.xnonce, b"", &mut buffer) //TODO Check if tag is being added
            .unwrap();

        let mut ciphertext = ZeroizeBytesArray::with_additional_capacity(16);

        ciphertext.set(buffer);

        self.ciphertext = ciphertext;

        self
    }

    pub fn decrypt(&mut self, key: &Key) -> BytesMut {
        let cipher = XChaCha8Poly1305::new(&key);

        let mut buffer = BytesMut::with_capacity(N + TAG_LENGTH); // Note: buffer needs 16-bytes overhead for auth tag
        buffer.extend_from_slice(self.ciphertext.expose());

        // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
        cipher
            .decrypt_in_place(&self.xnonce, b"", &mut buffer)
            .unwrap();

        buffer
    }
}

pub struct ZeroizeArray<const N: usize>([u8; N]);

impl<const N: usize> ZeroizeArray<N> {
    pub fn new(value: [u8; N]) -> Self {
        ZeroizeArray(value)
    }

    pub fn zeroed() -> Self {
        ZeroizeArray([0u8; N])
    }

    pub fn fill_from_slice(&mut self, value: [u8; N]) -> &mut Self {
        self.0.copy_from_slice(&value);

        self
    }

    pub fn expose(&self) -> [u8; N] {
        self.0
    }

    pub fn expose_borrowed(&self) -> &[u8; N] {
        &self.0
    }

    pub fn clone(&self) -> ZeroizeArray<N> {
        Self(self.0)
    }

    pub fn chacha_key(&self) -> &Key {
        Key::from_slice(self.0.as_slice())
    }

    pub fn own(self) -> Self {
        self
    }

    pub fn insert(&mut self, index: usize, value: u8) -> &mut Self {
        self.0[index] = value;

        self
    }

    pub fn csprng() -> Self {
        let mut buffer = [0u8; N];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        let csprng = ZeroizeArray(buffer);

        buffer.copy_from_slice(&[0u8; N]);

        csprng
    }
}

impl<const N: usize> Zeroize for ZeroizeArray<N> {
    fn zeroize(&mut self) {
        self.0[..].copy_from_slice(&[0u8; N]);
    }
}

impl<const N: usize> Drop for ZeroizeArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeArray<N> {}

pub struct ZeroizeBytesArray<const N: usize>(BytesMut);

impl<const N: usize> ZeroizeBytesArray<N> {
    pub fn new() -> Self {
        ZeroizeBytesArray(BytesMut::with_capacity(N))
    }

    pub fn set(&mut self, value: BytesMut) -> &mut Self {
        self.0.put(&value[..]);

        self
    }

    pub fn with_additional_capacity(capacity: usize) -> Self {
        ZeroizeBytesArray(BytesMut::with_capacity(N + capacity))
    }

    pub fn expose(&self) -> &BytesMut {
        &self.0
    }

    pub fn clone(&self) -> ZeroizeBytesArray<N> {
        Self(self.0.clone())
    }

    pub fn chacha_key(&self) -> &Key {
        Key::from_slice(&self.0[..])
    }

    pub fn csprng() -> Self {
        let mut buffer = [0u8; N];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        let mut bytes_buffer = BytesMut::with_capacity(N);

        bytes_buffer.put(&buffer[..]);

        buffer.copy_from_slice(&[0u8; N]);

        ZeroizeBytesArray(bytes_buffer)
    }
}

impl<const N: usize> Zeroize for ZeroizeBytesArray<N> {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

impl<const N: usize> Drop for ZeroizeBytesArray<N> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<const N: usize> ZeroizeOnDrop for ZeroizeBytesArray<N> {}

pub struct ZeroizeBytes(BytesMut);

impl ZeroizeBytes {
    pub fn new() -> Self {
        ZeroizeBytes(BytesMut::new())
    }

    pub fn set(&mut self, value: BytesMut) -> &mut Self {
        self.0.put(&value[..]);

        self
    }

    pub fn new_with_capacity(capacity: usize) -> Self {
        ZeroizeBytes(BytesMut::with_capacity(capacity))
    }

    pub fn expose(&self) -> &BytesMut {
        &self.0
    }

    pub fn clone(&self) -> ZeroizeBytes {
        Self(self.0.clone())
    }

    pub fn chacha_key(&self) -> &Key {
        Key::from_slice(&self.0[..])
    }

    pub fn csprng<const BUFFER_SIZE: usize>() -> Self {
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        let mut bytes_buffer = BytesMut::with_capacity(BUFFER_SIZE);

        bytes_buffer.put(&buffer[..]);

        buffer.copy_from_slice(&[0u8; BUFFER_SIZE]);

        ZeroizeBytes(bytes_buffer)
    }
}

impl Zeroize for ZeroizeBytes {
    fn zeroize(&mut self) {
        self.0.clear()
    }
}

impl Drop for ZeroizeBytes {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for ZeroizeBytes {}
