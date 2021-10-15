use crate::{
  hasher::Digest,
  Error,
};
use core::{
  convert::{
    TryFrom,
    TryInto,
  },
  fmt::Debug,
};

#[cfg(feature = "serde-codec")]
use serde_big_array::BigArray;

use bytecursor::ByteCursor;
use sp_std::vec::Vec;
use unsigned_varint::{
  decode,
  encode as varint_encode,
};

/// Trait that implements hashing.
///
/// It is usually implemented by a custom code table enum that derives the
/// [`Multihash` derive].
///
/// [`Multihash` derive]: crate::derive
pub trait MultihashDigest<const S: usize>:
  TryFrom<u64> + Into<u64> + Send + Sync + Unpin + Copy + Eq + Debug + 'static {
  /// Calculate the hash of some input data.
  ///
  /// # Example
  ///
  /// ```
  /// // `Code` implements `MultihashDigest`
  /// use sp_multihash::{
  ///   Code,
  ///   MultihashDigest,
  /// };
  ///
  /// let hash = Code::Sha3_256.digest(b"Hello world!");
  /// println!("{:02x?}", hash);
  /// ```
  fn digest(&self, input: &[u8]) -> Multihash<S>;

  /// Create a multihash from an existing [`Digest`].
  ///
  /// # Example
  ///
  /// ```
  /// use sp_multihash::{
  ///   Code,
  ///   MultihashDigest,
  ///   Sha3_256,
  ///   StatefulHasher,
  /// };
  ///
  /// let mut hasher = Sha3_256::default();
  /// hasher.update(b"Hello world!");
  /// let hash = Code::multihash_from_digest(&hasher.finalize());
  /// println!("{:02x?}", hash);
  /// ```
  #[allow(clippy::needless_lifetimes)]
  fn multihash_from_digest<'a, D, const DIGEST_SIZE: usize>(
    digest: &'a D,
  ) -> Multihash<S>
  where
    D: Digest<DIGEST_SIZE>,
    Self: From<&'a D>;
}

/// A Multihash instance that only supports the basic functionality and no
/// hashing.
///
/// With this Multihash implementation you can operate on Multihashes in a
/// generic way, but no hasher implementation is associated with the code.
///
/// # Example
///
/// ```
/// use sp_multihash::Multihash;
///
/// const Sha3_256: u64 = 0x16;
/// let digest_bytes = [
///   0x16, 0x20, 0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04, 0x09, 0x99,
///   0xaa, 0xc8, 0x9e, 0x76, 0x22, 0xf3, 0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72,
///   0xfd, 0x94, 0xa3, 0x1c, 0x3b, 0xfb, 0xf2, 0x4e, 0x39, 0x38,
/// ];
/// let mh = Multihash::from_bytes(&digest_bytes).unwrap();
/// assert_eq!(mh.code(), Sha3_256);
/// assert_eq!(mh.size(), 32);
/// assert_eq!(mh.digest(), &digest_bytes[2..]);
/// ```
#[cfg_attr(feature = "serde-codec", derive(serde::Deserialize))]
#[cfg_attr(feature = "serde-codec", derive(serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Multihash<const S: usize> {
  /// The code of the Multihash.
  code: u64,
  /// The actual size of the digest in bytes (not the allocated size).
  size: u8,
  /// The digest.
  #[cfg_attr(feature = "serde-codec", serde(with = "BigArray"))]
  digest: [u8; S],
}

impl<const S: usize> Default for Multihash<S> {
  fn default() -> Self { Self { code: 0, size: 0, digest: [0; S] } }
}

impl<const S: usize> Multihash<S> {
  /// Wraps the digest in a multihash.
  pub fn wrap(code: u64, input_digest: &[u8]) -> Result<Self, Error> {
    if input_digest.len() > S {
      return Err(Error::InvalidSize(input_digest.len() as _));
    }
    let size = input_digest.len();
    let mut digest = [0; S];
    digest[..size].copy_from_slice(input_digest);
    Ok(Self { code, size: size as u8, digest })
  }

  /// Returns the code of the multihash.
  pub fn code(&self) -> u64 { self.code }

  /// Returns the size of the digest.
  pub fn size(&self) -> u8 { self.size }

  /// Returns the digest.
  pub fn digest(&self) -> &[u8] { &self.digest[..self.size as usize] }

  /// Reads a multihash from a byte stream.
  pub fn read(r: &mut ByteCursor) -> Result<Self, Error>
  where Self: Sized {
    let (code, size, digest) = match read_multihash(r) {
      Ok((c, s, d)) => (c, s, d),
      Err(e) => return Err(e),
    };
    Ok(Self { code, size, digest })
  }

  /// Parses a multihash from a bytes.
  ///
  /// You need to make sure the passed in bytes have the correct length. The
  /// digest length needs to match the `size` value of the multihash.
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error>
  where Self: Sized {
    let mut r = ByteCursor::new(bytes.to_vec());
    let result = match Self::read(&mut r) {
      Ok(r) => r,
      Err(_) => return Err(Error::Varint(decode::Error::Overflow)),
    };
    // There were more bytes supplied than read
    if bytes.len() >= r.position() as usize + 1 {
      return Err(Error::InvalidSize(r.get_ref().len().try_into().expect(
        "Currently the maximum size is 255, therefore always fits into usize",
      )));
    }

    Ok(result)
  }

  /// Writes a multihash to a byte stream.
  pub fn write(&self, w: &mut ByteCursor) -> Result<(), Error> {
    write_multihash(w, self.code(), self.size(), self.digest())
  }

  /// Returns the bytes of a multihash.
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = ByteCursor::new(Vec::with_capacity(self.size().into()));
    self.write(&mut bytes).expect("writing to a vec should never fail");

    bytes.into_inner()
  }
}

// Don't hash the whole allocated space, but just the actual digest
#[allow(clippy::derive_hash_xor_eq)]
impl<const S: usize> core::hash::Hash for Multihash<S> {
  fn hash<T: core::hash::Hasher>(&self, state: &mut T) {
    self.code.hash(state);
    self.digest().hash(state);
  }
}

impl<const S: usize> From<Multihash<S>> for Vec<u8> {
  fn from(multihash: Multihash<S>) -> Self { multihash.to_bytes() }
}

#[cfg(feature = "scale-codec")]
impl<const S: usize> parity_scale_codec::Encode for Multihash<S> {
  fn encode_to<EncOut: parity_scale_codec::Output + ?Sized>(
    &self,
    dest: &mut EncOut,
  ) {
    self.code.encode_to(dest);
    self.size.encode_to(dest);
    dest.write(self.digest());
  }
}

#[cfg(feature = "scale-codec")]
impl<const S: usize> parity_scale_codec::EncodeLike for Multihash<S> {}

#[cfg(feature = "scale-codec")]
impl<const S: usize> parity_scale_codec::Decode for Multihash<S> {
  fn decode<DecIn: parity_scale_codec::Input>(
    input: &mut DecIn,
  ) -> Result<Self, parity_scale_codec::Error> {
    let mut mh = Multihash {
      code: parity_scale_codec::Decode::decode(input)?,
      size: parity_scale_codec::Decode::decode(input)?,
      digest: [0; S],
    };
    if mh.size as usize > S {
      Err(parity_scale_codec::Error::from("invalid size"))
    } else {
      input.read(&mut mh.digest[..mh.size as usize])?;
      Ok(mh)
    }
  }
}

/// Writes the multihash to a byte stream.
pub fn write_multihash(
  w: &mut ByteCursor,
  code: u64,
  size: u8,
  digest: &[u8],
) -> Result<(), Error> {
  let mut code_buf = varint_encode::u64_buffer();
  let code = varint_encode::u64(code, &mut code_buf);

  let mut size_buf = varint_encode::u8_buffer();
  let size = varint_encode::u8(size, &mut size_buf);

  match w.write_all(code) {
    Ok(_) => (),
    Err(_) => return Err(Error::Varint(decode::Error::Overflow)),
  };
  match w.write_all(size) {
    Ok(_) => (),
    Err(_) => return Err(Error::Varint(decode::Error::Overflow)),
  };
  match w.write_all(digest) {
    Ok(_) => (),
    Err(_) => return Err(Error::Varint(decode::Error::Overflow)),
  };
  w.set_position(0);
  Ok(())
}

/// Reads 64 bits from a byte array into a u64 starting at the current
/// Bytecursor position Adapted from unsigned-varint's read_u64 generated
/// function
pub fn read_u64(r: &mut ByteCursor) -> Result<u64, Error> {
  let mut b = varint_encode::u64_buffer();
  for i in 0..b.len() {
    let n = r.read(&mut b[i..(i + 1)]);
    if n == 0 {
      return Err(Error::Varint(decode::Error::Overflow));
    }
    if decode::is_last(b[i]) {
      match decode::u64(&b[..=i]) {
        Ok(d) => return Ok(d.0),
        Err(_) => return Err(Error::Varint(decode::Error::Overflow)),
      };
      // return Ok(decode::u64(&b[..=i]).unwrap().0);
    }
  }
  Err(Error::Varint(decode::Error::Overflow))
}

/// Reads a multihash from a byte stream that contains a full multihash (code,
/// size and the digest)
///
/// Returns the code, size and the digest. The size is the actual size and not
/// the maximum/allocated size of the digest.
///
/// Currently the maximum size for a digest is 255 bytes.
pub fn read_multihash<const S: usize>(
  r: &mut ByteCursor,
) -> Result<(u64, u8, [u8; S]), Error> {
  let code = match read_u64(r) {
    Ok(c) => c,
    Err(e) => return Err(e),
  };
  let size = match read_u64(r) {
    Ok(s) => s,
    Err(e) => return Err(e),
  };

  if size > S.try_into().unwrap() || size > u8::MAX as u64 {
    return Err(Error::InvalidSize(size));
  }

  let mut digest = [0; S];

  match r.read_exact(&mut digest[..size as usize]) {
    Ok(_) => (),
    Err(_) => return Err(Error::Varint(decode::Error::Overflow)),
  }
  Ok((code, size as u8, digest))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::multihash_impl::Code;

  #[test]
  fn roundtrip() {
    let hash = Code::Sha2_256.digest(b"hello world");
    let mut buf = ByteCursor::new([0u8; 35].to_vec());
    hash.write(&mut buf).unwrap();
    buf.set_position(0);
    let hash2 = Multihash::read(&mut buf).unwrap();
    assert_eq!(hash, hash2);
  }

  #[test]
  #[cfg(feature = "scale-codec")]
  fn test_scale() {
    use crate::{Hasher, Sha2_256};
    use parity_scale_codec::{
      Decode,
      Encode,
    };

    let mh1 = Multihash::<32>::wrap(
      Code::Sha2_256.into(),
      Sha2_256::digest(b"hello world").as_ref(),
    )
    .unwrap();
    // println!("mh1: code = {}, size = {}, digest = {:?}", mh1.code(), mh1.size(), mh1.digest());
    let mh1_bytes = mh1.encode();
    // println!("Multihash<32>: {}", hex::encode(&mh1_bytes));
    let mh2: Multihash<32> = Decode::decode(&mut &mh1_bytes[..]).unwrap();
    assert_eq!(mh1, mh2);

    let mh3: Multihash<64> = Code::Sha2_256.digest(b"hello world");
    // println!("mh3: code = {}, size = {}, digest = {:?}", mh3.code(), mh3.size(), mh3.digest());
    let mh3_bytes = mh3.encode();
    // println!("Multihash<64>: {}", hex::encode(&mh3_bytes));
    let mh4: Multihash<64> = Decode::decode(&mut &mh3_bytes[..]).unwrap();
    assert_eq!(mh3, mh4);

    assert_eq!(mh1_bytes, mh3_bytes);
  }

  #[test]
  #[cfg(feature = "serde-codec")]
  fn test_serde() {
    let mh = Multihash::<32>::default();
    let bytes = serde_json::to_string(&mh).unwrap();
    let mh2 = serde_json::from_str(&bytes).unwrap();
    assert_eq!(mh, mh2);
  }
}
