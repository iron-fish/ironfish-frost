/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Internal module to help with serialization and deserialization.

use crate::io;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[inline]
#[cfg(feature = "dkg")]
pub(crate) fn write_u16<W: io::Write>(mut writer: W, value: u16) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

#[inline]
pub(crate) fn write_u32<W: io::Write>(mut writer: W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

#[inline]
pub(crate) fn write_usize<W: io::Write>(writer: W, value: usize) -> io::Result<()> {
    let value: u32 = value
        .try_into()
        .map_err(|_| io::Error::other("size too large to fit into 32 bits"))?;
    write_u32(writer, value)
}

#[inline]
#[cfg(feature = "dkg")]
pub(crate) fn write_variable_length<W, I, F>(mut writer: W, iter: I, f: F) -> io::Result<()>
where
    W: io::Write,
    I: IntoIterator,
    I::IntoIter: ExactSizeIterator,
    F: Fn(&mut W, I::Item) -> io::Result<()>,
{
    let iter = iter.into_iter();
    write_usize(&mut writer, iter.len())?;
    for item in iter {
        f(&mut writer, item)?;
    }
    Ok(())
}

#[inline]
#[cfg(feature = "dkg")]
pub(crate) fn write_variable_length_bytes<W: io::Write>(
    mut writer: W,
    bytes: &[u8],
) -> io::Result<()> {
    write_usize(&mut writer, bytes.len())?;
    writer.write_all(bytes)
}

#[inline]
#[cfg(feature = "dkg")]
pub(crate) fn read_u16<R: io::Read>(mut reader: R) -> io::Result<u16> {
    let mut value = [0u8; 2];
    reader.read_exact(&mut value)?;
    Ok(u16::from_le_bytes(value))
}

#[inline]
pub(crate) fn read_u32<R: io::Read>(mut reader: R) -> io::Result<u32> {
    let mut value = [0u8; 4];
    reader.read_exact(&mut value)?;
    Ok(u32::from_le_bytes(value))
}

#[inline]
pub(crate) fn read_usize<R: io::Read>(reader: R) -> io::Result<usize> {
    read_u32(reader).map(|value| value as usize)
}

#[inline]
#[cfg(feature = "dkg")]
pub(crate) fn read_variable_length<R, F, T>(mut reader: R, f: F) -> io::Result<Vec<T>>
where
    R: io::Read,
    F: Fn(&mut R) -> io::Result<T>,
{
    let len = read_usize(&mut reader)?;
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(f(&mut reader)?);
    }
    Ok(items)
}

#[inline]
#[cfg(feature = "dkg")]
pub(crate) fn read_variable_length_bytes<R: io::Read>(mut reader: R) -> io::Result<Vec<u8>> {
    let len = read_usize(&mut reader)?;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem;
    use rand::thread_rng;
    use rand::Rng;

    macro_rules! test_serde {
        ( $value:expr, $write:expr, $read:expr, size = $size:expr ) => {
            let value = $value;
            let mut serialized = [0u8; $size];

            let mut writer = &mut serialized[..];
            #[allow(clippy::redundant_closure_call)]
            $write(&mut writer, value.clone()).expect("serialization failed");
            assert_eq!(writer.len(), 0, "serialization did not fill output buffer");

            let mut reader = &serialized[..];
            #[allow(clippy::redundant_closure_call)]
            let deserialized = $read(&mut reader).expect("deserialization failed");
            assert_eq!(
                reader.len(),
                0,
                "deserialization did not consume output buffer"
            );

            assert_eq!(
                value, deserialized,
                "deserialization did not return the original value"
            );
        };
    }

    macro_rules! test_int {
        ( $type:ty, $write:expr, $read:expr, size = $size:expr ) => {
            test_serde!(<$type>::MIN, $write, $read, size = $size);
            test_serde!(<$type>::MAX, $write, $read, size = $size);

            let mut rng = thread_rng();
            for _ in 0..1000 {
                let value: $type = rng.gen();
                test_serde!(value, $write, $read, size = $size);
            }
        };
    }

    #[test]
    #[cfg(feature = "dkg")]
    fn write_read_u16() {
        test_int!(u16, write_u16, read_u16, size = 2);
    }

    #[test]
    fn write_read_u32() {
        test_int!(u32, write_u32, read_u32, size = 4);
    }

    #[test]
    fn write_read_usize() {
        test_serde!(usize::MIN, write_usize, read_usize, size = 4);
        test_serde!(u32::MAX as usize, write_usize, read_usize, size = 4);

        if mem::size_of::<usize>() > mem::size_of::<u32>() {
            write_usize(&mut [0u8; 4][..], (u32::MAX as usize) + 1)
                .expect_err("serialization should have failed due to overflow");
            write_usize(&mut [0u8; 4][..], usize::MAX)
                .expect_err("serialization should have failed due to overflow");
        }
    }

    #[test]
    #[cfg(feature = "dkg")]
    fn write_read_variable_length() {
        test_serde!(
            Vec::<u16>::new(),
            |writer, iter| write_variable_length(writer, iter, |writer, item| write_u16(
                writer, item
            )),
            |reader| read_variable_length(reader, |reader| read_u16(reader)),
            size = 4
        );

        test_serde!(
            vec![1, 2, 3, 4, 5, 6],
            |writer, iter| write_variable_length(writer, iter, |writer, item| write_u16(
                writer, item
            )),
            |reader| read_variable_length(reader, |reader| read_u16(reader)),
            size = 4 + 6 * 2
        );
    }

    #[test]
    #[cfg(feature = "dkg")]
    fn write_read_variable_length_bytes() {
        test_serde!(
            &b""[..],
            write_variable_length_bytes,
            read_variable_length_bytes,
            size = 4
        );
        test_serde!(
            &b"abcdef"[..],
            write_variable_length_bytes,
            read_variable_length_bytes,
            size = 4 + 6
        );
    }
}
