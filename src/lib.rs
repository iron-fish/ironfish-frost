/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]
#![warn(pointer_structural_match)]
#![warn(unreachable_pub)]
#![warn(unused_crate_dependencies)]
#![warn(unused_qualifications)]

mod serde;

mod checksum;

pub mod multienc;
pub mod participant;

#[cfg(feature = "dkg")]
pub mod dkg;

#[cfg(feature = "signing")]
pub mod nonces;
#[cfg(feature = "signing")]
pub mod signature_share;
#[cfg(feature = "signing")]
pub mod signing_commitment;

pub use reddsa::frost::redjubjub as frost;

#[cfg(feature = "std")]
mod io {
    pub(crate) use std::io::Error;
    pub(crate) use std::io::ErrorKind;
    pub(crate) use std::io::Read;
    pub(crate) use std::io::Result;
    pub(crate) use std::io::Write;
}

#[cfg(not(feature = "std"))]
#[macro_use]
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod io {
    use core::cmp;
    use core::mem;

    #[derive(Clone, Debug)]
    pub struct Error;

    impl Error {
        pub fn other<T>(_: T) -> Self {
            Self
        }
    }

    pub(crate) type Result<T> = core::result::Result<T, Error>;

    pub trait Read {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

        fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.read(buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf = &mut buf[n..];
                    }
                    Err(e) => return Err(e),
                }
            }
            if buf.is_empty() {
                Ok(())
            } else {
                Err(Error)
            }
        }

        fn by_ref(&mut self) -> &mut Self
        where
            Self: Sized,
        {
            self
        }
    }

    impl<R: Read> Read for &mut R {
        #[inline]
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            (*self).read(buf)
        }

        #[inline]
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
            (*self).read_exact(buf)
        }
    }

    impl Read for &[u8] {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let n = cmp::min(self.len(), buf.len());
            let (copy, remaining) = self.split_at(n);
            buf[..n].copy_from_slice(copy);
            *self = remaining;
            Ok(n)
        }
    }

    pub trait Write {
        fn write(&mut self, buf: &[u8]) -> Result<usize>;

        fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.write(buf) {
                    Ok(0) => return Err(Error),
                    Ok(n) => {
                        buf = &buf[n..];
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }
    }

    impl<W: Write> Write for &mut W {
        #[inline]
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            (*self).write(buf)
        }

        #[inline]
        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            (*self).write_all(buf)
        }
    }

    impl Write for &mut [u8] {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let n = cmp::min(self.len(), buf.len());
            let (copy, remaining) = mem::take(self).split_at_mut(n);
            copy.copy_from_slice(&buf[..n]);
            *self = remaining;
            Ok(n)
        }
    }
}

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
impl io::Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

