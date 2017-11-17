/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::{io, error, result, str};
use std::io::Seek;
use std::io::SeekFrom;
use std::convert::From;
use std::fmt;

/// Custom error type specific to the [`SliceReader`](struct.SliceReader.html) struct.
#[derive(Debug)]
pub enum Error {
    /// Not enough bytes left in slice to read requested value.
    NotEnoughLeft(usize),
    /// I/O error happened while reading the slice.
    IoError(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotEnoughLeft(n) => write!(f, "NotEoughLeft({})", n),
            Error::IoError(ref e) => write!(f, "IoError({})", e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::NotEnoughLeft(_) => "not enough bytes left in slice",
            Error::IoError(_) => "I/O error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::IoError(ref err) => Some(err as &error::Error),
            _ => None,
        }
    }
}


/// A specialized [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html) type for
/// slice reading operations.
/// 
/// This typedef is used to shorten `std::result::Result<T, slread::Error>` to `slread::Result<T>`.
pub type Result<T> = result::Result<T, Error>;


/// Tool to decode protocols from a byte slice.
///
/// The slice can be consumed as different types of integers (`u16`, `u32`, ...) for binary protocols
/// or read line by line for text protocols.
///
/// All numbers read from the slice are assumed to be stored in big endian (network order).
pub struct SliceReader<'a> {
    slice: &'a [u8],
    pos: usize,
    size: usize,
}

impl<'a> Seek for SliceReader<'a> {
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => self.pos = n as usize,
            SeekFrom::End(n) => {
                let pos = self.size as i64 + n;
                if pos < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Seeking before byte 0."));
                }
                self.pos = pos as usize;
            },
            SeekFrom::Current(n) => {
                let pos = self.pos as i64 + n;
                if pos < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Seeking before byte 0."));
                }
                self.pos = pos as usize;
            }
        }
        Ok(self.pos as u64)
    }
}

impl<'a> SliceReader<'a> {
    /// Creates a new `SliceReader` from a slice of `u8`.
    #[inline]
    pub fn new(slice: &[u8]) -> SliceReader {
        SliceReader {
            slice: slice,
            pos: 0,
            size: slice.len(),
        }
    }

    /// Reads and consumes a `u8` from the slice.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.left() < 1 {
            Err(Error::NotEnoughLeft(0))
        } else {
            let result = self.slice[self.pos];
            self.pos += 1;
            Ok(result)
        }
    }

    /// Reads and consumes a `u16` from the slice.
    #[inline]
    pub fn read_u16(&mut self) -> Result<u16> {
        let left = self.left();
        if left < 2 {
            self.pos += 2;
            Err(Error::NotEnoughLeft(left))
        } else {
            let result = (self.slice[self.pos] as u16) << 8 |
                self.slice[self.pos + 1] as u16;
            self.pos += 2;
            Ok(result)
        }
    }

    /// Reads and consumes a `u24` from the slice.
    ///
    /// `u24` is actually a `u32` but only consumes 3 bytes from the slice.
    #[inline]
    pub fn read_u24(&mut self) -> Result<u32> {
        let left = self.left();
        if left < 3 {
            self.pos += 3;
            Err(Error::NotEnoughLeft(left))
        } else {
            let result = (self.slice[self.pos] as u32) << 16 |
                (self.slice[self.pos + 1] as u32) << 8 |
                self.slice[self.pos + 2] as u32;
            self.pos += 3;
            Ok(result)
        }
    }

    /// Reads and consumes a `u32` from the slice.
    ///
    /// # Example
    ///
    /// ```
    /// use t2plugin::slread::SliceReader;
    /// use t2plugin::nethdr::Packet;
    /// 
    /// ...
    /// let slr = SliceReader::new(packet.l7_header());
    /// // read the first 32 bits of the packet payload
    /// let id = try!(slr.read_u32());
    /// ```
    #[inline]
    pub fn read_u32(&mut self) -> Result<u32> {
        let left = self.left();
        if left < 4 {
            self.pos += 4;
            Err(Error::NotEnoughLeft(left))
        } else {
            let result = (self.slice[self.pos] as u32) << 24 |
                (self.slice[self.pos + 1] as u32) << 16 |
                (self.slice[self.pos + 2] as u32) << 8 |
                self.slice[self.pos + 3] as u32;
            self.pos += 4;
            Ok(result)
        }
    }

    /// Reads and consumes a `u48` from the slice.
    ///
    /// `u48` is actually a `u64` but only consumes 6 bytes from the slice.
    #[inline]
    pub fn read_u48(&mut self) -> Result<u64> {
        let left = self.left();
        if left < 6 {
            self.pos += 6;
            Err(Error::NotEnoughLeft(left))
        } else {
            let result = (self.slice[self.pos] as u64) << 40 |
                (self.slice[self.pos + 1] as u64) << 32 |
                (self.slice[self.pos + 2] as u64) << 24 |
                (self.slice[self.pos + 3] as u64) << 16 |
                (self.slice[self.pos + 4] as u64) << 8 |
                self.slice[self.pos + 5] as u64;
            self.pos += 6;
            Ok(result)
        }
    }

    /// Reads and consumes a `u64` from the slice.
    #[inline]
    pub fn read_u64(&mut self) -> Result<u64> {
        let left = self.left();
        if left < 8 {
            self.pos += 8;
            Err(Error::NotEnoughLeft(left))
        } else {
            let result = (self.slice[self.pos] as u64) << 56 |
                (self.slice[self.pos + 1] as u64) << 48 |
                (self.slice[self.pos + 2] as u64) << 40 |
                (self.slice[self.pos + 3] as u64) << 32 |
                (self.slice[self.pos + 4] as u64) << 24 |
                (self.slice[self.pos + 5] as u64) << 16 |
                (self.slice[self.pos + 6] as u64) << 8 |
                self.slice[self.pos + 7] as u64;
            self.pos += 8;
            Ok(result)
        }
    }

    /// Copies and consumes a sub-slice to a mutable buffer.
    ///
    /// # Example
    ///
    /// ```
    /// use t2plugin::slread::SliceReader;
    /// use t2plugin::nethdr::Packet;
    /// 
    /// ...
    /// let slr = SliceReader::new(packet.l7_header());
    /// let mut data = [0u8; 6];
    /// try!(slr.read_copy(&mut data));
    /// ```
    #[inline]
    pub fn read_copy(&mut self, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let left = self.left();
        if left < len {
            self.pos += len;
            Err(Error::NotEnoughLeft(left))
        } else {
            buf.copy_from_slice(&self.slice[self.pos .. self.pos + len]);
            self.pos += len;
            Ok(())
        }
    }

    /// Returns and consumes a sub-slice containing `count` bytes.
    ///
    /// The lifetime of the returned slice is the same as the one of the slice provided when
    /// creating this `SliceReader` with the [`new`](#method.new) method.
    #[inline]
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let left = self.left();
        if left < count {
            self.pos += count;
            Err(Error::NotEnoughLeft(left))
        } else {
            let slice = &self.slice[self.pos .. self.pos + count];
            self.pos += count;
            Ok(slice)
        }
    }

    /// Reads buffer until the first occurence of `byte`.
    ///
    /// The lifetime of the returned slice is the same as the one of the slice provided when
    /// creating this `SliceReader` with the [`new`](#method.new) method.
    #[inline]
    pub fn read_until(&mut self, byte: u8) -> Result<&'a [u8]> {
        if self.left() < 1 {
            return Err(Error::NotEnoughLeft(0));
        }
        // find next 'byte' position
        let start = self.pos;
        let end = if let Some(index) = self.slice[start ..].iter().position(|&e| e == byte) {
            start + index + 1
        } else {
            self.size
        };
        self.pos = end;
        Ok(&self.slice[start .. end])
    }

    /// Reads a line from the buffer.
    ///
    /// The line is returned as a slice of byte. This is necessary in order to also process lines
    /// which contain invalid UTF-8 characters.
    ///
    /// The lifetime of the returned line is the same as the one of the slice provided when
    /// creating this `SliceReader` with the [`new`](#method.new) method.
    ///
    /// # Example
    ///
    /// ```
    /// use t2plugin::slread::{SliceReader, TrimBytes};
    /// use t2plugin::nethdr::Packet;
    ///
    /// let slr = SliceReader::new(packet.l7_header());
    /// // read the packet payload line by line
    /// while let Ok(line) = slr.read_line() {
    ///     if line.starts_with(b"User-Agent: ") {
    ///         let ua = line[12 ..].trim();
    ///         // do something with HTTP user agent
    ///     }
    /// }
    /// ```
    #[inline]
    pub fn read_line(&mut self) -> Result<&'a [u8]> {
        self.read_until(b'\n')
    }

    /// Skips `count` bytes of the slice.
    #[inline]
    pub fn skip(&mut self, count: usize) {
        self.pos += count;
    }

    /// Seeks back `count` bytes in the slice.
    #[inline]
    pub fn rewind(&mut self, count: usize) -> Result<()> {
        if self.pos < count {
            Err(Error::IoError(io::Error::new(io::ErrorKind::InvalidInput, "Seeking before byte 0.")))
        } else {
            self.pos -= count;
            Ok(())
        }
    }

    /// Return the number of bytes left in the slice.
    #[inline]
    pub fn left(&self) -> usize {
        if self.pos >= self.size { 0 } else { self.size - self.pos }
    }

    /// Returns the current position in the buffer.
    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Shortens the slice by `count` bytes.
    ///
    /// On success, returns the slice new length.
    #[inline]
    pub fn cut_tail(&mut self, count: usize) -> Result<usize> {
        if self.size < count {
            Err(Error::NotEnoughLeft(self.size))
        } else {
            self.size -= count;
            Ok(self.size)
        }
    }
}


/// Trait to trim a byte slice `&[u8]` similarly to `str::trim()`.
pub trait TrimBytes {
    /// Returns a byte slice with leading and trailing whitespace removed.
    ///
    /// # Example
    ///
    /// ```
    /// use t2plugin::slread::{SliceReader, TrimBytes};
    /// use t2plugin::nethdr::Packet;
    ///
    /// let slr = SliceReader::new(packet.l7_header());
    /// // read the first line of the packet payload and trim it
    /// let line = try!(slr.read_line()).trim();
    /// ```
    fn trim(&self) -> &Self;
}

// helper functions for trim
fn is_not_whitespace(b: &u8) -> bool {
    fn is_whitespace(b: &u8) -> bool {
        *b == b' ' || *b == b'\t' || *b == b'\n' || *b == b'\r' || *b == 0x0b || *b == 0x0c
    }
    !is_whitespace(b)
}

impl TrimBytes for [u8] {
    #[inline]
    fn trim(&self) -> &Self {
        if let Some(start) = self.iter().position(is_not_whitespace) {
            if let Some(end) = self.iter().rposition(is_not_whitespace) {
                return &self[start .. end + 1]
            }
        }
        &[]
    }
}
