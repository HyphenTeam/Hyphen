#![forbid(unsafe_code)]

//! Canonical, bounded binary encoding for Hyphen protocol objects.
//!
//! The format is fixed-width little-endian for numeric primitives. Sequence,
//! map, string and byte lengths are unsigned 64-bit integers. Enum variants are
//! unsigned 32-bit integers. Struct and tuple fields are encoded in declaration
//! order without field names. Decoding rejects trailing bytes.

use std::fmt;

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::ser::{
    self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use serde::Serialize;
use thiserror::Error;

pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_COLLECTION_LEN: usize = 1_000_000;
pub const DEFAULT_MAX_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_collection_len: usize,
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_collection_len: DEFAULT_MAX_COLLECTION_LEN,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

impl Limits {
    pub const fn new(max_bytes: usize, max_collection_len: usize, max_depth: usize) -> Self {
        Self {
            max_bytes,
            max_collection_len,
            max_depth,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("codec input or output exceeds the configured byte limit")]
    SizeLimit,
    #[error("collection length exceeds the configured element limit")]
    CollectionLimit,
    #[error("object nesting exceeds the configured depth limit")]
    DepthLimit,
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("trailing bytes after the decoded object")]
    TrailingBytes,
    #[error("integer length does not fit this platform")]
    LengthOverflow,
    #[error("invalid boolean tag {0}")]
    InvalidBool(u8),
    #[error("invalid option tag {0}")]
    InvalidOption(u8),
    #[error("invalid Unicode scalar value {0:#x}")]
    InvalidChar(u32),
    #[error("invalid UTF-8 string")]
    InvalidUtf8,
    #[error("non-finite floating-point values are not canonical")]
    NonFiniteFloat,
    #[error("map keys are not in strictly increasing canonical byte order")]
    NonCanonicalMap,
    #[error("sequence or map serializer did not provide a length")]
    UnknownLength,
    #[error("unsupported serde operation: {0}")]
    Unsupported(&'static str),
    #[error("serialization error: {0}")]
    Message(String),
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Message(message.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Message(message.to_string())
    }
}

pub fn serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    serialize_with_limits(value, Limits::default())
}

pub fn serialize_with_limit<T: Serialize + ?Sized>(
    value: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, Error> {
    serialize_with_limits(
        value,
        Limits {
            max_bytes,
            ..Limits::default()
        },
    )
}

pub fn serialize_with_limits<T: Serialize + ?Sized>(
    value: &T,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut encoder = Encoder {
        output: Vec::new(),
        limits,
        depth: 0,
    };
    value.serialize(&mut encoder)?;
    Ok(encoder.output)
}

pub fn deserialize<T: DeserializeOwned>(input: &[u8]) -> Result<T, Error> {
    deserialize_with_limits(input, Limits::default())
}

pub fn deserialize_with_limit<T: DeserializeOwned>(
    input: &[u8],
    max_bytes: usize,
) -> Result<T, Error> {
    deserialize_with_limits(
        input,
        Limits {
            max_bytes,
            ..Limits::default()
        },
    )
}

pub fn deserialize_with_limits<T: DeserializeOwned>(
    input: &[u8],
    limits: Limits,
) -> Result<T, Error> {
    if input.len() > limits.max_bytes {
        return Err(Error::SizeLimit);
    }
    let mut decoder = Decoder {
        input,
        position: 0,
        limits,
        depth: 0,
    };
    let value = T::deserialize(&mut decoder)?;
    if decoder.position != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

struct Encoder {
    output: Vec<u8>,
    limits: Limits,
    depth: usize,
}

impl Encoder {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let new_len = self
            .output
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::SizeLimit)?;
        if new_len > self.limits.max_bytes {
            return Err(Error::SizeLimit);
        }
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    fn length(&mut self, length: usize) -> Result<(), Error> {
        if length > self.limits.max_collection_len {
            return Err(Error::CollectionLimit);
        }
        let length = u64::try_from(length).map_err(|_| Error::LengthOverflow)?;
        self.write(&length.to_le_bytes())
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth = self.depth.checked_add(1).ok_or(Error::DepthLimit)?;
        if self.depth > self.limits.max_depth {
            return Err(Error::DepthLimit);
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }
}

struct Compound<'a> {
    encoder: &'a mut Encoder,
    remaining: usize,
}

impl Compound<'_> {
    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        if self.remaining == 0 {
            return Err(Error::Message("too many compound elements".into()));
        }
        self.remaining -= 1;
        value.serialize(&mut *self.encoder)
    }

    fn finish(self) -> Result<(), Error> {
        if self.remaining != 0 {
            return Err(Error::Message("too few compound elements".into()));
        }
        self.encoder.leave();
        Ok(())
    }
}

struct CanonicalMap<'a> {
    encoder: &'a mut Encoder,
    remaining: usize,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    pending_key: Option<Vec<u8>>,
    buffered_bytes: usize,
}

impl CanonicalMap<'_> {
    fn child_limits(&self) -> Result<Limits, Error> {
        let mut limits = self.encoder.limits;
        limits.max_bytes = limits
            .max_bytes
            .checked_sub(self.encoder.output.len())
            .and_then(|remaining| remaining.checked_sub(self.buffered_bytes))
            .ok_or(Error::SizeLimit)?;
        limits.max_depth = limits
            .max_depth
            .checked_sub(self.encoder.depth)
            .ok_or(Error::DepthLimit)?;
        Ok(limits)
    }

    fn account_buffered(&mut self, length: usize) -> Result<(), Error> {
        self.buffered_bytes = self
            .buffered_bytes
            .checked_add(length)
            .ok_or(Error::SizeLimit)?;
        let available = self
            .encoder
            .limits
            .max_bytes
            .checked_sub(self.encoder.output.len())
            .ok_or(Error::SizeLimit)?;
        if self.buffered_bytes > available {
            return Err(Error::SizeLimit);
        }
        Ok(())
    }
}

impl<'a> ser::Serializer for &'a mut Encoder {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Compound<'a>;
    type SerializeTuple = Compound<'a>;
    type SerializeTupleStruct = Compound<'a>;
    type SerializeTupleVariant = Compound<'a>;
    type SerializeMap = CanonicalMap<'a>;
    type SerializeStruct = Compound<'a>;
    type SerializeStructVariant = Compound<'a>;

    fn serialize_bool(self, value: bool) -> Result<(), Error> {
        self.write(&[u8::from(value)])
    }
    fn serialize_i8(self, value: i8) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_i16(self, value: i16) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_i32(self, value: i32) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_i64(self, value: i64) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_i128(self, value: i128) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_u8(self, value: u8) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_u16(self, value: u16) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_u32(self, value: u32) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_u64(self, value: u64) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_u128(self, value: u128) -> Result<(), Error> {
        self.write(&value.to_le_bytes())
    }
    fn serialize_f32(self, value: f32) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(Error::NonFiniteFloat);
        }
        self.write(&value.to_bits().to_le_bytes())
    }
    fn serialize_f64(self, value: f64) -> Result<(), Error> {
        if !value.is_finite() {
            return Err(Error::NonFiniteFloat);
        }
        self.write(&value.to_bits().to_le_bytes())
    }
    fn serialize_char(self, value: char) -> Result<(), Error> {
        self.write(&(value as u32).to_le_bytes())
    }
    fn serialize_str(self, value: &str) -> Result<(), Error> {
        self.length(value.len())?;
        self.write(value.as_bytes())
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<(), Error> {
        self.length(value.len())?;
        self.write(value)
    }
    fn serialize_none(self) -> Result<(), Error> {
        self.write(&[0])
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Error> {
        self.write(&[1])?;
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant: u32,
        _v: &'static str,
    ) -> Result<(), Error> {
        self.serialize_u32(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        variant: u32,
        _v: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.serialize_u32(variant)?;
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        let len = len.ok_or(Error::UnknownLength)?;
        self.length(len)?;
        self.enter()?;
        Ok(Compound {
            encoder: self,
            remaining: len,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        self.enter()?;
        Ok(Compound {
            encoder: self,
            remaining: len,
        })
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        self.serialize_tuple(len)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant: u32,
        _v: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        self.serialize_u32(variant)?;
        self.serialize_tuple(len)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        let len = len.ok_or(Error::UnknownLength)?;
        self.length(len)?;
        self.enter()?;
        Ok(CanonicalMap {
            encoder: self,
            remaining: len,
            entries: Vec::with_capacity(len),
            pending_key: None,
            buffered_bytes: 0,
        })
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        self.serialize_tuple(len)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant: u32,
        _v: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        self.serialize_u32(variant)?;
        self.serialize_tuple(len)
    }
}

macro_rules! compound_impl {
    ($trait_name:ident, $method:ident) => {
        impl $trait_name for Compound<'_> {
            type Ok = ();
            type Error = Error;
            fn $method<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
                self.element(value)
            }
            fn end(self) -> Result<(), Error> {
                self.finish()
            }
        }
    };
}
compound_impl!(SerializeSeq, serialize_element);
compound_impl!(SerializeTuple, serialize_element);
compound_impl!(SerializeTupleStruct, serialize_field);
compound_impl!(SerializeTupleVariant, serialize_field);

impl SerializeStruct for Compound<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl SerializeStructVariant for Compound<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}

impl SerializeMap for CanonicalMap<'_> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        if self.remaining == 0 || self.pending_key.is_some() {
            return Err(Error::Message("invalid map key sequence".into()));
        }
        let key_bytes = serialize_with_limits(key, self.child_limits()?)?;
        self.account_buffered(key_bytes.len())?;
        self.pending_key = Some(key_bytes);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| Error::Message("map value has no key".into()))?;
        let value_bytes = serialize_with_limits(value, self.child_limits()?)?;
        self.account_buffered(value_bytes.len())?;
        self.entries.push((key, value_bytes));
        self.remaining -= 1;
        Ok(())
    }

    fn end(mut self) -> Result<(), Error> {
        if self.remaining != 0 || self.pending_key.is_some() {
            return Err(Error::Message("incomplete map".into()));
        }
        self.entries
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if self.entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::NonCanonicalMap);
        }
        for (key, value) in self.entries {
            self.encoder.write(&key)?;
            self.encoder.write(&value)?;
        }
        self.encoder.leave();
        Ok(())
    }
}

struct Decoder<'de> {
    input: &'de [u8],
    position: usize,
    limits: Limits,
    depth: usize,
}

impl<'de> Decoder<'de> {
    fn read(&mut self, length: usize) -> Result<&'de [u8], Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::UnexpectedEof)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(Error::UnexpectedEof)?;
        self.position = end;
        Ok(bytes)
    }

    fn collection_len(&mut self) -> Result<usize, Error> {
        let value = u64::from_le_bytes(self.read(8)?.try_into().expect("fixed length"));
        let length = usize::try_from(value).map_err(|_| Error::LengthOverflow)?;
        if length > self.limits.max_collection_len {
            return Err(Error::CollectionLimit);
        }
        Ok(length)
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth = self.depth.checked_add(1).ok_or(Error::DepthLimit)?;
        if self.depth > self.limits.max_depth {
            return Err(Error::DepthLimit);
        }
        Ok(())
    }
}

struct Sequence<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    remaining: usize,
}

impl<'de> SeqAccess<'de> for &mut Sequence<'_, 'de> {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.decoder).map(Some)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct CanonicalMapDecoder<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    remaining: usize,
    last_key: Option<Vec<u8>>,
    awaiting_value: bool,
}

impl<'de> MapAccess<'de> for &mut CanonicalMapDecoder<'_, 'de> {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if self.remaining == 0 {
            return Ok(None);
        }
        if self.awaiting_value {
            return Err(Error::Message("map key before value".into()));
        }
        let start = self.decoder.position;
        let key = seed.deserialize(&mut *self.decoder)?;
        let bytes = self.decoder.input[start..self.decoder.position].to_vec();
        if self.last_key.as_ref().is_some_and(|last| last >= &bytes) {
            return Err(Error::NonCanonicalMap);
        }
        self.last_key = Some(bytes);
        self.awaiting_value = true;
        Ok(Some(key))
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        if !self.awaiting_value {
            return Err(Error::Message("map value before key".into()));
        }
        let value = seed.deserialize(&mut *self.decoder)?;
        self.awaiting_value = false;
        self.remaining -= 1;
        Ok(value)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

macro_rules! deserialize_number {
    ($name:ident, $visit:ident, $type:ty, $size:expr) => {
        fn $name<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            let bytes: [u8; $size] = self.read($size)?.try_into().expect("fixed length");
            visitor.$visit(<$type>::from_le_bytes(bytes))
        }
    };
}

impl<'de> de::Deserializer<'de> for &mut Decoder<'de> {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::Unsupported("deserialize_any"))
    }
    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.read(1)?[0] {
            0 => visitor.visit_bool(false),
            1 => visitor.visit_bool(true),
            tag => Err(Error::InvalidBool(tag)),
        }
    }
    deserialize_number!(deserialize_i8, visit_i8, i8, 1);
    deserialize_number!(deserialize_i16, visit_i16, i16, 2);
    deserialize_number!(deserialize_i32, visit_i32, i32, 4);
    deserialize_number!(deserialize_i64, visit_i64, i64, 8);
    deserialize_number!(deserialize_i128, visit_i128, i128, 16);
    deserialize_number!(deserialize_u8, visit_u8, u8, 1);
    deserialize_number!(deserialize_u16, visit_u16, u16, 2);
    deserialize_number!(deserialize_u32, visit_u32, u32, 4);
    deserialize_number!(deserialize_u64, visit_u64, u64, 8);
    deserialize_number!(deserialize_u128, visit_u128, u128, 16);
    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let bits = u32::from_le_bytes(self.read(4)?.try_into().expect("fixed length"));
        let value = f32::from_bits(bits);
        if !value.is_finite() {
            return Err(Error::NonFiniteFloat);
        }
        visitor.visit_f32(value)
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let bits = u64::from_le_bytes(self.read(8)?.try_into().expect("fixed length"));
        let value = f64::from_bits(bits);
        if !value.is_finite() {
            return Err(Error::NonFiniteFloat);
        }
        visitor.visit_f64(value)
    }
    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let scalar = u32::from_le_bytes(self.read(4)?.try_into().expect("fixed length"));
        visitor.visit_char(char::from_u32(scalar).ok_or(Error::InvalidChar(scalar))?)
    }
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let len = self.collection_len()?;
        let value = std::str::from_utf8(self.read(len)?).map_err(|_| Error::InvalidUtf8)?;
        visitor.visit_borrowed_str(value)
    }
    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let len = self.collection_len()?;
        visitor.visit_borrowed_bytes(self.read(len)?)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_bytes(visitor)
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.read(1)?[0] {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(self),
            tag => Err(Error::InvalidOption(tag)),
        }
    }
    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let len = self.collection_len()?;
        self.visit_sequence(len, visitor)
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        self.visit_sequence(len, visitor)
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.visit_sequence(len, visitor)
    }
    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let len = self.collection_len()?;
        self.enter()?;
        let mut access = CanonicalMapDecoder {
            decoder: self,
            remaining: len,
            last_key: None,
            awaiting_value: false,
        };
        let result = visitor.visit_map(&mut access);
        if result.is_ok() && (access.remaining != 0 || access.awaiting_value) {
            self.depth -= 1;
            return Err(Error::Message("map decoder left entries unread".into()));
        }
        self.depth -= 1;
        result
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.visit_sequence(fields.len(), visitor)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let variant = u32::from_le_bytes(self.read(4)?.try_into().expect("fixed length"));
        visitor.visit_enum(VariantDecoder {
            decoder: self,
            variant,
        })
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::Unsupported("ignored_any"))
    }
}

impl<'de> Decoder<'de> {
    fn visit_sequence<V: Visitor<'de>>(
        &mut self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        if len > self.limits.max_collection_len {
            return Err(Error::CollectionLimit);
        }
        self.enter()?;
        let mut access = Sequence {
            decoder: self,
            remaining: len,
        };
        let result = visitor.visit_seq(&mut access);
        if result.is_ok() && access.remaining != 0 {
            self.depth -= 1;
            return Err(Error::Message(
                "sequence decoder left elements unread".into(),
            ));
        }
        self.depth -= 1;
        result
    }
}

struct VariantDecoder<'a, 'de> {
    decoder: &'a mut Decoder<'de>,
    variant: u32,
}
impl<'de> EnumAccess<'de> for VariantDecoder<'_, 'de> {
    type Error = Error;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        let value = seed.deserialize(self.variant.into_deserializer())?;
        Ok((value, self))
    }
}
impl<'de> VariantAccess<'de> for VariantDecoder<'_, 'de> {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self.decoder)
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_tuple(self.decoder, len, visitor)
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_tuple(self.decoder, fields.len(), visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::{BTreeMap, HashMap};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Fixture {
        tag: u8,
        count: u64,
        bytes: Vec<u8>,
        optional: Option<u32>,
    }

    #[test]
    fn fixed_format_vector_and_round_trip() {
        let fixture = Fixture {
            tag: 7,
            count: 0x0102,
            bytes: vec![3, 4],
            optional: Some(9),
        };
        let encoded = serialize(&fixture).unwrap();
        assert_eq!(
            encoded,
            vec![7, 2, 1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 4, 1, 9, 0, 0, 0]
        );
        assert_eq!(deserialize::<Fixture>(&encoded).unwrap(), fixture);
    }

    #[test]
    fn rejects_trailing_oversized_and_deep_inputs() {
        let mut encoded = serialize(&7u8).unwrap();
        encoded.push(0);
        assert_eq!(deserialize::<u8>(&encoded), Err(Error::TrailingBytes));
        assert_eq!(deserialize_with_limit::<u8>(&[7], 0), Err(Error::SizeLimit));
        let nested = vec![vec![vec![1u8]]];
        let limits = Limits::new(1024, 16, 2);
        assert_eq!(
            serialize_with_limits(&nested, limits),
            Err(Error::DepthLimit)
        );
    }

    #[test]
    fn canonical_map_round_trip() {
        let map = BTreeMap::from([(1u32, 2u64), (3, 4), (256, 5)]);
        let encoded = serialize(&map).unwrap();
        assert_eq!(deserialize::<BTreeMap<u32, u64>>(&encoded).unwrap(), map);

        let first = HashMap::from([(256u32, 5u64), (1, 2), (3, 4)]);
        let second = HashMap::from([(3u32, 4u64), (256, 5), (1, 2)]);
        assert_eq!(serialize(&first).unwrap(), serialize(&second).unwrap());
    }

    #[test]
    fn rejects_hostile_lengths_before_allocation() {
        let huge = u64::MAX.to_le_bytes();
        assert_eq!(
            deserialize_with_limits::<Vec<()>>(&huge, Limits::new(64, 16, 8)),
            Err(Error::CollectionLimit)
        );
        assert_eq!(
            deserialize_with_limits::<String>(&huge, Limits::new(64, 16, 8)),
            Err(Error::CollectionLimit)
        );
    }

    #[test]
    fn rejects_truncated_primitives_and_invalid_scalar_tags() {
        assert_eq!(deserialize::<u64>(&[1, 2, 3]), Err(Error::UnexpectedEof));
        assert_eq!(deserialize::<bool>(&[2]), Err(Error::InvalidBool(2)));
        assert_eq!(
            deserialize::<Option<u8>>(&[3]),
            Err(Error::InvalidOption(3))
        );
        assert_eq!(
            deserialize::<char>(&0xd800u32.to_le_bytes()),
            Err(Error::InvalidChar(0xd800))
        );

        let mut invalid_utf8 = 1u64.to_le_bytes().to_vec();
        invalid_utf8.push(0xff);
        assert_eq!(
            deserialize::<String>(&invalid_utf8),
            Err(Error::InvalidUtf8)
        );
    }

    #[test]
    fn rejects_non_finite_floats_and_noncanonical_maps() {
        assert_eq!(serialize(&f64::NAN), Err(Error::NonFiniteFloat));
        assert_eq!(
            deserialize::<f32>(&f32::INFINITY.to_bits().to_le_bytes()),
            Err(Error::NonFiniteFloat)
        );

        let mut duplicate_keys = 2u64.to_le_bytes().to_vec();
        duplicate_keys.extend_from_slice(&[1, 2, 1, 3]);
        assert_eq!(
            deserialize::<BTreeMap<u8, u8>>(&duplicate_keys),
            Err(Error::NonCanonicalMap)
        );
    }

    struct UnknownLength;

    impl Serialize for UnknownLength {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_seq(None)?.end()
        }
    }

    #[test]
    fn rejects_unknown_lengths_and_output_overflow() {
        assert_eq!(serialize(&UnknownLength), Err(Error::UnknownLength));
        assert_eq!(
            serialize_with_limit(&vec![0u8; 32], 16),
            Err(Error::SizeLimit)
        );
    }

    #[test]
    fn decoder_enforces_depth_and_never_panics_on_short_corpus() {
        let nested = serialize(&vec![vec![vec![1u8]]]).unwrap();
        assert_eq!(
            deserialize_with_limits::<Vec<Vec<Vec<u8>>>>(&nested, Limits::new(1024, 16, 2),),
            Err(Error::DepthLimit)
        );

        for length in 0..=64 {
            for fill in [0u8, 1, 0x7f, 0xff] {
                let input = vec![fill; length];
                let result = std::panic::catch_unwind(|| deserialize::<Fixture>(&input));
                assert!(
                    result.is_ok(),
                    "decoder panicked for length={length}, fill={fill}"
                );
            }
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    enum SmallEnum {
        Zero,
        One(u8),
    }

    #[test]
    fn derived_enum_rejects_unknown_variant() {
        let encoded = 7u32.to_le_bytes();
        assert!(deserialize::<SmallEnum>(&encoded).is_err());
    }
}
