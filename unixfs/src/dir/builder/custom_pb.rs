//! Custom protobuf types which are used in encoding directorys.

use super::NamedLeaf;
use crate::pb::UnixFs;
use cid::Cid;
use quick_protobuf::{MessageWrite, Writer, WriterBackend};

/// Newtype which uses the &[Option<(NamedLeaf)>] as Vec<PBLink>.
pub(super) struct CustomFlatUnixFs<'a> {
    pub(super) links: &'a [Option<NamedLeaf>],
    pub(super) data: UnixFs<'a>,
}

impl<'a> CustomFlatUnixFs<'a> {
    fn mapped(&self) -> impl Iterator<Item = NamedLeafAsPBLink<'_>> + '_ {
        self.links
            .iter()
            .map(|triple| triple.as_ref().map(|l| NamedLeafAsPBLink(l)).unwrap())
    }
}

impl<'a> MessageWrite for CustomFlatUnixFs<'a> {
    fn get_size(&self) -> usize {
        use quick_protobuf::sizeofs::*;

        let links = self
            .mapped()
            .map(|link| 1 + sizeof_len(link.get_size()))
            .sum::<usize>();

        links + 1 + sizeof_len(self.data.get_size())
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> quick_protobuf::Result<()> {
        self.mapped()
            .try_for_each(|l| w.write_with_tag(18, |w| w.write_message(&l)))?;
        w.write_with_tag(10, |w| w.write_message(&self.data))
    }
}

/// Custom NamedLeaf as PBLink "adapter."
struct NamedLeafAsPBLink<'a>(&'a NamedLeaf);

impl<'a> MessageWrite for NamedLeafAsPBLink<'a> {
    fn get_size(&self) -> usize {
        use quick_protobuf::sizeofs::*;

        // ones are the tags
        1 + sizeof_len((self.0).0.len())
            + 1
            + sizeof_len(WriteableCid(&(self.0).1).get_size())
            //+ sizeof_len(self.1.link.to_bytes().len())
            + 1
            + sizeof_varint((self.0).2)
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> quick_protobuf::Result<()> {
        w.write_with_tag(10, |w| w.write_message(&WriteableCid(&(self.0).1)))?;
        //w.write_with_tag(10, |w| w.write_bytes(&self.1.link.to_bytes()))?;
        w.write_with_tag(18, |w| w.write_string((self.0).0.as_str()))?;
        w.write_with_tag(24, |w| w.write_uint64((self.0).2))?;
        Ok(())
    }
}

/// Newtype around Cid to allow embedding it as PBLink::Hash without allocating a vector.
struct WriteableCid<'a>(&'a Cid);

impl<'a> MessageWrite for WriteableCid<'a> {
    fn get_size(&self) -> usize {
        use cid::Version::*;
        use quick_protobuf::sizeofs::*;

        let hash_len = self.0.hash().to_bytes().len();

        match self.0.version() {
            V0 => hash_len,
            V1 => {
                let version_len = 1;
                let codec_len = sizeof_varint(u64::from(self.0.codec()));
                version_len + codec_len + hash_len
            }
        }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> quick_protobuf::Result<()> {
        use cid::Version::*;

        match self.0.version() {
            V0 => { /* cidv0 has only the _multi_hash */ }
            V1 => {
                // it is possible that CidV1 should not be linked to from a unixfs
                // directory; at least go-ipfs 0.5 `ipfs files` denies making a cbor link
                // but happily accepts and does refs over one.
                w.write_u8(1)?;
                w.write_varint(u64::from(self.0.codec()))?;
            }
        }

        self.0
            .hash()
            .to_bytes()
            .iter()
            // while this looks bad it cannot be measured; note we cannot use the
            // write_bytes because that is length prefixed bytes write
            .try_for_each(|b| w.write_u8(*b))
    }
}
