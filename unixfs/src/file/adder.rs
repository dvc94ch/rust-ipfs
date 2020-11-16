use cid::Cid;

use crate::pb::{FlatUnixFs, PBLink, UnixFs, UnixFsType};
use alloc::borrow::Cow;
use core::fmt;
use multihash::MultihashDigest;
use quick_protobuf::{MessageWrite, Writer};

use sha2::{Digest, Sha256};

/// File tree builder. Implements [`core::default::Default`] which tracks the recent defaults.
///
/// Custom file tree builder can be created with [`FileAdder::builder()`] and configuring the
/// chunker and collector.
///
/// Current implementation maintains an internal buffer for the block creation and uses a
/// non-customizable hash function to produce Cid version 0 links. Currently does not support
/// inline links.
#[derive(Default)]
pub struct FileAdder {
    chunker: Chunker,
    collector: Collector,
    block_buffer: Vec<u8>,
    // all unflushed links as a flat vec; this is compacted as we grow and need to create a link
    // block for the last N blocks, as decided by the collector.
    // FIXME: this is a cause of likely "accidentally quadratic" behavior visible when adding a
    // large file and using a minimal chunk size. Could be that this must be moved to Collector to
    // help collector (or layout) to decide how this should be persisted.
    unflushed_links: Vec<Link>,
}

impl fmt::Debug for FileAdder {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "FileAdder {{ chunker: {:?}, block_buffer: {}/{}, unflushed_links: {} }}",
            self.chunker,
            self.block_buffer.len(),
            self.block_buffer.capacity(),
            LinkFormatter(&self.unflushed_links),
        )
    }
}

struct LinkFormatter<'a>(&'a [Link]);

impl fmt::Display for LinkFormatter<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.iter().peekable();

        write!(fmt, "[")?;

        let mut current = match iter.peek() {
            Some(Link { depth, .. }) => depth,
            None => return write!(fmt, "]"),
        };

        let mut count = 0;

        for Link {
            depth: next_depth, ..
        } in iter
        {
            if current == next_depth {
                count += 1;
            } else {
                write!(fmt, "{}: {}/", current, count)?;

                let steps_between = if current > next_depth {
                    current - next_depth
                } else {
                    next_depth - current
                };

                for _ in 0..steps_between - 1 {
                    write!(fmt, "0/")?;
                }
                count = 1;
                current = next_depth;
            }
        }

        write!(fmt, "{}: {}]", current, count)
    }
}

/// Represents an intermediate structure which will be serialized into link blocks as both PBLink
/// and UnixFs::blocksize. Also holds `depth`, which helps with compaction of the link blocks.
struct Link {
    /// Depth of this link. Zero is leaf, and anything above it is, at least for
    /// [`BalancedCollector`], the compacted link blocks.
    depth: usize,
    /// The link target
    target: Cid,
    /// Total size is dag-pb specific part of the link: aggregated size of the linked subtree.
    total_size: u64,
    /// File size is the unixfs specific blocksize for this link. In UnixFs link blocks, there is a
    /// UnixFs::blocksizes item for each link.
    file_size: u64,
}

impl fmt::Debug for Link {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Link")
            .field("depth", &self.depth)
            .field("target", &format_args!("{}", self.target))
            .field("total_size", &self.total_size)
            .field("file_size", &self.file_size)
            .finish()
    }
}

/// Convenience type to facilitate configuring [`FileAdder`]s.
#[derive(Default)]
pub struct FileAdderBuilder {
    chunker: Chunker,
    collector: Collector,
}

impl FileAdderBuilder {
    /// Configures the builder to use the given chunker.
    pub fn with_chunker(self, chunker: Chunker) -> Self {
        FileAdderBuilder { chunker, ..self }
    }

    /// Configures the builder to use the given collector or layout.
    pub fn with_collector(self, collector: impl Into<Collector>) -> Self {
        FileAdderBuilder {
            collector: collector.into(),
            ..self
        }
    }

    /// Returns a new FileAdder
    pub fn build(self) -> FileAdder {
        let FileAdderBuilder { chunker, collector } = self;

        FileAdder {
            chunker,
            collector,
            ..Default::default()
        }
    }
}

impl FileAdder {
    /// Returns a [`FileAdderBuilder`] for creating a non-default FileAdder.
    pub fn builder() -> FileAdderBuilder {
        FileAdderBuilder::default()
    }

    /// Returns the likely amount of buffering the file adding will work with best.
    ///
    /// When using the size based chunker and input larger than or equal to the hint is `push()`'ed
    /// to the chunker, the internal buffer will not be used.
    pub fn size_hint(&self) -> usize {
        self.chunker.size_hint()
    }

    /// Called to push new file bytes into the tree builder.
    ///
    /// Returns the newly created blocks (at most 2) and their respective Cids, and the amount of
    /// `input` consumed.
    pub fn push(&mut self, input: &[u8]) -> (impl Iterator<Item = (Cid, Vec<u8>)>, usize) {
        let (accepted, ready) = self.chunker.accept(input, &self.block_buffer);

        if self.block_buffer.is_empty() && ready {
            // save single copy as the caller is giving us whole chunks.
            //
            // TODO: though, this path does make one question if there is any point in keeping
            // block_buffer and chunker here; perhaps FileAdder should only handle pre-chunked
            // blocks and user takes care of chunking (and buffering)?
            //
            // cat file | my_awesome_chunker | my_brilliant_collector
            let leaf = Self::flush_buffered_leaf(accepted, &mut self.unflushed_links, false);
            assert!(leaf.is_some(), "chunk completed, must produce a new block");
            self.block_buffer.clear();
            let links = self.flush_buffered_links(false);
            (leaf.into_iter().chain(links.into_iter()), accepted.len())
        } else {
            // slower path as we manage the buffer.

            if self.block_buffer.capacity() == 0 {
                // delay the internal buffer creation until this point, as the caller clearly wants
                // to use it.
                self.block_buffer.reserve(self.size_hint());
            }

            self.block_buffer.extend_from_slice(accepted);
            let written = accepted.len();

            let (leaf, links) = if !ready {
                // a new block did not become ready, which means we couldn't have gotten a new cid.
                (None, Vec::new())
            } else {
                // a new leaf must be output, as well as possibly a new link block
                let leaf = Self::flush_buffered_leaf(
                    self.block_buffer.as_slice(),
                    &mut self.unflushed_links,
                    false,
                );
                assert!(leaf.is_some(), "chunk completed, must produce a new block");
                self.block_buffer.clear();
                let links = self.flush_buffered_links(false);

                (leaf, links)
            };
            (leaf.into_iter().chain(links.into_iter()), written)
        }
    }

    /// Called after the last [`FileAdder::push`] to finish the tree construction.
    ///
    /// Returns a list of Cids and their respective blocks.
    ///
    /// Note: the API will hopefully evolve in a direction which will not allocate a new Vec for
    /// every block in the near-ish future.
    pub fn finish(mut self) -> impl Iterator<Item = (Cid, Vec<u8>)> {
        let last_leaf = Self::flush_buffered_leaf(
            &self.block_buffer.as_slice(),
            &mut self.unflushed_links,
            true,
        );
        let root_links = self.flush_buffered_links(true);
        // should probably error if there is neither?
        last_leaf.into_iter().chain(root_links.into_iter())
    }

    /// Returns `None` when the input is empty but there are links, otherwise a new Cid and a
    /// block.
    fn flush_buffered_leaf(
        input: &[u8],
        unflushed_links: &mut Vec<Link>,
        finishing: bool,
    ) -> Option<(Cid, Vec<u8>)> {
        if input.is_empty() && (!finishing || !unflushed_links.is_empty()) {
            return None;
        }

        // for empty unixfs file the bytes is missing but filesize is present.

        let data = if !input.is_empty() {
            Some(Cow::Borrowed(input))
        } else {
            None
        };

        let filesize = Some(input.len() as u64);

        let inner = FlatUnixFs {
            links: Vec::new(),
            data: UnixFs {
                Type: UnixFsType::File,
                Data: data,
                filesize,
                // no blocksizes as there are no links
                ..Default::default()
            },
        };

        let (cid, vec) = render_and_hash(&inner);

        let total_size = vec.len();

        let link = Link {
            depth: 0,
            target: cid.clone(),
            total_size: total_size as u64,
            file_size: input.len() as u64,
        };

        unflushed_links.push(link);

        Some((cid, vec))
    }

    fn flush_buffered_links(&mut self, finishing: bool) -> Vec<(Cid, Vec<u8>)> {
        self.collector
            .flush_links(&mut self.unflushed_links, finishing)
    }

    /// Test helper for collecting all of the produced blocks; probably not a good idea outside
    /// smaller test cases. When `amt` is zero, the whole content is processed at the speed of
    /// chunker, otherwise `all_content` is pushed at `amt` sized slices with the idea of catching
    /// bugs in chunkers.
    #[cfg(test)]
    fn collect_blocks(mut self, all_content: &[u8], mut amt: usize) -> Vec<(Cid, Vec<u8>)> {
        let mut written = 0;
        let mut blocks_received = Vec::new();

        if amt == 0 {
            amt = all_content.len();
        }

        while written < all_content.len() {
            let end = written + (all_content.len() - written).min(amt);
            let slice = &all_content[written..end];

            let (blocks, pushed) = self.push(slice);
            blocks_received.extend(blocks);
            written += pushed;
        }

        let last_blocks = self.finish();
        blocks_received.extend(last_blocks);

        blocks_received
    }
}

fn render_and_hash(flat: &FlatUnixFs<'_>) -> (Cid, Vec<u8>) {
    // TODO: as shown in later dagger we don't really need to render the FlatUnixFs fully; we could
    // either just render a fixed header and continue with the body OR links, though the links are
    // a bit more complicated.
    let mut out = Vec::with_capacity(flat.get_size());
    let mut writer = Writer::new(&mut out);
    flat.write_message(&mut writer)
        .expect("unsure how this could fail");
    let mh = multihash::Code::Sha2_256.digest(&out);
    let cid = Cid::new_v0(mh).expect("sha2_256 is the correct multihash for cidv0");
    (cid, out)
}

/// Chunker strategy
#[derive(Debug, Clone)]
pub enum Chunker {
    /// Size based chunking
    Size(usize),
}

impl Default for Chunker {
    /// Returns a default chunker which matches go-ipfs 0.6
    fn default() -> Self {
        Chunker::Size(256 * 1024)
    }
}

impl Chunker {
    fn accept<'a>(&mut self, input: &'a [u8], buffered: &[u8]) -> (&'a [u8], bool) {
        use Chunker::*;

        match self {
            Size(max) => {
                let l = input.len().min(*max - buffered.len());
                let accepted = &input[..l];
                let ready = buffered.len() + l >= *max;
                (accepted, ready)
            }
        }
    }

    fn size_hint(&self) -> usize {
        use Chunker::*;

        match self {
            Size(max) => *max,
        }
    }
}

/// Collector or layout strategy. For more information, see the [Layout section of the spec].
/// Currently only the default balanced collector/layout has been implemented.
///
/// [Layout section of the spec]: https://github.com/ipfs/specs/blob/master/UNIXFS.md#layout
#[derive(Debug, Clone)]
pub enum Collector {
    /// Balanced trees.
    Balanced(BalancedCollector),
}

impl Default for Collector {
    fn default() -> Self {
        Collector::Balanced(Default::default())
    }
}

impl Collector {
    fn flush_links(&mut self, pending: &mut Vec<Link>, finishing: bool) -> Vec<(Cid, Vec<u8>)> {
        use Collector::*;

        match self {
            Balanced(bc) => bc.flush_links(pending, finishing),
        }
    }
}

/// BalancedCollector creates balanced UnixFs trees, most optimized for random access to different
/// parts of the file. Currently supports only link count threshold or the branching factor.
#[derive(Clone)]
pub struct BalancedCollector {
    branching_factor: usize,
    // reused between link block generation
    reused_links: Vec<PBLink<'static>>,
    // reused between link block generation
    reused_blocksizes: Vec<u64>,
}

impl fmt::Debug for BalancedCollector {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "BalancedCollector {{ branching_factor: {} }}",
            self.branching_factor
        )
    }
}

impl Default for BalancedCollector {
    /// Returns a default collector which matches go-ipfs 0.6
    ///
    /// The origin for 174 is not described in the the [specs], but has likely to do something
    /// with being "good enough" regarding prefetching when reading and allows reusing some of the
    /// link blocks if parts of a longer file change.
    ///
    /// [specs]: https://github.com/ipfs/specs/blob/master/UNIXFS.md
    fn default() -> Self {
        Self::with_branching_factor(174)
    }
}

impl From<BalancedCollector> for Collector {
    fn from(b: BalancedCollector) -> Self {
        Collector::Balanced(b)
    }
}

impl BalancedCollector {
    /// Configure Balanced collector with the given branching factor.
    pub fn with_branching_factor(branching_factor: usize) -> Self {
        assert!(branching_factor > 0);

        Self {
            branching_factor,
            reused_links: Vec::new(),
            reused_blocksizes: Vec::new(),
        }
    }

    /// In-place compression of the `pending` links to a balanced hierarchy. When `finishing`, the
    /// links will be compressed iteratively from the lowest level to produce a single root link
    /// block.
    fn flush_links(&mut self, pending: &mut Vec<Link>, finishing: bool) -> Vec<(Cid, Vec<u8>)> {
        /*

        file    |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
        links-0 |-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|E|F|G|
        links-1 |-------|-------|-------|-------|-B-----|-C-----|-D-----|\   /
        links-2 |-A-----------------------------|                         ^^^
              ^                                                     one short
               \--- link.depth

        pending [A, B, C, D, E, F, G]

        #flush_buffered_links(...) first iteration:

        file    |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
        links-0 |-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|E|F|G|
        links-1 |-------|-------|-------|-------|-B-----|-C-----|-D-----|=#1==|
        links-2 |-A-----------------------------|

        pending [A, B, C, D, E, F, G] => [A, B, C, D, 1]

        new link block #1 is created for E, F, and G.

        #flush_buffered_links(...) second iteration:

        file    |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
        links-0 |-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
        links-1 |-------|-------|-------|-------|-B-----|-C-----|-D-----|-#1--|
        links-2 |-A-----------------------------|=========================#2==|

        pending [A, B, C, D, 1] => [A, 2]

        new link block #2 is created for B, C, D, and #1.

        #flush_buffered_links(...) last iteration:

        file    |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
        links-0 |-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
        links-1 |-------|-------|-------|-------|-------|-------|-------|-#1--|
        links-2 |-A-----------------------------|-------------------------#2--|
        links-3 |=========================================================#3==|

        pending [A, 2] => [3]

        new link block #3 is created for A, and #2. (the root block)
        */

        let mut ret = Vec::new();

        let mut reused_links = core::mem::take(&mut self.reused_links);
        let mut reused_blocksizes = core::mem::take(&mut self.reused_blocksizes);

        if let Some(need) = self.branching_factor.checked_sub(reused_links.capacity()) {
            reused_links.reserve(need);
        }

        if let Some(need) = self
            .branching_factor
            .checked_sub(reused_blocksizes.capacity())
        {
            reused_blocksizes.reserve(need);
        }

        'outer: for level in 0.. {
            if pending.len() == 1 && finishing
                || pending.len() <= self.branching_factor && !finishing
            {
                // when there is just a single linking block left and we are finishing, we are
                // done. It might not be part of the `ret` as will be the case with single chunk
                // files for example.
                //
                // normally when not finishing we do nothing if we don't have enough links.
                break;
            }

            // when finishing, we iterate the level to completion in blocks of
            // self.branching_factor and *insert* values at the offset of the first compressed
            // link. on following iterations this will be the index after the higher level index.
            let mut starting_point = 0;

            // when creating the link blocks, start overwriting the pending links at the first
            // found link for this depth. this index will be incremented for successive link
            // blocks.
            let mut last_overwrite = None;

            while let Some(mut first_at) = &pending[starting_point..]
                .iter()
                .position(|Link { depth, .. }| depth == &level)
            {
                // fix first_at as absolute index from being possible relative to the
                // starting_point
                first_at += starting_point;

                if !finishing && pending[first_at..].len() <= self.branching_factor {
                    if let Some(last_overwrite) = last_overwrite {
                        // drain any processed
                        pending.drain((last_overwrite + 1)..first_at);
                    }
                    break 'outer;
                }

                reused_links.clear();
                reused_blocksizes.clear();

                let mut nested_size = 0;
                let mut nested_total_size = 0;

                let last = (first_at + self.branching_factor).min(pending.len());

                for (index, link) in pending[first_at..last].iter().enumerate() {
                    assert_eq!(
                        link.depth,
                        level,
                        "unexpected link depth {} when searching at level {} index {}",
                        link.depth,
                        level,
                        index + first_at
                    );

                    Self::partition_link(
                        link,
                        &mut reused_links,
                        &mut reused_blocksizes,
                        &mut nested_size,
                        &mut nested_total_size,
                    );
                }

                debug_assert_eq!(reused_links.len(), reused_blocksizes.len());

                let inner = FlatUnixFs {
                    links: reused_links,
                    data: UnixFs {
                        Type: UnixFsType::File,
                        filesize: Some(nested_size),
                        blocksizes: reused_blocksizes,
                        ..Default::default()
                    },
                };

                let (cid, vec) = render_and_hash(&inner);

                // start overwriting at the first index of this level, then continue forward on
                // next iterations.
                let index = last_overwrite.map(|i| i + 1).unwrap_or(first_at);
                pending[index] = Link {
                    depth: level + 1,
                    target: cid.clone(),
                    total_size: nested_total_size + vec.len() as u64,
                    file_size: nested_size,
                };

                ret.push((cid, vec));

                reused_links = inner.links;
                reused_blocksizes = inner.data.blocksizes;

                starting_point = last;
                last_overwrite = Some(index);
            }

            if let Some(last_overwrite) = last_overwrite {
                pending.truncate(last_overwrite + 1);
            }

            // this holds regardless of finishing; we would had broken 'outer had there been less
            // than full blocks left.
            debug_assert_eq!(
                pending.iter().position(|l| l.depth == level),
                None,
                "should have no more of depth {}: {}",
                level,
                LinkFormatter(pending.as_slice())
            );
        }

        self.reused_links = reused_links;
        self.reused_blocksizes = reused_blocksizes;

        ret
    }

    /// Each link needs to be partitioned into the four mut arguments received by this function in
    /// order to produce the expected UnixFs output.
    fn partition_link(
        link: &Link,
        links: &mut Vec<PBLink<'static>>,
        blocksizes: &mut Vec<u64>,
        nested_size: &mut u64,
        nested_total_size: &mut u64,
    ) {
        links.push(PBLink {
            Hash: Some(link.target.to_bytes().into()),
            Name: Some("".into()),
            Tsize: Some(link.total_size),
        });
        blocksizes.push(link.file_size);
        *nested_size += link.file_size;
        *nested_total_size += link.total_size;
    }
}

#[cfg(test)]
mod tests {

    use super::{BalancedCollector, Chunker, FileAdder};
    use crate::test_support::FakeBlockstore;
    use cid::Cid;
    use core::convert::TryFrom;
    use hex_literal::hex;

    #[test]
    fn test_size_chunker() {
        assert_eq!(size_chunker_scenario(1, 4, 0), (1, true));
        assert_eq!(size_chunker_scenario(2, 4, 0), (2, true));
        assert_eq!(size_chunker_scenario(2, 1, 0), (1, false));
        assert_eq!(size_chunker_scenario(2, 1, 1), (1, true));
        assert_eq!(size_chunker_scenario(32, 3, 29), (3, true));
        // this took some debugging time:
        assert_eq!(size_chunker_scenario(32, 4, 29), (3, true));
    }

    fn size_chunker_scenario(max: usize, input_len: usize, existing_len: usize) -> (usize, bool) {
        let input = vec![0; input_len];
        let existing = vec![0; existing_len];

        let (accepted, ready) = Chunker::Size(max).accept(&input, &existing);
        (accepted.len(), ready)
    }

    #[test]
    fn favourite_single_block_file() {
        let blocks = FakeBlockstore::with_fixtures();
        // everyones favourite content
        let content = b"foobar\n";

        let mut adder = FileAdder::default();

        {
            let (mut ready_blocks, bytes) = adder.push(content);
            assert!(ready_blocks.next().is_none());
            assert_eq!(bytes, content.len());
        }

        // real impl would probably hash this ... except maybe hashing is faster when done inline?
        // or maybe not
        let (_, file_block) = adder
            .finish()
            .next()
            .expect("there must have been the root block");

        assert_eq!(
            blocks.get_by_str("QmRgutAxd8t7oGkSm4wmeuByG6M51wcTso6cubDdQtuEfL"),
            file_block.as_slice()
        );
    }

    #[test]
    fn favourite_multi_block_file() {
        // root should be QmRJHYTNvC3hmd9gJQARxLR1QMEincccBV53bBw524yyq6

        let blocks = FakeBlockstore::with_fixtures();
        let content = b"foobar\n";
        let adder = FileAdder::builder().with_chunker(Chunker::Size(2)).build();

        let blocks_received = adder.collect_blocks(content, 0);

        // the order here is "fo", "ob", "ar", "\n", root block
        // while verifying the root Cid would be *enough* this is easier to eyeball, ... not really
        // that much but ...
        let expected = [
            "QmfVyMoStzTvdnUR7Uotzh82gmL427q9z3xW5Y8fUoszi4",
            "QmdPyW4CWE3QBkgjWfjM5f7Tjb3HukxVuBXZtkqAGwsMnm",
            "QmNhDQpphvMWhdCzP74taRzXDaEfPGq8vWfFRzD7mEgePM",
            "Qmc5m94Gu7z62RC8waSKkZUrCCBJPyHbkpmGzEePxy2oXJ",
            "QmRJHYTNvC3hmd9gJQARxLR1QMEincccBV53bBw524yyq6",
        ]
        .iter()
        .map(|key| {
            let cid = Cid::try_from(*key).unwrap();
            let block = blocks.get_by_str(key).to_vec();
            (cid, block)
        })
        .collect::<Vec<_>>();

        assert_eq!(blocks_received, expected);
    }

    #[test]
    fn three_layers() {
        let content = b"Lorem ipsum dolor sit amet, sit enim montes aliquam. Cras non lorem, \
            rhoncus condimentum, irure et ante. Pulvinar suscipit odio ante, et tellus a enim, \
            wisi ipsum, vel rhoncus eget faucibus varius, luctus turpis nibh vel odio nulla pede.";

        assert!(content.len() > 174 && content.len() < 2 * 174);

        // go-ipfs 0.5 result: QmRQ6NZNUs4JrCT2y7tmCC1wUhjqYuTssB8VXbbN3rMffg, 239 blocks and root
        // root has two links:
        //  - QmXUcuLGKc8SCMEqG4wgct6NKsSRZQfvB2FCfjDow1PfpB (174 links)
        //  - QmeEn8dxWTzGAFKvyXoLj4oWbh9putL4vSw4uhLXJrSZhs (63 links)
        //
        // in future, if we ever add inline Cid generation this test would need to be changed not
        // to use those inline cids or raw leaves
        let adder = FileAdder::builder().with_chunker(Chunker::Size(1)).build();

        let blocks_received = adder.collect_blocks(content, 0);

        assert_eq!(blocks_received.len(), 240);

        assert_eq!(
            blocks_received.last().unwrap().0.to_string(),
            "QmRQ6NZNUs4JrCT2y7tmCC1wUhjqYuTssB8VXbbN3rMffg"
        );
    }

    #[test]
    fn three_layers_all_subchunks() {
        let content = b"Lorem ipsum dolor sit amet, sit enim montes aliquam. Cras non lorem, \
            rhoncus condimentum, irure et ante. Pulvinar suscipit odio ante, et tellus a enim, \
            wisi ipsum, vel rhoncus eget faucibus varius, luctus turpis nibh vel odio nulla pede.";

        for amt in 1..32 {
            let adder = FileAdder::builder().with_chunker(Chunker::Size(32)).build();
            let blocks_received = adder.collect_blocks(content, amt);
            assert_eq!(
                blocks_received.last().unwrap().0.to_string(),
                "QmYSLcVQqxKygiq7x9w1XGYxU29EShB8ZemiaQ8GAAw17h",
                "amt: {}",
                amt
            );
        }
    }

    #[test]
    fn empty_file() {
        let blocks = FileAdder::default().collect_blocks(b"", 0);
        assert_eq!(blocks.len(), 1);
        // 0a == field dag-pb body (unixfs)
        // 04 == dag-pb body len, varint, 4 bytes
        // 08 == field type tag, varint, 1 byte
        // 02 == field type (File)
        // 18 == field filesize tag, varint
        // 00 == filesize, varint, 1 byte
        assert_eq!(blocks[0].1.as_slice(), &hex!("0a 04 08 02 18 00"));
        assert_eq!(
            blocks[0].0.to_string(),
            "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
        );
    }

    #[test]
    fn full_link_block_and_a_byte() {
        let buf = vec![0u8; 2];

        // this should produce a root with two links
        //             +----------^---+
        //             |              |
        //  |----------------------| |-| <-- link blocks
        //   ^^^^^^^^^^^^^^^^^^^^^^   ^
        //          174 blocks        \--- 1 block

        let branching_factor = 174;

        let mut adder = FileAdder::builder()
            .with_chunker(Chunker::Size(2))
            .with_collector(BalancedCollector::with_branching_factor(branching_factor))
            .build();
        let mut blocks_count = 0;

        for _ in 0..branching_factor {
            let (blocks, written) = adder.push(buf.as_slice());
            assert_eq!(written, buf.len());

            blocks_count += blocks.count();
        }

        let (blocks, written) = adder.push(&buf[0..1]);
        assert_eq!(written, 1);
        blocks_count += blocks.count();

        let last_blocks = adder.finish().collect::<Vec<_>>();
        blocks_count += last_blocks.len();

        // chunks == 174
        // one link block for 174
        // one is for the single byte block
        // one is a link block for the singular single byte block
        // other is for the root block
        assert_eq!(blocks_count, branching_factor + 1 + 1 + 1 + 1);

        assert_eq!(
            last_blocks.last().unwrap().0.to_string(),
            "QmcHNWF1d56uCDSfJPA7t9fadZRV9we5HGSTGSmwuqmMP9"
        );
    }

    #[test]
    fn full_link_block() {
        let buf = vec![0u8; 1];

        let branching_factor = 174;

        let mut adder = FileAdder::builder()
            .with_chunker(Chunker::Size(1))
            .with_collector(BalancedCollector::with_branching_factor(branching_factor))
            .build();
        let mut blocks_count = 0;

        for _ in 0..branching_factor {
            let (blocks, written) = adder.push(buf.as_slice());
            assert_eq!(written, buf.len());

            blocks_count += blocks.count();
        }

        let mut last_blocks = adder.finish();

        // go-ipfs waits until finish to get a single link block, no additional root block

        let last_block = last_blocks.next().expect("must not have flushed yet");
        blocks_count += 1;

        assert_eq!(last_blocks.next(), None);

        assert_eq!(
            last_block.0.to_string(),
            "QmdgQac8c6Bo3MP5bHAg2yQ25KebFUsmkZFvyByYzf8UCB"
        );

        assert_eq!(blocks_count, 175);
    }
}
