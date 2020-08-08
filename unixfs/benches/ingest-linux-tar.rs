use criterion::{black_box, criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let tar_bytes = std::fs::read("linux-5.6.tar").expect("read failed");
    c.bench_function("ingest-linux-tar", |b| b.iter(|| ingest_tar(&tar_bytes)));
}

fn ingest_tar(bytes: &[u8]) {
    use cid::Cid;
    use ipfs_unixfs::dir::builder::{BufferingTreeBuilder, TreeOptions};
    use ipfs_unixfs::file::adder::FileAdder;
    use std::io::Read;

    let mut buffer = Vec::new();

    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let mut entries = archive.entries().unwrap();

    let mut opts = TreeOptions::default();
    opts.wrap_with_directory();
    let mut tree = BufferingTreeBuilder::new(opts);

    while let Some(entry) = entries.next() {
        let mut entry = entry.unwrap();
        let path = std::str::from_utf8(&*entry.path_bytes())
            .unwrap()
            .to_string(); // need to get rid of this

        if let Some(_link_name) = entry.link_name_bytes() {
            continue;
        }

        if !path.ends_with('/') {
            let mut adder = FileAdder::default();

            // with the std::io::Read it'd be good to read into the fileadder, or read into ...
            // something. trying to acccess the buffer from in side FileAdder does not seem the be the
            // way to go.

            if let Some(needed) = adder.size_hint().checked_sub(buffer.capacity()) {
                buffer.reserve(needed);
            }

            if let Some(mut needed) = adder.size_hint().checked_sub(buffer.len()) {
                let zeros = [0u8; 64];

                while needed > zeros.len() {
                    buffer.extend_from_slice(&zeros[..]);
                    needed -= zeros.len();
                }

                buffer.extend(std::iter::repeat(0).take(needed));
            }

            let mut total_written = 0usize;

            loop {
                match entry.read(&mut buffer[0..]).unwrap() {
                    0 => {
                        let blocks = adder.finish();
                        let (cid, subtotal) = blocks
                            .fold(
                                None,
                                |acc: Option<(Cid, usize)>, (cid, bytes): (Cid, Vec<u8>)| match acc
                                {
                                    Some((_, total)) => Some((cid, total + bytes.len())),
                                    None => Some((cid, bytes.len())),
                                },
                            )
                            .expect("this is probably always present");

                        total_written += subtotal;

                        tree.put_file(&path, cid, total_written as u64).unwrap();
                        break;
                    }
                    n => {
                        let mut read = 0;
                        while read < n {
                            let (blocks, consumed) = adder.push(&buffer[read..n]);
                            read += consumed;
                            total_written += blocks.map(|(_, bytes)| bytes.len()).sum::<usize>();
                        }
                    }
                }
            }
        } else {
            tree.set_metadata(&path[..path.len() - 1], ipfs_unixfs::Metadata::default())
                .unwrap();
        }
    }

    let mut iter = tree.build();

    let mut last: Option<(Cid, u64, usize)> = None;

    while let Some(res) = iter.next_borrowed() {
        let res = res.unwrap();

        match &mut last {
            Some(ref mut s) => {
                s.0 = res.cid.to_owned();
                s.1 = res.total_size;
                s.2 = res.block.len();
            }
            n @ None => {
                *n = Some((res.cid.to_owned(), res.total_size, res.block.len()));
            }
        }
    }

    let last = last.unwrap();

    black_box(last);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
