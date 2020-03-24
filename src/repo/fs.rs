//! Persistent fs backed repo
use crate::error::Error;
use crate::repo::{BlockStore, BlockStoreEvent};
#[cfg(feature = "rocksdb")]
use crate::repo::{Column, DataStore};
use async_std::path::{Path, PathBuf};
use async_std::sync::{Arc, Mutex};
use async_std::{fs, task};
use async_trait::async_trait;
use core::convert::TryFrom;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::channel::mpsc;
use futures::sink::SinkExt;
use futures::stream::{Stream, StreamExt};
use libipld::cid::Cid;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::ErrorKind;

fn block_path(path: &Path, cid: &Cid) -> PathBuf {
    let mut cid = cid.to_string();
    cid.push_str(".data");
    path.join(cid)
}

#[derive(Debug)]
pub struct FsBlockStore {
    path: PathBuf,
    cids: Arc<Mutex<HashSet<Cid>>>,
    sender: mpsc::Sender<BlockStoreEvent>,
    receiver: mpsc::Receiver<BlockStoreEvent>,
}

#[async_trait]
impl BlockStore for FsBlockStore {
    async fn open(path: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&path).await?;
        let mut stream = fs::read_dir(&path).await?;
        let mut cids = HashSet::new();
        while let Some(res) = stream.next().await {
            let path = res?.path();
            if path.extension() != Some(OsStr::new("data")) {
                continue;
            }
            let cid_str = path.file_stem().unwrap().to_str().unwrap();
            let cid = Cid::try_from(cid_str)?;
            cids.insert(cid);
        }
        let cids = Arc::new(Mutex::new(cids));
        let (sender, receiver) = mpsc::channel(1);
        Ok(Self {
            path,
            cids,
            sender,
            receiver,
        })
    }

    fn contains(&mut self, cid: &Cid) -> bool {
        task::block_on(async { self.cids.lock().await.contains(cid) })
    }

    fn get(&mut self, cid: Cid) {
        let path = block_path(&self.path, &cid);
        let mut sender = self.sender.clone();
        task::spawn(async move {
            match fs::read(path).await {
                Ok(data) => {
                    sender
                        .send(BlockStoreEvent::Get(cid, Ok(Some(data.into_boxed_slice()))))
                        .await
                        .ok();
                }
                Err(err) => {
                    if err.kind() == ErrorKind::NotFound {
                        sender.send(BlockStoreEvent::Get(cid, Ok(None))).await.ok();
                    } else {
                        sender
                            .send(BlockStoreEvent::Get(cid, Err(err.into())))
                            .await
                            .ok();
                    }
                }
            };
        });
    }

    fn put(&mut self, cid: Cid, data: Box<[u8]>) {
        let path = block_path(&self.path, &cid);
        let mut sender = self.sender.clone();
        let cids = self.cids.clone();
        task::spawn(async move {
            if let Err(err) = fs::write(path, data).await {
                sender
                    .send(BlockStoreEvent::Put(cid, Err(err.into())))
                    .await
                    .ok();
            } else {
                cids.lock().await.insert(cid.clone());
                sender.send(BlockStoreEvent::Put(cid, Ok(()))).await.ok();
            }
        });
    }

    fn remove(&mut self, cid: Cid) {
        let path = block_path(&self.path, &cid);
        let mut sender = self.sender.clone();
        let cids = self.cids.clone();
        task::spawn(async move {
            match fs::remove_file(path).await {
                Ok(()) => {
                    cids.lock().await.remove(&cid);
                    sender.send(BlockStoreEvent::Remove(cid, Ok(()))).await.ok();
                }
                Err(err) => {
                    if err.kind() == ErrorKind::NotFound {
                        sender.send(BlockStoreEvent::Remove(cid, Ok(()))).await.ok();
                    } else {
                        sender
                            .send(BlockStoreEvent::Remove(cid, Err(err.into())))
                            .await
                            .ok();
                    }
                }
            }
        });
    }
}

impl Stream for FsBlockStore {
    type Item = BlockStoreEvent;

    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
        let next = self.receiver.next();
        futures::pin_mut!(next);
        next.poll(ctx)
    }
}

#[derive(Clone, Debug)]
#[cfg(feature = "rocksdb")]
pub struct RocksDataStore {
    path: PathBuf,
    db: Arc<Mutex<Option<rocksdb::DB>>>,
}

#[cfg(feature = "rocksdb")]
trait ResolveColumnFamily {
    fn resolve<'a>(&self, db: &'a rocksdb::DB) -> &'a rocksdb::ColumnFamily;
}

#[cfg(feature = "rocksdb")]
impl ResolveColumnFamily for Column {
    fn resolve<'a>(&self, db: &'a rocksdb::DB) -> &'a rocksdb::ColumnFamily {
        let name = match *self {
            Column::Ipns => "ipns",
        };

        // not sure why this isn't always present?
        db.cf_handle(name).unwrap()
    }
}

#[cfg(feature = "rocksdb")]
#[async_trait]
impl DataStore for RocksDataStore {
    fn new(path: PathBuf) -> Self {
        RocksDataStore {
            path,
            db: Arc::new(Mutex::new(None)),
        }
    }

    async fn init(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn open(&self) -> Result<(), Error> {
        let db = self.db.clone();
        let path = self.path.clone();
        let mut db_opts = rocksdb::Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);

        let ipns_opts = rocksdb::Options::default();
        let ipns_cf = rocksdb::ColumnFamilyDescriptor::new("ipns", ipns_opts);
        let rdb = rocksdb::DB::open_cf_descriptors(&db_opts, &path, vec![ipns_cf])?;
        *db.lock().unwrap() = Some(rdb);
        Ok(())
    }

    async fn contains(&self, col: Column, key: &[u8]) -> Result<bool, Error> {
        let db = self.db.clone();
        let key = key.to_owned();
        let db = db.lock().unwrap();
        let db = db.as_ref().unwrap();
        let cf = col.resolve(db);
        let contains = db.get_cf(cf, &key)?.is_some();
        Ok(contains)
    }

    async fn get(&self, col: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let db = self.db.clone();
        let key = key.to_owned();
        let db = db.lock().unwrap();
        let db = db.as_ref().unwrap();
        let cf = col.resolve(db);
        let get = db.get_cf(cf, &key)?.map(|value| value.to_vec());
        Ok(get)
    }

    async fn put(&self, col: Column, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let db = self.db.clone();
        let key = key.to_owned();
        let value = value.to_owned();
        let db = db.lock().unwrap();
        let db = db.as_ref().unwrap();
        let cf = col.resolve(db);
        db.put_cf(cf, &key, &value)?;
        Ok(())
    }

    async fn remove(&self, col: Column, key: &[u8]) -> Result<(), Error> {
        let db = self.db.clone();
        let key = key.to_owned();
        let db = db.lock().unwrap();
        let db = db.as_ref().unwrap();
        let cf = col.resolve(db);
        db.delete_cf(cf, &key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libipld::cid::{Cid, Codec};
    use multihash::Sha2_256;
    use std::env::temp_dir;

    #[async_std::test]
    async fn test_fs_blockstore() {
        let mut tmp = temp_dir();
        tmp.push("blockstore1");
        std::fs::remove_dir_all(tmp.clone()).ok();
        let mut store = FsBlockStore::open(tmp.clone().into()).await.unwrap();

        let data = b"1".to_vec().into_boxed_slice();
        let cid = Cid::new_v1(Codec::Raw, Sha2_256::digest(&data));

        assert!(!store.contains(&cid));

        store.get(cid.clone());
        let event = store.next().await.unwrap();
        assert_eq!(event, BlockStoreEvent::Get(cid.clone(), Ok(None)));

        store.remove(cid.clone());
        let event = store.next().await.unwrap();
        assert_eq!(event, BlockStoreEvent::Remove(cid.clone(), Ok(())));

        store.put(cid.clone(), data.clone());
        let event = store.next().await.unwrap();
        assert_eq!(event, BlockStoreEvent::Put(cid.clone(), Ok(())));

        assert!(store.contains(&cid));

        store.get(cid.clone());
        let event = store.next().await.unwrap();
        assert_eq!(
            event,
            BlockStoreEvent::Get(cid.clone(), Ok(Some(data.clone())))
        );

        store.remove(cid.clone());
        let event = store.next().await.unwrap();
        assert_eq!(event, BlockStoreEvent::Remove(cid.clone(), Ok(())));

        assert!(!store.contains(&cid));

        store.get(cid.clone());
        let event = store.next().await.unwrap();
        assert_eq!(event, BlockStoreEvent::Get(cid.clone(), Ok(None)));

        std::fs::remove_dir_all(tmp).ok();
    }

    #[async_std::test]
    async fn test_fs_blockstore_open() {
        let mut tmp = temp_dir();
        tmp.push("blockstore2");
        std::fs::remove_dir_all(&tmp).ok();

        let data = b"1".to_vec().into_boxed_slice();
        let cid = Cid::new_v1(Codec::Raw, Sha2_256::digest(&data));

        let mut store = FsBlockStore::open(tmp.clone().into()).await.unwrap();
        assert!(!store.contains(&cid));

        store.put(cid.clone(), data.clone());
        store.next().await;

        let mut store = FsBlockStore::open(tmp.clone().into()).await.unwrap();
        assert!(store.contains(&cid));

        store.get(cid.clone());
        let event = store.next().await.unwrap();
        assert_eq!(event, BlockStoreEvent::Get(cid, Ok(Some(data))));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[async_std::test]
    #[cfg(feature = "rocksdb")]
    fn test_rocks_datastore() {
        let mut tmp = temp_dir();
        tmp.push("datastore1");
        std::fs::remove_dir_all(&tmp).ok();
        let store = RocksDataStore::new(tmp.clone().into());

        let col = Column::Ipns;
        let key = [1, 2, 3, 4];
        let value = [5, 6, 7, 8];

        assert_eq!(store.init().await.unwrap(), ());
        assert_eq!(store.open().await.unwrap(), ());

        let contains = store.contains(col, &key);
        assert_eq!(contains.await.unwrap(), false);
        let get = store.get(col, &key);
        assert_eq!(get.await.unwrap(), None);
        let remove = store.remove(col, &key);
        assert_eq!(remove.await.unwrap(), ());

        let put = store.put(col, &key, &value);
        assert_eq!(put.await.unwrap(), ());
        let contains = store.contains(col, &key);
        assert_eq!(contains.await.unwrap(), true);
        let get = store.get(col, &key);
        assert_eq!(get.await.unwrap(), Some(value.to_vec()));

        let remove = store.remove(col, &key);
        assert_eq!(remove.await.unwrap(), ());
        let contains = store.contains(col, &key);
        assert_eq!(contains.await.unwrap(), false);
        let get = store.get(col, &key);
        assert_eq!(get.await.unwrap(), None);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
