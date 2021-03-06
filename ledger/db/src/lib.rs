// Copyright (c) 2018-2020 MobileCoin Inc.

//! Persistent storage for the blockchain.
#![warn(unused_extern_crates)]
#![feature(test)]

#[cfg(test)]
extern crate test;

use core::convert::TryInto;
use lmdb::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use mcserial::{deserialize, serialize};
use std::{path::PathBuf, sync::Arc};
use transaction::{Block, BlockContents, BlockID, BlockSignature, BLOCK_VERSION};

mod error;
mod ledger_trait;
pub mod tx_out_store;

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils;

pub use error::Error;
pub use ledger_trait::Ledger;
use transaction::{
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipProof},
};
use tx_out_store::TxOutStore;

const MAX_LMDB_FILE_SIZE: usize = 1_099_511_627_776; // 1 TB

// LMDB Database names.
pub const COUNTS_DB_NAME: &str = "ledger_db:counts";
pub const BLOCKS_DB_NAME: &str = "ledger_db:blocks";
pub const BLOCK_CONTENTS_DB_NAME: &str = "ledger_db:block_contents";
pub const BLOCK_SIGNATURES_DB_NAME: &str = "ledger_db:block_signatures";
pub const KEY_IMAGES_DB_NAME: &str = "ledger_db:key_images";
pub const KEY_IMAGES_BY_BLOCK_DB_NAME: &str = "ledger_db:key_images_by_block";

// Keys used by the `counts` database.
const NUM_BLOCKS_KEY: &str = "num_blocks";

#[derive(Clone)]
pub struct LedgerDB {
    env: Arc<Environment>,

    /// Aggregate counts about the ledger.
    /// * `NUM_BLOCKS_KEY` --> number of blocks in the ledger.
    counts: Database,

    /// Blocks by block number. `block number -> Block`
    blocks: Database,

    /// Block contents by block number, `block number -> BlockContents`
    block_contents: Database,

    /// Block signatures by number. `block number -> BlockSignature`
    block_signatures: Database,

    /// Key Images
    key_images: Database,

    /// Key Images by Block
    key_images_by_block: Database,

    /// Storage abstraction for TxOuts.
    tx_out_store: TxOutStore,

    /// Location on filesystem.
    path: PathBuf,
}

/// LedgerDB is an append-only log (or chain) of blocks of transactions.
impl Ledger for LedgerDB {
    /// Appends a block and its associated transactions to the blockchain.
    ///
    /// # Arguments
    /// * `block` - A block.
    /// * `block_contents` - The contents of the block.
    /// * `signature` - This node's signature over the block.
    fn append_block(
        &mut self,
        block: &Block,
        block_contents: &BlockContents,
        signature: Option<&BlockSignature>,
    ) -> Result<(), Error> {
        // Note: This function must update every LMDB database managed by LedgerDB.
        let mut db_transaction = self.env.begin_rw_txn()?;

        self.validate_append_block(block, block_contents)?;

        self.write_key_images(block.index, &block_contents.key_images, &mut db_transaction)?;

        for tx_out in &block_contents.outputs {
            self.tx_out_store.push(tx_out, &mut db_transaction)?;
        }

        self.write_block(block, block_contents, signature, &mut db_transaction)?;
        db_transaction.commit()?;
        Ok(())
    }

    /// Get the total number of Blocks in the ledger.
    fn num_blocks(&self) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        Ok(key_bytes_to_u64(
            &db_transaction.get(self.counts, &NUM_BLOCKS_KEY)?,
        ))
    }

    /// Get the total number of TxOuts in the ledger.
    fn num_txos(&self) -> Result<u64, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.tx_out_store.num_tx_outs(&db_transaction)
    }

    /// Gets a Block by its index in the blockchain.
    fn get_block(&self, block_number: u64) -> Result<Block, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(block_number);
        let block_bytes = db_transaction.get(self.blocks, &key)?;
        let block = deserialize(&block_bytes)?;
        Ok(block)
    }

    /// Get the contents of a block.
    fn get_block_contents(&self, block_number: u64) -> Result<BlockContents, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(block_number);
        let bytes = db_transaction.get(self.block_contents, &key)?;
        let block_contents = deserialize(&bytes)?;
        Ok(block_contents)
    }

    /// Gets a block signature by its index in the blockchain.
    fn get_block_signature(&self, block_number: u64) -> Result<BlockSignature, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key = u64_to_key_bytes(block_number);
        let signature_bytes = db_transaction.get(self.block_signatures, &key)?;
        let signature = deserialize(&signature_bytes)?;
        Ok(signature)
    }

    /// Returns the index of the TxOut with the given hash.
    fn get_tx_out_index_by_hash(&self, tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        let db_transaction: RoTransaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_index_by_hash(tx_out_hash, &db_transaction)
    }

    /// Gets a TxOut by its index in the ledger.
    fn get_tx_out_by_index(&self, index: u64) -> Result<TxOut, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        self.tx_out_store
            .get_tx_out_by_index(index, &db_transaction)
    }

    /// Returns true if the Ledger contains the given KeyImage.
    fn check_key_image(&self, key_image: &KeyImage) -> Result<Option<u64>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        match db_transaction.get(self.key_images, &key_image) {
            Ok(db_bytes) => {
                assert_eq!(db_bytes.len(), 8, "Expected exactly 8 le bytes (u64 block height) to be stored with key image, found {}", db_bytes.len());
                let mut u64_buf = [0u8; 8];
                u64_buf.copy_from_slice(db_bytes);
                Ok(Some(u64::from_le_bytes(u64_buf)))
            }
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(Error::LmdbError(e)),
        }
    }

    /// Gets the KeyImages used by transactions in a single Block.
    fn get_key_images_by_block(&self, block_number: u64) -> Result<Vec<KeyImage>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        let key_images: Vec<KeyImage> = deserialize(
            db_transaction.get(self.key_images_by_block, &u64_to_key_bytes(block_number))?,
        )?;
        Ok(key_images)
    }

    /// Gets a proof of memberships for TxOuts with indexes `indexes`.
    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        let db_transaction = self.env.begin_ro_txn()?;
        indexes
            .iter()
            .map(|index| {
                self.tx_out_store
                    .get_merkle_proof_of_membership(*index, &db_transaction)
            })
            .collect()
    }
}

impl LedgerDB {
    /// Opens an existing Ledger Database in the given path.
    pub fn open(path: PathBuf) -> Result<LedgerDB, Error> {
        let env = Environment::new()
            .set_max_dbs(20)
            .set_map_size(MAX_LMDB_FILE_SIZE)
            // TODO - needed because currently our test cloud machines have slow disks.
            .set_flags(EnvironmentFlags::NO_SYNC)
            .open(&path)?;

        let counts = env.open_db(Some(COUNTS_DB_NAME))?;
        let blocks = env.open_db(Some(BLOCKS_DB_NAME))?;
        let block_contents = env.open_db(Some(BLOCK_CONTENTS_DB_NAME))?;
        let block_signatures = env.open_db(Some(BLOCK_SIGNATURES_DB_NAME))?;
        let key_images = env.open_db(Some(KEY_IMAGES_DB_NAME))?;
        let key_images_by_block = env.open_db(Some(KEY_IMAGES_BY_BLOCK_DB_NAME))?;

        let tx_out_store = TxOutStore::new(&env)?;

        Ok(LedgerDB {
            env: Arc::new(env),
            path,
            counts,
            blocks,
            block_contents,
            block_signatures,
            key_images,
            key_images_by_block,
            tx_out_store,
        })
    }

    /// Creates a fresh Ledger Database in the given path.
    pub fn create(path: PathBuf) -> Result<(), Error> {
        let env = Environment::new()
            .set_max_dbs(20)
            .set_map_size(MAX_LMDB_FILE_SIZE)
            .open(&path)
            .unwrap_or_else(|_| {
                panic!(
                    "Could not create environment for ledger_db. Check that path exists {:?}",
                    path
                )
            });

        let counts = env.create_db(Some(COUNTS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCKS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCK_CONTENTS_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(BLOCK_SIGNATURES_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(KEY_IMAGES_DB_NAME), DatabaseFlags::empty())?;
        env.create_db(Some(KEY_IMAGES_BY_BLOCK_DB_NAME), DatabaseFlags::empty())?;

        TxOutStore::create(&env)?;

        let mut db_transaction = env.begin_rw_txn()?;

        db_transaction.put(
            counts,
            &NUM_BLOCKS_KEY,
            &u64_to_key_bytes(0),
            WriteFlags::empty(),
        )?;

        db_transaction.commit()?;
        Ok(())
    }

    /// Write a `Block`.
    fn write_block(
        &self,
        block: &Block,
        block_contents: &BlockContents,
        signature: Option<&BlockSignature>,
        db_transaction: &mut RwTransaction,
    ) -> Result<(), lmdb::Error> {
        // Update total number of blocks.
        let num_blocks_before: u64 =
            key_bytes_to_u64(&db_transaction.get(self.counts, &NUM_BLOCKS_KEY)?);
        db_transaction.put(
            self.counts,
            &NUM_BLOCKS_KEY,
            &u64_to_key_bytes(num_blocks_before + 1),
            WriteFlags::empty(),
        )?;

        db_transaction.put(
            self.blocks,
            &u64_to_key_bytes(block.index),
            &serialize(block).unwrap_or_else(|_| panic!("Could not serialize block {:?}", block)),
            WriteFlags::empty(),
        )?;

        db_transaction.put(
            self.block_contents,
            &u64_to_key_bytes(block.index),
            &serialize(block_contents).unwrap_or_else(|_| {
                panic!("Could not serialize block contents{:?}", block_contents)
            }),
            WriteFlags::empty(),
        )?;

        if let Some(signature) = signature {
            db_transaction.put(
                self.block_signatures,
                &u64_to_key_bytes(block.index),
                &serialize(signature).unwrap_or_else(|_| {
                    panic!("Could not serialize block signature {:?}", signature)
                }),
                WriteFlags::empty(),
            )?;
        }

        Ok(())
    }

    fn write_key_images(
        &self,
        block_index: u64,
        key_images: &[KeyImage],
        db_transaction: &mut RwTransaction,
    ) -> Result<(), Error> {
        // Update Key Images
        for key_image in key_images {
            if self.contains_key_image(key_image)? {
                return Err(Error::KeyImageAlreadySpent);
            }
            db_transaction.put(
                self.key_images,
                &key_image,
                &block_index.to_le_bytes(),
                WriteFlags::empty(),
            )?;
        }
        db_transaction.put(
            self.key_images_by_block,
            &u64_to_key_bytes(block_index),
            &serialize(&key_images)?,
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    /// Checks if a block can be appended to the db.
    fn validate_append_block(
        &self,
        block: &Block,
        block_contents: &BlockContents,
    ) -> Result<(), Error> {
        // Check that version is correct
        if block.version != BLOCK_VERSION {
            return Err(Error::InvalidBlock);
        }

        // A block must have outputs.
        if block_contents.outputs.is_empty() {
            // TODO: better error type.
            return Err(Error::InvalidBlock);
        }

        // TODO: enable this.
        // // Non-origin blocks must have key images.
        // if block.index == 0 && block_contents.key_images.is_empty() {
        //     return Err(Error::InvalidBlock);
        // }

        // Check if block is being appended at the correct place.
        let num_blocks = self.num_blocks()?;
        if num_blocks == 0 {
            // This must be an origin block.
            if block.index != 0 || block.parent_id != BlockID::default() {
                return Err(Error::InvalidBlock);
            }
        } else {
            // The block must have the correct index and parent.
            let last_block = self.get_block(num_blocks - 1)?;
            if block.index != num_blocks || block.parent_id != last_block.id {
                return Err(Error::InvalidBlock);
            }
        }

        // Check that the block contents match the hash.
        if block.contents_hash != block_contents.hash() {
            return Err(Error::InvalidBlockContents);
        }

        // Check that none of the key images were previously spent.
        for key_image in &block_contents.key_images {
            if self.contains_key_image(key_image)? {
                return Err(Error::KeyImageAlreadySpent);
            }
        }

        // Validate block id.
        if !block.is_block_id_valid() {
            return Err(Error::InvalidBlockID);
        }

        // All good
        Ok(())
    }
}

// Specifies how we serialize the u64 chunk number in lmdb
// The lexicographical sorting of the numbers, done by lmdb, must match the
// numeric order of the chunks. Thus we use Big Endian byte order here
pub fn u64_to_key_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn key_bytes_to_u64(bytes: &[u8]) -> u64 {
    assert_eq!(8, bytes.len());
    u64::from_be_bytes(bytes.try_into().unwrap())
}

#[cfg(test)]
mod ledger_db_test {
    use super::*;
    use core::convert::TryFrom;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use keys::RistrettoPrivate;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::RngCore;
    use tempdir::TempDir;
    use test::Bencher;
    use transaction::{account_keys::AccountKey, compute_block_id};

    /// Creates a LedgerDB instance.
    fn create_db() -> LedgerDB {
        let temp_dir = TempDir::new("test").unwrap();
        let path = temp_dir.path().to_path_buf();
        LedgerDB::create(path.clone()).unwrap();
        LedgerDB::open(path).unwrap()
    }

    /// Populates the LedgerDB with initial data, and returns the Block entities that were written.
    ///
    /// # Arguments
    /// * `db` - LedgerDb.
    /// * `num_blocks` - number of blocks  to write to `db`.
    /// * `n_txs_per_block` - number of transactions per block.
    ///
    fn populate_db(db: &mut LedgerDB, num_blocks: u64, num_outputs_per_block: u64) -> Vec<Block> {
        let initial_amount: u64 = 5_000 * 1_000_000_000_000;

        // Generate 1 public / private addresses and create transactions.
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);

        let mut parent_block: Option<Block> = None;
        let mut blocks: Vec<Block> = Vec::new();

        for block_index in 0..num_blocks {
            let outputs: Vec<TxOut> = (0..num_outputs_per_block)
                .map(|_i| {
                    TxOut::new(
                        initial_amount,
                        &account_key.default_subaddress(),
                        &RistrettoPrivate::from_random(&mut rng),
                        Default::default(),
                        &mut rng,
                    )
                    .unwrap()
                })
                .collect();

            let key_images: Vec<KeyImage> = Vec::new();
            let block_contents = BlockContents::new(key_images, outputs.clone());

            let block = match parent_block {
                None => Block::new_origin_block(&outputs),
                Some(parent) => Block::new(
                    BLOCK_VERSION,
                    &parent.id,
                    block_index,
                    &Default::default(),
                    &block_contents,
                ),
            };
            assert_eq!(block_index, block.index);

            db.append_block(&block, &block_contents, None)
                .expect("failed writing initial transactions");
            blocks.push(block.clone());
            parent_block = Some(block);
        }

        // Verify that db now contains n transactions.
        assert_eq!(db.num_blocks().unwrap(), num_blocks as u64);

        blocks
    }

    #[test]
    // Test initial conditions of a new LedgerDB instance.
    fn test_ledger_db_initialization() {
        let ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        assert_eq!(ledger_db.num_txos().unwrap(), 0);
    }

    fn get_origin_block_and_contents(account_key: &AccountKey) -> (Block, BlockContents) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let output = TxOut::new(
            1000,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        let outputs = vec![output];
        let block = Block::new_origin_block(&outputs);
        let block_contents = BlockContents::new(vec![], outputs);

        (block, block_contents)
    }

    #[test]
    // Appending a block should correctly update each LMDB database.
    fn test_append_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // === Create and append the origin block. ===
        // The origin block contains a single output belonging to the `origin_account_key`.

        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);

        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        assert_eq!(1, ledger_db.num_blocks().unwrap());
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        assert_eq!(1, ledger_db.num_txos().unwrap());

        let origin_tx_out = origin_block_contents.outputs.get(0).unwrap().clone();
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        assert_eq!(
            origin_block_contents,
            ledger_db.get_block_contents(0).unwrap()
        );

        let key_images = ledger_db.get_key_images_by_block(0).unwrap();
        assert_eq!(key_images.len(), 0);

        // === Create and append a non-origin block. ===

        let recipient_account_key = AccountKey::random(&mut rng);
        let outputs: Vec<TxOut> = (0..4)
            .map(|_i| {
                TxOut::new(
                    1000,
                    &recipient_account_key.default_subaddress(),
                    &RistrettoPrivate::from_random(&mut rng),
                    Default::default(),
                    &mut rng,
                )
                .unwrap()
            })
            .collect();

        let key_images: Vec<KeyImage> = (0..5)
            .map(|_i| KeyImage::from(RistrettoPoint::random(&mut rng)))
            .collect();

        let block_contents = BlockContents::new(key_images.clone(), outputs);
        let block = Block::new(
            BLOCK_VERSION,
            &origin_block.id,
            1,
            &Default::default(),
            &block_contents,
        );

        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();

        assert_eq!(2, ledger_db.num_blocks().unwrap());
        // The origin block should still be in the ledger:
        assert_eq!(origin_block, ledger_db.get_block(0).unwrap());
        // The new block should be in the ledger:
        assert_eq!(block, ledger_db.get_block(1).unwrap());
        assert_eq!(5, ledger_db.num_txos().unwrap());

        // The origin's TxOut should still be in the ledger:
        assert_eq!(origin_tx_out, ledger_db.get_tx_out_by_index(0).unwrap());

        // Each TxOut from the current block should be in the ledger.
        for (i, tx_out) in block_contents.outputs.iter().enumerate() {
            // The first tx_out is the origin block, tx_outs are for the following block hence the
            // + 1
            assert_eq!(
                ledger_db.get_tx_out_by_index((i + 1) as u64).unwrap(),
                *tx_out
            );
        }

        assert!(ledger_db
            .contains_key_image(key_images.get(0).unwrap())
            .unwrap());

        let block_one_key_images = ledger_db.get_key_images_by_block(1).unwrap();
        assert_eq!(key_images, block_one_key_images);
    }

    #[test]
    #[ignore]
    // A block that attempts a double spend should be rejected.
    fn test_reject_double_spend() {
        unimplemented!();
    }

    #[test]
    // `num_blocks` should return the correct number of blocks.
    fn test_num_blocks() {
        let mut ledger_db = create_db();
        assert_eq!(ledger_db.num_blocks().unwrap(), 0);
        let n_blocks: u64 = 7;
        populate_db(&mut ledger_db, n_blocks, 1);
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks);
    }

    #[test]
    // Getting a block by index should return the correct block, if it exists.
    fn test_get_block_by_index() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        let expected_blocks = populate_db(&mut ledger_db, n_blocks, 1);

        for block_index in 0..n_blocks {
            let block = ledger_db
                .get_block(block_index as u64)
                .unwrap_or_else(|_| panic!("Could not get block {:?}", block_index));

            let expected_block: Block = expected_blocks.get(block_index as usize).unwrap().clone();
            assert_eq!(block, expected_block);
        }
    }

    #[test]
    // Getting a block by its index should return an error if the block doesn't exist.
    fn test_get_block_by_index_doesnt_exist() {
        let mut ledger_db = create_db();
        let n_blocks = 43;
        populate_db(&mut ledger_db, n_blocks, 1);

        let out_of_range = 999;

        match ledger_db.get_block(out_of_range) {
            Ok(_block) => panic!("Should not return a block."),
            Err(Error::NotFound) => {
                // This is expected.
            }
            Err(e) => panic!("Unexpected error {:?}", e),
        }
    }

    #[test]
    // `Ledger::contains_key_image` should find key images that exist.
    fn test_contains_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Write the next block, containing several key images.
        let account_key = AccountKey::random(&mut rng);
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(RistrettoPoint::random(&mut rng)))
            .collect();

        let tx_out = TxOut::new(
            10,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();
        let outputs = vec![tx_out];

        let block_contents = BlockContents::new(key_images.clone(), outputs);
        let block = Block::new(
            BLOCK_VERSION,
            &origin_block.id,
            1,
            &Default::default(),
            &block_contents,
        );

        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();

        // The ledger should each key image.
        for key_image in &key_images {
            assert!(ledger_db.contains_key_image(&key_image).unwrap());
        }
    }

    #[test]
    // `get_key_images_by_block` should return the correct set of key images used in a single block.
    fn test_get_key_images_by_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // Populate the ledger with some initial blocks.
        let n_blocks = 3;
        populate_db(&mut ledger_db, n_blocks, 2);

        // Append a new block to the ledger.
        let account_key = AccountKey::random(&mut rng);
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(RistrettoPoint::random(&mut rng)))
            .collect();

        let tx_out = TxOut::new(
            10,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();
        let outputs = vec![tx_out];

        let block_contents = BlockContents::new(key_images.clone(), outputs);
        let parent = ledger_db.get_block(n_blocks - 1).unwrap();
        let block = Block::new(
            BLOCK_VERSION,
            &parent.id,
            parent.index + 1,
            &Default::default(),
            &block_contents,
        );

        ledger_db
            .append_block(&block, &block_contents, None)
            .unwrap();

        let returned_key_images = ledger_db.get_key_images_by_block(block.index).unwrap();
        assert_eq!(key_images, returned_key_images);
    }

    #[test]
    /// Attempting to append an empty block should return Error::InvalidBlock.
    fn test_append_empty_block() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Write the next block, containing several key images but no outputs.
        let num_key_images = 3;
        let key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(RistrettoPoint::random(&mut rng)))
            .collect();

        let outputs = Vec::new();

        let block_contents = BlockContents::new(key_images.clone(), outputs);
        let block = Block::new(
            BLOCK_VERSION,
            &origin_block.id,
            1,
            &Default::default(),
            &block_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block, &block_contents, None),
            Err(Error::InvalidBlock)
        );
    }

    #[test]
    /// Appending an block of incorrect version should return Error::InvalidBlock.
    fn test_append_block_with_invalid_version() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let (mut block, block_contents) = get_origin_block_and_contents(&account_key);

        let wrong_version = 1337;
        block.version = wrong_version;
        // Recompute the block ID to reflect the modified version.
        block.id = compute_block_id(
            block.version,
            &block.parent_id,
            block.index,
            &block.root_element,
            &block.contents_hash,
        );

        assert_eq!(
            ledger_db.append_block(&block, &block_contents, None),
            Err(Error::InvalidBlock)
        );
    }

    #[test]
    fn test_append_block_at_wrong_location() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        // initialize a ledger with 3 blocks.
        let n_blocks = 3;
        let blocks = populate_db(&mut ledger_db, n_blocks, 2);
        assert_eq!(ledger_db.num_blocks().unwrap(), n_blocks);

        let key_images = vec![KeyImage::from(RistrettoPoint::random(&mut rng))];

        let tx_out = TxOut::new(
            100,
            &account_key.default_subaddress(),
            &RistrettoPrivate::from_random(&mut rng),
            Default::default(),
            &mut rng,
        )
        .unwrap();

        let outputs = vec![tx_out];
        let block_contents = BlockContents::new(key_images, outputs);

        // Appending a block to a previously written location should fail.
        let mut new_block = Block::new(
            BLOCK_VERSION,
            &blocks[0].id,
            1,
            &Default::default(),
            &block_contents,
        );

        assert_eq!(
            ledger_db.append_block(&new_block, &block_contents, None),
            Err(Error::InvalidBlock)
        );

        // Appending a non-contiguous location should fail.
        new_block.index = 3 * n_blocks;
        assert_eq!(
            ledger_db.append_block(&new_block, &block_contents, None),
            Err(Error::InvalidBlock)
        );
    }

    #[test]
    /// Appending a block with a spent key image should return Error::KeyImageAlreadySpent.
    fn test_append_block_with_spent_key_image() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();

        // The origin block can't contain key images.
        let origin_account_key = AccountKey::random(&mut rng);
        let (origin_block, origin_block_contents) =
            get_origin_block_and_contents(&origin_account_key);
        ledger_db
            .append_block(&origin_block, &origin_block_contents, None)
            .unwrap();

        // Write the next block, containing several key images.
        let account_key = AccountKey::random(&mut rng);
        let num_key_images = 3;
        let block_one_key_images: Vec<KeyImage> = (0..num_key_images)
            .map(|_i| KeyImage::from(RistrettoPoint::random(&mut rng)))
            .collect();

        let block_one_contents = {
            let tx_out = TxOut::new(
                10,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                &mut rng,
            )
            .unwrap();
            let outputs = vec![tx_out];
            BlockContents::new(block_one_key_images.clone(), outputs)
        };

        let block_one = Block::new(
            BLOCK_VERSION,
            &origin_block.id,
            1,
            &Default::default(),
            &block_one_contents,
        );

        ledger_db
            .append_block(&block_one, &block_one_contents, None)
            .unwrap();

        // The next block reuses a key image.
        let block_two_contents = {
            let tx_out = TxOut::new(
                33,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                &mut rng,
            )
            .unwrap();
            let outputs = vec![tx_out];
            BlockContents::new(block_one_key_images.clone(), outputs)
        };

        let block_two = Block::new(
            BLOCK_VERSION,
            &block_one.id,
            2,
            &Default::default(),
            &block_two_contents,
        );

        assert_eq!(
            ledger_db.append_block(&block_two, &block_two_contents, None),
            Err(Error::KeyImageAlreadySpent)
        );
    }

    #[test]
    // append_block rejects invalid blocks.
    fn test_append_invalid_blocks() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut ledger_db = create_db();
        let account_key = AccountKey::random(&mut rng);

        let (origin_block, origin_block_contents) = get_origin_block_and_contents(&account_key);

        // append_block rejects a block with invalid id.
        {
            let mut block = origin_block.clone();
            block.id.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, &origin_block_contents, None),
                Err(Error::InvalidBlockID)
            );
        }

        // append_block rejects a block with invalid contents hash.
        {
            let mut block = origin_block.clone();
            block.contents_hash.0[0] += 1;
            assert_eq!(
                ledger_db.append_block(&block, &origin_block_contents, None),
                Err(Error::InvalidBlockContents)
            );
        }

        assert_eq!(
            ledger_db.append_block(&origin_block, &origin_block_contents, None),
            Ok(())
        );

        // append_block rejects a block with non-existent parent.
        {
            let tx_out = TxOut::new(
                100,
                &account_key.default_subaddress(),
                &RistrettoPrivate::from_random(&mut rng),
                Default::default(),
                &mut rng,
            )
            .unwrap();

            let key_images = vec![KeyImage::from(RistrettoPoint::random(&mut rng))];
            let block_contents = BlockContents::new(key_images, vec![tx_out]);

            let bytes = [14u8; 32];
            let bad_parent_id = BlockID::try_from(&bytes[..]).unwrap();

            // This block has a bad parent id.
            let block_one_bad = Block::new(
                BLOCK_VERSION,
                &bad_parent_id,
                1,
                &Default::default(),
                &block_contents,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_bad, &block_contents, None),
                Err(Error::InvalidBlock)
            );

            // This block correctly has block zero as its parent.
            let block_one_good = Block::new(
                BLOCK_VERSION,
                &origin_block.id,
                1,
                &Default::default(),
                &block_contents,
            );

            assert_eq!(
                ledger_db.append_block(&block_one_good, &block_contents, None),
                Ok(())
            );
        }
    }

    // FIXME(MC-526): If these benches are not marked ignore, they get run during cargo test
    // and they are not compiled with optimizations which makes them take several minutes
    // I think they should probably be moved to `ledger_db/benches/...` ?
    #[bench]
    #[ignore]
    fn bench_num_blocks(b: &mut Bencher) {
        let mut ledger_db = create_db();
        let n_blocks = 150;
        let n_txs_per_block = 1;
        let _ = populate_db(&mut ledger_db, n_blocks, n_txs_per_block);

        b.iter(|| ledger_db.num_blocks().unwrap())
    }

    #[bench]
    #[ignore]
    fn bench_get_block(b: &mut Bencher) {
        let mut ledger_db = create_db();
        let n_blocks = 30;
        let n_txs_per_block = 1000;
        let _ = populate_db(&mut ledger_db, n_blocks, n_txs_per_block);
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        b.iter(|| ledger_db.get_block(rng.next_u64() % n_blocks).unwrap())
    }
}
