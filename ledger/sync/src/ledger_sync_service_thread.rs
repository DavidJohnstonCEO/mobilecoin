// Copyright (c) 2018-2020 MobileCoin Inc.

//! An integration between `PollingNetworkState` and `LedgerSyncService` that performs the sync in
//! a background thread.

use crate::{LedgerSyncService, PollingNetworkState, TransactionsFetcher};
use common::logger::{log, Logger};
use ledger_db::Ledger;
use mcconnection::{BlockchainConnection, ConnectionManager};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

/// Maximal number of blocks to attempt to sync at each loop iteration.
const MAX_BLOCKS_PER_SYNC_ITERATION: u32 = 10;

pub struct LedgerSyncServiceThread {
    join_handle: Option<thread::JoinHandle<()>>,
    currently_behind: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
}

impl LedgerSyncServiceThread {
    pub fn new<
        L: Ledger + 'static,
        BC: BlockchainConnection + 'static,
        TF: TransactionsFetcher + 'static,
    >(
        ledger: L,
        manager: ConnectionManager<BC>,
        network_state: PollingNetworkState<BC>,
        transactions_fetcher: TF,
        poll_interval: Duration,
        logger: Logger,
    ) -> Self {
        let ledger_sync_service = LedgerSyncService::new(
            ledger.clone(),
            manager,
            transactions_fetcher,
            logger.clone(),
        );

        let currently_behind = Arc::new(AtomicBool::new(false));
        let stop_requested = Arc::new(AtomicBool::new(false));

        let thread_currently_behind = currently_behind.clone();
        let thread_stop_requested = stop_requested.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("LedgerSync".into())
                .spawn(move || {
                    Self::thread_entrypoint(
                        ledger,
                        ledger_sync_service,
                        network_state,
                        poll_interval,
                        thread_currently_behind,
                        thread_stop_requested,
                        logger,
                    );
                })
                .expect("Failed spawning LedgerSync thread"),
        );

        Self {
            join_handle,
            currently_behind,
            stop_requested,
        }
    }

    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("LedgerSync thread join failed");
        }
    }

    pub fn is_behind(&self) -> bool {
        self.currently_behind.load(Ordering::SeqCst)
    }

    fn thread_entrypoint<
        L: Ledger,
        BC: BlockchainConnection + 'static,
        TF: TransactionsFetcher + 'static,
    >(
        ledger: L,
        mut ledger_sync_service: LedgerSyncService<L, BC, TF>,
        mut network_state: PollingNetworkState<BC>,
        poll_interval: Duration,
        currently_behind: Arc<AtomicBool>,
        stop_requested: Arc<AtomicBool>,
        logger: Logger,
    ) {
        log::debug!(logger, "LedgerSyncServiceThread has started.");

        loop {
            if stop_requested.load(Ordering::SeqCst) {
                log::debug!(logger, "LedgerSyncServiceThread stop requested.");
                break;
            }

            // See if we're currently behind. If we're not, poll to be sure.
            let mut is_behind = ledger_sync_service.is_behind(&network_state);
            if !is_behind {
                network_state.poll();
                is_behind = ledger_sync_service.is_behind(&network_state);
            }

            // Store current state and log.
            currently_behind.store(is_behind, Ordering::SeqCst);
            if is_behind {
                log::debug!(
                    logger,
                    "ledger sync service is_behind: {:?} num blocks {:?}",
                    is_behind,
                    ledger.num_blocks().unwrap()
                );
            }

            // Maybe sync, maybe wait and check again.
            if is_behind {
                let _ = ledger_sync_service
                    .attempt_ledger_sync(&network_state, MAX_BLOCKS_PER_SYNC_ITERATION);
            } else if !stop_requested.load(Ordering::SeqCst) {
                log::trace!(
                    logger,
                    "Sleeping, num_blocks = {}...",
                    ledger.num_blocks().unwrap()
                );
                std::thread::sleep(poll_interval);
            }
        }
    }
}

impl Drop for LedgerSyncServiceThread {
    fn drop(&mut self) {
        self.stop();
    }
}
