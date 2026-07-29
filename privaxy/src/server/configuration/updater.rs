use super::FilterFailureStore;
use crate::blocker::AdblockRequester;
use crate::proxy::userscripts::{reload_userscripts, UserScriptStore};
use futures::future::{AbortHandle, Abortable};

use tokio::sync::mpsc::Receiver;
use tokio::sync::{self, mpsc::Sender};

pub struct ConfigurationUpdater {
    filters_updater_abort_handle: AbortHandle,
    rx: Receiver<super::Configuration>,
    pub tx: Sender<super::Configuration>,
    http_client: reqwest::Client,
    adblock_requester: AdblockRequester,
    filter_failure_store: FilterFailureStore,
    /// Refreshed on the same timer as the filter lists, so a userscript
    /// installed from a URL actually picks up upstream changes.
    user_script_store: UserScriptStore,
}

impl ConfigurationUpdater {
    pub(crate) async fn new(
        configuration: super::Configuration,
        http_client: reqwest::Client,
        adblock_requester: AdblockRequester,
        filter_failure_store: FilterFailureStore,
        user_script_store: UserScriptStore,
        tx_rx: Option<(
            sync::mpsc::Sender<super::Configuration>,
            sync::mpsc::Receiver<super::Configuration>,
        )>,
    ) -> Self {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let (tx, rx) = match tx_rx {
            Some((tx, rx)) => (tx, rx),
            None => sync::mpsc::channel(1),
        };

        let http_client_clone = http_client.clone();
        let adblock_requester_clone = adblock_requester.clone();
        let filter_failure_store_clone = filter_failure_store.clone();
        let user_script_store_clone = user_script_store.clone();

        let filters_updater = Abortable::new(
            async move {
                Self::filters_updater(
                    configuration,
                    adblock_requester_clone,
                    http_client_clone.clone(),
                    filter_failure_store_clone,
                    user_script_store_clone,
                )
                .await
            },
            abort_registration,
        );

        tokio::spawn(filters_updater);

        Self {
            filters_updater_abort_handle: abort_handle,
            rx,
            tx,
            http_client,
            adblock_requester,
            filter_failure_store,
            user_script_store,
        }
    }

    pub(crate) fn start(mut self) {
        tokio::spawn(async move {
            loop {
                let mut configuration = self.rx.recv().await.unwrap();
                // Abort the previously-spawned filters_updater so it doesn't
                // keep running in the background holding its own Configuration
                // clone and racing to replace the engine on its own timer.
                self.filters_updater_abort_handle.abort();

                // Failure entries for filters that were removed or disabled
                // by this configuration change are no longer actionable.
                self.filter_failure_store
                    .sync_with_filters(&configuration.filters);

                let filters = super::filter::get_filters_content(
                    &mut configuration,
                    &self.http_client,
                    &self.filter_failure_store,
                )
                .await;
                self.adblock_requester.replace_engine(filters).await;

                let adblock_requester_clone = self.adblock_requester.clone();
                let http_client_clone = self.http_client.clone();
                let filter_failure_store_clone = self.filter_failure_store.clone();
                let user_script_store_clone = self.user_script_store.clone();

                let (abort_handle, abort_registration) = AbortHandle::new_pair();
                self.filters_updater_abort_handle = abort_handle;

                tokio::spawn(Abortable::new(
                    async move {
                        Self::filters_updater(
                            configuration,
                            adblock_requester_clone,
                            http_client_clone,
                            filter_failure_store_clone,
                            user_script_store_clone,
                        )
                        .await;
                    },
                    abort_registration,
                ));

                log::info!("Applied new configuration");
            }
        });
    }

    async fn filters_updater(
        mut configuration: super::Configuration,
        adblock_requester: AdblockRequester,
        http_client: reqwest::Client,
        filter_failure_store: FilterFailureStore,
        user_script_store: UserScriptStore,
    ) {
        loop {
            tokio::time::sleep(super::FILTERS_UPDATE_AFTER).await;

            configuration
                .update_filters(http_client.clone(), &filter_failure_store)
                .await;

            // We don't bother diffing the filters as replacing the engine is very cheap and
            // filters are not updated often enough that the cost would matter.
            let filters = super::filter::get_filters_content(
                &mut configuration,
                &http_client,
                &filter_failure_store,
            )
            .await;
            adblock_requester.replace_engine(filters).await;

            // Userscripts installed from a URL are refreshed on the same timer,
            // then recompiled so the new bodies are actually injected.
            //
            // Read from disk rather than using this task's `configuration`: the
            // userscript API deliberately does not push through the updater
            // channel (that would rebuild the adblock engine for a change which
            // has nothing to do with filters), so this copy is stale with respect
            // to userscripts — recompiling the store from it would wipe every
            // script installed since startup. `Configuration::save` renames a
            // fully-written temporary file into place, so a concurrent write is
            // observed either wholly or not at all even without the save lock.
            //
            // Only on-disk bodies are refreshed: this task holds no save lock, so
            // it must not write the configuration file, and a changed `@name` is
            // picked up the next time the API touches that script.
            match super::Configuration::read_from_home().await {
                Ok(mut current) => {
                    current.update_userscripts(&http_client).await;
                    reload_userscripts(&user_script_store, &current, &http_client).await;
                }
                Err(err) => log::warn!("Skipping the userscript refresh: {err}"),
            }

            log::info!("Updated filters and userscripts");
        }
    }
}
