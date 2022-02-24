// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Tests and test helpers for BEEFY.

use futures::{future, stream::FuturesUnordered, Future, FutureExt, StreamExt};
use parking_lot::{Mutex, RwLock};
use std::{pin::Pin, sync::Arc, task::Poll, time::Duration};
use tokio::runtime::{Handle, Runtime};

use sc_consensus::{BoxJustificationImport, LongestChain};
use sc_finality_grandpa::{
	block_import, run_grandpa_voter, Config, GenesisAuthoritySetProvider, GrandpaParams, LinkHalf,
	SharedVoterState,
};
use sc_keystore::LocalKeystore;
use sc_network::config::{ProtocolConfig, Role};
use sc_network_test::{
	Block, BlockImportAdapter, FullPeerConfig, PassThroughVerifier, Peer, PeersClient,
	PeersFullClient, TestNetFactory,
};

use beefy_primitives::{
	crypto::AuthorityId as BeefyId, BeefyApi, ValidatorSet as BeefyValidatorSet,
	KEY_TYPE as BeefyKeyType,
};
use sp_api::{ApiRef, ProvideRuntimeApi};
use sp_application_crypto::key_types::GRANDPA;
use sp_blockchain::Result;
use sp_finality_grandpa::AuthorityList;
use sp_keyring::Ed25519Keyring;
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::{generic::BlockId, traits::Header as HeaderT};

use crate::{keystore::tests::Keyring as BeefyKeyring, notification::*};

const GRANDPA_PROTOCOL_NAME: &'static str = "/grandpa/1";
const BEEFY_PROTOCOL_NAME: &'static str = "/beefy/1";

type BeefyPeer = Peer<PeerData, GrandpaBlockImport>;
type GrandpaBlockImport = sc_finality_grandpa::GrandpaBlockImport<
	substrate_test_runtime_client::Backend,
	Block,
	PeersFullClient,
	LongestChain<substrate_test_runtime_client::Backend, Block>,
>;

pub struct BeefyLinkHalf {
	signed_commitment_stream: BeefySignedCommitmentStream<Block>,
	beefy_best_block_stream: BeefyBestBlockStream<Block>,
}
type GrandpaLinkHalf =
	LinkHalf<Block, PeersFullClient, LongestChain<substrate_test_runtime_client::Backend, Block>>;

#[derive(Default)]
struct PeerData {
	grandpa_link_half: Mutex<Option<GrandpaLinkHalf>>,
	beefy_link_half: Mutex<Option<BeefyLinkHalf>>,
}

struct BeefyTestNet {
	peers: Vec<BeefyPeer>,
	test_config: TestCfg,
	test_api: Arc<TestApi>,
}

impl BeefyTestNet {
	fn new(test_config: TestCfg, n_authority: usize, n_full: usize) -> Self {
		let mut net = BeefyTestNet {
			peers: Vec::with_capacity(n_authority + n_full),
			test_config,
			test_api: Arc::new(TestApi {}),
		};

		for _ in 0..n_authority {
			net.add_authority_peer();
		}

		for _ in 0..n_full {
			net.add_full_peer();
		}

		net
	}

	fn add_authority_peer(&mut self) {
		self.add_full_peer_with_config(FullPeerConfig {
			notifications_protocols: vec![GRANDPA_PROTOCOL_NAME.into()],
			is_authority: true,
			..Default::default()
		})
	}
}

impl TestNetFactory for BeefyTestNet {
	type Verifier = PassThroughVerifier;
	type BlockImport = GrandpaBlockImport;
	type PeerData = PeerData;

	/// Create new test network with peers and given config.
	fn from_config(_config: &ProtocolConfig) -> Self {
		BeefyTestNet {
			peers: Vec::new(),
			test_config: Default::default(),
			test_api: Arc::new(TestApi {}),
		}
	}

	fn make_verifier(
		&self,
		_client: PeersClient,
		_cfg: &ProtocolConfig,
		_: &PeerData,
	) -> Self::Verifier {
		PassThroughVerifier::new(false) // use non-instant finality.
	}

	fn peer(&mut self, i: usize) -> &mut BeefyPeer {
		&mut self.peers[i]
	}

	fn peers(&self) -> &Vec<BeefyPeer> {
		&self.peers
	}

	fn mut_peers<F: FnOnce(&mut Vec<BeefyPeer>)>(&mut self, closure: F) {
		closure(&mut self.peers);
	}

	fn make_block_import(
		&self,
		client: PeersClient,
	) -> (BlockImportAdapter<Self::BlockImport>, Option<BoxJustificationImport<Block>>, PeerData) {
		let (client, backend) = (client.as_client(), client.as_backend());
		let (import, link) = block_import(
			client.clone(),
			&self.test_config,
			LongestChain::new(backend.clone()),
			None,
		)
		.expect("Could not create block import for fresh peer.");
		let justification_import = Box::new(import.clone());
		(
			BlockImportAdapter::new(import),
			Some(justification_import),
			PeerData {
				grandpa_link_half: Mutex::new(Some(link)),
				beefy_link_half: Mutex::new(None),
			},
		)
	}

	fn default_config() -> ProtocolConfig {
		// This is unused.
		ProtocolConfig::default()
	}

	fn add_full_peer(&mut self) {
		self.add_full_peer_with_config(FullPeerConfig {
			notifications_protocols: vec![GRANDPA_PROTOCOL_NAME.into()],
			is_authority: false,
			..Default::default()
		})
	}
}

#[derive(Default, Clone)]
pub(crate) struct TestCfg {
	genesis_authorities: AuthorityList,
}
impl TestCfg {
	pub fn new(genesis_authorities: AuthorityList) -> Self {
		Self { genesis_authorities }
	}
}

#[derive(Clone)]
pub(crate) struct TestApi {}

// compiler gets confused and warns us about unused inner
#[allow(dead_code)]
pub(crate) struct RuntimeApi {
	inner: TestApi,
}

impl ProvideRuntimeApi<Block> for TestApi {
	type Api = RuntimeApi;

	fn runtime_api<'a>(&'a self) -> ApiRef<'a, Self::Api> {
		RuntimeApi { inner: self.clone() }.into()
	}
}

sp_api::mock_impl_runtime_apis! {
	impl BeefyApi<Block> for RuntimeApi {
		fn validator_set() -> Option<BeefyValidatorSet<BeefyId>> {
			BeefyValidatorSet::new(make_beefy_ids(&[BeefyKeyring::Alice, BeefyKeyring::Bob, BeefyKeyring::Charlie]), 0)
		}
	}
}

impl GenesisAuthoritySetProvider<Block> for TestCfg {
	fn get(&self) -> Result<AuthorityList> {
		Ok(self.genesis_authorities.clone())
	}
}

const TEST_GOSSIP_DURATION: Duration = Duration::from_millis(500);

fn make_beefy_ids(keys: &[BeefyKeyring]) -> Vec<BeefyId> {
	keys.iter().map(|key| key.clone().public().into()).collect()
}

fn make_grandpa_ids(keys: &[Ed25519Keyring]) -> AuthorityList {
	keys.iter().map(|key| key.clone().public().into()).map(|id| (id, 1)).collect()
}

fn create_beefy_keystore(authority: BeefyKeyring) -> SyncCryptoStorePtr {
	let keystore = Arc::new(LocalKeystore::in_memory());
	SyncCryptoStore::ecdsa_generate_new(&*keystore, BeefyKeyType, Some(&authority.to_seed()))
		.expect("Creates authority key");
	keystore
}

fn create_grandpa_keystore(authority: Ed25519Keyring) -> (SyncCryptoStorePtr, tempfile::TempDir) {
	let keystore_path = tempfile::tempdir().expect("Creates keystore path");
	let keystore =
		Arc::new(LocalKeystore::open(keystore_path.path(), None).expect("Creates keystore"));
	SyncCryptoStore::ed25519_generate_new(&*keystore, GRANDPA, Some(&authority.to_seed()))
		.expect("Creates authority key");

	(keystore, keystore_path)
}

// Spawns grandpa voters. Returns a future to spawn on the runtime.
fn initialize_grandpa(
	net: &mut BeefyTestNet,
	peers: &[Ed25519Keyring],
) -> impl Future<Output = ()> {
	let voters = FuturesUnordered::new();

	for (peer_id, key) in peers.iter().enumerate() {
		let (keystore, _) = create_grandpa_keystore(*key);

		let (net_service, link) = {
			// temporary needed for some reason
			let link = net.peers[peer_id]
				.data
				.grandpa_link_half
				.lock()
				.take()
				.expect("link initialized at startup; qed");
			(net.peers[peer_id].network_service().clone(), link)
		};

		let grandpa_params = GrandpaParams {
			config: Config {
				gossip_duration: TEST_GOSSIP_DURATION,
				justification_period: 32,
				keystore: Some(keystore),
				name: Some(format!("peer#{}", peer_id)),
				local_role: Role::Authority,
				observer_enabled: true,
				telemetry: None,
				protocol_name: GRANDPA_PROTOCOL_NAME.into(),
			},
			link,
			network: net_service,
			voting_rule: (),
			prometheus_registry: None,
			shared_voter_state: SharedVoterState::empty(),
			telemetry: None,
		};
		let voter =
			run_grandpa_voter(grandpa_params).expect("all in order with client and network");

		fn assert_send<T: Send>(_: &T) {}
		assert_send(&voter);

		voters.push(voter);
	}

	voters.for_each(|_| async move {})
}

// Spawns beefy voters. Returns a future to spawn on the runtime.
fn initialize_beefy(net: &mut BeefyTestNet, peers: &[BeefyKeyring]) -> impl Future<Output = ()> {
	let voters = FuturesUnordered::new();

	for (peer_id, key) in peers.iter().enumerate() {
		let keystore = create_beefy_keystore(*key);

		let (signed_commitment_sender, signed_commitment_stream) =
			BeefySignedCommitmentStream::<Block>::channel();
		let (beefy_best_block_sender, beefy_best_block_stream) =
			BeefyBestBlockStream::<Block>::channel();

		let beefy_link_half = BeefyLinkHalf { signed_commitment_stream, beefy_best_block_stream };
		*net.peers[peer_id].data.beefy_link_half.lock() = Some(beefy_link_half);

		let beefy_params = crate::BeefyParams {
			client: net.peers[peer_id].client().as_client(),
			backend: net.peers[peer_id].client().as_backend(),
			runtime: net.test_api.clone(),
			key_store: Some(keystore),
			network: net.peers[peer_id].network_service().clone(),
			signed_commitment_sender,
			beefy_best_block_sender,
			min_block_delta: 4,
			prometheus_registry: None,
			protocol_name: BEEFY_PROTOCOL_NAME.into(),
		};
		let gadget = crate::start_beefy_gadget::<_, _, _, _, _>(beefy_params);

		fn assert_send<T: Send>(_: &T) {}
		assert_send(&gadget);
		voters.push(gadget);
	}

	voters.for_each(|_| async move {})
}

fn block_until_complete(
	future: impl Future + Unpin,
	net: &Arc<Mutex<BeefyTestNet>>,
	runtime: &mut Runtime,
) {
	let drive_to_completion = futures::future::poll_fn(|cx| {
		net.lock().poll(cx);
		Poll::<()>::Pending
	});
	runtime.block_on(future::select(future, drive_to_completion));
}

// run the voters to completion. provide a closure to be invoked after
// the voters are spawned but before blocking on them.
fn run_to_completion_with<F>(
	runtime: &mut Runtime,
	blocks: u64,
	net: Arc<Mutex<BeefyTestNet>>,
	peers: &[Ed25519Keyring],
	with: F,
) -> u64
where
	F: FnOnce(Handle) -> Option<Pin<Box<dyn Future<Output = ()>>>>,
{
	let mut wait_for = Vec::new();

	let highest_finalized = Arc::new(RwLock::new(0));

	if let Some(f) = (with)(runtime.handle().clone()) {
		wait_for.push(f);
	};

	for (peer_id, _) in peers.iter().enumerate() {
		let highest_finalized = highest_finalized.clone();
		let client = net.lock().peers[peer_id].client().clone();

		wait_for.push(Box::pin(
			client
				.finality_notification_stream()
				.take_while(move |n| {
					let mut highest_finalized = highest_finalized.write();
					if *n.header.number() > *highest_finalized {
						*highest_finalized = *n.header.number();
					}
					future::ready(n.header.number() < &blocks)
				})
				.collect::<Vec<_>>()
				.map(|_| ()),
		));
	}

	// wait for all finalized on each.
	let wait_for = ::futures::future::join_all(wait_for);

	block_until_complete(wait_for, &net, runtime);
	let highest_finalized = *highest_finalized.read();
	highest_finalized
}

fn run_to_completion(
	runtime: &mut Runtime,
	blocks: u64,
	net: Arc<Mutex<BeefyTestNet>>,
	peers: &[Ed25519Keyring],
) -> u64 {
	run_to_completion_with(runtime, blocks, net, peers, |_| None)
}

#[test]
fn beefy_finalizing_blocks() {
	sp_tracing::try_init_simple();

	let mut runtime = Runtime::new().unwrap();
	let peers = &[BeefyKeyring::Alice, BeefyKeyring::Bob, BeefyKeyring::Charlie];
	let grandpa_peers = &[Ed25519Keyring::Alice, Ed25519Keyring::Bob, Ed25519Keyring::Charlie];
	let voters = make_grandpa_ids(grandpa_peers);

	let mut net = BeefyTestNet::new(TestCfg::new(voters), 3, 0);
	runtime.spawn(initialize_grandpa(&mut net, grandpa_peers));
	runtime.spawn(initialize_beefy(&mut net, peers));

	net.peer(0).push_blocks(32, false);
	net.block_until_sync();

	let net = Arc::new(Mutex::new(net));
	run_to_completion(&mut runtime, 32, net.clone(), grandpa_peers);

	for i in 0..3 {
		let mut net = net.lock();

		// when block#32 (justification_period) is finalized, justification
		// is required => generated
		assert!(net.peer(i).client().justifications(&BlockId::Number(32)).unwrap().is_some());

		// check commitments and best-beefy-blocks are being produced
		let beefy_link_half = net.peer(i).data.beefy_link_half.lock().take().unwrap();
		let BeefyLinkHalf {
			signed_commitment_stream: _check_me,
			beefy_best_block_stream: _check_me_too,
		} = beefy_link_half;

		// TODO:
		// verify `_check_me` and `_check_me_too`
	}
}
