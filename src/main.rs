mod utils;

use crate::utils::{millisats_to_sats, parse_peer_info};
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Network;
use ldk_node::io::SqliteStore;
use ldk_node::lightning_invoice::Invoice;
use ldk_node::{Builder, ChannelId, Config, NetAddress, Node};
use std::convert::TryFrom;
use std::env;
use std::io;
use std::io::Write;
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

const APP_NAME: &str = "ldk-node-sample";

struct AppSettings {
	ldk_storage_dir_path: String,
	ldk_peer_listening_port: u16,
	network: Network,
}

fn parse_startup_args() -> Result<AppSettings, ()> {
	println!("Usage: {APP_NAME} <datadir> [<listening_port>] [<network>]");

	let mut arg_idx = 1;

	let ldk_storage_dir_path = match env::args().skip(arg_idx).next() {
		Some(s) => s,
		None => "datadir".to_owned(),
	};
	arg_idx = arg_idx + 1;

	let ldk_peer_listening_port: u16 = match env::args().skip(arg_idx).next().map(|p| p.parse()) {
		Some(Ok(p)) => p,
		Some(Err(_)) | None => 9735,
	};
	arg_idx = arg_idx + 1;

	let network: Network = match env::args().skip(arg_idx).next().as_ref().map(String::as_str) {
		Some("testnet") => Network::Testnet,
		Some("regtest") => Network::Regtest,
		Some("signet") => Network::Signet,
		Some("mainnet") => Network::Bitcoin,
		Some(net) => {
			panic!("Unsupported network provided. Options are: `regtest`, `testnet`, and `signet`. Got {}", net);
		}
		None => Network::Testnet,
	};

	Ok(AppSettings { ldk_storage_dir_path, ldk_peer_listening_port, network })
}

fn handle_events(node: &Node<SqliteStore>) {
	loop {
		// println!("waiting for events in the background...");
		let event = node.wait_next_event();
		println!("EVENT: {:?}", event);
		let _ = node.event_handled();
	}
}

fn list_peers(node: &Node<SqliteStore>) {
	let peers = node.list_peers();
	if peers.is_empty() {
		println!("No peers");
		return;
	}
	println!("Peers:");
	println!("NodeID \t| address");
	for p in peers {
		println!("- {} \t{}", p.node_id, p.address.to_string());
	}
}

fn list_channels(node: &Node<SqliteStore>) {
	let channels = node.list_channels();
	if channels.is_empty() {
		println!("No channels");
		return;
	}
	println!("Channels:");
	println!(
		"ChannelID \t| NodeID \t| ready? \t| capacity (sats) \t| balance (sats) \t| Funding TXO"
	);
	for ch in channels {
		println!(
			"- id {} \tnode {} \tready {} \tcap {} \tbal {} \ttxo {:?}",
			hex::encode(ch.channel_id.0),
			ch.counterparty_node_id,
			ch.is_channel_ready,
			ch.channel_value_sats,
			millisats_to_sats(ch.balance_msat),
			ch.funding_txo
		);
	}
}

fn connect_peer(node: &Node<SqliteStore>, peer_pubkey: PublicKey, peer_addr: NetAddress) {
	match node.connect(peer_pubkey, peer_addr.clone(), true) {
		Err(e) => println!("ERROR: Could not connect to peer {} {} {}", peer_pubkey, peer_addr, e),
		Ok(_) => println!("Connected to peer node {} {}", peer_pubkey, peer_addr),
	}
}

fn disconnect_peer(node: &Node<SqliteStore>, peer_pubkey: PublicKey) {
	match node.disconnect(peer_pubkey) {
		Err(e) => println!("ERROR: Could not disconnect from peer {} {}", peer_pubkey, e),
		Ok(_) => println!("Disconnected from peer node {}", peer_pubkey),
	}
}

fn get_listen_address(node: &Node<SqliteStore>) -> String {
	match node.listening_address() {
		None => "(not listening)".to_string(),
		Some(na) => na.to_string(),
	}
}

fn open_channel(
	node: &Node<SqliteStore>, node_id: PublicKey, peer_addr: NetAddress, chan_amt_sat: u64,
) {
	// check balance
	let current_spendable_onchain_balance_sats = node.spendable_onchain_balance_sats().unwrap_or(0);
	println!("balances {} {}", current_spendable_onchain_balance_sats, chan_amt_sat);
	if chan_amt_sat > current_spendable_onchain_balance_sats {
		println!(
			"Error: Current spendable onchain balance is less than required, {} sats",
			current_spendable_onchain_balance_sats
		);
		println!(
			"       Use 'newonchainaddress' to get an address, and send funds to it (onchain)"
		);
		return;
	}

	match node.connect_open_channel(node_id, peer_addr, chan_amt_sat, None, None, true) {
		Err(e) => println!("Error opening channel: {e}"),
		Ok(()) => println!(
			"Channel opened with capacity {} to node {}",
			chan_amt_sat,
			node_id.to_string()
		),
	}
}

fn close_channel(node: &Node<SqliteStore>, channel_id: &ChannelId, node_id: PublicKey) {
	match node.close_channel(channel_id, node_id) {
		Err(e) => println!("Error opening channel: {e}"),
		Ok(()) => println!("Channel closed, {} {}", hex::encode(channel_id.0), node_id),
	}
}

fn send_payment(node: &Node<SqliteStore>, invoice: &Invoice) {
	match node.send_payment(invoice) {
		Err(e) => println!("ERROR: Could not send payment, {} {}", e, invoice),
		Ok(payment_hash) => println!("Payment sent, hash {}", hex::encode(payment_hash.0)),
	}
}

fn list_payments(node: &Node<SqliteStore>) {
	let payments = node.list_payments();
	if payments.len() == 0 {
		println!("No payments found");
	} else {
		println!("Payments:");
		println!("amount (msats) \t| direction \t| status");
		for p in &payments {
			println!(
				"- {} \t{:?} \t{:?}",
				p.amount_msat.unwrap_or_default(),
				p.direction,
				p.status
			);
		}
	}
}

fn create_invoice(node: &Node<SqliteStore>, amount_msat: u64, description: &str) {
	match node.receive_payment(amount_msat, description, 999999) {
		Err(e) => println!("Error creating invoice, {e}"),
		Ok(invoice) => println!("Invoice: {}", invoice.to_string()),
	}
}

fn new_onchain_address(node: &Node<SqliteStore>) {
	match node.new_onchain_address() {
		Err(e) => println!("Error: {}", e),
		Ok(a) => {
			let onchain_address_str = a.to_string();
			println!(
				"New onchain address generated, onchain wallet can be funded by sending to it:  {}",
				onchain_address_str
			);
		}
	}
}

fn get_balances(node: &Node<SqliteStore>) {
	let onchain_spendable = match node.spendable_onchain_balance_sats() {
		Ok(b) => b,
		Err(e) => {
			println!("Error: Cannot retrieve balance, {e}");
			0
		}
	};
	let onchain_total = match node.total_onchain_balance_sats() {
		Ok(b) => b,
		Err(e) => {
			println!("Error: Cannot retrieve balance, {e}");
			0
		}
	};
	let channels = node.list_channels();
	let ln_total = millisats_to_sats(channels.iter().map(|c| c.balance_msat).sum::<u64>());
	let ln_spendable =
		millisats_to_sats(channels.iter().map(|c| c.outbound_capacity_msat).sum::<u64>());
	println!("Sat balances \t spendable \t total");
	println!("onchain:     \t {} \t {}", onchain_spendable, onchain_total);
	println!("lightning:   \t {} \t {}", ln_spendable, ln_total);
	println!(
		"total:       \t {} \t {}",
		onchain_spendable + ln_spendable,
		onchain_total + ln_total
	);
}

fn node_info(node: &Node<SqliteStore>) {
	println!("Node info:");
	println!("node pubkey:            \t{}", node.node_id());
	let channels = node.list_channels();
	println!("No. of channels:        \t{}", channels.len());
	println!("No. of usable channels: \t{}", channels.iter().filter(|c| c.is_usable).count());
	let local_balance_msat = channels.iter().map(|c| c.balance_msat).sum::<u64>();
	println!("Local balance (msat):   \t{}", local_balance_msat);
	let peers = node.list_peers();
	println!("No. of peers:           \t{}", peers.len());
}

pub(crate) fn poll_for_user_input(node: &Node<SqliteStore>) {
	println!("Enter \"help\" to view available commands. Press Ctrl-D to quit.");
	loop {
		print!("> ");
		std::io::stdout().flush().unwrap(); // Without flushing, the `>` doesn't print
		let mut line = String::new();
		if let Err(e) = io::stdin().read_line(&mut line) {
			break println!("ERROR: {}", e);
		}

		if line.len() == 0 {
			// We hit EOF / Ctrl-D
			break;
		}

		let mut words = line.split_whitespace();
		if let Some(word) = words.next() {
			match word {
				"help" => help(),
				"openchannel" => {
					let peer_pubkey_and_ip_addr = words.next();
					let channel_value_sat = words.next();
					if peer_pubkey_and_ip_addr.is_none() || channel_value_sat.is_none() {
						println!("ERROR: openchannel has 2 required arguments: `openchannel pubkey@host:port channel_amt_sats`");
						continue;
					}
					let peer_pubkey_and_ip_addr = peer_pubkey_and_ip_addr.unwrap();
					let (pubkey, peer_addr) =
						match parse_peer_info(peer_pubkey_and_ip_addr.to_string()) {
							Ok(info) => info,
							Err(e) => {
								println!("{:?}", e.into_inner().unwrap());
								continue;
							}
						};

					let chan_amt_sat: Result<u64, _> = channel_value_sat.unwrap().parse();
					if chan_amt_sat.is_err() {
						println!("ERROR: channel amount must be a number");
						continue;
					}

					open_channel(node, pubkey, peer_addr, chan_amt_sat.unwrap());
				}
				"sendpayment" => {
					let invoice_str = words.next();
					if invoice_str.is_none() {
						println!("ERROR: sendpayment requires an invoice: `sendpayment <invoice>`");
						continue;
					}

					let invoice = match Invoice::from_str(invoice_str.unwrap()) {
						Ok(inv) => inv,
						Err(e) => {
							println!("ERROR: invalid invoice: {:?}", e);
							continue;
						}
					};

					send_payment(node, &invoice);
				}
				"getinvoice" => {
					let amt_str = words.next();
					if amt_str.is_none() {
						println!("ERROR: getinvoice requires an amount in millisatoshis");
						continue;
					}

					let amt_msat: Result<u64, _> = amt_str.unwrap().parse();
					if amt_msat.is_err() {
						println!("ERROR: getinvoice provided payment amount was not a number");
						continue;
					}

					let description_first_opt = words.next();
					if description_first_opt.is_none() {
						println!("ERROR: getinvoice requires a description");
						continue;
					}
					let mut description = description_first_opt.unwrap().to_string();
					loop {
						match words.next() {
							None => break,
							Some(w) => description = description.add(&format!(" {}", w)),
						}
					}

					create_invoice(node, amt_msat.unwrap(), &description);
				}
				"connectpeer" => {
					let peer_pubkey_and_ip_addr = words.next();
					if peer_pubkey_and_ip_addr.is_none() {
						println!("ERROR: connectpeer requires peer connection info: `connectpeer pubkey@host:port`");
						continue;
					}
					let (pubkey, peer_addr) =
						match parse_peer_info(peer_pubkey_and_ip_addr.unwrap().to_string()) {
							Ok(info) => info,
							Err(e) => {
								println!("{:?}", e.into_inner().unwrap());
								continue;
							}
						};
					connect_peer(&node, pubkey, peer_addr.clone());
				}
				"disconnectpeer" => {
					let peer_pubkey = words.next();
					if peer_pubkey.is_none() {
						println!("ERROR: disconnectpeer requires peer public key: `disconnectpeer <peer_pubkey>`");
						continue;
					}

					let peer_pubkey = match PublicKey::from_str(peer_pubkey.unwrap()) {
						Ok(pubkey) => pubkey,
						Err(e) => {
							println!("ERROR: Could not parse peer pubkey {}", e.to_string());
							continue;
						}
					};

					disconnect_peer(node, peer_pubkey);
				}
				"listchannels" => list_channels(&node),
				"listpayments" => list_payments(&node),
				"closechannel" => {
					let channel_id_str = words.next();
					if channel_id_str.is_none() {
						println!("ERROR: closechannel requires a channel ID: `closechannel <channel_id> <peer_pubkey>`");
						continue;
					}
					let channel_id_vec = hex::decode(channel_id_str.unwrap());
					if channel_id_vec.is_err() || channel_id_vec.as_ref().unwrap().len() != 32 {
						println!("ERROR: couldn't parse channel_id");
						continue;
					}
					let channel_id = match <[u8; 32]>::try_from(channel_id_vec.unwrap()) {
						Err(_) => {
							println!("Invalid channel ID {}", channel_id_str.unwrap());
							continue;
						}
						Ok(ci) => ChannelId(ci),
					};

					let peer_pubkey_str = words.next();
					if peer_pubkey_str.is_none() {
						println!("ERROR: closechannel requires a peer pubkey: `closechannel <channel_id> <peer_pubkey>`");
						continue;
					}
					let peer_pubkey = match PublicKey::from_str(peer_pubkey_str.unwrap()) {
						Ok(pubkey) => pubkey,
						Err(e) => {
							println!("ERROR: Could not parse peer pubkey {}", e.to_string());
							continue;
						}
					};

					close_channel(&node, &channel_id, peer_pubkey);
				}
				"listpeers" => list_peers(node),
				"newonchainaddress" => new_onchain_address(node),
				"getbalance" => get_balances(node),
				"nodeinfo" => node_info(&node),
				"quit" | "exit" => break,
				_ => println!("Unknown command. See `\"help\" for available commands."),
			}
		}
	}
}

fn help() {
	println!("\nCOMMANDS:");
	println!("  help\tShows a list of commands.");
	println!("  quit\tClose the application.");
	println!("\n  Channels:");
	println!("      openchannel pubkey@host:port <amt_sats>    Open a channel, fund it from the onchain wallet. Amount in millisats.");
	println!("      closechannel <channel_id> <peer_pubkey>");
	println!("      listchannels");
	println!("\n  Payments:");
	println!("      sendpayment <invoice>                      Send a payment");
	println!("      getinvoice <amt_msats> <description>       Get an invoice for receiving. Amount in millisats.");
	// println!("      keysend <dest_pubkey> <amt_msats>");
	println!("      listpayments");
	println!("\n  Onchain:");
	println!("      newonchainaddress                          For funding the onchain wallet");
	println!("\n  Peers:");
	println!("      connectpeer pubkey@host:port");
	println!("      disconnectpeer <peer_pubkey>");
	println!("      listpeers");
	println!("\n  Other:");
	println!(
		"      getbalance                                 Show lightning and onchain balances"
	);
	println!("      nodeinfo");
}

fn main() {
	let package_version = env!("CARGO_PKG_VERSION");
	let package_name = env!("CARGO_PKG_NAME");
	println!("App+version:  {}  v{}", package_name, package_version);

	let settings = match parse_startup_args() {
		Ok(user_args) => user_args,
		Err(()) => return,
	};

	let mut datadir = dirs::data_local_dir().unwrap_or(PathBuf::from("."));
	datadir.push(APP_NAME);
	datadir.push(&settings.ldk_storage_dir_path);

	let mut config = Config::default();
	config.storage_dir_path = datadir.to_str().unwrap().to_string();
	config.listening_address = Some(
		NetAddress::from_str(&format!("localhost:{}", settings.ldk_peer_listening_port)).unwrap(),
	);
	// config.log_level = LogLevel::Debug;
	println!(
		"    Data dir path:       \t{}  ({})",
		settings.ldk_storage_dir_path, config.storage_dir_path
	);

	let network_string = settings.network.to_string();
	let mut builder = Builder::from_config(config);
	builder.set_network(settings.network);
	let esplora_server = format!("https://blockstream.info/{network_string}/api");
	println!("    Esplora server:      \t{}", esplora_server);
	builder.set_esplora_server(esplora_server);
	let gossip_server = format!("https://rapidsync.lightningdevkit.org/{network_string}/snapshot");
	println!("    Rapid gossip server: \t{}", gossip_server);
	builder.set_gossip_source_rgs(gossip_server);

	let node = Arc::new(builder.build().unwrap());

	node.start().unwrap();
	println!("LDK Node started!");
	println!("    Node id:             \t{}", node.node_id());
	println!("    Listen address:      \t{}", get_listen_address(&node));
	println!("    Network:             \t{}", settings.network);

	// tokio runtime for spawning in background (event handler)
	let runtime = tokio::runtime::Runtime::new().unwrap();
	let node_clone = node.clone();
	let event_loop_handle = runtime.handle().spawn(async move {
		handle_events(&node_clone);
	});

	// handle interactive commands
	poll_for_user_input(&node);

	event_loop_handle.abort();

	node.stop().unwrap();
	println!("Node stopped");

	runtime.shutdown_timeout(std::time::Duration::from_millis(1000));
}
