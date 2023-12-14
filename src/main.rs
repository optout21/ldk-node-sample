mod utils;

use crate::utils::{millisats_to_sats, parse_peer_info};
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::bitcoin::Network;
use ldk_node::io::sqlite_store::SqliteStore;
use ldk_node::lightning::ln::ChannelId;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::{Builder, Config, LogLevel, Node};
use std::convert::TryFrom;
use std::env;
use std::io;
use std::io::Write;
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

const APP_NAME: &str = "ldk-node-sample";

#[derive(Debug, Eq, PartialEq)]
struct AppSettings {
	ldk_storage_dir_path: String,
	ldk_peer_listening_port: u16,
	network: Network,
	/// Esplora server URL
	esplora_url: String,
	log_level: Option<LogLevel>,
}

const DEFAULT_ESPLORA_SERVER: &str = "blockstream.info";

impl AppSettings {
	fn default() -> Self {
		Self {
			ldk_storage_dir_path: "datadir".to_owned(),
			ldk_peer_listening_port: 9735,
			network: Network::Testnet,
			esplora_url: Self::default_esplora_url(DEFAULT_ESPLORA_SERVER, Network::Testnet),
			log_level: None,
		}
	}

	fn default_esplora_url(esplora_server: &str, network: Network) -> String {
		format!(
			"https://{}/{}api",
			esplora_server,
			if network == Network::Bitcoin { "".to_owned() } else { format!("{}/", network) }
		)
	}
}

fn parse_startup_args() -> Result<AppSettings, ()> {
	let args: Vec<String> = env::args().collect();
	parse_startup_args_string(&args)
}

fn parse_startup_args_string(args: &Vec<String>) -> Result<AppSettings, ()> {
	println!("Usage: {APP_NAME} [<datadir>] [--port <listening_port>] [--network <network>|--testnet|--mainnet] [--esplora <esplora_url>] [--log <log_level>]");

	let mut settings = AppSettings::default();
	settings.esplora_url = "".to_owned(); // set later

	let mut arg_idx = 1;

	if let Some(dd) = args.get(arg_idx) {
		// check for case when datadir option was missing,starts with '-'
		if dd[0..1].to_owned() == "-".to_owned() {
			println!("Error: Invalid datadir {dd}");
			return Err(());
		}
		settings.ldk_storage_dir_path = dd.to_owned();
	};
	arg_idx = arg_idx + 1;

	loop {
		match args.get(arg_idx) {
			None => break,
			Some(s) => {
				println!("s {arg_idx} {s}");
				if *s == "--port".to_owned() {
					arg_idx = arg_idx + 1;
					if let Some(Ok(n)) = args.get(arg_idx).map(|s| s.parse::<u16>()) {
						settings.ldk_peer_listening_port = n;
					}
				} else if *s == "--testnet".to_owned() {
					settings.network = Network::Testnet;
				} else if *s == "--mainnet".to_owned() {
					settings.network = Network::Bitcoin;
				} else if *s == "--network".to_owned() {
					arg_idx = arg_idx + 1;
					if let Some(ns) = args.get(arg_idx) {
						if *ns == "testnet".to_owned() {
							settings.network = Network::Testnet;
						} else if *ns == "mainnet".to_owned() {
							settings.network = Network::Bitcoin;
						} else {
							println!("Error: Unsupported network {ns}");
							return Err(());
						}
					}
				} else if *s == "--esplora".to_owned() {
					arg_idx = arg_idx + 1;
					if let Some(url) = args.get(arg_idx) {
						settings.esplora_url = url.to_owned();
					}
				} else if *s == "--log".to_owned() {
					arg_idx = arg_idx + 1;
					if let Some(level) = args.get(arg_idx) {
						match level.as_str() {
							"error" => settings.log_level = Some(LogLevel::Error),
							"warn" => settings.log_level = Some(LogLevel::Warn),
							"info" => settings.log_level = Some(LogLevel::Info),
							"debug" => settings.log_level = Some(LogLevel::Debug),
							"trace" => settings.log_level = Some(LogLevel::Trace),
							"none" | _ => settings.log_level = None,
						}
					}
				} else {
					println!("Error: Unknown argument {s}, ignoring");
				}
				arg_idx = arg_idx + 1;
			}
		}
	}

	// fill default esplora server if needed
	if settings.esplora_url.len() == 0 {
		settings.esplora_url =
			AppSettings::default_esplora_url(DEFAULT_ESPLORA_SERVER, settings.network);
	}

	Ok(settings)
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

fn connect_peer(node: &Node<SqliteStore>, peer_pubkey: PublicKey, peer_addr: SocketAddress) {
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
	if let Some(addrs) = node.listening_addresses() {
		if addrs.len() >= 1 {
			return addrs[0].to_string();
		}
	}
	"(not listening)".to_string()
}

fn open_channel(
	node: &Node<SqliteStore>, node_id: PublicKey, peer_addr: SocketAddress, chan_amt_sat: u64,
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

fn send_payment(node: &Node<SqliteStore>, invoice: &Bolt11Invoice) {
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

					let invoice = match Bolt11Invoice::from_str(invoice_str.unwrap()) {
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
	config.listening_addresses = Some(
		vec![SocketAddress::from_str(&format!("localhost:{}", settings.ldk_peer_listening_port)).unwrap()],
	);
	if let Some(log_level) = settings.log_level {
		config.log_level = log_level;
	}
	println!(
		"    Data dir path:       \t{}  ({})",
		settings.ldk_storage_dir_path, config.storage_dir_path
	);

	let network_string = settings.network.to_string();
	let mut builder = Builder::from_config(config);
	builder.set_network(settings.network);
	println!("    Esplora server:      \t{}", settings.esplora_url);
	builder.set_esplora_server(settings.esplora_url);
	let gossip_server = format!("https://rapidsync.lightningdevkit.org/{network_string}/snapshot");
	println!("    Rapid gossip server: \t{}", gossip_server);
	builder.set_gossip_source_rgs(gossip_server);
	if let Some(log_level) = settings.log_level {
		println!("    Log level:           \t{}", log_level);
	}

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

#[cfg(test)]
mod test {
	use super::{parse_startup_args_string, AppSettings, LogLevel, Network};

	fn build_args(args1: Vec<&str>) -> Vec<String> {
		let mut res = vec!["executablename".to_owned()];
		for s in args1 {
			res.push(s.to_owned());
		}
		res
	}

	#[test]
	fn test_parse_startup_args_string() {
		assert_eq!(
			parse_startup_args_string(&vec![]).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "datadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert_eq!(
			parse_startup_args_string(&build_args(vec![])).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "datadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir"])).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert!(parse_startup_args_string(&build_args(vec!["--port"])).is_err());
		assert!(parse_startup_args_string(&build_args(vec!["--unsupported"])).is_err());
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir", "--port", "666"])).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 666,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert!(parse_startup_args_string(&build_args(vec!["--port", "not a number"])).is_err());
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir", "--network", "testnet"]))
				.unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir", "--network", "mainnet"]))
				.unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Bitcoin,
				esplora_url: "https://blockstream.info/api".to_owned(),
				log_level: None,
			}
		);
		assert!(parse_startup_args_string(&build_args(vec![
			"mydatadir",
			"--network",
			"unsupported"
		]))
		.is_err());
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir", "--testnet"])).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir", "--mainnet"])).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Bitcoin,
				esplora_url: "https://blockstream.info/api".to_owned(),
				log_level: None,
			}
		);
		assert_eq!(
			parse_startup_args_string(&build_args(vec![
				"mydatadir",
				"--esplora",
				"http://myesploraserver/v9/testnet/api"
			]))
			.unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "http://myesploraserver/v9/testnet/api".to_owned(),
				log_level: None,
			}
		);
		assert_eq!(
			parse_startup_args_string(&build_args(vec!["mydatadir", "--log", "debug"])).unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 9735,
				network: Network::Testnet,
				esplora_url: "https://blockstream.info/testnet/api".to_owned(),
				log_level: Some(LogLevel::Debug),
			}
		);

		// all options
		assert_eq!(
			parse_startup_args_string(&build_args(vec![
				"mydatadir",
				"--log",
				"info",
				"--esplora",
				"https://mempool.space/api",
				"--network",
				"mainnet",
				"--port",
				"666",
			]))
			.unwrap(),
			AppSettings {
				ldk_storage_dir_path: "mydatadir".to_owned(),
				ldk_peer_listening_port: 666,
				network: Network::Bitcoin,
				esplora_url: "https://mempool.space/api".to_owned(),
				log_level: Some(ldk_node::LogLevel::Info),
			}
		);
	}
}
