/// Non-core logic utils, mainly parsing.
///
use ldk_node::bitcoin::secp256k1::PublicKey;
use ldk_node::NetAddress;
use std::str::FromStr;

pub(crate) fn hex_to_compressed_pubkey(hex: &str) -> Option<PublicKey> {
	if hex.len() != 33 * 2 {
		return None;
	}
	let data = match hex::decode(hex) {
		Ok(vec) => vec,
		Err(_) => return None,
	};
	match PublicKey::from_slice(&data) {
		Ok(pk) => Some(pk),
		Err(_) => None,
	}
}

pub(crate) fn parse_peer_info(
	peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, NetAddress), std::io::Error> {
	let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split("@");
	let pubkey = pubkey_and_addr.next();
	let peer_addr_str = pubkey_and_addr.next();
	if peer_addr_str.is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
		));
	}

	let addr = NetAddress::from_str(peer_addr_str.unwrap());
	if addr.is_err() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: couldn't parse pubkey@host:port into a network address",
		));
	}

	let pubkey = hex_to_compressed_pubkey(pubkey.unwrap());
	if pubkey.is_none() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::Other,
			"ERROR: unable to parse given pubkey for node",
		));
	}

	Ok((pubkey.unwrap(), addr.unwrap()))
}

pub(crate) fn millisats_to_sats(amount_msat: u64) -> u64 {
	(amount_msat as f64 / 1000f64).floor() as u64
}
