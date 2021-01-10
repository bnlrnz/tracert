use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, MutablePacket};
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::util;

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

// Receive timeout in seconds:
static TIMEOUT_SECS: Duration = Duration::from_secs(5);

// The lengths of the request message parts (IP / ICMP / total):
const REQ_IP_HEADER_LEN: usize = 5;
const REQ_ICMP_HEADER_LEN: usize = 8;
const REQ_ICMP_PAYLOAD_LEN: usize = 32;
const REQ_TOTAL_LEN: usize = (REQ_IP_HEADER_LEN * 4) + REQ_ICMP_HEADER_LEN + REQ_ICMP_PAYLOAD_LEN;

fn create_icmp_packet(
    destination: Ipv4Addr,
    ttl: u8,
    buffer_ip: &mut [u8],
) -> Result<MutableIpv4Packet, String> {
    let mut ipv4_packet = MutableIpv4Packet::new(buffer_ip)
        .ok_or_else(|| "Could not create MutableIpv4Packet".to_string())?;

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(REQ_IP_HEADER_LEN as u8);
    ipv4_packet.set_total_length(REQ_TOTAL_LEN as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(destination);

    let mut buffer_icmp = [0 as u8; REQ_ICMP_HEADER_LEN + REQ_ICMP_PAYLOAD_LEN];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer_icmp)
        .ok_or_else(|| "Could not create MutableEchoRequestPacket (icmp)".to_string())?;

    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_payload(&[42; REQ_ICMP_PAYLOAD_LEN]);

    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);

    ipv4_packet.set_payload(icmp_packet.packet_mut());

    Ok(ipv4_packet)
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("Please provide IPv4 address as argument.".to_string());
    }

    let ip_addr = Ipv4Addr::from_str(&args[1]).map_err(|e| format!("{}", e))?;
    let (mut tx, mut rx) = transport_channel(1024, Layer3(IpNextHeaderProtocols::Icmp))
        .map_err(|e| format!("Could not open channel: {} - Try run as root.", e))?;

    let mut rx = icmp_packet_iter(&mut rx);
    let mut curr_ip_addr = None;
    let mut ttl = 1;

    println!("Tracing route to {} ...", ip_addr);

    while curr_ip_addr != Some(IpAddr::V4(ip_addr)) {
        let mut buffer_ip = [0 as u8; REQ_TOTAL_LEN];
        let icmp_packet = create_icmp_packet(ip_addr, ttl, &mut buffer_ip)?;

        tx.send_to(icmp_packet, std::net::IpAddr::V4(ip_addr))
            .map_err(|e| format!("Could not send ICMP req: {}", e))?;

        curr_ip_addr = rx
            .next_with_timeout(TIMEOUT_SECS)
            .map_err(|e| format!("Coult not receive ICMP resp: {}", e))?
            .map(|(_, ip)| ip);

        let curr_output = curr_ip_addr.map_or_else(|| "<timeout>".to_string(), |ip| ip.to_string());
        println!("TTL: {} - {}", ttl, curr_output);

        ttl += 1;
    }

    Ok(())
}
