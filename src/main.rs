extern crate pnet;

use pnet::transport::TransportChannelType::Layer3;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, icmp_packet_iter};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::MutablePacket;
use pnet::util;

use std::str::FromStr;
use std::net::{Ipv4Addr, IpAddr};
use std::time::Duration;

// Receive timeout in seconds:
static TIMEOUT_SECS: Duration = Duration::from_secs(5);

// The lengths of the request message parts (IP / ICMP / total):
static REQ_IP_HEADER_LEN: usize = 20;
static REQ_ICMP_HEADER_LEN: usize = 8;
static REQ_TOTAL_LEN: usize = REQ_IP_HEADER_LEN + REQ_ICMP_HEADER_LEN;

fn create_icmp_packet<'a>(destination: Ipv4Addr, ttl: u8, buffer_ip: &'a mut [u8], buffer_icmp: &'a mut [u8]) -> Result<MutableIpv4Packet<'a>,String>{
    let mut ipv4_packet = match MutableIpv4Packet::new(buffer_ip){
        Some(packet) => packet,
        None => return Err("Could not create MutableIpv4Packet".to_string()),
    };

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(REQ_IP_HEADER_LEN as u8);
    ipv4_packet.set_total_length(REQ_TOTAL_LEN as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(destination);

    let mut icmp_packet = match MutableEchoRequestPacket::new(buffer_icmp){
        Some(packet) => packet,
        None => return Err("Could not create MutableEchoRequestPacket (icmp)".to_string()),
    };

    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    return Ok(ipv4_packet)
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("Please provide IPv4 address as argument.".to_string());
    }

    let ip_addr = match Ipv4Addr::from_str(&args[1]){
        Ok(ip_addr) => ip_addr,
        Err(e) => return Err(format!("{}", e)),
    };

    let (mut tx, mut rx) = match transport_channel(1024, Layer3(IpNextHeaderProtocols::Icmp)){
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("Could not open channel: {}", e)),
    };
    
    let mut results = vec![];
    let mut rx = icmp_packet_iter(&mut rx);
    let mut ttl = 1;
    let mut prev_addr: Option<IpAddr> = None;
    loop {
        let mut buffer_ip = [0 as u8; 40];
        let mut buffer_icmp = [0 as u8; 40];

        let icmp_packet = create_icmp_packet(ip_addr, ttl, &mut buffer_ip, &mut buffer_icmp)?;
        let _ = match tx.send_to(icmp_packet, std::net::IpAddr::V4(ip_addr)){
            Ok(_) => {},
            Err(e) => return Err(format!("Could not send ICMP req: {}", e)),
        };

        if let Ok(result) = rx.next_with_timeout(TIMEOUT_SECS) {
            let (_, ip_addr) = match result{
                Some(tup) => tup,
                None => return Err(format!("timeout receiving icmp packet")),
            };
            if Some(ip_addr) == prev_addr{
                break;
            }
            prev_addr = Some(ip_addr);
            results.push((ttl, ip_addr.to_string()));
        }
        ttl += 1;
    }

    results.sort_by(|a,b| a.0.cmp(&b.0));

    for (ttl, ip_addr) in results {
        println!("TTL: {} - {}", ttl, ip_addr.to_string());
    }

    Ok(())
}
