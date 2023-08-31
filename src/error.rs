use std::{error::Error, fmt, fmt::Display, net::Ipv6Addr};

#[derive(Debug)]
pub enum YggErrors {
    InvalidSourceAddress(Ipv6Addr, Ipv6Addr),
    UnderSizedIpv6Packet(usize),
    InvalidPacket,
    InvalidDestinationAddress(Ipv6Addr),
    SendError(String),
}
impl Display for YggErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YggErrors::InvalidSourceAddress(addr, src_addr) => {
                write!(f, "Invalid source address {addr} {src_addr}")
            }
            YggErrors::UnderSizedIpv6Packet(size) => {
                write!(f, "Undersized IPv6 packet, length: {size}")
            }
            YggErrors::InvalidPacket => write!(f, "Invalid packet"),
            YggErrors::InvalidDestinationAddress(addr) => {
                write!(f, "Invalid destination address {addr}")
            }
            YggErrors::SendError(msg) => write!(f, "Send error: {msg}"),
        }
    }
}
impl Error for YggErrors {}
