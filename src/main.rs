use std::fs::File;
use std::io::Cursor;
use std::net::UdpSocket;

use dns::dns::{DnsPacket, DnsQuestion, QueryType};
use dns::packet;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let qname = "www.sohu.com";
    let qtype = QueryType::A;

    let server = ("1.1.1.1", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 10888))?;

    let mut packet = DnsPacket::new();

    let mut question = DnsQuestion::new();
    question.name = qname.to_string();
    question.qtype = qtype;
    question.qclass = 1;

    packet.header.id = 1234;
    packet.header.qd_count = 1;
    packet.header.rd = true;
    packet.questions.push(question);

    let mut w = vec![0; 64];
    let mut req_buffer = packet::PacketWriter::new(Cursor::new(&mut w));
    packet.write(&mut req_buffer)?;
    println!("write: {:?}", &w);

    socket.send_to(&w, server)?;

    let mut rv = vec![0; 512];
    socket.recv_from(&mut rv)?;
    let mut buffer = packet::PacketReader::new(Cursor::new(&mut rv));

    // let f = File::open("packet/response_packet.txt")?;
    // let mut buffer = packet::PacketBufReader::new(f);

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
