use dns::dns::{DnsPacket, DnsQuestion, QueryType, ResultCode};
use dns::packet::{PacketReader, PacketWriter};
use std::io::Cursor;
use std::net::UdpSocket;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

/// Forwarded query to target server
fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // use public DNS
    let server = ("1.1.1.1", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut packet = DnsPacket::new();

    let mut question = DnsQuestion::new();
    question.name = qname.to_string();
    question.qtype = qtype;
    question.qclass = 1;

    packet.header.id = 6666;
    packet.header.qd_count = 1;
    packet.header.rd = true;
    packet.questions.push(question);

    let mut w = vec![0; 64];
    let mut req_buffer = PacketWriter::new(Cursor::new(&mut w));
    packet.write(&mut req_buffer)?;
    socket.send_to(&w, server)?;

    let mut rv = vec![0; 512];
    socket.recv_from(&mut rv)?;
    let mut buffer = PacketReader::new(Cursor::new(&mut rv));

    println!("response from public DNS: {:?}", buffer.get_ref());
    DnsPacket::from_buffer(&mut buffer)
}

/// Handle a single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut w = vec![0; 64];

    let (_, src) = socket.recv_from(&mut w)?;

    let mut req_buffer = PacketReader::new(Cursor::new(&mut w));
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // initialize response packet
    let mut packet = DnsPacket::new();
    // make sure use the same id as request
    packet.header.id = request.header.id;
    packet.header.rd = true;
    packet.header.ra = true;
    packet.header.qr = true;

    // normal case, exactly one question is present
    if let Some(question) = request.questions.pop() {
        println!("received query: {:?}", question);

        if let Ok(result) = lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.rcode = result.header.rcode;

            for rec in result.answers {
                println!("answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rcode = ResultCode::SERVFAIL;
        }
    }
    // make sure that a question is actually present
    else {
        packet.header.rcode = ResultCode::FORMERR;
    }

    let mut w = vec![0; 512];
    let mut res_buffer = PacketWriter::new(Cursor::new(&mut w));

    let len = packet.write(&mut res_buffer)?;
    let data = &res_buffer.get_ref()[..len];

    println!("write packet: {:?}", data,);
    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 5300))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => println!("handle query success"),
            Err(e) => eprintln!("error: {}", e),
        }
    }
}
