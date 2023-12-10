use dns::dns::{DnsPacket, DnsQuestion, QueryType, ResultCode};
use dns::packet::{PacketReader, PacketWriter};
use std::io::Cursor;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

/// Recursive lookup name
fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // starting with a root server
    // https://www.internic.net/domain/named.root
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    let mut name = qname.to_owned();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, name, ns);

        let server = (ns, 53);
        let response = lookup(name.as_str(), qtype, server)?;

        if !response.answers.is_empty() && response.header.rcode == ResultCode::NOERROR {
            // if name servers not return any A record, and have CNAME record,
            // try to lookup it instead.
            if let Some(cname) = response.get_first_cname() {
                name = cname;
                continue;
            }
            // find it
            if response.have_a() {
                return Ok(response);
            }
        }

        // the authoritative name servers telling us that the name doesn't exist.
        if response.header.rcode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // fast path: find a new nameserver based on NS and a corresponding A
        // record in the additional section.
        if let Some(resolved_ns) = response.get_resolved_ns(name.as_str()) {
            ns = resolved_ns;
            continue;
        }

        // slow path: have to resolve the ip of a NS record.
        let unresolved_ns = match response.get_unresolved_ns(name.as_str()) {
            Some(x) => x,
            None => return Ok(response),
        };

        // lookup the IP of an name server.
        let recursive_response = recursive_lookup(&unresolved_ns, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_first_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

/// Forwarded query to a delegate name server
fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    // would block the execution because the data is
    // not ready to be read or the operation is not
    // cannot be completed immediately, so we need
    // to set read/write timeout
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;

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

    let packet = DnsPacket::from_buffer(&mut buffer);
    println!("response from public DNS: {:?}", packet);
    packet
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

        match recursive_lookup(&question.name, question.qtype) {
            Ok(result) => {
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
            }
            Err(e) => {
                println!("lookup error: {}", e);
                packet.header.rcode = ResultCode::SERVFAIL;
            }
        }
    }
    // make sure that a question is actually present
    else {
        packet.header.rcode = ResultCode::FORMERR;
    }

    let mut w = vec![0; 4096];
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
