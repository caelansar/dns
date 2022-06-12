use std::{
    io::{Read, Seek},
    net::Ipv4Addr,
};
type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

use crate::packet;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+-----------+--+--+--+--+--+--+--+-----------+
// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
// +--+-----------+--+--+--+--+--+--+--+-----------+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // packet identifier 16 bits

    pub qr: bool,   // query response 1 bit
    pub opcode: u8, // operation code 4 bits
    pub aa: bool,   // authoritative answer 1 bit
    pub tc: bool,   // truncated answer 1 bit
    pub rd: bool,   // recursion disired 1 bit

    pub ra: bool,          // recursion available 1 bit
    pub z: bool,           // 1 bit
    pub ad: bool,          // authenticated data 1 bit
    pub cd: bool,          // checking disable 1 bit
    pub rcode: ResultCode, // response code 4 bits

    pub qd_count: u16, // question count 16 bits
    pub an_count: u16, // answer count 16 bits
    pub ns_count: u16, // authority count 16 bits
    pub ar_count: u16, // additional count 16 bits
}
impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: false,
            ad: false,
            cd: false,
            rcode: ResultCode::NOERROR,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }

    pub fn read<R: Read + Seek>(&mut self, buffer: &mut packet::PacketBufReader<R>) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.rd = (a & (1 << 0)) > 0;
        self.tc = (a & (1 << 1)) > 0;
        self.aa = (a & (1 << 2)) > 0;
        self.opcode = a >> 3;
        self.qr = (a & (1 << 7)) > 0;

        self.rcode = ResultCode::from_num(b);
        self.cd = (b & (1 << 4)) > 0;
        self.ad = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.ra = (b & (1 << 7)) > 0;

        self.qd_count = buffer.read_u16()?;
        self.an_count = buffer.read_u16()?;
        self.ns_count = buffer.read_u16()?;
        self.ar_count = buffer.read_u16()?;

        Ok(())
    }
}
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QNAME                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QTYPE                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QCLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn new() -> DnsQuestion {
        DnsQuestion {
            name: String::new(),
            qtype: QueryType::UNKNOWN(0),
            qclass: 0,
        }
    }

    pub fn read<R: Read + Seek>(&mut self, buffer: &mut packet::PacketBufReader<R>) -> Result<()> {
        self.name = buffer.read_name()?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        self.qclass = buffer.read_u16()?;

        Ok(())
    }
}

// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NAME                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    TYPE                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    CLASS                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    TTL                        |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    RDLENGTH                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    RDATA                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}
impl DnsRecord {
    pub fn read<R: Read + Seek>(buffer: &mut packet::PacketBufReader<R>) -> Result<DnsRecord> {
        let domain = buffer.read_name()?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    (raw_addr >> 24) as u8,
                    (raw_addr >> 16) as u8,
                    (raw_addr >> 8) as u8,
                    (raw_addr >> 0) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer<R: Read + Seek>(
        buffer: &mut packet::PacketBufReader<R>,
    ) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.qd_count {
            let mut question = DnsQuestion::new();
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.an_count {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.ns_count {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.ar_count {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }
}
