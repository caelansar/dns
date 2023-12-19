use std::{
    io::{Read, Seek, Write},
    net::{Ipv4Addr, Ipv6Addr},
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
            _ => ResultCode::NOERROR,
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

    pub fn read<R: Read + Seek>(&mut self, buffer: &mut packet::PacketReader<R>) -> Result<()> {
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

    pub fn write<W: Write>(&mut self, buffer: &mut packet::PacketWriter<W>) -> Result<usize> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.rd as u8)
                | ((self.tc as u8) << 1)
                | ((self.aa as u8) << 2)
                | (self.opcode << 3)
                | ((self.qr as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rcode as u8)
                | ((self.cd as u8) << 4)
                | ((self.ad as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.ra as u8) << 7),
        )?;

        buffer.write_u16(self.qd_count)?;
        buffer.write_u16(self.an_count)?;
        buffer.write_u16(self.ns_count)?;
        buffer.write_u16(self.ar_count)?;
        Ok(12)
    }
}
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    SOA,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
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

    pub fn read<R: Read + Seek>(&mut self, buffer: &mut packet::PacketReader<R>) -> Result<()> {
        self.name = buffer.read_name()?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        self.qclass = buffer.read_u16()?;

        Ok(())
    }

    pub fn write<W: Write>(&self, buffer: &mut packet::PacketWriter<W>) -> Result<usize> {
        let mut size = 0;
        size += buffer.write_name(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(self.qclass)?;
        Ok(size + 4)
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
#[derive(Debug, Clone)]
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
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    SOA {
        domain: String,
        m_name: String,
        r_name: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read<R: Read + Seek>(buffer: &mut packet::PacketReader<R>) -> Result<Self> {
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
                    (raw_addr) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let host = buffer.read_name()?;

                Ok(DnsRecord::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let cname = buffer.read_name()?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::SOA => {
                let m_name = buffer.read_name()?;
                let r_name = buffer.read_name()?;

                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;

                Ok(DnsRecord::SOA {
                    domain,
                    m_name,
                    r_name,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let host = buffer.read_name()?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            _ => {
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
    pub fn write<R: Write>(&self, buffer: &mut packet::PacketWriter<R>) -> Result<usize> {
        let mut size = 0;
        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                size += buffer.write_name(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
                size += 14;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                size += buffer.write_name(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                buffer.write_u16(16)?;
                size += 10;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                    size += 2;
                }
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                size += buffer.write_name(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                size += 8;

                buffer.write_u16(buffer.get_name_len(host) as u16)?;
                size += 2;
                size += buffer.write_name(host)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                size += buffer.write_name(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                size += 8;

                buffer.write_u16(buffer.get_name_len(host) as u16)?;
                size += 2;
                size += buffer.write_name(host)?;
            }
            DnsRecord::SOA {
                ref domain,
                ref m_name,
                ref r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl,
            } => {
                size += buffer.write_name(domain)?;
                buffer.write_u16(QueryType::SOA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                size += 8;

                size += buffer.write_name(m_name)?;
                size += buffer.write_name(r_name)?;

                buffer.write_u32(serial)?;
                buffer.write_u32(refresh)?;
                buffer.write_u32(retry)?;
                buffer.write_u32(expire)?;
                buffer.write_u32(minimum)?;
                size += 20;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                size += buffer.write_name(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                size += 8;

                buffer.write_u16(buffer.get_name_len(host) as u16 + 2)?;
                size += 4;

                buffer.write_u16(priority)?;
                size += 2;
                size += buffer.write_name(host)?;
            }
            _ => {
                println!("unknown record: {:?}", self);
            }
        }
        Ok(size)
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

    pub fn from_buffer<R: Read + Seek>(buffer: &mut packet::PacketReader<R>) -> Result<DnsPacket> {
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

    pub fn write<W: Write>(&mut self, buffer: &mut packet::PacketWriter<W>) -> Result<usize> {
        let mut size = 0;
        self.header.qd_count = self.questions.len() as u16;
        self.header.an_count = self.answers.len() as u16;
        self.header.ar_count = self.resources.len() as u16;
        self.header.ns_count = self.authorities.len() as u16;
        size += self.header.write(buffer)?;

        for question in &self.questions {
            size += question.write(buffer)?;
        }
        for rec in &self.answers {
            size += rec.write(buffer)?;
        }
        for rec in &self.authorities {
            size += rec.write(buffer)?;
        }
        for rec in &self.resources {
            size += rec.write(buffer)?;
        }

        Ok(size)
    }

    /// whether there is A record
    pub fn have_a(&self) -> bool {
        self.answers
            .iter()
            .filter(|record| matches!(record, DnsRecord::A { .. }))
            .count()
            > 0
    }

    /// get first A record from a packet
    pub fn get_first_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    /// get first CNAME record from a packet
    pub fn get_first_cname(&self) -> Option<String> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::CNAME { host, .. } => Some(host.to_owned()),
            _ => None,
        })
    }

    /// returns an iterator over all name servers in the authorities section,
    /// represented as (domain, host) tuples
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities.iter().filter_map(|record| {
            if let DnsRecord::NS { domain, host, .. } = record {
                if qname.ends_with(domain) {
                    return Some((domain.as_str(), host.as_str()));
                }
            }
            None
        })
    }

    /// assume that name servers often bundle the corresponding A records
    /// get it from resources section
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .cloned()
            .next()
    }

    /// get the host name of an appropriate name server. because in other cases
    /// there won't be any A records in the additional section
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}
