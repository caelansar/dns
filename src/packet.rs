use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct PacketBufReader<R: Read> {
    pub read: R,
}

impl<R: Read + Seek> PacketBufReader<R> {
    pub fn new(r: R) -> Self {
        Self { read: r }
    }

    // Step position forward
    pub fn step(&mut self, step: usize) -> Result<()> {
        self.read.seek(SeekFrom::Current(step as i64))?;
        Ok(())
    }

    // Read a single byte
    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.read.read_u8()?;
        Ok(b)
    }

    // Read 2 bytes
    pub fn read_u16(&mut self) -> Result<u16> {
        let b = self.read.read_u16::<BigEndian>()?;
        Ok(b)
    }

    // Read 4 bytes
    pub fn read_u32(&mut self) -> Result<u32> {
        let b = self.read.read_u32::<BigEndian>()?;
        Ok(b)
    }

    // Read a name
    pub fn read_name(&mut self) -> Result<String> {
        let mut jumped = false;
        let max_jumps = 20;
        let mut jumps_performed = 0;

        let mut first_jump_pos: Option<u64> = None;
        let mut name_part: Vec<String> = Vec::new();
        loop {
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }
            let len = self.read_u8()?;
            if (len & 0xC0) == 0xC0 {
                // get offset
                let b2 = self.read_u8()? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;

                // record current position
                let pos = self.read.stream_position()?;
                if first_jump_pos.is_none() {
                    first_jump_pos = Some(pos);
                }

                self.read.seek(SeekFrom::Start(offset as u64))?;

                // indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                // we are done
                if len == 0 {
                    break;
                }

                let mut b = vec![0u8; len as usize];
                self.read.read_exact(&mut b)?;
                name_part.push(String::from_utf8_lossy(&b).to_lowercase());
            }
        }

        if jumped {
            self.read.seek(SeekFrom::Start(first_jump_pos.unwrap()))?;
        }

        let rv = name_part.join(".");
        Ok(rv)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Cursor, Read};
    use super::PacketBufReader;

    #[test]
    fn packet_buffer_reader() {
        let data = vec![
            0x72, 0x6b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62,
            0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x04, 0xdc, 0xb5, 0x26,
            0x94, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x04, 0xdc,
            0xb5, 0x26, 0xfb,
        ];
        let mut pr = PacketBufReader {
            read: Cursor::new(data),
        };

        let mut header = [0u8; 12];
        pr.read.read(&mut header).unwrap();
        println!("{:?}", header);

        let s = pr.read_name().unwrap();
        println!("qname: {}", s);

        pr.read.consume(4);

        let s = pr.read_name().unwrap();
        println!("name {}", s);

        pr.read.consume(14);

        let s = pr.read_name().unwrap();
        println!("name {}", s);
    }
}
