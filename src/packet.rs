use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::Deref,
};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct PacketReader<R> {
    pub read: R,
}

impl<R: Read> Deref for PacketReader<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}

impl<R: Read + Seek> PacketReader<R> {
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
        let mut buf = [0u8; 1];
        self.read.read_exact(&mut buf)?;
        Ok(u8::from_be_bytes(buf))
    }

    // Read 2 bytes
    pub fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    // Read 4 bytes
    pub fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
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

pub struct PacketWriter<W: Write> {
    pub write: W,
}

impl<W: Write> Deref for PacketWriter<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.write
    }
}

impl<W: Write> PacketWriter<W> {
    pub fn new(w: W) -> Self {
        Self { write: w }
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write.write_all(val.to_be_bytes().as_slice())?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write.write_all(val.to_be_bytes().as_slice())?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write.write_all(val.to_be_bytes().as_slice())?;

        Ok(())
    }

    pub fn get_name_len(&self, name: impl AsRef<str>) -> usize {
        let mut size = 0;
        for part in name.as_ref().split('.') {
            size += 1;
            size += part.as_bytes().len();
        }
        size += 1;
        size
    }

    pub fn write_name(&mut self, name: impl AsRef<str>) -> Result<usize> {
        let mut size = 0;
        for part in name.as_ref().split('.') {
            self.write_u8(part.len() as u8)?;
            size += 1;
            size += self.write.write(part.as_bytes())?;
        }
        size += 1;
        self.write_u8(0)?;
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketReader, PacketWriter};
    use std::io::{BufReader, Cursor, Read, Seek};

    #[test]
    fn packet_buffer_reader() {
        let data = vec![
            0x72, 0x6b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62,
            0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x04, 0xdc, 0xb5, 0x26,
            0x94, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x04, 0xdc,
            0xb5, 0x26, 0xfb,
        ];
        let mut pr = PacketReader {
            read: BufReader::new(Cursor::new(data)),
        };

        let mut header = [0u8; 12];
        pr.read.read_exact(&mut header).unwrap();
        println!("{:?}", header);

        let s = pr.read_name().unwrap();
        assert_eq!("baidu.com", s);
        println!("position1 {}", pr.read.stream_position().unwrap());

        pr.read.read_exact(&mut [0u8; 4]).unwrap();

        let s = pr.read_name().unwrap();
        assert_eq!("baidu.com", s);
        println!("position2 {}", pr.read.stream_position().unwrap());

        pr.read.read_exact(&mut [0u8; 14]).unwrap();

        let s = pr.read_name().unwrap();
        assert_eq!("baidu.com", s);
        println!("position3 {}", pr.read.stream_position().unwrap());
    }

    #[test]
    fn packet_write() {
        let mut v = vec![0; 10];
        let w = Cursor::new(&mut v);
        let domain_name = "baidu.com";
        let mut pw = PacketWriter { write: w };
        pw.write_name(domain_name).unwrap();
        assert_eq!(&vec![5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0], &v);
    }
}
