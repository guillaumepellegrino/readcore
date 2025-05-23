use elf::ElfBytes;
use elf::endian::AnyEndian;
use elf::endian::EndianParse;
use clap::Parser;

fn align4(size: usize) -> usize {
    if size & 0x03 != 0 {
        (size & 0xFFFFFFFC) + 4
    }
    else {
        size
    }
}

/// Read coredump (Proof of Concept).
/// (it works only for ARM 32bits, for now)
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Interface Name
    core: String,

    /// Config file name
    #[arg(short, long)]
    address: Vec<u32>,

    /// Staging directory
    #[arg(short, long)]
    stagingdir: Option<String>,
}

fn addr2line_read(stagingdir: &str, filename: &str, reladdr: u64) {
    let file = format!("{}/{}", stagingdir, filename);
    let loader = addr2line::Loader::new(&file).unwrap();
    let location = loader.find_location(reladdr).unwrap().unwrap();
    let srcfile = location.file.unwrap_or_default();
    let srcline= location.line.unwrap_or_default();
    let sym = loader.find_symbol(reladdr).unwrap_or_default();
    println!("{}() at {}:{}", sym, srcfile, srcline);
}

pub struct Note<'a> {
    pub r#type: u32,
    pub name: &'a str,
    pub desc: &'a [u8],
}

impl<'a> Note<'a> {
    pub fn read(parser: &impl EndianParse, offset: &mut usize, data: &'a [u8]) -> Self {
        let namesz = parser.parse_u32_at(offset, data).unwrap() as usize;
        let descsz = parser.parse_u32_at(offset, data).unwrap() as usize;
        let r#type = parser.parse_u32_at(offset, data).unwrap();
        let name = &data[*offset..*offset+namesz].split_last().unwrap().1;
        let name = std::str::from_utf8(&name).unwrap();
        let desc = &data[*offset+align4(namesz)..*offset+namesz+descsz];
        *offset += align4(namesz);
        *offset += align4(descsz);
        Self {
            r#type,
            name,
            desc,
        }
    }
}

fn main() {
    let mut args = Args::parse();

    let path = std::path::PathBuf::from(args.core);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
    let parser = file.ehdr.endianness;

    // Get the ELF file's COREDUMP NOTE
    let program_headers = file.segments().expect("No Program Headers");
    let phdr_note = program_headers.iter()
        .find(|phdr|{phdr.p_type == elf::abi::PT_NOTE})
        .expect("COREDUMP NOTE not found");

    let notes = file
        .segment_data(&phdr_note)
        .expect("Should be able to get note section data");

    let mut offset = 0;
    loop {
        let note = Note::read(&parser, &mut offset, notes);
        if note.r#type == elf::abi::NT_PRSTATUS as u32 {
            let mut prstatus = vec![];
            let mut offset = 0;
            while let Ok(word) = parser.parse_u32_at(&mut offset, note.desc) {
                prstatus.push(word);
            }
            //println!("prstatus={:08x?}", prstatus);
            let sp_idx = 31;
            let lr_idx = 32;
            let pc_idx = 33;
            let sp = prstatus[sp_idx];
            let lr = prstatus[lr_idx];
            let pc = prstatus[pc_idx];
            println!("Coredump registers:");
            println!("  PC=0x{:08x?}", pc);
            println!("  LR=0x{:08x?}", lr);
            println!("  SP=0x{:08x?}", sp);
            if args.address.is_empty() {
                args.address.push(pc);
                args.address.push(lr);
            }
        }

        if offset >= notes.len() {
            break;
        }
    }

    let mut offset = 0;
    loop {
        let note = Note::read(&parser, &mut offset, notes);
        //println!("note: type={}, name={} descsz={}", note.r#type, note.name, note.desc.len());
        if note.r#type == elf::abi::NT_FILE as u32 {
            let files = note.r#desc;
            let mut offset = 0;
            let count = parser.parse_u32_at(&mut offset, files).unwrap() as usize;
            let _page_size = parser.parse_u32_at(&mut offset, files).unwrap();

            let names_offset = offset + count * 12;
            let mut names = vec![];
            for name in files[names_offset..].split(|x| *x == 0) {
                let name = std::str::from_utf8(&name).unwrap();
                names.push(name);
            }

            for i in 0..count {
                let start = parser.parse_u32_at(&mut offset, files).unwrap();
                let end = parser.parse_u32_at(&mut offset, files).unwrap();
                let file_offset = parser.parse_u32_at(&mut offset, files).unwrap();

                for address in &args.address {
                    let address = *address;
                    if address >= start && address < end {
                        let relative = address - start;
                        //println!("0x{:02x} 0x{:02x} 0x{:02x} {}", start, end, file_offset, names[i]);
                        //println!("0x{:02x} is at {}+0x{:02x}", address, names[i], relative);
                        if let Some(stagingdir) = &args.stagingdir {
                            print!("[0x{:08x}] ", address);
                            addr2line_read(&stagingdir, names[i], relative as u64);
                        }
                    }
                }
                if args.address.is_empty() {
                    println!("file 0x{:02x} 0x{:02x} 0x{:02x} {}", start, end, file_offset, names[i]);
                }
            }
        }

        if offset >= notes.len() {
            break;
        }
    }
}
