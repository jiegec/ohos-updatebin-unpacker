use clap::Parser;
use memmap::MmapOptions;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to update.bin
    #[arg(short, long)]
    path: PathBuf,

    /// Path to extracted files
    #[arg(short, long)]
    output: Option<PathBuf>,
}

// reference: https://gitee.com/openharmony/update_packaging_tools
// from 178: 2 byte compinfo length
const COMPINFO_LEN_OFFSET: usize = 178;
// from 180: array of compinfo
const UPGRADE_FILE_HEADER_LEN: usize = 180;
// each comp info: 87 bytes
const UPGRADE_COMPINFO_SIZE_L2: usize = 87;
const COMPONENT_ADDR_SIZE_L2: usize = 32;
const COMPONENT_SIZE_OFFSET: usize = 11;
const UPGRADE_RESERVE_LEN: usize = 16;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(output) = &args.output {
        std::fs::create_dir_all(output)?;
    }

    let file = File::open(&args.path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    let compinfo_len =
        u16::from_le_bytes([mmap[COMPINFO_LEN_OFFSET], mmap[COMPINFO_LEN_OFFSET + 1]]) as usize;
    assert!(compinfo_len % UPGRADE_COMPINFO_SIZE_L2 == 0);
    let count = compinfo_len / UPGRADE_COMPINFO_SIZE_L2;
    println!("Component count: {}", count);

    let mut component_offset = UPGRADE_FILE_HEADER_LEN + compinfo_len + UPGRADE_RESERVE_LEN;

    let mut known_offset: HashMap<&str, (&str, usize)> = HashMap::new();
    known_offset.insert("/fw_dtb", ("dtb", 0x2160));
    known_offset.insert("/ramdisk", ("cpio.gz", 0x800));
    known_offset.insert("/updater_ramdisk", ("cpio.gz", 0x800));
    known_offset.insert("/updater_ramdisk_bak", ("cpio.gz", 0x800));
    known_offset.insert("/updater_vendor", ("cpio.gz", 0x800));
    known_offset.insert("/updater_vendor_bak", ("cpio.gz", 0x800));
    loop {
        // parse tlv
        let tag = u16::from_le_bytes([mmap[component_offset + 0x0], mmap[component_offset + 0x1]])
            as usize;
        match tag {
            8 => component_offset += 2,
            // TODO: handle this better
            _ => break,
        }
        let sign_len = u32::from_le_bytes([
            mmap[component_offset + 0x0],
            mmap[component_offset + 0x1],
            mmap[component_offset + 0x2],
            mmap[component_offset + 0x3],
        ]) as usize;
        let offset = component_offset + 4;
        println!(
            "Found signature: offset {}(0x{:x}), length {}(0x{:x})",
            offset, offset, sign_len, sign_len
        );
        component_offset += 4 + sign_len;
    }

    let mut offset = UPGRADE_FILE_HEADER_LEN;
    for _ in 0..count {
        // format(0x57 in length):
        // 0x00-0x20: file name
        // 0x2f-0x32: file size
        let name = &mmap[offset + 0x0..offset + 0x20];
        let name_str = std::ffi::CStr::from_bytes_until_nul(name)?.to_str()?;
        let base = COMPONENT_ADDR_SIZE_L2 + 4 + COMPONENT_SIZE_OFFSET;
        let size = u32::from_le_bytes([
            mmap[offset + base + 0x0],
            mmap[offset + base + 0x1],
            mmap[offset + base + 0x2],
            mmap[offset + base + 0x3],
        ]) as usize;
        println!(
            "Component name: {}, length: {}(0x{:x}), offset: {}(0x{:x})",
            name_str, size, size, component_offset, component_offset
        );
        offset += UPGRADE_COMPINFO_SIZE_L2;

        if let Some(output) = &args.output {
            let path = output.join(format!(".{}", name_str));
            let mut file = File::create(&path)?;
            file.write_all(&mmap[component_offset..component_offset + size])?;
            println!("Saved to {}", path.canonicalize()?.display());

            if let Some((suffix, offset)) = known_offset.get(name_str) {
                // extra raw content
                let path = output.join(format!(".{}.{}", name_str, suffix));
                let mut file = File::create(&path)?;
                file.write_all(&mmap[component_offset + offset..component_offset + size])?;
                println!("Saved to {}", path.canonicalize()?.display());
            }
        }

        component_offset += size;
    }
    Ok(())
}
