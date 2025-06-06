use std::fs;
use std::io::{BufRead, BufReader, Error};

fn main() {
    process_proc();
}


fn process_proc() { 
    // if process not found, ignore
    if let Ok(mut buf) = retrieve_proc(&String::from("udp"), 1) {
        let mut line = String::new();
        while buf.read_line(&mut line).unwrap_or_default() > 0 {
            println!("{}", line);
            line.clear();
        }
    }
}


/// Opens network process file from /proc
/// 
/// # Arguments 
/// * `protocol` - Protocol to analyse (e.g. UDP, TCP)
/// * `pid` - Target process ID
///
/// # Errors 
/// Returns `io::Error` if:
/// - Process doesn't exist 
/// - Access denied 
/// - Filesystem error
fn retrieve_proc(protocol: &str, pid: i32) -> Result<BufReader<fs::File>, Error> {
    let path = format!("/proc/{}/net/{}", pid, protocol);
    let fd = fs::File::open(path)?;
    Ok(BufReader::new(fd))
}

// store snapshot somehow
// inet_request in rust 
