use std::env;
use std::io::{self, ErrorKind, BufRead, BufReader};
use tokio::*;
use rayon::*;
use std::fs::File;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ssh2::*;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize};

struct CommandArgs {
    use_telnet: bool,
    use_ssh: bool,
    use_http: bool,
    pass_wordlist: String,
    user_wordlist: String,
    username: String,
}

impl Default for CommandArgs {
    fn default() -> Self {
        Self {
            use_telnet: false,
            use_ssh: false,
            use_http: false,
            pass_wordlist: "".to_string(),
            user_wordlist: "".to_string(),
            username: "".to_string(),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: hydric <mode> <user> <password> <ip> <port>; check --help for further switches");
        return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
    }

    let mut cmd_args = CommandArgs::default();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-t" => cmd_args.use_telnet = true,
            "-s" => cmd_args.use_ssh = true,
            "-h" => cmd_args.use_http = true,
            "-p" => {
                i += 1;
                if i >= args.len() {
                    return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
                }
                cmd_args.pass_wordlist = args[i].clone();
            },
            "-P" => {
                i += 1;
                if i >= args.len() {
                    return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
                }
                cmd_args.pass_wordlist = args[i].clone();
            },
            "-u" => {
                i += 1;
                if i >= args.len() {
                    return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
                }
                cmd_args.username = args[i].clone();
            },
            "-U" => {
                i += 1;
                if i >= args.len() {
                    return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
                }
                cmd_args.user_wordlist = args[i].clone();
            },
            _ => return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments"))),
        }
        i += 1;
    }

    if !cmd_args.use_ssh && !cmd_args.use_telnet && !cmd_args.use_http {
        return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
    }

    if cmd_args.username.is_empty() {
        return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
    }

    if cmd_args.pass_wordlist.is_empty() {
        return Err(Box::new(io::Error::new(ErrorKind::InvalidInput, "Invalid Arguments")));
    }

    Ok(())
}


fn ssh_brute_force(ip: &str, port: u16, username: &str, password_file: &str) -> Option<(String, String)> {
    let passwords = read_password_file(password_file)?;
    let attempts = Arc::new(AtomicUsize::new(0));
    let success = Arc::new(AtomicBool::new(false));
    let output = Arc::new(Mutex::new(vec![]));

    passwords.par_iter().for_each(|password| {
        if success.load(Ordering::Relaxed) {
            return;
        }

        let addr = format!("{}:{}", ip, port);
        let stream = TcpStream::connect(addr).unwrap();
        let mut session = ssh2::Session::new().unwrap();
        session.set_tcp_stream(stream);
        session.handshake().unwrap();
        let mut channel = session.channel_session().unwrap();

        let username_password = format!("{}:{}", username, password);

        channel.exec("hostname").unwrap();
        channel.write_all(username_password.as_bytes()).unwrap();

        let mut reader = BufReader::new(channel);

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        attempts.fetch_add(1, Ordering::Relaxed);

        let mut output_guard = output.lock().unwrap();
        output_guard.push(format!("{}:{} - {}:{} - {}", ip, port, username, password, line.trim()));
        drop(output_guard);

        if line.trim() == "Authentication succeeded" {
            success.store(true, Ordering::Relaxed);
            return;
        }

        std::thread::sleep(Duration::from_secs(5));
    });

    let output_guard = output.lock().unwrap();
    for line in &*output_guard {
        println!("{}", line);
    }
    drop(output_guard);

    if success.load(Ordering::Relaxed) {
        Some((username.to_owned(), passwords[0].to_owned()))
    } else {
        println!("No credentials were found after {} attempts", attempts.load(Ordering::Relaxed));
        None
    }
}

fn read_password_file(password_file: &str) -> Option<Vec<String>> {
    let file = std::fs::File::open(password_file).ok()?;
    let reader = BufReader::new(file);
    let passwords = reader.lines().map(|line| line.unwrap()).collect::<Vec<String>>();
    Some(passwords)
}

/* fn ssh_brute_force(ip: &str, port: i32, userlist_path: &str, passlist_path: &str) {
    let user_list = read_wordlist(userlist_path);
    let pass_list = read_wordlist(passlist_path);
    let mut found = false;

    let start_time = Instant::now();

    user_list.par_iter().for_each(|user| {
        if found {
            return;
        }

        pass_list.par_iter().for_each(|pass| {
            if found {
                return;
            }

            let client_config = ClientConfig::new().password(pass).to_owned();
            let tcp = TcpStream::connect((ip, port));
            let ssh = match tcp {
                Ok(stream) => {
                    let ssh = SshSession::new(stream, &client_config);
                    match ssh {
                        Ok(ssh) => ssh,
                        Err(_) => return,
                    }
                }
                Err(_) => return,
            };

            let auth = ssh.authenticate(user);
            match auth {
                Ok(_) => {
                    println!("Success! Username: {}, Password: {}", user, pass);
                    found = true;
                }
                Err(_) => {
                    // Auth failed
                }
            }
        });
    });

    let elapsed = start_time.elapsed();
    println!(
        "Tried {} username and password combinations in {}.{}s",
        user_list.len() * pass_list.len(),
        elapsed.as_secs(),
        elapsed.subsec_nanos()
    );

    if !found {
        println!("No credentials found.");
    }
} */