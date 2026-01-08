use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    execute,
    style::{Color, Print, SetForegroundColor},
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType, size},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write, stdout, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use rand::RngCore;
use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use zeroize::Zeroize;
use chrono::Local;
use argon2::Argon2;

#[derive(Debug, Clone)]
enum VaultError {
    FileNotFound(String),
    EncryptionError(String),
    DecryptionError,
    IOError(String),
    CompressionError(String),
    CorruptedFile,
    TarError(String),
    InvalidPath,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VaultError::FileNotFound(p) => write!(f, "File not found: {}", p),
            VaultError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            VaultError::DecryptionError => write!(f, "Decryption failed (Wrong key?)"),
            VaultError::IOError(e) => write!(f, "IO Error: {}", e),
            VaultError::CompressionError(e) => write!(f, "Compression error: {}", e),
            VaultError::CorruptedFile => write!(f, "File corrupted or wrong key"),
            VaultError::TarError(e) => write!(f, "Archive error: {}", e),
            VaultError::InvalidPath => write!(f, "Invalid path"),
        }
    }
}

struct App {
    path: String,
    pass: String,
    logs: Vec<String>,
    is_pass: bool,
    busy: bool,
    last_error: Option<VaultError>,
}

impl App {
    fn new() -> Self {
        Self {
            path: String::new(),
            pass: String::new(),
            logs: vec!["shhcrypt Engine v1.0.0 Active".into()],
            is_pass: false,
            busy: false,
            last_error: None,
        }
    }

    fn add_log(&mut self, msg: &str) {
        let timestamp = Local::now().format("%H:%M:%S").to_string();
        let log_msg = format!("[{}] {}", timestamp, msg);
        self.logs.push(log_msg);
        if self.logs.len() > 100 { self.logs.remove(0); }
    }

    fn set_error(&mut self, err: VaultError, target: &str) {
        let err_msg = format!("FAIL on {}: {}", target, err);
        self.add_log(&err_msg);
        self.last_error = Some(err);
    }

    fn clear(&mut self) {
        self.path.zeroize();
        self.path.clear();
        self.pass.zeroize();
        self.pass.clear();
        self.is_pass = false;
        self.last_error = None;
        self.add_log("Session cleared.");
    }
}

fn derive_key(password: &str) -> Vec<u8> {
    let salt = b"static_salt_for_shhcrypt_v1.0";
    let mut output_key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt, &mut output_key).expect("Key Derivation Error");
    output_key.to_vec()
}

fn secure_delete(path: &Path) -> Result<(), VaultError> {
    if !path.exists() { return Ok(()); }
    if path.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| VaultError::IOError(e.to_string()))? {
            secure_delete(&entry.map_err(|e| VaultError::IOError(e.to_string()))?.path())?;
        }
        fs::remove_dir(path).map_err(|e| VaultError::IOError(e.to_string()))?;
    } else {
        let file_size = fs::metadata(path).map_err(|e| VaultError::IOError(e.to_string()))?.len();
        let mut file = OpenOptions::new().write(true).open(path).map_err(|e| VaultError::IOError(e.to_string()))?;
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; 65536];
        for _ in 0..3 {
            file.seek(SeekFrom::Start(0)).map_err(|e| VaultError::IOError(e.to_string()))?;
            let mut written = 0;
            while written < file_size {
                let chunk_size = std::cmp::min(65536, (file_size - written) as usize);
                rng.fill_bytes(&mut buffer[..chunk_size]);
                file.write_all(&buffer[..chunk_size]).map_err(|e| VaultError::IOError(e.to_string()))?;
                written += chunk_size as u64;
            }
        }
        file.flush().ok();
        drop(file);
        fs::remove_file(path).map_err(|e| VaultError::IOError(e.to_string()))?;
    }
    Ok(())
}

fn process_file(path_str: &str, mut password: String) -> Result<String, VaultError> {
    let clean_path = path_str.trim().replace("'", "").replace("\"", "");
    let path = PathBuf::from(&clean_path);
    if !path.exists() { return Err(VaultError::FileNotFound(clean_path)); }

    let key_bytes = derive_key(&password);
    password.zeroize();
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| VaultError::EncryptionError("Cipher Failure".into()))?;

    let parent = path.parent().unwrap_or(Path::new("."));

    if clean_path.ends_with(".shh") {
        let mut file = File::open(&path).map_err(|e| VaultError::IOError(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        file.read_exact(&mut nonce_bytes).map_err(|_| VaultError::CorruptedFile)?;
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted).map_err(|e| VaultError::IOError(e.to_string()))?;

        let compressed = cipher.decrypt(Nonce::from_slice(&nonce_bytes), Payload::from(&encrypted[..]))
            .map_err(|_| VaultError::DecryptionError)?;

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut tar_data = Vec::new();
        decoder.read_to_end(&mut tar_data).map_err(|e| VaultError::CompressionError(e.to_string()))?;

        let temp_tar = parent.join(".shh_tmp.tar");
        fs::write(&temp_tar, tar_data).map_err(|e| VaultError::IOError(e.to_string()))?;
        tar::Archive::new(File::open(&temp_tar).map_err(|e| VaultError::IOError(e.to_string()))?)
            .unpack(parent).map_err(|e| VaultError::TarError(e.to_string()))?;

        fs::remove_file(&temp_tar).ok();
        secure_delete(&path)?;
        Ok(format!("DECRYPTED: {}", clean_path))
    } else {
        let temp_tar = parent.join(".shh_tmp.tar");
        let mut builder = tar::Builder::new(File::create(&temp_tar).map_err(|e| VaultError::IOError(e.to_string()))?);
        let name = path.file_name().ok_or(VaultError::InvalidPath)?;
        if path.is_dir() { builder.append_dir_all(name, &path) } else { builder.append_path_with_name(&path, name) }
            .map_err(|e| VaultError::TarError(e.to_string()))?;
        builder.finish().map_err(|e| VaultError::TarError(e.to_string()))?;

        let tar_bytes = fs::read(&temp_tar).map_err(|e| VaultError::IOError(e.to_string()))?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&tar_bytes).map_err(|e| VaultError::CompressionError(e.to_string()))?;
        let compressed = encoder.finish().map_err(|e| VaultError::CompressionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce_bytes), Payload::from(&compressed[..]))
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        let out_path = format!("{}.shh", clean_path);
        let mut out_file = File::create(out_path).map_err(|e| VaultError::IOError(e.to_string()))?;
        out_file.write_all(&nonce_bytes).map_err(|e| VaultError::IOError(e.to_string()))?;
        out_file.write_all(&encrypted).map_err(|e| VaultError::IOError(e.to_string()))?;

        fs::remove_file(&temp_tar).ok();
        secure_delete(&path)?;
        Ok(format!("ENCRYPTED: {}", clean_path))
    }
}

fn render(out: &mut io::Stdout, app: &App, w: u16, h: u16) -> io::Result<()> {
    execute!(out, Clear(ClearType::All))?;
    let color = if app.busy { Color::Red } else if app.last_error.is_some() { Color::Yellow } else { Color::Cyan };
    execute!(out, SetForegroundColor(color))?;
    
    execute!(out, cursor::MoveTo(0,0), Print(format!("╔{}╗", "═".repeat(w as usize - 2))))?;
    execute!(out, cursor::MoveTo(0,h-1), Print(format!("╚{}╝", "═".repeat(w as usize - 2))))?;
    for y in 1..h-1 { execute!(out, cursor::MoveTo(0,y), Print("║"), cursor::MoveTo(w-1,y), Print("║"))?; }

    let brand = "CipherStray/shhcrypt";
    let exit_hint = "exit = q";
    execute!(out, cursor::MoveTo(w - brand.len() as u16 - 2, 1), SetForegroundColor(Color::DarkGrey), Print(brand))?;
    execute!(out, cursor::MoveTo(w - exit_hint.len() as u16 - 2, 2), Print(exit_hint))?;

    let max_text_width = (w - 12) as usize; 

    let display_path = if app.path.len() > max_text_width {
        format!("...{}", &app.path[app.path.len() - max_text_width + 3..])
    } else {
        app.path.clone()
    };
    execute!(out, cursor::MoveTo(2,2), SetForegroundColor(Color::Green), Print("TARGET: "), SetForegroundColor(Color::White), Print(display_path))?;
    
    if app.is_pass { 
        execute!(out, cursor::MoveTo(2,4), SetForegroundColor(Color::Yellow), Print("KEY: "), SetForegroundColor(Color::White), Print("*".repeat(app.pass.len())))?; 
    }
    
    if let Some(err) = &app.last_error { 
        let err_str = format!("ERROR: {}", err);
        let display_err = if err_str.len() > max_text_width { &err_str[..max_text_width] } else { &err_str };
        execute!(out, cursor::MoveTo(2,6), SetForegroundColor(Color::Red), Print(display_err))?; 
    }

    let log_y = 8;
    for (i, log) in app.logs.iter().rev().take((h - log_y - 2) as usize).enumerate() {
        let display_log = if log.len() > max_text_width {
            format!("{}...", &log[..max_text_width - 3])
        } else {
            log.clone()
        };
        execute!(out, cursor::MoveTo(2, log_y + i as u16), SetForegroundColor(Color::DarkGrey), Print(format!("> {}", display_log)))?;
    }
    
    out.flush()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut out = stdout();
    let mut app = App::new();
    execute!(out, cursor::Hide)?;
    loop {
        let (w, h) = size()?;
        render(&mut out, &app, w, h)?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') if !app.busy && !app.is_pass && app.path.is_empty() => break,
                    KeyCode::Esc => app.clear(),
                    KeyCode::Enter => {
                        if !app.is_pass { if !app.path.is_empty() { app.is_pass = true; } }
                        else if !app.pass.is_empty() {
                            app.busy = true;
                            render(&mut out, &app, w, h)?;
                            let p = app.path.clone();
                            let pass = app.pass.clone();
                            match process_file(&p, pass) {
                                Ok(msg) => { 
                                    app.add_log(&msg); 
                                    app.path.clear(); 
                                    app.pass.zeroize(); 
                                    app.pass.clear(); 
                                    app.is_pass = false; 
                                    app.last_error = None; 
                                }
                                Err(e) => { 
                                    app.set_error(e, &p); 
                                    app.pass.zeroize(); 
                                    app.pass.clear(); 
                                }
                            }
                            app.busy = false;
                        }
                    }
                    KeyCode::Char(c) => if !app.busy { if app.is_pass { app.pass.push(c) } else { app.path.push(c) } },
                    KeyCode::Backspace => if !app.busy { if app.is_pass { app.pass.pop(); } else { app.path.pop(); } },
                    _ => {}
                }
            }
        }
    }
    execute!(out, cursor::Show, Clear(ClearType::All), cursor::MoveTo(0,0))?;
    disable_raw_mode()?;
    Ok(())
}
