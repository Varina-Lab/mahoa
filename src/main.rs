use std::io::{self, Write}; // Thư viện để tương tác với input/output

// Các thư viện mã hóa
use sha2::{Sha256, Digest};
use aes::Aes256;
use cfb_mode::Cfb;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

// Thư viện để tạo số ngẫu nhiên
use rand::RngCore;

// Thư viện cho Base64
use base64::{Engine as _, engine::general_purpose::STANDARD as Base64Engine};

// Định nghĩa kiểu cho Encrypter và Decrypter để code gọn hơn
type Aes256CfbEnc = Cfb<Aes256, cfb_mode::Encrypt>;
type Aes256CfbDec = Cfb<Aes256, cfb_mode::Decrypt>;

// Định nghĩa một kiểu lỗi chung cho toàn bộ chương trình
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Hàm tạo key từ password bằng SHA-256, tương đương hàm `key` trong Go
/// Rust sử dụng array `[u8; 32]` thay vì slice để an toàn hơn về kích thước
fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Hàm mã hóa, tương đương `encrypt` trong Go
fn encrypt(plaintext: &str, password: &str) -> Result<String> {
    let key = derive_key(password);
    
    // Tạo một Initialization Vector (IV) ngẫu nhiên. AES có block size là 16 bytes.
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Tạo một encrypter với key và IV vừa tạo
    let mut cipher = Aes256CfbEnc::new(&key.into(), &iv.into());

    // Dữ liệu cần mã hóa
    let mut buffer = plaintext.as_bytes().to_vec();
    cipher.encrypt(&mut buffer);

    // Ghép IV vào trước ciphertext: [IV][Ciphertext]
    let mut combined_result = iv.to_vec();
    combined_result.extend_from_slice(&buffer);

    // Encode toàn bộ kết quả bằng Base64
    Ok(Base64Engine.encode(&combined_result))
}

/// Hàm giải mã, tương đương `decrypt` trong Go
fn decrypt(encoded_text: &str, password: &str) -> Result<String> {
    let key = derive_key(password);
    
    // Giải mã Base64
    let decoded_data = Base64Engine.decode(encoded_text)?;
    
    // Kiểm tra độ dài dữ liệu, phải lớn hơn kích thước của IV
    if decoded_data.len() < 16 {
        return Err("Dữ liệu mã hóa không hợp lệ: quá ngắn".into());
    }

    // Tách IV và ciphertext ra. Đây là cách làm rất an toàn và hiệu quả trong Rust.
    let (iv_slice, ciphertext_slice) = decoded_data.split_at(16);

    // Tạo một decrypter với key và IV đã tách ra
    let mut cipher = Aes256CfbDec::new(&key.into(), iv_slice.into());

    // Giải mã
    let mut buffer = ciphertext_slice.to_vec();
    cipher.decrypt(&mut buffer);

    // Chuyển kết quả bytes về lại String
    // String::from_utf8 có thể lỗi nếu kết quả không phải là UTF-8 hợp lệ
    let plaintext = String::from_utf8(buffer)?;
    
    Ok(plaintext)
}

/// Hàm main, xử lý logic giao diện dòng lệnh
fn main() -> Result<()> {
    loop {
        print!("1 - Mã hóa\n2 - Giải mã\nChọn (hoặc gõ 'q' để thoát): ");
        io::stdout().flush()?; // Đảm bảo prompt được hiển thị ngay lập tức

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => {
                println!("-----------------------------");
                print!("Chuỗi cần mã hóa: ");
                io::stdout().flush()?;
                let mut text = String::new();
                io::stdin().read_line(&mut text)?;

                print!("Mật khẩu: ");
                io::stdout().flush()?;
                let mut password = String::new();
                io::stdin().read_line(&mut password)?;
                println!("-----------------------------------");

                match encrypt(text.trim(), password.trim()) {
                    Ok(encrypted) => println!("Kết quả mã hóa:\n{}", encrypted),
                    Err(e) => eprintln!("Lỗi mã hóa: {}", e),
                }
            },
            "2" => {
                println!("-----------------------------");
                print!("Chuỗi đã mã hóa: ");
                io::stdout().flush()?;
                let mut encoded = String::new();
                io::stdin().read_line(&mut encoded)?;

                print!("Mật khẩu: ");
                io::stdout().flush()?;
                let mut password = String::new();
                io::stdin().read_line(&mut password)?;
                println!("-----------------------------------");

                match decrypt(encoded.trim(), password.trim()) {
                    Ok(decrypted) => println!("Kết quả giải mã:\n{}", decrypted),
                    Err(e) => eprintln!("Lỗi giải mã: {}", e),
                }
            },
            "q" | "Q" => {
                println!("Tạm biệt!");
                break;
            }
            _ => {
                println!("Lựa chọn không hợp lệ. Vui lòng chọn 1 hoặc 2.");
            }
        }
        println!("\n"); // Thêm dòng trống cho dễ nhìn
    }
    Ok(())
}
