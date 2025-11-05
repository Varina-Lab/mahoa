use aes::Aes256;
use base64::{engine::general_purpose::STANDARD, Engine};
use cfb_mode::{Decryptor, Encryptor};
use cipher::{AsyncStreamCipher, KeyIvInit};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

fn encrypt(plaintext: &str, password: &str) -> Result<String> {
    let key = derive_key(password);
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Encryptor::<Aes256>::new(&key.into(), &iv.into());
    let mut buffer = plaintext.as_bytes().to_vec();
    cipher.encrypt(&mut buffer);

    let mut combined_result = iv.to_vec();
    combined_result.extend_from_slice(&buffer);

    Ok(STANDARD.encode(&combined_result))
}

fn decrypt(encoded_text: &str, password: &str) -> Result<String> {
    let key = derive_key(password);
    let decoded_data = STANDARD.decode(encoded_text)?;

    if decoded_data.len() < 16 {
        return Err("Invalid encrypted data: too short".into());
    }

    let (iv_slice, ciphertext_slice) = decoded_data.split_at(16);
    let cipher = Decryptor::<Aes256>::new(&key.into(), iv_slice.into());
    let mut buffer = ciphertext_slice.to_vec();
    cipher.decrypt(&mut buffer);

    String::from_utf8(buffer).map_err(|e| e.into())
}

fn prompt_for_input(prompt_text: &str) -> io::Result<String> {
    print!("{}", prompt_text);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn main() -> Result<()> {
    loop {
        let choice = prompt_for_input("1 - Encrypt\n2 - Decrypt\nChoose an option (or 'q' to quit): ")?;

        match choice.as_str() {
            "1" => {
                println!("-----------------------------");
                let text = prompt_for_input("Enter text to encrypt: ")?;
                let password = prompt_for_input("Enter password: ")?;
                println!("-----------------------------------");
                match encrypt(&text, &password) {
                    Ok(encrypted) => println!("Encrypted result:\n{}", encrypted),
                    Err(e) => eprintln!("Encryption error: {}", e),
                }
            }
            "2" => {
                println!("-----------------------------");
                let encoded = prompt_for_input("Enter encrypted text: ")?;
                let password = prompt_for_input("Enter password: ")?;
                println!("-----------------------------------");
                match decrypt(&encoded, &password) {
                    Ok(decrypted) => println!("Decrypted result:\n{}", decrypted),
                    Err(e) => eprintln!("Decryption error: {}", e),
                }
            }
            "q" | "Q" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Invalid option. Please choose 1 or 2.");
            }
        }
        println!("\n");
    }
    Ok(())
}
