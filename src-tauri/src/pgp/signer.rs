use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::serialize::stream::{Message, Signer as OpenpgpSigner};
use openpgp::policy::StandardPolicy;
use openpgp::armor::Writer as ArmorWriter;
use std::path::{Path, PathBuf};
use std::fs;
use std::io::Write;

pub struct PgpManifestSigner;

impl PgpManifestSigner {
    /// Produces an ASCII-armored detached PGP signature (`-----BEGIN PGP SIGNATURE----- ...`) for arbitrary data
    pub fn sign_detached(data: &[u8], private_key_pem: &str) -> Result<String, String> {
        let p = &StandardPolicy::new();
        let cert = openpgp::cert::CertParser::from_bytes(private_key_pem.as_bytes())
            .map_err(|e| format!("Failed to initialize cert parser: {}", e))?
            .next()
            .ok_or_else(|| "No certificate found in private key data".to_string())?
            .map_err(|e| format!("Failed to parse private key: {}", e))?;

        let keypair = cert
            .keys()
            .with_policy(p, None)
            .secret()
            .for_signing()
            .next()
            .ok_or_else(|| "No valid signing key found in certificate".to_string())?
            .key()
            .clone()
            .into_keypair()
            .map_err(|e| format!("Failed to create signing keypair: {}", e))?;

        let mut sink = Vec::new();
        {
            let mut armored = ArmorWriter::new(&mut sink, openpgp::armor::Kind::Signature)
                .map_err(|e| format!("Failed to create armored writer: {}", e))?;
            let message = Message::new(&mut armored);
            let mut signer = OpenpgpSigner::new(message, keypair)
                .map_err(|e| format!("Failed to initialize PGP signer builder: {}", e))?
                .detached()
                .build()
                .map_err(|e| format!("Failed to build PGP signer: {}", e))?;
            signer
                .write_all(data)
                .map_err(|e| format!("Failed to write data to signer: {}", e))?;
            signer
                .finalize()
                .map_err(|e| format!("Failed to finalize PGP signature: {}", e))?;
            armored
                .finalize()
                .map_err(|e| format!("Failed to finalize ASCII armor writer: {}", e))?;
        }

        String::from_utf8(sink).map_err(|e| format!("Invalid UTF-8 in PGP signature: {}", e))
    }

    /// Reads a file from disk, signs its contents, and saves an ASCII-armored detached signature as `<file>.asc`
    pub fn sign_file(file_path: &Path, private_key_pem: &str) -> Result<PathBuf, String> {
        let data = fs::read(file_path)
            .map_err(|e| format!("Failed to read file {} for signing: {}", file_path.display(), e))?;
        
        let sig_pem = Self::sign_detached(&data, private_key_pem)?;
        
        let sig_path = file_path.with_extension(format!(
            "{}.asc",
            file_path.extension().and_then(|s| s.to_str()).unwrap_or("txt")
        ));
        
        fs::write(&sig_path, sig_pem)
            .map_err(|e| format!("Failed to write PGP signature file {}: {}", sig_path.display(), e))?;
            
        Ok(sig_path)
    }
}
