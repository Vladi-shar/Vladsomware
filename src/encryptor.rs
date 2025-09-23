use std::path::PathBuf;
use windows::{core::*, Win32::Security::Cryptography::*};

pub(crate) struct Encryptor {
    aes_handle: Owned<BCRYPT_ALG_HANDLE>,
    key_handle: Owned<BCRYPT_KEY_HANDLE>,
    pub(crate) key: Vec<u8>,
    key_object: Vec<u8>,
    pub(crate) key_file_name: String,
}

impl Encryptor {
    pub(crate) fn new() -> eframe::Result<Self, Error> {
        Ok(Self {
            aes_handle: Owned::default(),
            key_handle: Owned::default(),
            key: Vec::default(),
            key_object: Vec::default(),
            key_file_name: String::default(),
        })
    }
    fn export_key_data_blob(&mut self) -> Result<Vec<u8>> {
        unsafe {
            let mut cb = 0u32;
            BCryptExportKey(
                *self.key_handle,
                None,
                PCWSTR(BCRYPT_KEY_DATA_BLOB.as_ptr()),
                None,
                &mut cb,
                0,
            )
            .ok()?;

            let mut blob = vec![0u8; cb as usize];
            BCryptExportKey(
                *self.key_handle,
                None,
                PCWSTR(BCRYPT_KEY_DATA_BLOB.as_ptr()),
                Some(&mut blob),
                &mut cb,
                0,
            )
            .ok()?;

            Ok(blob)
        }
    }

    fn import_key_data_blob(&mut self, blob: &[u8]) -> Result<()> {
        unsafe {
            let mut object_len = [0u8; 4];
            let mut bytes_copied = 0;
            BCryptGetProperty(
                (*self.aes_handle).into(),
                BCRYPT_OBJECT_LENGTH,
                Some(&mut object_len),
                &mut bytes_copied,
                0,
            )
            .ok()?;
            let object_len = u32::from_le_bytes(object_len) as usize;
            self.key_object = vec![0u8; object_len];

            BCryptImportKey(
                (*self.aes_handle).into(),
                None,
                PCWSTR(BCRYPT_OPAQUE_KEY_BLOB.as_ptr()),
                &mut *self.key_handle,
                Some(&mut self.key_object),
                &blob,
                0,
            )
            .ok()?;
            Ok(())
        }
    }

    fn open_aes_gcm(&mut self) -> Result<Owned<BCRYPT_ALG_HANDLE>> {
        let mut aes = Owned::default();
        unsafe {
            BCryptOpenAlgorithmProvider(&mut *aes, BCRYPT_AES_ALGORITHM, None, Default::default())
                .ok()?;

            BCryptSetProperty(
                (*aes).into(),
                BCRYPT_CHAINING_MODE,
                BCRYPT_CHAIN_MODE_GCM.as_wide().align_to::<u8>().1,
                0,
            )
            .ok()?;
        }
        Ok(aes)
    }

    pub(crate) fn load_key(&mut self, key_path: &PathBuf) -> Result<()> {
        let blob = std::fs::read(key_path)?;
        self.aes_handle = self.open_aes_gcm()?;

        self.import_key_data_blob(&blob)?;
        self.key = blob;
        self.key_file_name = key_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        Ok(())
    }

    pub(crate) fn gen_key(&mut self, key_file_name: String) -> Result<()> {
        unsafe {
            let mut rng = Owned::default();
            BCryptOpenAlgorithmProvider(&mut *rng, BCRYPT_RNG_ALGORITHM, None, Default::default())
                .ok()?;

            self.aes_handle = self.open_aes_gcm()?;

            let mut object_len = [0u8; 4];
            let mut bytes_copied = 0;
            BCryptGetProperty(
                (*self.aes_handle).into(),
                BCRYPT_OBJECT_LENGTH,
                Some(&mut object_len),
                &mut bytes_copied,
                0,
            )
            .ok()?;
            let object_len = u32::from_le_bytes(object_len) as usize;
            let mut key_bytes = vec![0u8; object_len];
            let mut key_material = vec![0u8; 32];
            BCryptGenRandom((*rng).into(), &mut key_material, Default::default()).ok()?;

            BCryptGenerateSymmetricKey(
                *self.aes_handle,
                &mut *self.key_handle,
                Some(&mut key_bytes),
                key_material.as_mut_slice(),
                0,
            )
            .ok()?;

            self.key = self.export_key_data_blob()?;
            self.key_file_name = key_file_name;

            Ok(())
        }
    }
}
