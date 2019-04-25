use std::{error, net::SocketAddr, str};

use byteorder::{ByteOrder, NetworkEndian};
use crc32fast::Hasher as Crc32Hasher;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};

pub type Error = Box<error::Error + Send + Sync>;

#[derive(Debug)]
pub struct StunBindingRequest {
    pub transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
    pub remote_user: String,
    pub server_user: String,
}

pub fn parse_stun_binding_request(bytes: &[u8]) -> Option<StunBindingRequest> {
    if bytes.len() < STUN_HEADER_LEN {
        return None;
    }

    let stun_type = NetworkEndian::read_u16(&bytes[0..2]);
    if stun_type != StunType::BindingRequest as u16 {
        return None;
    }

    let length = NetworkEndian::read_u16(&bytes[2..4]) as usize;
    if length < 4 || STUN_HEADER_LEN + length > bytes.len() {
        return None;
    }

    if bytes[4..8] != STUN_COOKIE {
        return None;
    }

    let mut transaction_id = [0; STUN_TRANSACTION_ID_LEN];
    transaction_id.copy_from_slice(&bytes[8..STUN_HEADER_LEN]);

    let mut offset = STUN_HEADER_LEN;
    while offset < length - 4 {
        let payload_type = NetworkEndian::read_u16(&bytes[offset..offset + 2]);
        let payload_len = NetworkEndian::read_u16(&bytes[offset + 2..offset + 4]) as usize;
        offset += 4;
        let padded_len = (payload_len + STUN_ALIGNMENT - 1) & !(STUN_ALIGNMENT - 1);
        if offset + padded_len > length {
            return None;
        }
        if payload_type == StunAttributeType::User as u16 {
            let server_and_remote_user = &bytes[offset..offset + payload_len];
            let colon = server_and_remote_user.iter().position(|&c| c == b':')?;
            let server_user = &server_and_remote_user[0..colon];
            let remote_user = &server_and_remote_user[colon + 1..];
            if server_user.len() > STUN_MAX_IDENTIFIER_LEN
                || remote_user.len() > STUN_MAX_IDENTIFIER_LEN
            {
                return None;
            }
            let server_user = str::from_utf8(server_user).ok()?.to_owned();
            let remote_user = str::from_utf8(remote_user).ok()?.to_owned();

            return Some(StunBindingRequest {
                transaction_id,
                remote_user,
                server_user,
            });
        }
        offset += padded_len;
    }
    None
}

pub fn write_stun_success_response(
    transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
    remote_addr: SocketAddr,
    passwd: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    const ATTRIBUTE_MARKER_LEN: usize = 4;
    const IPV4_ADDR_ATTRIBUTE_LEN: usize = 8;
    const IPV6_ADDR_ATTRIBUTE_LEN: usize = 20;
    const INTEGRITY_ATTRIBUTE_LEN: usize = 20;
    const FINGERPRINT_ATTRIBUTE_LEN: usize = 4;

    let addr_attribute_len = if remote_addr.is_ipv4() {
        IPV4_ADDR_ATTRIBUTE_LEN
    } else {
        IPV6_ADDR_ATTRIBUTE_LEN
    };
    let content_len_integrity =
        ATTRIBUTE_MARKER_LEN * 2 + addr_attribute_len + INTEGRITY_ATTRIBUTE_LEN;
    let content_len = content_len_integrity + ATTRIBUTE_MARKER_LEN + FINGERPRINT_ATTRIBUTE_LEN;

    if STUN_HEADER_LEN + content_len > out.len() {
        return Err("output buffer too small for STUN response".into());
    }

    let (header, rest) = out.split_at_mut(STUN_HEADER_LEN);
    let (addr_attribute, rest) = rest.split_at_mut(ATTRIBUTE_MARKER_LEN + addr_attribute_len);
    let (integrity_attribute, fingerprint_attribute) =
        rest.split_at_mut(ATTRIBUTE_MARKER_LEN + INTEGRITY_ATTRIBUTE_LEN);

    NetworkEndian::write_u16(&mut header[0..2], StunType::SuccessResponse as u16);
    NetworkEndian::write_u16(&mut header[2..4], content_len_integrity as u16);
    header[4..8].copy_from_slice(&STUN_COOKIE);
    header[8..20].copy_from_slice(&transaction_id);

    NetworkEndian::write_u16(
        &mut addr_attribute[0..2],
        StunAttributeType::XorMappedAddress as u16,
    );
    NetworkEndian::write_u16(&mut addr_attribute[2..4], addr_attribute_len as u16);
    match remote_addr {
        SocketAddr::V4(remote_addr) => {
            addr_attribute[4] = 0;
            addr_attribute[5] = StunAddressFamily::IPV4 as u8;
            NetworkEndian::write_u16(&mut addr_attribute[6..8], remote_addr.port());
            xor_range(&mut addr_attribute[6..8], &STUN_COOKIE);
            addr_attribute[8..12].copy_from_slice(&remote_addr.ip().octets());
            xor_range(&mut addr_attribute[8..12], &STUN_COOKIE);
        }
        SocketAddr::V6(remote_addr) => {
            addr_attribute[4] = 0;
            addr_attribute[5] = StunAddressFamily::IPV6 as u8;
            NetworkEndian::write_u16(&mut addr_attribute[6..8], remote_addr.port());
            xor_range(&mut addr_attribute[6..8], &STUN_COOKIE);
            addr_attribute[8..24].copy_from_slice(&remote_addr.ip().octets());
            xor_range(&mut addr_attribute[8..12], &STUN_COOKIE);
            xor_range(&mut addr_attribute[12..24], &transaction_id);
        }
    }

    let key = PKey::hmac(passwd)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
    signer.update(header)?;
    signer.update(addr_attribute)?;
    let mut hmac = [0; INTEGRITY_ATTRIBUTE_LEN];
    signer.sign(&mut hmac)?;

    NetworkEndian::write_u16(
        &mut integrity_attribute[0..2],
        StunAttributeType::MessageIntegrity as u16,
    );
    NetworkEndian::write_u16(
        &mut integrity_attribute[2..4],
        INTEGRITY_ATTRIBUTE_LEN as u16,
    );
    integrity_attribute[4..].copy_from_slice(&hmac);

    NetworkEndian::write_u16(&mut header[2..4], content_len as u16);

    let mut crc = Crc32Hasher::new();
    crc.update(&header);
    crc.update(&addr_attribute);
    crc.update(&integrity_attribute);
    let crc = crc.finalize();

    NetworkEndian::write_u16(
        &mut fingerprint_attribute[0..2],
        StunAttributeType::Fingerprint as u16,
    );
    NetworkEndian::write_u16(
        &mut fingerprint_attribute[2..4],
        FINGERPRINT_ATTRIBUTE_LEN as u16,
    );
    NetworkEndian::write_u32(&mut fingerprint_attribute[4..8], crc ^ STUN_CRC_XOR);

    Ok(STUN_HEADER_LEN + content_len)
}

enum StunType {
    BindingRequest = 0x0001,
    SuccessResponse = 0x0101,
}

enum StunAttributeType {
    User = 0x06,
    MessageIntegrity = 0x08,
    XorMappedAddress = 0x20,
    Fingerprint = 0x8028,
}

enum StunAddressFamily {
    IPV4 = 0x01,
    IPV6 = 0x02,
}

const STUN_TRANSACTION_ID_LEN: usize = 12;
const STUN_MAX_IDENTIFIER_LEN: usize = 128;
const STUN_HEADER_LEN: usize = 20;
const STUN_ALIGNMENT: usize = 4;
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const STUN_CRC_XOR: u32 = 0x5354554e;

fn xor_range(target: &mut [u8], xor: &[u8]) {
    for i in 0..target.len() {
        target[i] ^= xor[i];
    }
}
