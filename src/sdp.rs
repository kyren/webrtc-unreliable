use std::{error, str};

use futures::{future, Future, Stream};
use rand::Rng;

pub type Error = Box<error::Error + Send + Sync>;

#[derive(Debug)]
pub struct SdpFields {
    pub ice_ufrag: String,
    pub ice_passwd: String,
    pub mid: String,
}

pub fn parse_sdp_fields<I, E, S>(body: S) -> impl Future<Item = SdpFields, Error = Error>
where
    I: AsRef<[u8]>,
    S: Stream<Item = I, Error = E>,
    E: error::Error + Send + Sync + 'static,
{
    const MAX_SDP_LINE: usize = 512;

    #[derive(Default, Debug)]
    struct MaybeSdpFields {
        ice_ufrag: Option<String>,
        ice_passwd: Option<String>,
        mid: Option<String>,
    }

    fn after_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
        if s.starts_with(prefix) {
            Some(&s[prefix.len()..])
        } else {
            None
        }
    }

    let mut line_buf = Vec::new();
    line_buf.reserve(MAX_SDP_LINE);

    body.map_err(Error::from)
        .fold(
            MaybeSdpFields::default(),
            move |mut fields, chunk| -> Result<_, Error> {
                for &c in chunk.as_ref() {
                    if c == b'\r' || c == b'\n' {
                        if !line_buf.is_empty() {
                            if let Some(ice_ufrag) = after_prefix(&line_buf, b"a=ice-ufrag:") {
                                fields.ice_ufrag = Some(String::from_utf8(ice_ufrag.to_vec())?);
                            }
                            if let Some(ice_passwd) = after_prefix(&line_buf, b"a=ice-pwd:") {
                                fields.ice_passwd = Some(String::from_utf8(ice_passwd.to_vec())?);
                            }
                            if let Some(mid) = after_prefix(&line_buf, b"a=mid:") {
                                fields.mid = Some(String::from_utf8(mid.to_vec())?);
                            }
                            line_buf.clear();
                        }
                    } else {
                        if line_buf.len() < MAX_SDP_LINE {
                            line_buf.push(c);
                        }
                    }
                }
                Ok(fields)
            },
        )
        .and_then(|maybe_fields| {
            match (
                maybe_fields.ice_ufrag,
                maybe_fields.ice_passwd,
                maybe_fields.mid,
            ) {
                (Some(ice_ufrag), Some(ice_passwd), Some(mid)) => future::ok(SdpFields {
                    ice_ufrag,
                    ice_passwd,
                    mid,
                }),
                _ => future::err(Error::from("not all SDP fields provided")),
            }
        })
}

pub fn gen_sdp_response<R: Rng>(
    rng: &mut R,
    cert_fingerprint: &str,
    server_ip: &str,
    server_is_ipv6: bool,
    server_port: u16,
    ufrag: &str,
    pass: &str,
    remote_mid: &str,
) -> String {
    format!(
        "{{\"answer\":{{\"sdp\":\"v=0\\r\\n\
         o=- {rand1} 1 IN {ipv} {port}\\r\\n\
         s=-\\r\\n\
         t=0 0\\r\\n\
         m=application {port} UDP/DTLS/SCTP webrtc-datachannel\\r\\n\
         c=IN {ipv} {ip}\\r\\n\
         a=ice-lite\\r\\n\
         a=ice-ufrag:{ufrag}\\r\\n\
         a=ice-pwd:{pass}\\r\\n\
         a=fingerprint:sha-256 {fingerprint}\\r\\n\
         a=ice-options:trickle\\r\\n\
         a=setup:passive\\r\\n\
         a=mid:{mid}\\r\\n\
         a=sctp-port:{port}\\r\\n\",\
         \"type\":\"answer\"}},\"candidate\":{{\"sdpMLineIndex\":0,\
         \"sdpMid\":\"{mid}\",\"candidate\":\"candidate:1 1 UDP {rand2} {ip} {port} \
         typ host\"}}}}",
        rand1 = rng.gen::<u32>(),
        rand2 = rng.gen::<u32>(),
        fingerprint = cert_fingerprint,
        ip = server_ip,
        port = server_port,
        ufrag = ufrag,
        pass = pass,
        mid = remote_mid,
        ipv = if server_is_ipv6 { "IP6" } else { "IP4" },
    )
}
