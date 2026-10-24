//! BatchActivation SOAP encoding and parsing, from pinned ActivationWs source.
#![cfg_attr(not(test), allow(dead_code))]
use super::binary::invalid;
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use roxmltree::{Document, Node, ParsingOptions};
use sha2::Sha256;
use std::io;
#[cfg_attr(not(windows), allow(dead_code))]
pub const ACTION: &str = "http://www.microsoft.com/BatchActivationService/BatchActivate";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SERVICE: &str = "http://www.microsoft.com/BatchActivationService";
const REQUEST: &str = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";
const RESPONSE: &str = "http://www.microsoft.com/DRM/SL/BatchActivationResponse/1.0";
pub const MAX_RESPONSE: usize = 1024 * 1024;
#[derive(Clone, Copy)]
pub enum RequestType {
    Confirmation,
    Remaining,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Confirmation(String),
    Remaining(u32),
}
fn escaped(value: &str) -> io::Result<String> {
    if value.len() > 4096 || value.chars().any(|c| !matches!(c, '\t'|'\n'|'\r'|' '..='\u{d7ff}'|'\u{e000}'..='\u{fffd}'|'\u{10000}'..='\u{10ffff}')) {
        return Err(invalid("invalid activation request text"));
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\r', "&#xD;"))
}
pub fn request(kind: RequestType, iid: &str, epid: &str) -> io::Result<String> {
    if epid.is_empty() {
        return Err(invalid("empty extended product ID"));
    }
    let epid = escaped(epid)?;
    let (kind, iid) = match kind {
        RequestType::Confirmation => {
            if iid.is_empty() || iid.len() > 128 || !iid.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("invalid installation ID"));
            }
            (1, format!("<IID>{iid}</IID>"))
        }
        RequestType::Remaining => (2, String::new()),
    };
    // The digest authenticates these exact UTF-16LE bytes, with no BOM/NUL.
    let inner = format!(
        "<ActivationRequest xmlns=\"{REQUEST}\"><VersionNumber>2.0</VersionNumber><RequestType>{kind}</RequestType><Requests><Request><PID>{epid}</PID>{iid}</Request></Requests></ActivationRequest>"
    );
    let bytes: Vec<_> = inner.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut mac = Hmac::<Sha256>::new_from_slice(include_bytes!(
        "../../../vendor/mas/native/tsforge-activation-mac.bin"
    ))
    .map_err(|_| invalid("invalid activation MAC key"))?;
    mac.update(&bytes);
    let digest = STANDARD.encode(mac.finalize().into_bytes());
    let payload = STANDARD.encode(bytes);
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"{SOAP}\"><soap:Body><BatchActivate xmlns=\"{SERVICE}\"><request><Digest>{digest}</Digest><RequestXml>{payload}</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>"
    ))
}
fn document(text: &str) -> io::Result<Document<'_>> {
    if text.len() > MAX_RESPONSE {
        return Err(invalid("activation XML exceeds size limit"));
    }
    Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 10000,
            ..Default::default()
        },
    )
    .map_err(io::Error::other)
}
fn scalar(node: Node<'_, '_>) -> io::Result<String> {
    if node.children().any(|n| n.is_element()) {
        return Err(invalid("nested activation response scalar"));
    }
    Ok(node
        .children()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect())
}
fn one<'a, 'input>(
    root: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> io::Result<Option<Node<'a, 'input>>> {
    let mut nodes = root
        .descendants()
        .filter(|n| n.has_tag_name((namespace, name)));
    let first = nodes.next();
    if nodes.next().is_some() {
        return Err(invalid("ambiguous activation response field"));
    }
    Ok(first)
}
pub fn decode_text(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() > MAX_RESPONSE {
        return Err(invalid("activation response exceeds size limit"));
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        let bytes = &bytes[2..];
        if !bytes.len().is_multiple_of(2) {
            return Err(invalid("odd UTF-16 response length"));
        }
        let words: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| {
                if little {
                    u16::from_le_bytes(*b)
                } else {
                    u16::from_be_bytes(*b)
                }
            })
            .collect();
        String::from_utf16(&words).map_err(io::Error::other)
    } else {
        String::from_utf8(
            bytes
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(bytes)
                .to_vec(),
        )
        .map_err(io::Error::other)
    }
}
pub fn response(xml: &str) -> io::Result<Response> {
    let outer = document(xml)?;
    if !outer.root_element().has_tag_name((SOAP, "Envelope")) {
        return Err(invalid("invalid SOAP envelope"));
    }
    let body =
        one(outer.root_element(), SOAP, "Body")?.ok_or_else(|| invalid("missing SOAP body"))?;
    if one(body, SOAP, "Fault")?.is_some() {
        return Err(invalid("activation service returned SOAP fault"));
    }
    let text = scalar(
        one(body, SERVICE, "ResponseXml")?
            .ok_or_else(|| invalid("missing activation ResponseXml"))?,
    )?;
    let inner = document(&text)?;
    if inner.root_element().tag_name().namespace() != Some(RESPONSE) {
        return Err(invalid("invalid activation response namespace"));
    }
    if let Some(code) = one(inner.root_element(), RESPONSE, "ErrorCode")? {
        let code = scalar(code)?;
        let message = match code.as_str() {
            "0x7F" => "MAK activation limit exceeded",
            "0x67" => "product key blocked",
            "0x68" => "invalid product key",
            "0x86" => "invalid key type",
            "0x90" => "invalid installation ID",
            _ => "activation service error",
        };
        return Err(io::Error::other(format!("{message} ({code})")));
    }
    let kind = scalar(
        one(inner.root_element(), RESPONSE, "ResponseType")?
            .ok_or_else(|| invalid("missing activation response type"))?,
    )?;
    match kind.as_str() {
        "1" => {
            let cid = scalar(
                one(inner.root_element(), RESPONSE, "CID")?
                    .ok_or_else(|| invalid("missing confirmation ID"))?,
            )?;
            if cid.is_empty() || cid.len() > 128 || !cid.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("invalid confirmation ID"));
            }
            Ok(Response::Confirmation(cid))
        }
        "2" => {
            let value = scalar(
                one(inner.root_element(), RESPONSE, "ActivationRemaining")?
                    .ok_or_else(|| invalid("missing remaining activation count"))?,
            )?;
            Ok(Response::Remaining(value.parse().map_err(|_| {
                invalid("invalid remaining activation count")
            })?))
        }
        _ => Err(invalid("unknown activation response type")),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn envelope(payload: &str) -> String {
        format!(
            "<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><ResponseXml xmlns=\"{SERVICE}\">{}</ResponseXml></s:Body></s:Envelope>",
            escaped(payload).unwrap()
        )
    }
    fn payload(body: &str) -> String {
        format!("<ActivationResponse xmlns=\"{RESPONSE}\">{body}</ActivationResponse>")
    }
    #[test]
    fn independent_python_hmac_vector_matches_utf16_payload_and_xml_escaping() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/tsforge/activation-ws.json"
        ))
        .unwrap();
        let xml = request(
            RequestType::Confirmation,
            vector["iid"].as_str().unwrap(),
            vector["epid"].as_str().unwrap(),
        )
        .unwrap();
        let doc = document(&xml).unwrap();
        assert_eq!(
            scalar(one(doc.root_element(), SERVICE, "Digest").unwrap().unwrap()).unwrap(),
            vector["digest"]
        );
        assert_eq!(
            scalar(
                one(doc.root_element(), SERVICE, "RequestXml")
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            vector["request_base64"]
        );
        let xml = request(RequestType::Remaining, "ignored", "pid").unwrap();
        let doc = document(&xml).unwrap();
        let bytes = STANDARD
            .decode(
                scalar(
                    one(doc.root_element(), SERVICE, "RequestXml")
                        .unwrap()
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let words: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        assert!(!String::from_utf16(&words).unwrap().contains("<IID>"));
        assert!(request(RequestType::Confirmation, "1&2", "pid").is_err());
        assert!(request(RequestType::Confirmation, "123", "bad\0pid").is_err());
    }
    #[test]
    fn parses_cid_and_count_and_preserves_service_error_codes() {
        let cid = "123456".repeat(8);
        assert_eq!(
            response(&envelope(&payload(&format!(
                "<ResponseType>1</ResponseType><CID>{cid}</CID>"
            ))))
            .unwrap(),
            Response::Confirmation(cid)
        );
        assert_eq!(
            response(&envelope(&payload(
                "<ResponseType>2</ResponseType><ActivationRemaining>42</ActivationRemaining>"
            )))
            .unwrap(),
            Response::Remaining(42)
        );
        for code in ["0x7F", "0x67", "0x68", "0x86", "0x90", "0xUNKNOWN"] {
            assert!(
                response(&envelope(&payload(&format!(
                    "<ErrorCode>{code}</ErrorCode>"
                ))))
                .unwrap_err()
                .to_string()
                .contains(code)
            );
        }
    }
    #[test]
    fn response_text_handles_boms_and_rejects_invalid_unicode() {
        let text = "<response>测试😀</response>";
        for little in [true, false] {
            let bytes: Vec<_> = if little {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            }
            .into_iter()
            .chain(text.encode_utf16().flat_map(|w| {
                if little {
                    w.to_le_bytes()
                } else {
                    w.to_be_bytes()
                }
            }))
            .collect();
            assert_eq!(decode_text(&bytes).unwrap(), text);
        }
        assert_eq!(
            decode_text(&[b"\xef\xbb\xbf".as_slice(), text.as_bytes()].concat()).unwrap(),
            text
        );
        assert!(decode_text(&[0xff, 0xfe, 1]).is_err());
        assert!(decode_text(&[0xff]).is_err());
    }
    #[test]
    fn rejects_faults_ambiguous_fields_malformed_values_and_dtd() {
        for body in [
            "<ResponseType>3</ResponseType>",
            "<ResponseType>1</ResponseType>",
            "<ResponseType>1</ResponseType><CID>bad</CID>",
            "<ResponseType>2</ResponseType><ActivationRemaining>-1</ActivationRemaining>",
            "<ResponseType>1</ResponseType><CID>1</CID><CID>2</CID>",
            "<ResponseType>1</ResponseType><CID><nested/>1</CID>",
        ] {
            assert!(response(&envelope(&payload(body))).is_err());
        }
        assert!(
            response(&format!(
                "<s:Envelope xmlns:s=\"{SOAP}\"><s:Body><s:Fault/></s:Body></s:Envelope>"
            ))
            .is_err()
        );
        assert!(response("<!DOCTYPE a [<!ENTITY x 'value'>]><a>&x;</a>").is_err());
        assert!(response(&"x".repeat(MAX_RESPONSE + 1)).is_err());
    }
}
