use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CanonicalEvent {
    pub id: String,
    pub tenant_id: String,
    pub timestamp: String,
    pub ingested_at: String,
    pub source: String,
    pub source_type: String,
    pub event_type: String,
    pub category: String,
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default)]
    pub raw_event: Value,
}

pub fn from_process(
    tenant_id: &str,
    id: &str,
    timestamp: &str,
    process_name: &str,
) -> Result<CanonicalEvent, String> {
    if !tenant_id.starts_with("ten_") {
        return Err("tenant_id must use ten_ prefix".into());
    }
    if process_name.is_empty() {
        return Err("process name required".into());
    }
    Ok(CanonicalEvent {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        timestamp: timestamp.to_string(),
        ingested_at: timestamp.to_string(),
        source: "rust-endpoint-sensor".into(),
        source_type: "endpoint".into(),
        event_type: "process".into(),
        category: "process".into(),
        schema_version: "1.0.0".into(),
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        protocol: None,
        domain: None,
        raw_event: Value::Null,
    })
}

fn require_tenant(tenant_id: &str) -> Result<(), String> {
    if !tenant_id.starts_with("ten_") {
        return Err("tenant_id must use ten_ prefix".into());
    }
    Ok(())
}

fn nested_ip(raw: &Value, dotted: &str, nested_key: &str) -> Option<String> {
    if let Some(value) = raw.get(dotted).and_then(|item| item.as_str()) {
        return Some(value.to_string());
    }
    raw.get("id")
        .and_then(|obj| obj.get(nested_key))
        .and_then(|item| item.as_str())
        .map(|item| item.to_string())
}

fn nested_port(raw: &Value, dotted: &str, nested_key: &str) -> Option<u16> {
    if let Some(value) = raw.get(dotted).and_then(|item| item.as_u64()) {
        return u16::try_from(value).ok();
    }
    raw.get("id")
        .and_then(|obj| obj.get(nested_key))
        .and_then(|item| item.as_u64())
        .and_then(|item| u16::try_from(item).ok())
}

/// Parse a Zeek JSON record (conn/dns/http/ssl/files/notice) into CanonicalEvent 1.x.
pub fn from_zeek_json(tenant_id: &str, raw: &Value) -> Result<CanonicalEvent, String> {
    require_tenant(tenant_id)?;
    let kind = raw
        .get("_path")
        .or_else(|| raw.get("log_type"))
        .and_then(|item| item.as_str())
        .unwrap_or("conn");
    let category = match kind {
        "dns" => "dns",
        "http" => "http",
        "ssl" | "tls" => "tls",
        "files" => "file",
        "notice" => "notice",
        _ => "network",
    };
    let timestamp = raw
        .get("ts")
        .and_then(|item| item.as_str())
        .unwrap_or("1970-01-01T00:00:00Z");
    Ok(CanonicalEvent {
        id: format!(
            "evt_rust_{}",
            raw.get("uid")
                .and_then(|item| item.as_str())
                .unwrap_or("zeek")
        ),
        tenant_id: tenant_id.to_string(),
        timestamp: timestamp.to_string(),
        ingested_at: timestamp.to_string(),
        source: format!("zeek.{kind}"),
        source_type: "zeek".into(),
        event_type: kind.to_string(),
        category: category.into(),
        schema_version: "1.0.0".into(),
        src_ip: nested_ip(raw, "id.orig_h", "orig_h"),
        dst_ip: nested_ip(raw, "id.resp_h", "resp_h"),
        src_port: nested_port(raw, "id.orig_p", "orig_p"),
        dst_port: nested_port(raw, "id.resp_p", "resp_p"),
        protocol: raw
            .get("proto")
            .and_then(|item| item.as_str())
            .map(|item| item.to_string()),
        domain: raw
            .get("query")
            .or_else(|| raw.get("host"))
            .or_else(|| raw.get("server_name"))
            .and_then(|item| item.as_str())
            .map(|item| item.to_string()),
        raw_event: raw.clone(),
    })
}

/// Parse a Suricata EVE JSON record into CanonicalEvent 1.x.
pub fn from_suricata_eve(tenant_id: &str, raw: &Value) -> Result<CanonicalEvent, String> {
    require_tenant(tenant_id)?;
    let kind = raw
        .get("event_type")
        .and_then(|item| item.as_str())
        .ok_or("event_type required")?;
    let category = if kind == "alert" {
        "alert"
    } else if kind == "flow" {
        "network"
    } else {
        kind
    };
    let timestamp = raw
        .get("timestamp")
        .and_then(|item| item.as_str())
        .unwrap_or("1970-01-01T00:00:00Z");
    Ok(CanonicalEvent {
        id: format!(
            "evt_rust_{}",
            raw.get("flow_id")
                .map(|item| item.to_string())
                .unwrap_or_else(|| "eve".into())
        ),
        tenant_id: tenant_id.to_string(),
        timestamp: timestamp.to_string(),
        ingested_at: timestamp.to_string(),
        source: format!("suricata.{kind}"),
        source_type: "suricata".into(),
        event_type: kind.to_string(),
        category: category.into(),
        schema_version: "1.0.0".into(),
        src_ip: raw
            .get("src_ip")
            .and_then(|item| item.as_str())
            .map(|item| item.to_string()),
        dst_ip: raw
            .get("dest_ip")
            .and_then(|item| item.as_str())
            .map(|item| item.to_string()),
        src_port: raw
            .get("src_port")
            .and_then(|item| item.as_u64())
            .and_then(|item| u16::try_from(item).ok()),
        dst_port: raw
            .get("dest_port")
            .and_then(|item| item.as_u64())
            .and_then(|item| u16::try_from(item).ok()),
        protocol: raw
            .get("proto")
            .and_then(|item| item.as_str())
            .map(|item| item.to_string()),
        domain: raw
            .pointer("/tls/sni")
            .or_else(|| raw.pointer("/http/hostname"))
            .or_else(|| raw.pointer("/dns/rrname"))
            .and_then(|item| item.as_str())
            .map(|item| item.to_string()),
        raw_event: raw.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_bad_tenant() {
        assert!(from_process("x", "evt_1", "2026-09-05T00:00:00Z", "pwsh").is_err());
    }

    #[test]
    fn emits_canonical_version() {
        let event = from_process(
            "ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "evt_1",
            "2026-09-05T00:00:00Z",
            "pwsh",
        )
        .unwrap();
        assert_eq!(event.schema_version, "1.0.0");
        assert_eq!(event.category, "process");
    }

    #[test]
    fn parses_zeek_conn() {
        let raw = json!({
            "_path": "conn",
            "ts": "2026-09-05T10:00:00Z",
            "uid": "Cabc",
            "id": {"orig_h": "10.0.0.8", "resp_h": "10.0.0.9", "orig_p": 51234, "resp_p": 22},
            "proto": "tcp"
        });
        let event = from_zeek_json("ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &raw).unwrap();
        assert_eq!(event.source_type, "zeek");
        assert_eq!(event.src_ip.as_deref(), Some("10.0.0.8"));
        assert_eq!(event.dst_port, Some(22));
        assert_eq!(event.schema_version, "1.0.0");
    }

    #[test]
    fn parses_suricata_alert() {
        let raw = json!({
            "timestamp": "2026-09-05T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.8",
            "dest_ip": "198.51.100.10",
            "src_port": 4000,
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 99,
            "alert": {"signature": "ET TEST", "severity": 1}
        });
        let event = from_suricata_eve("ten_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &raw).unwrap();
        assert_eq!(event.source_type, "suricata");
        assert_eq!(event.category, "alert");
        assert_eq!(event.dst_ip.as_deref(), Some("198.51.100.10"));
    }
}
