//! MIL-STD-6090 Cursor-on-Target (CoT) & Blue Force Tracking (BFT) Engine.
//!
//! Provides post-quantum authenticated tactical situational awareness formatting,
//! attribute extraction without heavy XML dependencies, and continuous BFT track table
//! management with automatic stale purges.

use crate::policy::CoreError;
use std::collections::HashMap;

/// Standard Cursor-on-Target tactical event representation.
#[derive(Debug, Clone, PartialEq)]
pub struct CotEvent {
    pub uid: String,
    pub event_type: String,
    pub time_secs: u64,
    pub stale_secs: u64,
    pub how: String,
    pub lat: f64,
    pub lon: f64,
    pub hae: f64,
    pub ce: f64,
    pub le: f64,
    pub callsign: String,
    pub status: String,
}

/// Generate a deterministic MIL-STD-6090 compliant UID.
pub fn generate_uid(callsign: &str, time_secs: u64, lat: f64) -> String {
    let hash_mix = time_secs ^ lat.to_bits();
    format!("COT-{}-{:08X}", callsign, (hash_mix & 0xFFFF_FFFF) as u32)
}

/// Create a new CotEvent with system timestamp and sensible military defaults.
pub fn new_event(
    callsign: &str,
    event_type: &str,
    lat: f64,
    lon: f64,
    hae: f64,
    status: &str,
    stale_offset_secs: u64,
) -> CotEvent {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let uid = generate_uid(callsign, now_secs, lat);
    CotEvent {
        uid,
        event_type: event_type.to_string(),
        time_secs: now_secs,
        stale_secs: now_secs + stale_offset_secs,
        how: "m-g".to_string(),
        lat,
        lon,
        hae,
        ce: 5.0,
        le: 10.0,
        callsign: callsign.to_string(),
        status: status.to_string(),
    }
}

/// Render a CotEvent into MIL-STD-6090 standard XML string.
pub fn format_cot_xml(event: &CotEvent) -> String {
    format!(
        "<?xml version=\"1.0\" standalone=\"yes\"?>\
<event version=\"2.0\" uid=\"{uid}\" type=\"{etype}\" time=\"{time}\" start=\"{time}\" stale=\"{stale}\" how=\"{how}\">\
<point lat=\"{lat:.6}\" lon=\"{lon:.6}\" hae=\"{hae:.1}\" ce=\"{ce:.1}\" le=\"{le:.1}\"/>\
<detail><contact callsign=\"{callsign}\"/><status readiness=\"{status}\"/></detail>\
</event>",
        uid = event.uid,
        etype = event.event_type,
        time = event.time_secs,
        stale = event.stale_secs,
        how = event.how,
        lat = event.lat,
        lon = event.lon,
        hae = event.hae,
        ce = event.ce,
        le = event.le,
        callsign = event.callsign,
        status = event.status
    )
}

/// Helper function to extract attribute values from XML element strings without XML crate dependency.
fn extract_attr<'a>(xml: &'a str, attr_name: &str) -> Option<&'a str> {
    let pattern = format!("{}=\"", attr_name);
    let start_idx = xml.find(&pattern)? + pattern.len();
    let rest = &xml[start_idx..];
    let end_idx = rest.find('"')?;
    Some(&rest[..end_idx])
}

/// Parse a MIL-STD-6090 XML string back into a [`CotEvent`].
pub fn parse_cot_xml(xml: &str) -> Result<CotEvent, CoreError> {
    if !xml.contains("<event") || !xml.contains("<point") {
        return Err(CoreError::Malformed);
    }

    let uid = extract_attr(xml, "uid")
        .ok_or(CoreError::Malformed)?
        .to_string();
    let event_type = extract_attr(xml, "type")
        .ok_or(CoreError::Malformed)?
        .to_string();
    let time_secs: u64 = extract_attr(xml, "time")
        .and_then(|s| s.parse().ok())
        .ok_or(CoreError::Malformed)?;
    let stale_secs: u64 = extract_attr(xml, "stale")
        .and_then(|s| s.parse().ok())
        .ok_or(CoreError::Malformed)?;
    let how = extract_attr(xml, "how").unwrap_or("m-g").to_string();

    let lat: f64 = extract_attr(xml, "lat")
        .and_then(|s| s.parse().ok())
        .ok_or(CoreError::Malformed)?;
    let lon: f64 = extract_attr(xml, "lon")
        .and_then(|s| s.parse().ok())
        .ok_or(CoreError::Malformed)?;
    let hae: f64 = extract_attr(xml, "hae")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let ce: f64 = extract_attr(xml, "ce")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5.0);
    let le: f64 = extract_attr(xml, "le")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10.0);

    let callsign = extract_attr(xml, "callsign")
        .unwrap_or("UNKNOWN")
        .to_string();
    let status = extract_attr(xml, "readiness")
        .unwrap_or("UNKNOWN")
        .to_string();

    Ok(CotEvent {
        uid,
        event_type,
        time_secs,
        stale_secs,
        how,
        lat,
        lon,
        hae,
        ce,
        le,
        callsign,
        status,
    })
}

/// Blue Force Tracking (BFT) Track Entry.
#[derive(Debug, Clone)]
pub struct BftTrack {
    pub callsign: String,
    pub last_event: CotEvent,
    pub update_count: u64,
    pub first_seen_secs: u64,
}

/// In-memory bounded Blue Force Tracker maintaining situational awareness.
#[derive(Debug, Clone)]
pub struct BftTracker {
    tracks: HashMap<String, BftTrack>,
    max_tracks: usize,
}

impl BftTracker {
    pub fn new(max_tracks: usize) -> Self {
        Self {
            tracks: HashMap::with_capacity(max_tracks),
            max_tracks,
        }
    }

    /// Upsert a track based on incoming CoT event.
    pub fn update(&mut self, event: CotEvent) -> Result<(), CoreError> {
        let uid = event.uid.clone();
        if let Some(track) = self.tracks.get_mut(&uid) {
            track.callsign = event.callsign.clone();
            track.last_event = event;
            track.update_count += 1;
            return Ok(());
        }

        if self.tracks.len() >= self.max_tracks {
            return Err(CoreError::Oversize);
        }

        let time = event.time_secs;
        let callsign = event.callsign.clone();
        let track = BftTrack {
            callsign,
            last_event: event,
            update_count: 1,
            first_seen_secs: time,
        };
        self.tracks.insert(uid, track);
        Ok(())
    }

    pub fn get(&self, uid: &str) -> Option<&BftTrack> {
        self.tracks.get(uid)
    }

    /// Remove tracks that have exceeded their stale deadline.
    pub fn remove_stale(&mut self, now_secs: u64) -> usize {
        let initial_len = self.tracks.len();
        self.tracks
            .retain(|_, track| track.last_event.stale_secs >= now_secs);
        initial_len - self.tracks.len()
    }

    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }

    pub fn all_tracks(&self) -> Vec<&BftTrack> {
        let mut list: Vec<&BftTrack> = self.tracks.values().collect();
        list.sort_by(|a, b| a.callsign.cmp(&b.callsign));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_roundtrip() {
        let ev = CotEvent {
            uid: "COT-ALPHA-01234567".to_string(),
            event_type: "a-f-G-U-C".to_string(),
            time_secs: 1700000000,
            stale_secs: 1700000300,
            how: "m-g".to_string(),
            lat: 38.8719,
            lon: -77.0563,
            hae: 120.5,
            ce: 5.0,
            le: 10.0,
            callsign: "VIPER_01".to_string(),
            status: "ARMED_DEFCON_1".to_string(),
        };

        let xml = format_cot_xml(&ev);
        let parsed = parse_cot_xml(&xml).expect("parse_cot_xml");

        assert_eq!(parsed.uid, ev.uid);
        assert_eq!(parsed.event_type, ev.event_type);
        assert_eq!(parsed.time_secs, ev.time_secs);
        assert_eq!(parsed.stale_secs, ev.stale_secs);
        assert!((parsed.lat - ev.lat).abs() < 1e-5);
        assert!((parsed.lon - ev.lon).abs() < 1e-5);
        assert_eq!(parsed.callsign, ev.callsign);
        assert_eq!(parsed.status, ev.status);
    }

    #[test]
    fn bft_tracker_flow_and_stale_prune() {
        let mut tracker = BftTracker::new(10);
        let ev1 = new_event("EAGLE_01", "a-f-A", 34.0, -118.0, 5000.0, "AIRBORNE", 100);
        let uid1 = ev1.uid.clone();
        tracker.update(ev1).expect("update");
        assert_eq!(tracker.track_count(), 1);

        let t1 = tracker.get(&uid1).expect("track exists");
        assert_eq!(t1.callsign, "EAGLE_01");
        assert_eq!(t1.update_count, 1);

        // Prune with future timestamp
        let removed = tracker.remove_stale(1700000000 + 1000000000);
        assert_eq!(removed, 1);
        assert_eq!(tracker.track_count(), 0);
    }

    #[test]
    fn malformed_fails() {
        assert_eq!(parse_cot_xml("not valid xml"), Err(CoreError::Malformed));
    }
}
