//! Active Cyber Defense (ACD) Autonomous Threat Mitigation & Response Engine.
//!
//! Department of Defense (DoD) Continuous Authority to Operate (cATO) — Pillar 2:
//! Autonomously detects adversarial attacks and executes defensive playbooks without human latency:
//! 1. QUARANTINE_PEER: Automated temporary isolation upon replay flood detection
//! 2. SEVER_SESSION_AND_ISOLATE: Immediate session teardown upon tamper / HMAC chain break
//! 3. BLOCK_SOURCE_AND_REKEY: Source IP block & ratchet seed rotation upon authentication flood
//! 4. FORCE_TACTICAL_CLOAK: Dynamic padding & Poisson chaff enforcement upon traffic anomaly
//! 5. PURGE_EPHEMERAL_STATE: NIST SP 800-88 cryptographic wipe upon physical/memory fault
//!
//! Cryptographically signs threat events with Post-Quantum ML-DSA-87 (FIPS 204).

use crate::auth::Mldsa87SigningKey;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatTrigger {
    ReplayBurst,
    TamperDetected,
    AuthFailureFlood,
    TrafficAnomaly,
    FaultDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefensivePlaybook {
    QuarantinePeer,
    SeverSessionAndIsolate,
    BlockSourceAndRekey,
    ForceTacticalCloak,
    PurgeEphemeralState,
}

#[derive(Debug, Clone)]
pub struct ThreatIncident {
    pub trigger: ThreatTrigger,
    pub source_id: String,
    pub playbook: DefensivePlaybook,
    pub timestamp_epoch_secs: u64,
    pub signature: Option<Vec<u8>>,
}

struct AcdInner {
    replay_threshold: usize,
    replay_window: Duration,
    auth_fail_threshold: usize,
    auth_fail_window: Duration,
    quarantine_duration: Duration,

    // Sliding event windows: source_id -> VecDeque<Instant>
    replay_events: RwLock<HashMap<String, VecDeque<Instant>>>,
    auth_fail_events: RwLock<HashMap<String, VecDeque<Instant>>>,

    // Active quarantines: source_id -> expiry Instant
    quarantined_sources: RwLock<HashMap<String, Instant>>,

    // Tactical cloaking active flag
    tactical_cloak_active: RwLock<bool>,

    // Emergency isolation active flag
    emergency_isolation_active: RwLock<bool>,

    // Incident history
    incidents: RwLock<Vec<ThreatIncident>>,

    // Optional native ML-DSA-87 signer for audit evidence
    signer: Option<Arc<Mldsa87SigningKey>>,
}

/// Thread-safe Active Cyber Defense Engine
#[derive(Clone)]
pub struct ActiveCyberDefenseEngine {
    inner: Arc<AcdInner>,
}

impl Default for ActiveCyberDefenseEngine {
    fn default() -> Self {
        Self::new(3, 10.0, 5, 30.0, 300.0, None)
    }
}

impl ActiveCyberDefenseEngine {
    pub fn new(
        replay_threshold: usize,
        replay_window_secs: f64,
        auth_fail_threshold: usize,
        auth_fail_window_secs: f64,
        quarantine_duration_secs: f64,
        signer: Option<Arc<Mldsa87SigningKey>>,
    ) -> Self {
        Self {
            inner: Arc::new(AcdInner {
                replay_threshold: replay_threshold.max(1),
                replay_window: Duration::from_secs_f64(replay_window_secs.max(1.0)),
                auth_fail_threshold: auth_fail_threshold.max(1),
                auth_fail_window: Duration::from_secs_f64(auth_fail_window_secs.max(1.0)),
                quarantine_duration: Duration::from_secs_f64(quarantine_duration_secs.max(1.0)),
                replay_events: RwLock::new(HashMap::new()),
                auth_fail_events: RwLock::new(HashMap::new()),
                quarantined_sources: RwLock::new(HashMap::new()),
                tactical_cloak_active: RwLock::new(false),
                emergency_isolation_active: RwLock::new(false),
                incidents: RwLock::new(Vec::new()),
                signer,
            }),
        }
    }

    /// Check if a source IP or peer ID is actively quarantined (zero-allocation fast path).
    pub fn is_quarantined(&self, source_id: &str) -> bool {
        let now = Instant::now();
        if let Ok(guard) = self.inner.quarantined_sources.read() {
            if let Some(&expiry) = guard.get(source_id) {
                if now < expiry {
                    return true;
                }
            }
        }
        false
    }

    /// Check if tactical cloaking / chaff increase is active.
    pub fn is_tactical_cloak_active(&self) -> bool {
        *self.inner.tactical_cloak_active.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Check if emergency isolation was triggered.
    pub fn is_emergency_isolated(&self) -> bool {
        *self.inner.emergency_isolation_active.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Quarantine a source immediately.
    pub fn quarantine(&self, source_id: &str, duration: Option<Duration>) {
        let d = duration.unwrap_or(self.inner.quarantine_duration);
        let expiry = Instant::now() + d;
        if let Ok(mut guard) = self.inner.quarantined_sources.write() {
            guard.insert(source_id.to_string(), expiry);
        }
    }

    /// Clear expired quarantines.
    pub fn prune_quarantines(&self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.inner.quarantined_sources.write() {
            guard.retain(|_, expiry| *expiry > now);
        }
    }

    /// Record a security event and trigger defensive playbooks if thresholds are exceeded.
    pub fn record_event(&self, trigger: ThreatTrigger, source_id: &str) -> Option<DefensivePlaybook> {
        let now = Instant::now();
        let mut playbook_triggered = None;

        match trigger {
            ThreatTrigger::ReplayBurst => {
                if let Ok(mut map) = self.inner.replay_events.write() {
                    let queue = map.entry(source_id.to_string()).or_insert_with(VecDeque::new);
                    queue.push_back(now);
                    let cutoff = now.checked_sub(self.inner.replay_window).unwrap_or(now);
                    while let Some(&t) = queue.front() {
                        if t < cutoff {
                            queue.pop_front();
                        } else {
                            break;
                        }
                    }
                    if queue.len() >= self.inner.replay_threshold {
                        self.quarantine(source_id, None);
                        playbook_triggered = Some(DefensivePlaybook::QuarantinePeer);
                    }
                }
            }
            ThreatTrigger::AuthFailureFlood => {
                if let Ok(mut map) = self.inner.auth_fail_events.write() {
                    let queue = map.entry(source_id.to_string()).or_insert_with(VecDeque::new);
                    queue.push_back(now);
                    let cutoff = now.checked_sub(self.inner.auth_fail_window).unwrap_or(now);
                    while let Some(&t) = queue.front() {
                        if t < cutoff {
                            queue.pop_front();
                        } else {
                            break;
                        }
                    }
                    if queue.len() >= self.inner.auth_fail_threshold {
                        self.quarantine(source_id, Some(self.inner.quarantine_duration * 3));
                        playbook_triggered = Some(DefensivePlaybook::BlockSourceAndRekey);
                    }
                }
            }
            ThreatTrigger::TamperDetected => {
                // Immediate fail-closed sever & isolate on cryptographic tamper
                if let Ok(mut guard) = self.inner.emergency_isolation_active.write() {
                    *guard = true;
                }
                self.quarantine(source_id, Some(Duration::from_secs(86400)));
                playbook_triggered = Some(DefensivePlaybook::SeverSessionAndIsolate);
            }
            ThreatTrigger::TrafficAnomaly => {
                if let Ok(mut guard) = self.inner.tactical_cloak_active.write() {
                    *guard = true;
                }
                playbook_triggered = Some(DefensivePlaybook::ForceTacticalCloak);
            }
            ThreatTrigger::FaultDetected => {
                if let Ok(mut guard) = self.inner.emergency_isolation_active.write() {
                    *guard = true;
                }
                playbook_triggered = Some(DefensivePlaybook::PurgeEphemeralState);
            }
        }

        if let Some(pb) = playbook_triggered {
            self.record_incident(trigger, source_id, pb);
        }

        playbook_triggered
    }

    fn record_incident(&self, trigger: ThreatTrigger, source_id: &str, playbook: DefensivePlaybook) {
        let epoch_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sig = self.inner.signer.as_ref().map(|s| {
            let mut payload = Vec::new();
            payload.extend_from_slice(b"ACD-INCIDENT-v1\0");
            payload.extend_from_slice(format!("{trigger:?}|{source_id}|{playbook:?}|{epoch_now}").as_bytes());
            s.sign(b"ST2027-ACD-AUDIT-v1\0", &payload)
        });

        if let Ok(mut incs) = self.inner.incidents.write() {
            incs.push(ThreatIncident {
                trigger,
                source_id: source_id.to_string(),
                playbook,
                timestamp_epoch_secs: epoch_now,
                signature: sig,
            });
        }
    }

    /// Retrieve logged incidents.
    pub fn incident_count(&self) -> usize {
        self.inner.incidents.read().map(|i| i.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_burst_triggers_quarantine() {
        let acd = ActiveCyberDefenseEngine::new(3, 5.0, 5, 10.0, 60.0, None);
        let peer = "10.0.0.99";

        assert_eq!(acd.record_event(ThreatTrigger::ReplayBurst, peer), None);
        assert!(!acd.is_quarantined(peer));

        assert_eq!(acd.record_event(ThreatTrigger::ReplayBurst, peer), None);
        assert!(!acd.is_quarantined(peer));

        let pb = acd.record_event(ThreatTrigger::ReplayBurst, peer);
        assert_eq!(pb, Some(DefensivePlaybook::QuarantinePeer));
        assert!(acd.is_quarantined(peer));
        assert_eq!(acd.incident_count(), 1);
    }

    #[test]
    fn test_tamper_triggers_sever_session() {
        let acd = ActiveCyberDefenseEngine::new(3, 5.0, 5, 10.0, 60.0, None);
        let peer = "192.168.1.10";

        let pb = acd.record_event(ThreatTrigger::TamperDetected, peer);
        assert_eq!(pb, Some(DefensivePlaybook::SeverSessionAndIsolate));
        assert!(acd.is_emergency_isolated());
        assert!(acd.is_quarantined(peer));
    }

    #[test]
    fn test_traffic_anomaly_triggers_tactical_cloak() {
        let acd = ActiveCyberDefenseEngine::new(3, 5.0, 5, 10.0, 60.0, None);
        let peer = "peer_chaff_probe";

        let pb = acd.record_event(ThreatTrigger::TrafficAnomaly, peer);
        assert_eq!(pb, Some(DefensivePlaybook::ForceTacticalCloak));
        assert!(acd.is_tactical_cloak_active());
    }

    #[test]
    fn test_signed_incident_audit() {
        let (sk, vk) = Mldsa87SigningKey::generate().unwrap();
        let acd = ActiveCyberDefenseEngine::new(1, 10.0, 1, 10.0, 60.0, Some(Arc::new(sk)));

        acd.record_event(ThreatTrigger::TamperDetected, "adversary_1");
        assert_eq!(acd.incident_count(), 1);

        let inc = acd.inner.incidents.read().unwrap()[0].clone();
        assert!(inc.signature.is_some());
        let sig = inc.signature.unwrap();

        let mut payload = Vec::new();
        payload.extend_from_slice(b"ACD-INCIDENT-v1\0");
        payload.extend_from_slice(
            format!(
                "{:?}|adversary_1|{:?}|{}",
                ThreatTrigger::TamperDetected,
                DefensivePlaybook::SeverSessionAndIsolate,
                inc.timestamp_epoch_secs
            )
            .as_bytes(),
        );

        assert!(vk.verify(b"ST2027-ACD-AUDIT-v1\0", &payload, &sig).is_ok());
    }
}
