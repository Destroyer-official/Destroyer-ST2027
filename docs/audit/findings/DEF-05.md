# Finding Report: DEF-05 — Coarse Timestamp LRU Eviction Bug

- **Finding ID:** `DEF-05`
- **Module:** `operational_security` / `memory_security`
- **Affected File & Line:** [`operational_security.py:709-725`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/operational_security.py#L709-L725)
- **Classification:** Confirmed Defect (Remediated)
- **Severity:** High (Resource Exhaustion / Memory Leak Risk)

---

## 1. Observed Behavior & Evidence

In `MessageExpirationManager`, bounded storage is enforced when `len(self._messages) >= self.MAX_STORED_MESSAGES`. The original logic initialized:
```python
now = datetime.now()
oldest_id = None
oldest_time = now
for mid, m in self._messages.items():
    if m.created_at < oldest_time:
        oldest_time = m.created_at
        oldest_id = mid
if oldest_id:
    self._expire_message(oldest_id)
```
On Windows systems where system clock resolution can be coarse (~15.6 ms), if messages were inserted within the same tick or if all messages had timestamps identical to `now`, `oldest_id` remained `None`, causing eviction to be skipped entirely and permitting unbounded memory growth beyond `MAX_STORED_MESSAGES`.

---

## 2. Technical Consequences

- In high-throughput bursts, message store could exceed memory budgets, causing denial of service.
- Potential unbounded heap allocation in constrained tactical edge environments.

---

## 3. Remediation

Explicitly initialized `oldest_id` and `oldest_time` from the first entry in the dictionary:
```python
oldest_id = next(iter(self._messages))
oldest_time = self._messages[oldest_id].created_at
for mid, m in self._messages.items():
    if m.is_expired:
        oldest_id = mid
        break
    if m.created_at < oldest_time:
        oldest_time = m.created_at
        oldest_id = mid
self._expire_message(oldest_id)
```
This guarantees an eviction candidate is always identified and purged, preserving strict upper bounds.

---

## 4. Verification Evidence

- Executed `pytest tests/test_audit_forensic_remediations.py -v`.
- Bounded memory and eviction verified under simulated high-speed packet bursts.
- Verified status: **REMEDIATED & VERIFIED**.

