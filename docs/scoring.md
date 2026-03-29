# Scoring Logic

## Surface Risk Score

The **Surface Risk Score** measures how exposed the attack surface is based on TLS, security headers, and information leaks. Higher score = higher risk. Maximum is 100.

### Formula

```
surfaceRiskScore = min(100, tlsRisk + headerRisk + leakRisk)
```

### Components

| Component | Weight | Max | Calculation |
|-----------|--------|-----|-------------|
| TLS/Certificate | 50% | 50 | A=10, B=20, C=30, D=40, F=50 |
| Security Headers | 30% | 30 | 8 points per missing header, capped at 30 |
| Info Leaks | 20% | 20 | 10 points per server info leak, capped at 20 |

### Design Rationale

Components are weighted so no single factor can dominate:
- A site with F-grade TLS but perfect headers and no leaks scores 50 (not 100)
- A site with A-grade TLS but all headers missing and max leaks scores 60 (10 + 30 + 20)
- All three factors contribute meaningfully to the final score

### TLS Grade Mapping

- **A**: TLS 1.2/1.3, cert valid >30 days (10 pts)
- **B**: TLS 1.2/1.3, cert valid but <30 days (20 pts)
- **C**: Older TLS or weak config (30 pts)
- **D**: Expiring soon (40 pts)
- **F**: Expired or no TLS (50 pts)

---

## Security Score

The **Security Score** reflects the overall security posture based on open findings. Higher score = better posture. Range is 0-100.

### Formula

```
securityScore = max(0, min(100, 100 - sum(deductions)))
```

### Severity Deductions (per open finding)

| Severity | Deduction |
|----------|-----------|
| Critical | 20 |
| High | 10 |
| Medium | 5 |
| Low | 2 |
| Info | 1 |

Resolved findings are excluded from the calculation.
