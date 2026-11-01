# Dynamic AI Testing Policy

- Run active probes only against an endpoint whose owner has explicitly authorized the test and whose environment is isolated or designated for testing.
- Default to non-destructive, bounded scenarios, synthetic canary data, strict request caps, explicit allowlists and short timeouts.
- Do not exploit production systems, attempt credential theft, invoke destructive tools, access third-party data, or evade the target's authorization controls.
- Do not follow redirects to unapproved hosts. Network egress policies must block internal networks and cloud metadata endpoints; application-level DNS checks are only defense in depth.
- Store test IDs, response status, lengths and pass/fail assertions rather than raw responses containing user data or secrets.
- Distinguish “not tested”, “test error”, “inconclusive”, “potential issue” and “confirmed test-canary exposure”. A test failure is not a security pass.
