-- Create test zone for PowerDNS integration tests
INSERT OR IGNORE INTO domains (name, type) VALUES ('example.org', 'NATIVE');

-- SOA record (required)
INSERT OR IGNORE INTO records (domain_id, name, type, content, ttl, prio)
SELECT id, 'example.org', 'SOA', 'ns1.example.org hostmaster.example.org 1 10800 3600 604800 3600', 3600, 0
FROM domains WHERE name = 'example.org';

-- NS record (required)
INSERT OR IGNORE INTO records (domain_id, name, type, content, ttl, prio)
SELECT id, 'example.org', 'NS', 'ns1.example.org', 3600, 0
FROM domains WHERE name = 'example.org';

-- A record for NS
INSERT OR IGNORE INTO records (domain_id, name, type, content, ttl, prio)
SELECT id, 'ns1.example.org', 'A', '127.0.0.1', 3600, 0
FROM domains WHERE name = 'example.org';
