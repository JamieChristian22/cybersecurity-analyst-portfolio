-- Security log analysis queries for SQLite-compatible lab data.

-- 1) Failed logins
SELECT timestamp, username, src_ip, geo
FROM auth_events
WHERE action = 'failure'
ORDER BY timestamp;

-- 2) Off-hours successful logins (before 06:00 or after/equal 22:00)
SELECT timestamp, username, src_ip, geo
FROM auth_events
WHERE action = 'success'
  AND (CAST(strftime('%H', timestamp) AS INTEGER) < 6
       OR CAST(strftime('%H', timestamp) AS INTEGER) >= 22)
ORDER BY timestamp;

-- 3) Repeated failures by source IP
SELECT src_ip, COUNT(*) AS failure_count, COUNT(DISTINCT username) AS targeted_users
FROM auth_events
WHERE action = 'failure'
GROUP BY src_ip
HAVING COUNT(*) >= 4
ORDER BY failure_count DESC;

-- 4) Users with repeated failures
SELECT username, COUNT(*) AS failures
FROM auth_events
WHERE action = 'failure'
GROUP BY username
HAVING COUNT(*) >= 3
ORDER BY failures DESC;

-- 5) Success after prior failures from same user + source on same date
SELECT s.timestamp AS success_time, s.username, s.src_ip,
       COUNT(f.timestamp) AS prior_failures
FROM auth_events s
JOIN auth_events f
  ON s.username=f.username
 AND s.src_ip=f.src_ip
 AND f.action='failure'
 AND f.timestamp < s.timestamp
 AND date(f.timestamp)=date(s.timestamp)
WHERE s.action='success'
GROUP BY s.timestamp, s.username, s.src_ip
HAVING COUNT(f.timestamp) >= 3
ORDER BY success_time;

-- 6) Unusual geographies for successful logins
SELECT geo, COUNT(*) AS successes, COUNT(DISTINCT username) AS users
FROM auth_events
WHERE action='success'
GROUP BY geo
ORDER BY successes ASC;

-- 7) Top source IPs
SELECT src_ip,
       SUM(CASE WHEN action='failure' THEN 1 ELSE 0 END) AS failures,
       SUM(CASE WHEN action='success' THEN 1 ELSE 0 END) AS successes,
       COUNT(DISTINCT username) AS users
FROM auth_events
GROUP BY src_ip
ORDER BY failures DESC, users DESC;

-- 8) Incident-window filter
SELECT *
FROM auth_events
WHERE timestamp BETWEEN '2026-08-21T02:00:00' AND '2026-08-21T02:30:00'
ORDER BY timestamp;
