-- Strictly earlier failures in an inclusive 300-second window, same user and IP.
-- Fixture timestamps are UTC ISO-8601 with second precision; use unixepoch for comparisons.
SELECT s.event_id, s.timestamp, s.username, s.src_ip, COUNT(*) AS prior_failures
FROM auth_events AS s
JOIN auth_events AS f
  ON s.username = f.username AND s.src_ip = f.src_ip
 AND f.action = 'failure'
 AND unixepoch(f.timestamp) < unixepoch(s.timestamp)
 AND unixepoch(f.timestamp) >= unixepoch(s.timestamp) - 300
WHERE s.action = 'success'
GROUP BY s.event_id, s.timestamp, s.username, s.src_ip
HAVING COUNT(*) >= 3
ORDER BY s.timestamp, s.event_id;
