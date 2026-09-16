### person-id shape, `sunder import -offline -parallel 8`, 1,000,000 rows, Postgres 6g RAM / shared_buffers 1536MB, rev 23deb7a

| metric | v4 (random) | v7 (time-ordered) | v7 / v4 |
|---|---|---|---|
| rows/s (median) | 72,464 | 86,207 | 1.19x |
| wall seconds (median) | 14 | 12 | 0.84x |
| WAL written, MB | 1,934 | 1,923 | 0.99x |
| person_tokens_pkey after load, MB | 415 | 413 | 1.00x |
| person_tokens_pkey after VACUUM ANALYZE, MB | 415 | 413 | 1.00x |
| person_tokens heap, MB | 384 | 384 | 1.00x |
| ident_uq, MB | 182 | 182 | 1.00x |
| search_idx, MB | 7 | 7 | 1.00x |
| cids_pkey, MB | 62 | 63 | 1.02x |

raw rows/s per round - v4: 53476, 72464, 79365; v7: 81301, 86207, 90090

WAL ratio vs time ratio: if they track, the run is I/O bound and the timing comparison means something; if not, it measures CPU.
