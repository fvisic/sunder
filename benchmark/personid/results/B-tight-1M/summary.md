### person-id shape, `sunder import -offline -parallel 8`, 1,000,000 rows, Postgres 1g RAM / shared_buffers 256MB, rev 23deb7a-dirty

| metric | v4 (random) | v7 (time-ordered) | v7 / v4 |
|---|---|---|---|
| rows/s (median) | 35,842 | 55,866 | 1.56x |
| wall seconds (median) | 28 | 18 | 0.64x |
| WAL written, MB | 1,934 | 1,925 | 1.00x |
| person_tokens_pkey after load, MB | 415 | 413 | 1.00x |
| person_tokens_pkey after VACUUM ANALYZE, MB | 415 | 413 | 1.00x |
| person_tokens heap, MB | 384 | 384 | 1.00x |
| ident_uq, MB | 182 | 182 | 1.00x |
| search_idx, MB | 7 | 7 | 1.00x |
| cids_pkey, MB | 63 | 62 | 0.98x |

raw rows/s per round - v4: 33113, 39062, 35842; v7: 55866, 57143, 52083

WAL ratio vs time ratio: if they track, the run is I/O bound and the timing comparison means something; if not, it measures CPU.
