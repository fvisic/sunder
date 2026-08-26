-- Review medium: value tokens were unattributable and destructible by any
-- scope member - no record of who minted a token, and tokens.delete audited
-- an EMPTY detail, so destroying the only copy of a sealed value left no
-- trace of what was destroyed or whose it was. created_by records the
-- minting client; the delete audit now carries the token handle and this
-- attribution. (tokens.delete also leaves the "service" role preset - a
-- destructive, unrecoverable action is an explicit grant, not preset
-- baggage; "admin" keeps it.)
ALTER TABLE value_tokens ADD COLUMN created_by TEXT;
