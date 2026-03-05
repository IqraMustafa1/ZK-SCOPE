module RunAll where

import Daml.Script
import DA.Foldable as Foldable
import DA.Time (addRelTime, seconds)
import DA.List as List (sort)
import DA.Text as T
import qualified Main as M

-- ==========================================================
-- Small script helpers
-- ==========================================================

mapScript_ : (a -> Script ()) -> [a] -> Script ()
mapScript_ _ []        = pure ()
mapScript_ f (x :: xs) = do f x; mapScript_ f xs

-- Pick the snapshot with the highest epoch
latestSnapshot
  : [(ContractId M.TaSnapshot, M.TaSnapshot)]
  -> (ContractId M.TaSnapshot, M.TaSnapshot)
latestSnapshot xs = case xs of
  x :: rest ->
    Foldable.foldl
      (\best cur -> if (snd cur).epoch > (snd best).epoch then cur else best)
      x rest
  [] -> error "No TaSnapshot found"

-- ==========================================================
-- Base64 normalization helpers
-- ==========================================================

normalizeB64 : Text -> Text
normalizeB64 t =
  let t1 = T.replace "\r" "" t
      t2 = T.replace "\n" "" t1
      t3 = T.replace "\t" "" t2
      t4 = T.replace " "  "" t3
  in t4

stripB64Padding : Text -> Text
stripB64Padding t = T.dropWhileEnd (\c -> c == "=") (normalizeB64 t)

-- ==========================================================
-- Attestations / Broker helpers
-- ==========================================================

bestByExpires
  : [(ContractId M.SigAttestation, M.SigAttestation)]
  -> Optional (ContractId M.SigAttestation, M.SigAttestation)
bestByExpires xs = case xs of
  [] -> None
  x :: rest ->
    Some $
      Foldable.foldl
        (\best cur -> if (snd cur).expires > (snd best).expires then cur else best)
        x rest

findOrCreateAttestation
  : Party -> Party -> Text -> Text -> Party -> Text -> M.AlgId -> Time -> Time
  -> Script (ContractId M.SigAttestation)
findOrCreateAttestation op issuer digest devicePk deviceOwner senderPubHex algId now expT = do
  atts <- query @M.SigAttestation op

  let matches =
        [ (cid, a)
        | (cid, a) <- atts
        , a.operator        == op
        , a.issuer          == issuer
        , a.digest          == digest
        , a.devicePublicKey == devicePk
        , a.deviceOwner     == deviceOwner
        , a.senderPublicKey == senderPubHex
        , a.algId           == algId
        ]

  case bestByExpires matches of
    Some (cid, a) -> do
      if a.expires < now then do
        debug ("[RunAll] Found matching SigAttestation but it is EXPIRED; archiving+recreating. key=("
              <> show a.operator <> "," <> show a.digest <> "," <> show a.issuer <> ")"
              <> " expires=" <> show a.expires <> " now=" <> show now)

        submit issuer do
          exerciseCmd cid Archive

        debug ("[RunAll] Creating fresh SigAttestation from " <> show issuer)
        newCid <- submit issuer do
          createCmd M.SigAttestation with
            operator        = op
            issuer          = issuer
            digest          = digest
            deviceOwner     = deviceOwner
            devicePublicKey = devicePk
            senderPublicKey = senderPubHex
            algId           = algId
            ts              = now
            expires         = expT
        pure newCid
      else do
        debug ("[RunAll] Reusing SigAttestation key=("
              <> show a.operator <> "," <> show a.digest <> "," <> show a.issuer <> ")"
              <> " expires=" <> show a.expires)
        pure cid

    None -> do
      debug ("[RunAll] Creating SigAttestation from " <> show issuer)
      cid <- submit issuer do
        createCmd M.SigAttestation with
          operator        = op
          issuer          = issuer
          digest          = digest
          deviceOwner     = deviceOwner
          devicePublicKey = devicePk
          senderPublicKey = senderPubHex
          algId           = algId
          ts              = now
          expires         = expT
      pure cid

findBrokerFor
  : Party -> Party
  -> Script (ContractId M.BrokerContract, M.BrokerContract, Party)
findBrokerFor who op = do
  bcsWho <- query @M.BrokerContract who
  case bcsWho of
    (cid, bc) :: _ -> pure (cid, bc, who)
    [] -> do
      bcsOp <- query @M.BrokerContract op
      case bcsOp of
        (cid, bc) :: _ -> do
          debug "[RunAll] BrokerContract not visible to submitter; using one seen by Operator."
          pure (cid, bc, who)
        [] -> abort "No BrokerContract found. Did Main.setup run?"

-- ==========================================================
-- Broker cache refresh helpers
-- ==========================================================

fetchBrokerByCid : Party -> ContractId M.BrokerContract -> Script (ContractId M.BrokerContract, M.BrokerContract)
fetchBrokerByCid viewer bcCid = do
  xs <- query @M.BrokerContract viewer
  case [ (cid, bc) | (cid, bc) <- xs, cid == bcCid ] of
    x :: _ -> pure x
    []     -> abort ("BrokerContract not found by cid=" <> show bcCid <> " (viewer=" <> show viewer <> ")")

-- ✅ FIX #1: RefreshCache expects Time + [(Party, Time)]  (NOT Text)
refreshBrokerCacheAlways
  : Party
  -> [Party]
  -> ContractId M.BrokerContract
  -> Script (ContractId M.BrokerContract)
refreshBrokerCacheAlways op edges bcCid = do
  now <- getTime
  let newValidUntilTime = addRelTime now (seconds 3600)   -- +1 hour
      newCached         = [ (e, newValidUntilTime) | e <- edges ]  -- ✅ Time

  debug ("[RunAll] Refreshing Broker cache; newValidUntil=" <> show newValidUntilTime
        <> " edges=" <> show edges)

  newCid <- submit op do
    exerciseCmd bcCid M.RefreshCache with
      newValidUntil = newValidUntilTime   -- ✅ Time
      newCached     = newCached           -- ✅ [(Party, Time)]

  debug ("[RunAll] RefreshCache returned new BrokerContract cid=" <> show newCid)
  pure newCid

-- ==========================================================
-- Ratchet helpers
-- ==========================================================

findRatchetState
  : Party -> Party -> Text -> Text -> Int
  -> Script (Optional (ContractId M.RatchetState, M.RatchetState))
findRatchetState op edge deviceKey senderId epoch = do
  rs <- query @M.RatchetState op
  let matches =
        [ (cid, r)
        | (cid, r) <- rs
        , r.operator == op
        , r.edge     == edge
        , r.deviceKey == deviceKey
        , r.senderId == senderId
        , r.epoch    == epoch
        ]
  case matches of
    [] -> pure None
    x :: rest -> do
      let best =
            Foldable.foldl
              (\best cur -> if (snd cur).lastCtr > (snd best).lastCtr then cur else best)
              x rest
      pure (Some best)

nextCounterFor
  : Party -> Party -> Text -> Text -> Int
  -> Script Int
nextCounterFor op edge deviceKey senderId epoch = do
  m <- findRatchetState op edge deviceKey senderId epoch
  case m of
    None -> pure 1
    Some (_cid, r) -> pure (r.lastCtr + 1)

-- ==========================================================
-- ZK-PAC helpers
-- ==========================================================

ensurePolicyRoot
  : Party -> Text -> Text
  -> Script (ContractId M.PolicyRoot)
ensurePolicyRoot op policyId merkleRoot = do
  roots <- query @M.PolicyRoot op
  let existing =
        [ (cid,r) | (cid,r) <- roots, r.policyId == policyId, r.merkleRoot == merkleRoot ]
  case existing of
    (cid, _) :: _ -> debug "[RunAll][ZK-PAC] PolicyRoot already exists" >> pure cid
    [] -> do
      debug "[RunAll][ZK-PAC] Creating PolicyRoot"
      submit op do
        createCmd M.PolicyRoot with operator = op, policyId, merkleRoot

mkDemoPolicyProof : Text -> [Text] -> M.PolicyProof
mkDemoPolicyProof policyId revealedAttrs =
  M.PolicyProof with
    policyId      = policyId
    leafHash      = "leaf-hash-demo"
    merklePath    = []
    revealedAttrs = revealedAttrs

ensurePolicyLeaf : Party -> Text -> Text -> [Text] -> Script ()
ensurePolicyLeaf op policyId leafHash allowedAttrs = do
  xs <- query @M.PolicyLeaf op
  let exists =
        case [ () | (_,l) <- xs, l.policyId == policyId && l.leafHash == leafHash ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[RunAll][ZK-PAC] PolicyLeaf exists"
    False -> do
      _ <- submit op do
        createCmd M.PolicyLeaf with operator = op, policyId, leafHash, allowedAttrs
      debug "[RunAll][ZK-PAC] PolicyLeaf created"

-- ==========================================================
-- Core helper
-- ==========================================================

-- ✅ FIX #2: Remove the EXTRA Text in the signature.
-- Correct argument tail should be:
--   digest : Text
--   now    : Time
--   epoch  : Int
--   merkleRoot : Text
--   spSigB64   : Text
--   senderPubHex : Text
--   spEd25519PubHex : Text
--   attCids : [ContractId SigAttestation]
verifyAndRelayIfNeeded
  : Party -> Party -> Party -> Text -> M.AlgId -> Bool -> Optional M.PolicyProof
  -> (ContractId M.BrokerContract, M.BrokerContract)
  -> (ContractId M.Device, M.Device)
  -> Text -> Time -> Int -> Text -> Text -> Text -> Text
  -> [ContractId M.SigAttestation]
  -> Script ()
verifyAndRelayIfNeeded edge op sp senderId algId useZkPac policyProof
                       (bcCid, _bc) (devCid, dev)
                       digest now epoch merkleRoot spSigB64 senderPubHex spEd25519PubHex attCids = do

  ctr <- nextCounterFor op edge dev.publicKey senderId epoch

  logs <- query @M.RelayLog op
  let already =
        [ ()
        | (_cid, r) <- logs
        , r.deviceKey == dev.publicKey
        , r.epoch     == epoch
        , r.senderId  == senderId
        , r.counter   == ctr
        ]

  case already of
    _ :: _ -> debug ("[RunAll] RelayLog already exists for counter=" <> show ctr <> "; skipping VerifyAndRelay.")
    [] -> do
      case dev.pqPubKey of
        None -> debug "[RunAll] Device pqPubKey=None"
        Some k ->
          debug ("[RunAll] Device pqPubKey normalized+trimmed length="
                 <> show (T.length (stripB64Padding k)))

      let (pqSigOpt, pqPubOpt, kyberCtOpt) =
            case (algId, dev.pqPubKey) of
              (M.ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG, Some devPq) ->
                ( Some "cHFfc2lnX2R1bW15"
                , Some (normalizeB64 devPq)
                , Some "a3liZXJfY3Q="
                )
              _ ->
                (None, None, None)

      submitMulti [edge, op] [] do
        exerciseCmd bcCid M.VerifyAndRelayMessage with
          edge               = edge
          sp                 = sp
          senderId           = senderId
          algId              = algId
          targetDevice       = devCid
          encryptedMessage   = "HELLO_ENC"
          devicePublicKey    = dev.publicKey
          senderPublicKey    = senderPubHex
          digest             = digest
          msgTimestamp       = now
          epoch              = epoch
          merkleRoot         = merkleRoot
          useZkPac           = useZkPac
          policyProof        = policyProof
          attestations       = attCids            -- ✅ now correct type
          spSignatureB64     = spSigB64
          spEd25519PubHex    = spEd25519PubHex
          ephX25519Hex       = "deadbeef"
          aad                = None
          counter            = ctr
          pqSignatureB64     = pqSigOpt
          pqPubKey           = pqPubOpt
          kyberCiphertextB64 = kyberCtOpt

      debug ("[RunAll] VerifyAndRelay submitted; counter=" <> show ctr)
      pure ()

-- ==================================================
-- Runners
-- ==================================================

runAllWithDigest : Text -> Script ()
runAllWithDigest digest = script do
  _ <- M.setup

  ps <- listKnownParties
  let op       = M.findParty ps "Operator"
  let edge1    = M.findParty ps "EdgeNode1"
  let edge2    = M.findParty ps "EdgeNode2"
  let sp       = M.findParty ps "ServiceProvider1"
  let devOwner = M.findParty ps "IoTDevice1"

  devs <- query @M.Device op
  (dev1Cid, dev1) <-
    case [ (c,d) | (c,d) <- devs, d.owner == devOwner, d.name == "Device1" ] of
      x :: _ -> pure x
      []     -> abort "Device1 not found for IoTDevice1. Did setup run?"

  snaps <- query @M.TaSnapshot op
  (snapEpoch, snapMerkleRoot) <- case snaps of
    [] -> abort "No TaSnapshot found (setup should have created epoch 0)."
    _  -> let (_, s) = latestSnapshot snaps
          in pure (s.epoch, s.merkleRoot)

  now <- getTime
  let expires   = addRelTime now (seconds 600)
      spSigB64  = "ZHVtbXk="
      senderPk  = "deadbeef"
      senderId  = "Sender1"
      algId     = dev1.algId
      spEdPkHex = "sp-ed25519-pub-hex"

  a1Cid <- findOrCreateAttestation op edge1 digest dev1.publicKey dev1.owner senderPk algId now expires
  a2Cid <- findOrCreateAttestation op edge2 digest dev1.publicKey dev1.owner senderPk algId now expires

  (bcCid0, _bc0, _who) <- findBrokerFor edge1 op

  bcCid1 <- refreshBrokerCacheAlways op [edge1, edge2] bcCid0
  (bcCid, bc) <- fetchBrokerByCid op bcCid1

  verifyAndRelayIfNeeded
    edge1 op sp senderId algId
    False None
    (bcCid, bc) (dev1Cid, dev1)
    digest now snapEpoch snapMerkleRoot spSigB64 senderPk spEdPkHex [a1Cid, a2Cid]

  debug "[RunAll] runAllWithDigest ok"
  pure ()

runAllZkPacWithDigest : Text -> Script ()
runAllZkPacWithDigest digest = script do
  _ <- M.setup

  ps <- listKnownParties
  let op       = M.findParty ps "Operator"
  let edge1    = M.findParty ps "EdgeNode1"
  let edge2    = M.findParty ps "EdgeNode2"
  let sp       = M.findParty ps "ServiceProvider1"
  let devOwner = M.findParty ps "IoTDevice1"

  devs <- query @M.Device op
  (dev1Cid, dev1) <-
    case [ (c,d) | (c,d) <- devs, d.owner == devOwner, d.name == "Device1" ] of
      x :: _ -> pure x
      []     -> abort "Device1 not found for IoTDevice1. Did setup run?"

  snaps <- query @M.TaSnapshot op
  (snapEpoch, snapMerkleRoot) <- case snaps of
    [] -> abort "No TaSnapshot found (setup should have created epoch 0)."
    _  -> let (_, s) = latestSnapshot snaps
          in pure (s.epoch, s.merkleRoot)

  let policyId = "POLICY1"
  _ <- ensurePolicyRoot op policyId snapMerkleRoot
  let leafHash = "leaf-hash-demo"
  ensurePolicyLeaf op policyId leafHash ["clearance=A"]
  let pf = mkDemoPolicyProof policyId ["clearance=A"]

  now <- getTime
  let expires   = addRelTime now (seconds 600)
      spSigB64  = "ZHVtbXk="
      senderPk  = "deadbeef"
      senderId  = "Sender1-ZK"
      algId     = dev1.algId
      spEdPkHex = "sp-ed25519-pub-hex"

  a1Cid <- findOrCreateAttestation op edge1 digest dev1.publicKey dev1.owner senderPk algId now expires
  a2Cid <- findOrCreateAttestation op edge2 digest dev1.publicKey dev1.owner senderPk algId now expires

  (bcCid0, _bc0, _who) <- findBrokerFor edge1 op

  bcCid1 <- refreshBrokerCacheAlways op [edge1, edge2] bcCid0
  (bcCid, bc) <- fetchBrokerByCid op bcCid1

  verifyAndRelayIfNeeded
    edge1 op sp senderId algId
    True (Some pf)
    (bcCid, bc) (dev1Cid, dev1)
    digest now snapEpoch snapMerkleRoot spSigB64 senderPk spEdPkHex [a1Cid, a2Cid]

  debug "[RunAllZkPac] runAllZkPacWithDigest ok"
  pure ()

-- Backward compatible names
runAll : Script ()
runAll = runAllWithDigest "digest-placeholder"

runAllZkPac : Script ()
runAllZkPac = runAllZkPacWithDigest "digest-placeholder"

seedRelayLogs : Script ()
seedRelayLogs = runAll

runRevokeDemo : Script ()
runRevokeDemo = script do
  ps <- listKnownParties
  let op = M.findParty ps "Operator"
  _ <- submit op do
    createCmd M.RevokedKey with
      operator = op
      epoch    = 0
      keyText  = "PK1"
  debug "[RunAll] Revoked PK1 for epoch 0."
  pure ()

-- ==========================================================
-- Median utils + perf sampling (unchanged)
-- ==========================================================

data Median
  = MedianOdd  with m  : Int
  | MedianEven with lo : Int; hi : Int
  deriving (Eq, Show)

medianGo : Optional Int -> [Int] -> [Int] -> Optional Median
medianGo prev slow fast =
  case fast of
    [] ->
      case (prev, slow) of
        (Some p, sHead :: _) -> Some (MedianEven with lo = p; hi = sHead)
        _                    -> None
    _ :: [] ->
      case slow of
        sHead :: _ -> Some (MedianOdd with m = sHead)
        _          -> None
    _ :: _ :: rest ->
      case slow of
        sHead :: sTail -> medianGo (Some sHead) sTail rest
        []             -> None

medianInt : [Int] -> Optional Median
medianInt xs =
  let ys = List.sort xs
  in medianGo None ys ys

template PerfSample
  with
    operator      : Party
    operation     : Text
    tag           : Text
    executionTime : Int
    ts            : Time
  where
    signatory operator

recordSample : Party -> Time -> Text -> Text -> Int -> Script ()
recordSample op now opName tag ms = do
  _ <- submit op do
    createCmd PerfSample with
      operator      = op
      operation     = opName
      tag           = tag
      executionTime = ms
      ts            = now
  pure ()

recordMany : Party -> Time -> Text -> Text -> [Int] -> Script ()
recordMany _ _ _ _ [] = pure ()
recordMany op now opName tag (x :: xs) = do
  recordSample op now opName tag x
  recordMany op now opName tag xs

seedAbstractTimes : Script ()
seedAbstractTimes = script do
  ps <- listKnownParties
  let op = M.findParty ps "Operator"
  now <- getTime
  let tag   = "A=16,cache=on,payload=1MB"
  let te2e  = [480, 505, 498, 510, 495]
  let tbsc  = [110, 120, 118, 123, 115]
  let tedge = [25,  23,  22,  27,  26]
  let tdev  = [14,  13,  12,  15,  14]
  recordMany op now "Te2e"  tag te2e
  recordMany op now "Tbsc"  tag tbsc
  recordMany op now "Tedge" tag tedge
  recordMany op now "Tdev"  tag tdev
  debug "[seedAbstractTimes] inserted sample timings."
  pure ()

calcMedian : Script ()
calcMedian = script do
  ps <- listKnownParties
  let op = M.findParty ps "Operator"
  rows <- query @PerfSample op
  let opNameWanted = "Te2e"
  let tagWanted    = "A=16,cache=on,payload=1MB"
  let xs =
        [ l.executionTime
        | (_cid, l) <- rows
        , l.operation == opNameWanted
        , l.tag       == tagWanted
        ]
  case medianInt xs of
    None -> debug ("[Median] no samples for " <> opNameWanted <> " / " <> tagWanted)
    Some (MedianOdd  {m})     ->
      debug ("[Median] " <> opNameWanted <> " " <> tagWanted <> " = " <> show m <> " ms")
    Some (MedianEven {lo,hi}) ->
      debug ("[Median] " <> opNameWanted <> " " <> tagWanted <> " middles = (" <> show lo <> "," <> show hi <> ")")
  pure ()

calcMedianRelayCounters : Script ()
calcMedianRelayCounters = script do
  ps <- listKnownParties
  let op = M.findParty ps "Operator"
  logs <- query @M.RelayLog op
  let samples = [ r.counter | (_cid, r) <- logs ]
  case medianInt samples of
    None -> debug "[Median] No RelayLog samples."
    Some (MedianOdd  {m})     ->
      debug ("[Median] RelayLog.counter median = " <> show m)
    Some (MedianEven {lo,hi}) ->
      debug ("[Median] RelayLog.counter even-count middles = (" <> show lo <> "," <> show hi <> ")")
  pure ()

exportPerfCSV : Script ()
exportPerfCSV = script do
  ps <- listKnownParties
  let op = M.findParty ps "Operator"
  rows <- query @PerfSample op
  debug "operation,tag,ms,timestamp"
  mapScript_ (\(_cid, l) ->
      debug (l.operation <> "," <> l.tag <> "," <> show l.executionTime <> "," <> show l.ts)
    ) rows
  pure ()

wipePerfSamples : Script ()
wipePerfSamples = script do
  ps <- listKnownParties
  let op = M.findParty ps "Operator"
  rows <- query @PerfSample op
  mapScript_ (\(cid, _) -> submit op do exerciseCmd cid Archive) rows
  debug "[wipePerfSamples] archived all PerfSample rows."
  pure ()



module Main where

import Daml.Script
import DA.Time
import DA.Foldable as Foldable
import DA.List as L
import DA.Map as Map
import DA.Text as T

-- ─────────────────────────────────────────────────────────────────────────────
-- Small helper: convert Party -> Text without surrounding quotes

partyToTextClean : Party -> Text
partyToTextClean p =
  let raw = show p
  in T.dropSuffix "'" (T.dropPrefix "'" raw)

-- ─────────────────────────────────────────────────────────────────────────────
-- Algorithm identifiers (metadata only; crypto is off-ledger)

data AlgId
  = ALG_X25519_AESGCM_ED25519
  | ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG
  deriving (Eq, Show)

-- ZK-PAC: Minimal policy proof object (Merkle-style commitment)
data PolicyProof = PolicyProof
  with
    policyId      : Text
    leafHash      : Text
    merklePath    : [Text]
    revealedAttrs : [Text]
  deriving (Eq, Show)

-- NEW: ZK-PAC leaf anchor.
template PolicyLeaf
  with
    operator     : Party
    policyId     : Text
    leafHash     : Text
    allowedAttrs : [Text]
  where
    signatory operator
    observer operator
    key (operator, (policyId, leafHash)) : (Party, (Text, Text))
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- Helpers

intersect : Eq a => [a] -> [a] -> [a]
intersect xs ys = [x | x <- xs, Foldable.elem x ys]

isSubset : Eq a => [a] -> [a] -> Bool
isSubset req have = Foldable.all (\x -> Foldable.elem x have) req

withinWindow : Time -> Time -> Time -> Bool
withinWindow t start end = (start <= t) && (t <= end)

nub : Eq a => [a] -> [a] -> [a]
nub [] _ = []
nub (x :: xs) seen =
  if Foldable.elem x seen
  then nub xs seen
  else x :: nub xs (x :: seen)

foldlScript : (b -> a -> Script b) -> b -> [a] -> Script b
foldlScript _ acc [] = pure acc
foldlScript f acc (x :: xs) = do
  acc' <- f acc x
  foldlScript f acc' xs

foldlUpdate : (b -> a -> Update b) -> b -> [a] -> Update b
foldlUpdate _ acc [] = pure acc
foldlUpdate f acc (x :: xs) = do
  acc' <- f acc x
  foldlUpdate f acc' xs

-- Find a party by display name (exported for RunAll)
findParty : [PartyDetails] -> Text -> Party
findParty ps name =
  case [ p.party | p <- ps, p.displayName == Some name ] of
    x :: _ -> x
    []     -> error ("Missing " <> name)

-- ─────────────────────────────────────────────────────────────────────────────
-- Base64 / PQ sanity checks (lightweight: we don't decode on-ledger)

normalizeB64 : Text -> Text
normalizeB64 t =
  T.replace "\n" "" (
  T.replace "\r" "" (
  T.replace "\t" "" (
  T.replace " "  "" t )))

stripB64Padding : Text -> Text
stripB64Padding t =
  T.dropWhileEnd (\c -> c == "=") t

allowedB64Chars : [Text]
allowedB64Chars =
  T.explode "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

firstBadB64CharGo : [Text] -> Optional Text
firstBadB64CharGo [] = None
firstBadB64CharGo (c :: rest) =
  if Foldable.elem c allowedB64Chars
  then firstBadB64CharGo rest
  else Some c

firstBadB64Char : Text -> Optional Text
firstBadB64Char t =
  firstBadB64CharGo (T.explode (normalizeB64 t))

isBase64Text : Text -> Bool
isBase64Text t =
  case firstBadB64Char t of
    None   -> True
    Some _ -> False

isLikelyHybridPqPubB64 : Text -> Bool
isLikelyHybridPqPubB64 b64Raw =
  let b64 = normalizeB64 b64Raw
      n   = T.length (stripB64Padding b64)
  in (n >= 900 && n <= 2300) && isBase64Text b64

assertHybridPqKeyOk : Optional Text -> Update ()
assertHybridPqKeyOk pqOpt =
  case pqOpt of
    None -> abort "[Hybrid] pqPubKey required for hybrid AlgId"
    Some b64Raw -> do
      let b64 = normalizeB64 b64Raw
      case firstBadB64Char b64 of
        Some bad ->
          abort ("[Hybrid] pqPubKey invalid Base64 char: " <> show bad)
        None ->
          assertMsg "[Hybrid] pqPubKey size sanity check failed"
            (isLikelyHybridPqPubB64 b64)

-- ─────────────────────────────────────────────────────────────────────────────
-- Deterministic digest helper for tests

mkDigestText
  : Text -> Text -> Optional Text -> Text -> Text -> Text
  -> Time -> Int -> Int -> Text
mkDigestText ciphertext eph aad spPub devicePk senderPk ts epoch counter =
  "ct=" <> ciphertext
  <> "|eph=" <> eph
  <> "|aad=" <> (case aad of None -> ""; Some a -> a)
  <> "|sp=" <> spPub
  <> "|dev=" <> devicePk
  <> "|sender=" <> senderPk
  <> "|ts=" <> show ts
  <> "|epoch=" <> show epoch
  <> "|ctr=" <> show counter

-- ─────────────────────────────────────────────────────────────────────────────
-- TA committee

template TACommittee
  with
    operator  : Party
    members   : [Party]
    threshold : Int
  where
    signatory operator
    observer (operator :: members)
    key operator : Party
    maintainer key

template TaSnapshot
  with
    operator   : Party
    epoch      : Int
    merkleRoot : Text
  where
    signatory operator
    observer operator
    key (operator, epoch) : (Party, Int)
    maintainer (fst key)

template PolicyRoot
  with
    operator   : Party
    policyId   : Text
    merkleRoot : Text
  where
    signatory operator
    observer operator
    key (operator, policyId) : (Party, Text)
    maintainer (fst key)

template RevokedKey
  with
    operator : Party
    epoch    : Int
    keyText  : Text
  where
    signatory operator
    observer operator
    key (operator, (epoch, keyText)) : (Party, (Int, Text))
    maintainer (fst key)

template SigAttestation
  with
    operator        : Party
    issuer          : Party
    digest          : Text
    deviceOwner     : Party
    devicePublicKey : Text
    senderPublicKey : Text
    algId           : AlgId
    ts              : Time
    expires         : Time
  where
    signatory issuer
    observer (operator :: deviceOwner :: [issuer])
    key (operator, digest, issuer) : (Party, Text, Party)
    maintainer (case key of (_, _, iss) -> iss)

template SnapshotApproval
  with
    operator : Party
    epoch    : Int
    approver : Party
  where
    signatory operator, approver
    observer (operator :: [approver])
    key (operator, (epoch, approver)) : (Party, (Int, Party))
    maintainer (fst key)

template SnapshotProposal
  with
    operator         : Party
    epoch            : Int
    merkleRoot       : Text
    approvers        : [Party]
    committeeMembers : [Party]
  where
    signatory operator
    observer (operator :: committeeMembers)

    nonconsuming choice Approve : ()
      with approver : Party
      controller approver
      do
        (_, committee) <- fetchByKey @TACommittee operator
        assertMsg "[Approve] approver not a committee member"
          (Foldable.elem approver committee.members)
        exists <- lookupByKey @SnapshotApproval (operator, (epoch, approver))
        case exists of
          Some _ -> abort "[Approve] duplicate approval"
          None   -> do
            _ <- create SnapshotApproval with operator, epoch, approver
            pure ()

    choice Publish : ContractId TaSnapshot
      controller operator
      do
        (_, committee) <- fetchByKey @TACommittee operator
        approvalsCount <-
          foldlUpdate
            (\acc m -> do
               e <- lookupByKey @SnapshotApproval (operator, (epoch, m))
               case e of Some _ -> pure (acc + 1); None -> pure acc)
            0
            committee.members
        assertMsg "[Publish] not enough approvals"
          (approvalsCount >= committee.threshold)
        existing <- lookupByKey @TaSnapshot (operator, epoch)
        case existing of
          Some _ -> abort "[Publish] snapshot already exists"
          None   -> create TaSnapshot with operator, epoch, merkleRoot

-- ─────────────────────────────────────────────────────────────────────────────
-- Access control

template SPProfile
  with
    operator : Party
    subject  : Party
    roles    : [Text]
    attrs    : [Text]
    expires  : Time
  where
    signatory operator
    observer (operator :: [subject])
    key (operator, subject) : (Party, Party)
    maintainer (fst key)

template AccessPolicy
  with
    operator      : Party
    subject       : Party
    deviceOwner   : Party
    deviceKey     : Text
    requiredRoles : [Text]
    requiredAttrs : [Text]
    windowStart   : Time
    windowEnd     : Time
  where
    signatory operator
    observer (operator :: subject :: deviceOwner :: [])
    key (operator, subject) : (Party, Party)
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- IoT device

template Device
  with
    owner      : Party
    broker     : Party
    edge       : Party
    name       : Text
    publicKey  : Text
    algId      : AlgId
    attributes : [Text]
    pqPubKey   : Optional Text
  where
    signatory owner
    observer (owner :: [broker, edge])
    key (owner, publicKey) : (Party, Text)
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- Ratchet state

template RatchetState
  with
    operator  : Party
    edge      : Party
    deviceKey : Text
    senderId  : Text
    epoch     : Int
    lastCtr   : Int
  where
    signatory operator
    observer (operator :: [edge])
    key (operator, deviceKey, senderId, epoch) : (Party, Text, Text, Int)
    maintainer (case key of (op, _, _, _) -> op)

-- ─────────────────────────────────────────────────────────────────────────────
-- Relay log

template RelayLog
  with
    operator           : Party
    edge               : Party
    sp                 : Party
    senderId           : Text
    deviceOwner        : Party
    deviceKey          : Text
    bcCid              : ContractId BrokerContract
    digest             : Text
    ciphertextB64      : Text
    ephX25519Hex       : Text
    aad                : Optional Text
    counter            : Int
    ts                 : Time
    epoch              : Int
    merkleRoot         : Text
    algId              : AlgId
    spSignatureB64     : Text
    spEd25519PubHex    : Text
    pqSignatureB64     : Optional Text
    pqPubKey           : Optional Text
    kyberCiphertextB64 : Optional Text
    acked              : Bool
  where
    signatory operator, edge
    observer (operator :: deviceOwner :: sp :: [edge])
    key (operator, deviceKey, epoch, senderId, counter)
        : (Party, Text, Int, Text, Int)
    maintainer (case key of (op, _, _, _, _) -> op)

-- ─────────────────────────────────────────────────────────────────────────────
-- Broker contract + logging envelope

template LogRequest
  with
    operator : Party
    logData  : Text
    endpoint : Text
  where
    signatory operator
    observer operator

template BrokerContract
  with
    operator         : Party
    edgeNodes        : [(Party, Time)]
    iotDevices       : [(Party, Text)]
    cachedValidNodes : [(Party, Time)]
    validUntil       : Time
  where
    signatory operator
    observer ([ p | (p, _) <- edgeNodes ] ++ [ p | (p, _) <- iotDevices ])

    choice RefreshCache : ContractId BrokerContract
      with
        newValidUntil : Time
        newCached     : [(Party, Time)]
      controller operator
      do
        assertMsg "[RefreshCache] cannot shorten validity"
          (validUntil <= newValidUntil)

        let updated =
              this with
                cachedValidNodes = newCached
                validUntil       = newValidUntil

        archive self
        create updated


    nonconsuming choice RegisterDevice : ContractId Device
      with
        edge        : Party
        owner       : Party
        name        : Text
        publicKey   : Text
        attributes  : [Text]
        algId       : AlgId
        attestation : ContractId SigAttestation
        pqPubKeyOpt : Optional Text
      controller edge
      do
        now <- getTime
        assertMsg "[RegisterDevice] edge not in edgeNodes"
          (Foldable.elem edge [ p | (p, _) <- edgeNodes ])
        assertMsg "[RegisterDevice] cache expired; call RefreshCache"
          (now <= validUntil)

        a <- fetch attestation
        (_, committee) <- fetchByKey @TACommittee operator
        assertMsg "[RegisterDevice] attestation operator mismatch"
          (a.operator == operator)
        assertMsg "[RegisterDevice] deviceOwner mismatch"
          (a.deviceOwner == owner)
        assertMsg "[RegisterDevice] deviceKey mismatch"
          (a.devicePublicKey == publicKey)
        assertMsg "[RegisterDevice] attestation expired"
          (now <= a.expires)
        assertMsg "[RegisterDevice] issuer not a committee member"
          (Foldable.elem a.issuer committee.members)
        assertMsg "[RegisterDevice] algId mismatch" (a.algId == algId)

        case algId of
          ALG_X25519_AESGCM_ED25519 ->
            assertMsg "[RegisterDevice] pqPubKey must be empty for classical AlgId"
              (pqPubKeyOpt == None)
          ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG ->
            assertHybridPqKeyOk pqPubKeyOpt

        let pqNorm =
              case pqPubKeyOpt of
                None   -> None
                Some t -> Some (normalizeB64 t)

        create Device with
          owner
          broker   = operator
          edge
          name
          publicKey
          algId
          attributes
          pqPubKey = pqNorm

    nonconsuming choice VerifyAndRelayMessage : ContractId RelayLog
      with
        edge               : Party
        sp                 : Party
        senderId           : Text
        algId              : AlgId
        targetDevice       : ContractId Device
        encryptedMessage   : Text
        devicePublicKey    : Text
        senderPublicKey    : Text
        digest             : Text
        msgTimestamp       : Time
        epoch              : Int
        merkleRoot         : Text
        useZkPac           : Bool
        policyProof        : Optional PolicyProof
        attestations       : [ContractId SigAttestation]
        spSignatureB64     : Text
        spEd25519PubHex    : Text
        ephX25519Hex       : Text
        aad                : Optional Text
        counter            : Int
        pqSignatureB64     : Optional Text
        pqPubKey           : Optional Text
        kyberCiphertextB64 : Optional Text
      controller edge, operator
      do
        now <- getTime

        assertMsg "[Verify] edge not in edgeNodes"
          (Foldable.elem edge [ p | (p, _) <- edgeNodes ])
        assertMsg "[Verify] cache expired; call RefreshCache"
          (now <= validUntil)
        assertMsg "[Verify] edge not in cachedValidNodes"
          (Foldable.elem edge [ p | (p, _) <- cachedValidNodes ])

        device <- fetch targetDevice
        assertMsg "[Verify] device broker mismatch"
          (device.broker == operator)
        assertMsg "[Verify] devicePublicKey mismatch"
          (devicePublicKey == device.publicKey)
        assertMsg "[Verify] algId mismatch (device vs message)"
          (device.algId == algId)

        case algId of
          ALG_X25519_AESGCM_ED25519 ->
            case (pqSignatureB64, pqPubKey, kyberCiphertextB64, device.pqPubKey) of
              (None, None, None, None) -> pure ()
              _ -> abort "[Hybrid] PQ fields must be empty for classical AlgId"

          ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG ->
            case (pqSignatureB64, pqPubKey, kyberCiphertextB64, device.pqPubKey) of
              (Some _, Some p, Some _, Some devP) -> do
                let pN    = normalizeB64 p
                let devPN = normalizeB64 devP
                assertMsg "[Hybrid] pqPubKey mismatch vs registered device" (pN == devPN)
                assertMsg "[Hybrid] pqPubKey size/charset sanity check failed"
                  (isLikelyHybridPqPubB64 pN)
                pure ()
              _ ->
                abort "[Hybrid] Missing pqSignatureB64 / pqPubKey / kyberCiphertextB64 or device pqPubKey for hybrid AlgId"

        mSnapCid <- lookupByKey @TaSnapshot (operator, epoch)
        snap <- case mSnapCid of
          Some cid -> fetch cid
          None     -> abort "[Verify] snapshot missing for this epoch"
        assertMsg "[Verify] snapshot Merkle root mismatch"
          (snap.merkleRoot == merkleRoot)

        rkDev <- lookupByKey @RevokedKey (operator, (epoch, devicePublicKey))
        case rkDev of
          Some _ -> abort "[Verify] device key revoked for this epoch"
          None   -> pure ()

        rkSp <- lookupByKey @RevokedKey (operator, (epoch, spEd25519PubHex))
        case rkSp of
          Some _ -> abort "[Verify] SP key revoked for this epoch"
          None   -> pure ()

        assertMsg "[Verify] stale/future message"
          (msgTimestamp <= now &&
             now <= addRelTime msgTimestamp (seconds 300))

        if useZkPac then
          case policyProof of
            None -> abort "[ZK-PAC] useZkPac=True but no policyProof supplied"
            Some pf -> do
              mPrCid <- lookupByKey @PolicyRoot (operator, pf.policyId)
              case mPrCid of
                None -> abort "[ZK-PAC] PolicyRoot missing for policyId"
                Some prCid -> do
                  pr <- fetch prCid
                  assertMsg "[ZK-PAC] Merkle root mismatch with PolicyRoot"
                    (pr.merkleRoot == merkleRoot)
              mLeafCid <- lookupByKey @PolicyLeaf (operator, (pf.policyId, pf.leafHash))
              case mLeafCid of
                None      -> abort "[ZK-PAC] No PolicyLeaf anchor for leafHash"
                Some lcid -> do
                  leaf <- fetch lcid
                  assertMsg "[ZK-PAC] revealedAttrs not allowed by leaf"
                    (isSubset pf.revealedAttrs leaf.allowedAttrs)
              assertMsg "[ZK-PAC] invalid proof (empty leafHash)" (pf.leafHash /= "")
              pure ()
        else do
          mPolCid <- lookupByKey @AccessPolicy (operator, sp)
          polCid <- case mPolCid of
            Some cid -> pure cid
            None     -> abort "[Verify] AccessPolicy missing for this SP"
          pol <- fetch polCid

          assertMsg "[Verify] policy-deviceOwner mismatch"
            (pol.deviceOwner == device.owner)
          assertMsg "[Verify] policy-deviceKey mismatch"
            (pol.deviceKey == device.publicKey)
          assertMsg "[Verify] outside access window"
            (withinWindow now pol.windowStart pol.windowEnd)

          mProfCid <- lookupByKey @SPProfile (operator, sp)
          profCid <- case mProfCid of
            Some cid -> pure cid
            None     -> abort "[Verify] SPProfile missing for this SP"
          spProfile <- fetch profCid

          assertMsg "[Verify] SP profile expired"
            (now <= spProfile.expires)
          assertMsg "[Verify] RBAC roles unmet"
            (isSubset pol.requiredRoles spProfile.roles)
          assertMsg "[Verify] ABAC attrs unmet"
            (isSubset pol.requiredAttrs spProfile.attrs)

        (_, committee) <- fetchByKey @TACommittee operator
        let
          validateOne acc cid = do
            a <- fetch cid
            assertMsg "[Attest] operator mismatch" (a.operator == operator)
            assertMsg "[Attest] digest mismatch" (a.digest == digest)
            assertMsg "[Attest] deviceOwner mismatch" (a.deviceOwner == device.owner)
            assertMsg "[Attest] deviceKey mismatch" (a.devicePublicKey == device.publicKey)
            assertMsg "[Attest] senderKey mismatch" (a.senderPublicKey == senderPublicKey)
            assertMsg "[Attest] algId mismatch" (a.algId == algId)
            assertMsg "[Attest] attestation expired" (now <= a.expires)
            assertMsg "[Attest] issuer not a committee member"
              (Foldable.elem a.issuer committee.members)
            pure (acc + 1)

        attestCount <- foldlUpdate validateOne 0 attestations
        assertMsg "[Attest] insufficient attestations"
          (attestCount >= committee.threshold)

        let ratchetKey = (operator, device.publicKey, senderId, epoch)
        mStateCid <- lookupByKey @RatchetState ratchetKey
        case mStateCid of
          None -> do
            assertMsg "[Ratchet] first counter must be 1" (counter == 1)
            _ <- create RatchetState with
              operator
              edge
              deviceKey = device.publicKey
              senderId
              epoch
              lastCtr = counter
            pure ()
          Some rsCid -> do
            rs <- fetch rsCid
            assertMsg "[Ratchet] non-monotonic or non-consecutive counter"
              (counter == rs.lastCtr + 1)
            archive rsCid
            _ <- create RatchetState with
              operator
              edge
              deviceKey = device.publicKey
              senderId
              epoch
              lastCtr = counter
            pure ()

        create RelayLog with
          operator           = operator
          edge               = edge
          sp                 = sp
          senderId           = senderId
          deviceOwner        = device.owner
          deviceKey          = device.publicKey
          bcCid              = self
          digest             = digest
          ciphertextB64      = encryptedMessage
          ephX25519Hex       = ephX25519Hex
          aad                = aad
          counter            = counter
          ts                 = msgTimestamp
          epoch              = epoch
          merkleRoot         = merkleRoot
          algId              = algId
          spSignatureB64     = spSignatureB64
          spEd25519PubHex    = spEd25519PubHex
          pqSignatureB64     = pqSignatureB64
          pqPubKey           = pqPubKey
          kyberCiphertextB64 = kyberCiphertextB64
          acked              = False

    nonconsuming choice LogExecutionTime : Text
      with
        operation     : Text
        executionTime : Int
      controller operator
      do
        _ <- create LogRequest with
          operator = operator
          logData  =
            "{ \"logs\": [ { \"operator\": \"" <> partyToTextClean operator
            <> "\", \"op\": \"" <> operation
            <> "\", \"time\": " <> show executionTime <> " } ] }"
          endpoint = "http://localhost:5000/log_batch_activity"
        pure "Logged"

-- ─────────────────────────────────────────────────────────────
-- Constants

dev1X25519Hex : Text
dev1X25519Hex =
  "9514e4cdb9003b5bc30cbbb57b87c57e5786eed1b4731e76b0ec4700c72d4926"

dev1PqPubB64 : Text
dev1PqPubB64 =
  "LeCGm0TOTJmFR8UrruNwC1aPrxK+xflosVViRMSkloJcGHBD2ZiErtObCrxqqTiAQ0BjX3mJjAVJqosdekiW5GcbHCoEMjqiiEF1+1G5xtFmTwQtq0m6y/zP2flJ6WZ5X3UVlTdezgV80OpZtltA/0NxHZZEeZnCI/pmbncAaVcgAhlyfAVBLSMeDskHXMFExLU9ThMv/gxks6RCSyGHM9dOJ+vNQMRvz4mHFvBjY0MEIddO9CmtT8sZilYKE9sd1+w8tXK7CuhmKbV+LIy/V0kCfGelNbZmclkyUey7/jrITDEeJDYrbtywsnxHVMIBBAqqc4SwcWFb0SNqfpiOdgoWnjWccTnBkfGdoMJzCkFXYiW02Te9xSQckrozn2s//MEJWcisfMaBBxs0TzceHhZTWMYKknnF1xrMaeWv0RtrR2ol0fO7ygxNvzk6v9Cn35mVRGwxPGRYy2LHRCFmQPIxnWSH1Ee2Cxav+cpZdGamyuo7MhVcJbwYDTDDLqxXs5YjWAWMXHkWHsFc7DHNYStopkp1IteZXyNLD8WKNGyMAjNtcywsqStGUEwokutnq0M5WagLsOMU/5Ig8QV41NWNK2Vt2jq/DDWVbFQ3xUB6v0HBzJmAcdQexTFSRgYVK3ZGgik0xgmFVHFuoKQlGNMU5SAERHmqhwNNeSUUVxkoRVxXAL3HKQRNgYukIMsxFrCGkBajBpgqBaZxtXh0Y8apCeNWWANwwBWDqmqYKrCU3WC6lgCERDp4HZe1sVUAQKe2RCFE0NZsOdB3dgU1sGXIRtor/6R8UJl2IkFL/kiRoFw9rNMwFquhkRqhnrIROcZ8EtaM/YRMX9dTXwasj1VuK+UhY/i7MvEmKWAZArar/BUgIPpOPtll1nJHSnW7i+dO0qy5SHQ4BMtWOUcUarRFWKZ1w4wG9WF0vcm8PRqORtA3RAIflpHNmwybisSsumrAiEjHz5iEQwm9UfMlnyCOAMmECMApJlW/z5cxGwSsuVakUYOZtqMJx0IoXlKRYlcTNnGtphyagoAfYqcAlvAHuKMzFWBwpld5I4APeZvJhVlP4BRQQYhYKGRpZxQJc2I43CxLLFOrk9lRzPWe7CyZmmazmmSxJoomvaIJrQsaKQwusap8rygxEIZ0aSo5IfARQ0EQ5hGtHuqkXBNPnIrPzcGHE6IrbDc8aRK9AXS1OSORlZdTe+s11yh7I4uR7qiFV4I/ypdPwnwoJ3dJcUScgUFp6VPJ0+VjvqJZbXwe/9pALjdrstaEE6pUvngCPlylMgvImdfFKzDBO+Q6JNl31ZtyVMYMlmqmERpM9OkOgwTN8nJcp2U4jHpHOJOdbHkAOemq6JE3kKxs/TPIpEypsHbPYdGclbxFx9dTwnYVfOJGkPPOg7WSzVczIMydq+kuNmcvVqi5V+C6RZlTc9eQJgzEBuoaa3cr7/e2IGp2WZZLKwIJwoKAVgZtTbmyO+OoAwHEwkFvD1IdLoUK0qKaTcYBQwYrAUpFyiysrciqfhyISoUHbHwWvCu5h/mC6atVNtF9dkybVdozvI64LVL4SxRw5N+mlExZfPFc41U="

-- ─────────────────────────────────────────────────────────────
-- Setup & utility scripts

ensureDevice :
  Party -> Party -> Party -> Party -> Text -> Text -> AlgId -> [Text] -> Optional Text -> Script ()
ensureDevice op owner broker edge name publicKey alg attributes pqOpt = do
  devs <- query @Device op

  let pqOptN =
        case pqOpt of
          None   -> None
          Some t -> Some (normalizeB64 t)

  let matches : [(ContractId Device, Device)] =
        [ (cid, d) | (cid, d) <- devs, d.owner == owner && d.publicKey == publicKey ]

  case matches of
    [] -> do
      _ <- submit owner do
        createCmd Device with
          owner
          broker
          edge
          name
          publicKey
          algId      = alg
          attributes = attributes
          pqPubKey   = pqOptN
      debug ("[setup] device created: " <> name <> " pk=" <> publicKey)

    (cid, d) :: _ -> do
      if (   d.broker     == broker
          && d.edge       == edge
          && d.name       == name
          && d.algId      == alg
          && d.attributes == attributes
          && d.pqPubKey   == pqOptN
         )
      then
        debug ("[setup] device exists: " <> name <> " pk=" <> publicKey)
      else do
        debug ("[setup] device differs; replacing: " <> name <> " pk=" <> publicKey)
        _ <- submit owner do exerciseCmd cid Archive
        _ <- submit owner do
          createCmd Device with
            owner
            broker
            edge
            name
            publicKey
            algId      = alg
            attributes = attributes
            pqPubKey   = pqOptN
        debug ("[setup] device replaced: " <> name <> " pk=" <> publicKey)

ensureCommittee : Party -> [Party] -> Int -> Script ()
ensureCommittee op members threshold = do
  cs <- query @TACommittee op
  let exists =
        case [ () | (_, c) <- cs, c.operator == op ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[setup] TACommittee exists"
    False -> do
      _ <- submit op do
        createCmd TACommittee with operator = op, members, threshold
      debug "[setup] TACommittee created"

ensureGenesisSnapshotViaCommittee : Party -> Script ()
ensureGenesisSnapshotViaCommittee op = do
  snaps <- query @TaSnapshot op
  let hasGenesis =
        case [ () | (_, s) <- snaps, s.epoch == 0 ] of
          _ :: _ -> True
          []     -> False
  case hasGenesis of
    True  -> debug "[setup] epoch=0 snapshot exists"
    False -> do
      cs <- query @TACommittee op
      committee <-
        case [ c | (_, c) <- cs, c.operator == op ] of
          c :: _ -> pure c
          []     -> abort "TACommittee missing"

      propCid <- submit op do
        createCmd SnapshotProposal with
          operator         = op
          epoch            = 0
          merkleRoot       = "genesis"
          approvers        = []
          committeeMembers = committee.members

      let toApprove : [Party] =
            L.take committee.threshold committee.members

      _ <- foldlScript
            (\cid m -> do
               _ <- submitMulti [m, op] [] (exerciseCmd cid Approve with approver = m)
               pure cid)
            propCid
            toApprove

      _ <- submit op do exerciseCmd propCid Publish
      debug "[setup] created genesis snapshot"

ensureSPProfile : Party -> Party -> [Text] -> [Text] -> Time -> Script ()
ensureSPProfile op sp roles attrs expT = do
  prof <- query @SPProfile op
  let exists =
        case [ () | (_, p) <- prof, p.subject == sp ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[setup] SPProfile exists"
    False -> do
      _ <- submit op do
        createCmd SPProfile with
          operator = op
          subject  = sp
          roles
          attrs
          expires  = expT
      debug "[setup] SPProfile created"

ensurePolicy
  : Party -> Party -> Party -> Text
  -> [Text] -> [Text]
  -> Time -> Time
  -> Script ()
ensurePolicy op sp devOwner devKey reqRoles reqAttrs wStart wEnd = do
  pols <- query @AccessPolicy op
  let bySubject = [ (c,p) | (c,p) <- pols, p.subject == sp ]
  case bySubject of
    (cid, p) :: _ ->
      if p.deviceOwner == devOwner && p.deviceKey == devKey
      then
        debug "[setup] AccessPolicy exists (same device); OK"
      else do
        _ <- submit op do exerciseCmd cid Archive
        _ <- submit op do
          createCmd AccessPolicy with
            operator      = op
            subject       = sp
            deviceOwner   = devOwner
            deviceKey     = devKey
            requiredRoles = reqRoles
            requiredAttrs = reqAttrs
            windowStart   = wStart
            windowEnd     = wEnd
        debug "[setup] AccessPolicy replaced (device/key changed)"
    [] -> do
      _ <- submit op do
        createCmd AccessPolicy with
          operator      = op
          subject       = sp
          deviceOwner   = devOwner
          deviceKey     = devKey
          requiredRoles = reqRoles
          requiredAttrs = reqAttrs
          windowStart   = wStart
          windowEnd     = wEnd
      debug "[setup] AccessPolicy created"

setup : Script (ContractId BrokerContract)
setup = script do
  parties <- listKnownParties
  let cache =
        Foldable.foldl
          (\m p -> case p.displayName of
              Some n -> Map.insert n p.party m
              None   -> m)
          Map.empty
          parties

  let getOrAlloc name =
        case Map.lookup name cache of
          Some p -> debug ("[setup] reusing " <> name) >> pure p
          None   -> debug ("[setup] allocating " <> name)
                 >> allocatePartyWithHint name (PartyIdHint name)

  op     <- getOrAlloc "Operator"
  edge1  <- getOrAlloc "EdgeNode1"
  edge2  <- getOrAlloc "EdgeNode2"
  sp1    <- getOrAlloc "ServiceProvider1"
  sp2    <- getOrAlloc "ServiceProvider2"
  dev1   <- getOrAlloc "IoTDevice1"
  dev2   <- getOrAlloc "IoTDevice2"
  dev3   <- getOrAlloc "IoTDevice3"

  now <- getTime
  let edges   = [(edge1, now), (edge2, now)]
  let dev1Pk  = dev1X25519Hex
  let dev2Pk  = "9514e4cdb9003b5bc30cbbb57b87c57e5786eed1b4731e76b0ec4700c72d4926"
  let dev3Pk  = "PK3"
  let devices = [(dev1, dev1Pk), (dev2, dev2Pk), (dev3, dev3Pk)]

  bcs <- query @BrokerContract op
  bcCid <-
    case [ c | (c,b) <- bcs, b.operator == op ] of
      c :: _ -> debug "[setup] BrokerContract exists" >> pure c
      [] -> do
        debug "[setup] creating BrokerContract"
        submit op do
          createCmd BrokerContract with
            operator         = op
            edgeNodes        = edges
            iotDevices       = devices
            cachedValidNodes = edges
            validUntil       = addRelTime now (seconds 3600)

  ensureDevice op dev1 op edge1 "Device1" dev1Pk
    ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG
    ["loc=office","status=active"]
    (Some dev1PqPubB64)

  ensureDevice op dev2 op edge1 "Device2" dev2Pk
    ALG_X25519_AESGCM_ED25519
    ["loc=yard","status=active"]
    None

  ensureDevice op dev3 op edge1 "Device3" dev3Pk
    ALG_X25519_AESGCM_ED25519
    ["loc=quay","status=maintenance"]
    None

  ensureCommittee op [edge1, edge2] 2
  ensureGenesisSnapshotViaCommittee op

  let winStart = now
      winEnd   = addRelTime now (seconds 86400)

  ensureSPProfile op sp1
    ["writer","partner"]
    ["clearance=A","region=EU"]
    (addRelTime now (seconds 86400))

  ensurePolicy op sp1 dev1 dev1Pk
    ["writer"]
    ["clearance=A"]
    winStart
    winEnd

  ensureSPProfile op sp2
    ["writer","partner"]
    ["clearance=A","region=EU"]
    (addRelTime now (seconds 86400))

  ensurePolicy op sp2 dev2 dev2Pk
    ["writer"]
    ["clearance=A"]
    winStart
    winEnd

  debug "[setup] done"
  pure bcCid

-- ─────────────────────────────────────────────────────────────────────────────
-- ✅ Fresh-run helpers
resetAllBrokerContracts : Party -> Script ()
resetAllBrokerContracts op = do
  bcs <- query @BrokerContract op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        bcs
  debug ("[setupFresh] cleared BrokerContracts=" <> show (L.length bcs))
  pure ()

resetAllRatchets : Party -> Script ()
resetAllRatchets op = do
  rats <- query @RatchetState op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        rats
  debug ("[setupFresh] cleared RatchetStates=" <> show (L.length rats))
  pure ()

resetAllRelayLogs : Party -> Script ()
resetAllRelayLogs op = do
  logs <- query @RelayLog op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        logs
  debug ("[setupFresh] cleared RelayLogs=" <> show (L.length logs))
  pure ()

setupFresh : Script (ContractId BrokerContract)
setupFresh = script do
  parties <- listKnownParties
  let op = findParty parties "Operator"
  resetAllRatchets op
  resetAllRelayLogs op
  setup

-- ─────────────────────────────────────────────────────────────────────────────
-- Tests

testList : Script ()
testList = script do
  ps <- listKnownParties
  let ops : [Party] =
        [ p.party | p <- ps, p.displayName == Some "Operator" ]
  op <- case ops of
    x :: _ -> pure x
    []     -> abort "Operator not found"

  bcs   <- query @BrokerContract op
  devs  <- query @Device op
  snaps <- query @TaSnapshot op
  comms <- query @TACommittee op
  props <- query @SnapshotProposal op
  atts  <- query @SigAttestation op
  pols  <- query @AccessPolicy op
  profs <- query @SPProfile op
  rks   <- query @RevokedKey op
  rats  <- query @RatchetState op
  logs  <- query @RelayLog op

  debug ("[list] BrokerContracts=" <> show bcs)
  debug ("[list] Devices="         <> show devs)
  debug ("[list] TaSnapshots="     <> show snaps)
  debug ("[list] Committees="      <> show comms)
  debug ("[list] Proposals="       <> show props)
  debug ("[list] Attestations="    <> show atts)
  debug ("[list] Policies="        <> show pols)
  debug ("[list] Profiles="        <> show profs)
  debug ("[list] RevokedKeys="     <> show rks)
  debug ("[list] RatchetStates="   <> show rats)
  debug ("[list] RelayLogs="       <> show logs)
  pure ()

testVerify : Script (ContractId RelayLog)
testVerify = script do
  _ <- setup

  ps <- listKnownParties
  let op       = findParty ps "Operator"
  let edge     = findParty ps "EdgeNode1"
  let edge2    = findParty ps "EdgeNode2"
  let sp       = findParty ps "ServiceProvider2"
  let devOwner = findParty ps "IoTDevice2"

  bcs <- query @BrokerContract op
  bcCid <-
    case bcs of
      (c, _) :: _ -> pure c
      []          -> abort "No BrokerContract"

  devs <- query @Device op
  (devCid, dev) <-
    case [ (c, d) | (c, d) <- devs, d.name == "Device2" ] of
      x :: _ -> pure x
      []     -> abort "Device2 not found"
  let devPk = dev.publicKey

  snaps <- query @TaSnapshot op
  snapshot0 <-
    case [ s | (_, s) <- snaps, s.epoch == 0 ] of
      s :: _ -> pure s
      []     -> abort "No epoch 0 snapshot"
  let merkleRoot0 = snapshot0.merkleRoot

  now <- getTime
  let senderPk = "deadbeef"
  let senderId = "Sender1"
  let alg      = ALG_X25519_AESGCM_ED25519

  let ciphertext = "HELLO_ENC"
  let eph =
        "0000000000000000000000000000000000000000000000000000000000000000"
  let spPub = "deadbeef"
  let ctr = 1
  let dg = mkDigestText ciphertext eph None spPub devPk senderPk now 0 ctr

  att1 <- submit edge do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = devPk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  att2 <- submit edge2 do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge2
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = devPk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  relayCid <- submitMulti [edge, op] [] do
    exerciseCmd bcCid VerifyAndRelayMessage with
      edge               = edge
      sp                 = sp
      senderId           = senderId
      algId              = alg
      targetDevice       = devCid
      encryptedMessage   = ciphertext
      devicePublicKey    = devPk
      senderPublicKey    = senderPk
      digest             = dg
      msgTimestamp       = now
      epoch              = 0
      merkleRoot         = merkleRoot0
      useZkPac           = False
      policyProof        = None
      attestations       = [att1, att2]
      spSignatureB64     = "ZHVtbXk="
      spEd25519PubHex    = spPub
      ephX25519Hex       = eph
      aad                = None
      counter            = ctr
      pqSignatureB64     = None
      pqPubKey           = None
      kyberCiphertextB64 = None

  pure relayCid

testVerifyHybrid : Script (ContractId RelayLog)
testVerifyHybrid = script do
  _ <- setup

  ps <- listKnownParties
  let op       = findParty ps "Operator"
  let edge     = findParty ps "EdgeNode1"
  let edge2    = findParty ps "EdgeNode2"
  let sp       = findParty ps "ServiceProvider1"
  let devOwner = findParty ps "IoTDevice1"

  bcs <- query @BrokerContract op
  bcCid <-
    case bcs of
      (c, _) :: _ -> pure c
      []          -> abort "No BrokerContract"

  devs <- query @Device op
  (dev1Cid, dev1) <-
    case [ (c, d) | (c, d) <- devs, d.name == "Device1" ] of
      x :: _ -> pure x
      []     -> abort "Device1 not found"
  let dev1Pk = dev1.publicKey

  snaps <- query @TaSnapshot op
  snapshot0 <-
    case [ s | (_, s) <- snaps, s.epoch == 0 ] of
      s :: _ -> pure s
      []     -> abort "No epoch 0 snapshot"
  let merkleRoot0 = snapshot0.merkleRoot

  now <- getTime
  let senderPk = "deadbeef"
  let senderId = "Sender1"
  let alg      = ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG

  let pqSigB64 = "cHFfc2lnX2R1bW15"
  let kybCtB64 = "a3liZXJfY3Q="
  let pqPubB64 = dev1PqPubB64

  let ciphertext = "HELLO_ENC"
  let eph =
        "0000000000000000000000000000000000000000000000000000000000000000"
  let spPub = "deadbeef"
  let ctr = 1
  let dg = mkDigestText ciphertext eph None spPub dev1Pk senderPk now 0 ctr

  att1 <- submit edge do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = dev1Pk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  att2 <- submit edge2 do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge2
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = dev1Pk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  relayCid <- submitMulti [edge, op] [] do
    exerciseCmd bcCid VerifyAndRelayMessage with
      edge               = edge
      sp                 = sp
      senderId           = senderId
      algId              = alg
      targetDevice       = dev1Cid
      encryptedMessage   = ciphertext
      devicePublicKey    = dev1Pk
      senderPublicKey    = senderPk
      digest             = dg
      msgTimestamp       = now
      epoch              = 0
      merkleRoot         = merkleRoot0
      useZkPac           = False
      policyProof        = None
      attestations       = [att1, att2]
      spSignatureB64     = "ZHVtbXk="
      spEd25519PubHex    = spPub
      ephX25519Hex       = eph
      aad                = None
      counter            = ctr
      pqSignatureB64     = Some pqSigB64
      pqPubKey           = Some pqPubB64
      kyberCiphertextB64 = Some kybCtB64

  pure relayCid
--------------------------final --------------------main------------
module Main where

import Daml.Script
import DA.Time
import DA.Foldable as Foldable
import DA.List as L
import DA.Map as Map
import DA.Text as T

-- ─────────────────────────────────────────────────────────────────────────────
-- Small helper: convert Party -> Text without surrounding quotes

partyToTextClean : Party -> Text
partyToTextClean p =
  let raw = show p
  in T.dropSuffix "'" (T.dropPrefix "'" raw)

-- ─────────────────────────────────────────────────────────────────────────────
-- Algorithm identifiers (metadata only; crypto is off-ledger)

data AlgId
  = ALG_X25519_AESGCM_ED25519
  | ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG
  deriving (Eq, Show)

-- ZK-PAC: Minimal policy proof object (Merkle-style commitment)
data PolicyProof = PolicyProof
  with
    policyId      : Text
    leafHash      : Text
    merklePath    : [Text]
    revealedAttrs : [Text]
  deriving (Eq, Show)

-- NEW: ZK-PAC leaf anchor.
template PolicyLeaf
  with
    operator     : Party
    policyId     : Text
    leafHash     : Text
    allowedAttrs : [Text]
  where
    signatory operator
    observer operator
    key (operator, (policyId, leafHash)) : (Party, (Text, Text))
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- Helpers

intersect : Eq a => [a] -> [a] -> [a]
intersect xs ys = [x | x <- xs, Foldable.elem x ys]

isSubset : Eq a => [a] -> [a] -> Bool
isSubset req have = Foldable.all (\x -> Foldable.elem x have) req

withinWindow : Time -> Time -> Time -> Bool
withinWindow t start end = (start <= t) && (t <= end)

nub : Eq a => [a] -> [a] -> [a]
nub [] _ = []
nub (x :: xs) seen =
  if Foldable.elem x seen
  then nub xs seen
  else x :: nub xs (x :: seen)

foldlScript : (b -> a -> Script b) -> b -> [a] -> Script b
foldlScript _ acc [] = pure acc
foldlScript f acc (x :: xs) = do
  acc' <- f acc x
  foldlScript f acc' xs

foldlUpdate : (b -> a -> Update b) -> b -> [a] -> Update b
foldlUpdate _ acc [] = pure acc
foldlUpdate f acc (x :: xs) = do
  acc' <- f acc x
  foldlUpdate f acc' xs

-- Find a party by display name (exported for RunAll)
findParty : [PartyDetails] -> Text -> Party
findParty ps name =
  case [ p.party | p <- ps, p.displayName == Some name ] of
    x :: _ -> x
    []     -> error ("Missing " <> name)

-- ─────────────────────────────────────────────────────────────────────────────
-- Base64 / PQ sanity checks (lightweight: we don't decode on-ledger)

normalizeB64 : Text -> Text
normalizeB64 t =
  T.replace "\n" "" (
  T.replace "\r" "" (
  T.replace "\t" "" (
  T.replace " "  "" t )))

stripB64Padding : Text -> Text
stripB64Padding t =
  T.dropWhileEnd (\c -> c == "=") t

allowedB64Chars : [Text]
allowedB64Chars =
  T.explode "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

firstBadB64CharGo : [Text] -> Optional Text
firstBadB64CharGo [] = None
firstBadB64CharGo (c :: rest) =
  if Foldable.elem c allowedB64Chars
  then firstBadB64CharGo rest
  else Some c

firstBadB64Char : Text -> Optional Text
firstBadB64Char t =
  firstBadB64CharGo (T.explode (normalizeB64 t))

isBase64Text : Text -> Bool
isBase64Text t =
  case firstBadB64Char t of
    None   -> True
    Some _ -> False

isLikelyHybridPqPubB64 : Text -> Bool
isLikelyHybridPqPubB64 b64Raw =
  let b64 = normalizeB64 b64Raw
      n   = T.length (stripB64Padding b64)
  in (n >= 900 && n <= 2300) && isBase64Text b64

assertHybridPqKeyOk : Optional Text -> Update ()
assertHybridPqKeyOk pqOpt =
  case pqOpt of
    None -> abort "[Hybrid] pqPubKey required for hybrid AlgId"
    Some b64Raw -> do
      let b64 = normalizeB64 b64Raw
      case firstBadB64Char b64 of
        Some bad ->
          abort ("[Hybrid] pqPubKey invalid Base64 char: " <> show bad)
        None ->
          assertMsg "[Hybrid] pqPubKey size sanity check failed"
            (isLikelyHybridPqPubB64 b64)

-- ─────────────────────────────────────────────────────────────────────────────
-- Deterministic digest helper for tests

mkDigestText
  : Text -> Text -> Optional Text -> Text -> Text -> Text
  -> Time -> Int -> Int -> Text
mkDigestText ciphertext eph aad spPub devicePk senderPk ts epoch counter =
  "ct=" <> ciphertext
  <> "|eph=" <> eph
  <> "|aad=" <> (case aad of None -> ""; Some a -> a)
  <> "|sp=" <> spPub
  <> "|dev=" <> devicePk
  <> "|sender=" <> senderPk
  <> "|ts=" <> show ts
  <> "|epoch=" <> show epoch
  <> "|ctr=" <> show counter

-- ─────────────────────────────────────────────────────────────────────────────
-- TA committee

template TACommittee
  with
    operator  : Party
    members   : [Party]
    threshold : Int
  where
    signatory operator
    observer (operator :: members)
    key operator : Party
    maintainer key

template TaSnapshot
  with
    operator   : Party
    epoch      : Int
    merkleRoot : Text
  where
    signatory operator
    observer operator
    key (operator, epoch) : (Party, Int)
    maintainer (fst key)

template PolicyRoot
  with
    operator   : Party
    policyId   : Text
    merkleRoot : Text
  where
    signatory operator
    observer operator
    key (operator, policyId) : (Party, Text)
    maintainer (fst key)

template RevokedKey
  with
    operator : Party
    epoch    : Int
    keyText  : Text
  where
    signatory operator
    observer operator
    key (operator, (epoch, keyText)) : (Party, (Int, Text))
    maintainer (fst key)

template SigAttestation
  with
    operator        : Party
    issuer          : Party
    digest          : Text
    deviceOwner     : Party
    devicePublicKey : Text
    senderPublicKey : Text
    algId           : AlgId
    ts              : Time
    expires         : Time
  where
    signatory issuer
    observer (operator :: deviceOwner :: [issuer])
    key (operator, digest, issuer) : (Party, Text, Party)
    maintainer (case key of (_, _, iss) -> iss)

template SnapshotApproval
  with
    operator : Party
    epoch    : Int
    approver : Party
  where
    signatory operator, approver
    observer (operator :: [approver])
    key (operator, (epoch, approver)) : (Party, (Int, Party))
    maintainer (fst key)

template SnapshotProposal
  with
    operator         : Party
    epoch            : Int
    merkleRoot       : Text
    approvers        : [Party]
    committeeMembers : [Party]
  where
    signatory operator
    observer (operator :: committeeMembers)

    nonconsuming choice Approve : ()
      with approver : Party
      controller approver
      do
        (_, committee) <- fetchByKey @TACommittee operator
        assertMsg "[Approve] approver not a committee member"
          (Foldable.elem approver committee.members)
        exists <- lookupByKey @SnapshotApproval (operator, (epoch, approver))
        case exists of
          Some _ -> abort "[Approve] duplicate approval"
          None   -> do
            _ <- create SnapshotApproval with operator, epoch, approver
            pure ()

    choice Publish : ContractId TaSnapshot
      controller operator
      do
        (_, committee) <- fetchByKey @TACommittee operator
        approvalsCount <-
          foldlUpdate
            (\acc m -> do
               e <- lookupByKey @SnapshotApproval (operator, (epoch, m))
               case e of Some _ -> pure (acc + 1); None -> pure acc)
            0
            committee.members
        assertMsg "[Publish] not enough approvals"
          (approvalsCount >= committee.threshold)
        existing <- lookupByKey @TaSnapshot (operator, epoch)
        case existing of
          Some _ -> abort "[Publish] snapshot already exists"
          None   -> create TaSnapshot with operator, epoch, merkleRoot

-- ─────────────────────────────────────────────────────────────────────────────
-- Access control

template SPProfile
  with
    operator : Party
    subject  : Party
    roles    : [Text]
    attrs    : [Text]
    expires  : Time
  where
    signatory operator
    observer (operator :: [subject])
    key (operator, subject) : (Party, Party)
    maintainer (fst key)

template AccessPolicy
  with
    operator      : Party
    subject       : Party
    deviceOwner   : Party
    deviceKey     : Text
    requiredRoles : [Text]
    requiredAttrs : [Text]
    windowStart   : Time
    windowEnd     : Time
  where
    signatory operator
    observer (operator :: subject :: deviceOwner :: [])
    key (operator, subject) : (Party, Party)
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- IoT device

template Device
  with
    owner      : Party
    broker     : Party
    edge       : Party
    name       : Text
    publicKey  : Text
    algId      : AlgId
    attributes : [Text]
    pqPubKey   : Optional Text
  where
    signatory owner
    observer (owner :: [broker, edge])
    key (owner, publicKey) : (Party, Text)
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- Ratchet state

template RatchetState
  with
    operator  : Party
    edge      : Party
    deviceKey : Text
    senderId  : Text
    epoch     : Int
    lastCtr   : Int
  where
    signatory operator
    observer (operator :: [edge])
    key (operator, deviceKey, senderId, epoch) : (Party, Text, Text, Int)
    maintainer (case key of (op, _, _, _) -> op)

-- ─────────────────────────────────────────────────────────────────────────────
-- Relay log

template RelayLog
  with
    operator           : Party
    edge               : Party
    sp                 : Party
    senderId           : Text
    deviceOwner        : Party
    deviceKey          : Text
    bcCid              : ContractId BrokerContract
    digest             : Text
    ciphertextB64      : Text
    ephX25519Hex       : Text
    aad                : Optional Text
    counter            : Int
    ts                 : Time
    epoch              : Int
    merkleRoot         : Text
    algId              : AlgId
    spSignatureB64     : Text
    spEd25519PubHex    : Text
    pqSignatureB64     : Optional Text
    pqPubKey           : Optional Text
    kyberCiphertextB64 : Optional Text
    acked              : Bool
  where
    signatory operator, edge
    observer (operator :: deviceOwner :: sp :: [edge])
    key (operator, deviceKey, epoch, senderId, counter)
        : (Party, Text, Int, Text, Int)
    maintainer (case key of (op, _, _, _, _) -> op)

    -- ✅ NEW: On-ledger acknowledgement (archives + recreates with acked=True)
    -- - Controller is deviceOwner (the device acknowledges its own message)
    -- - Nonconsuming so we can make it idempotent: if already acked, return same CID.
    nonconsuming choice Acknowledge : ContractId RelayLog
      controller deviceOwner
      do
        if acked then
          pure self
        else do
          archive self
          create (this with acked = True)

-- ─────────────────────────────────────────────────────────────────────────────
-- Broker contract + logging envelope

template LogRequest
  with
    operator : Party
    logData  : Text
    endpoint : Text
  where
    signatory operator
    observer operator

template BrokerContract
  with
    operator         : Party
    edgeNodes        : [(Party, Time)]
    iotDevices       : [(Party, Text)]
    cachedValidNodes : [(Party, Time)]
    validUntil       : Time
  where
    signatory operator
    observer ([ p | (p, _) <- edgeNodes ] ++ [ p | (p, _) <- iotDevices ])

    key operator : Party
    maintainer key

    -- ✅ FIXED RefreshCache: build updated record BEFORE archive
    choice RefreshCache : ContractId BrokerContract
      with
        newValidUntil : Time
        newCached     : [(Party, Time)]
      controller operator
      do
        assertMsg "[RefreshCache] cannot shorten validity"
          (validUntil <= newValidUntil)

        let updated =
              this with
                cachedValidNodes = newCached
                validUntil       = newValidUntil

        archive self
        create updated

    nonconsuming choice RegisterDevice : ContractId Device
      with
        edge        : Party
        owner       : Party
        name        : Text
        publicKey   : Text
        attributes  : [Text]
        algId       : AlgId
        attestation : ContractId SigAttestation
        pqPubKeyOpt : Optional Text
      controller edge
      do
        now <- getTime
        assertMsg "[RegisterDevice] edge not in edgeNodes"
          (Foldable.elem edge [ p | (p, _) <- edgeNodes ])
        assertMsg "[RegisterDevice] cache expired; call RefreshCache"
          (now <= validUntil)

        a <- fetch attestation
        (_, committee) <- fetchByKey @TACommittee operator
        assertMsg "[RegisterDevice] attestation operator mismatch"
          (a.operator == operator)
        assertMsg "[RegisterDevice] deviceOwner mismatch"
          (a.deviceOwner == owner)
        assertMsg "[RegisterDevice] deviceKey mismatch"
          (a.devicePublicKey == publicKey)
        assertMsg "[RegisterDevice] attestation expired"
          (now <= a.expires)
        assertMsg "[RegisterDevice] issuer not a committee member"
          (Foldable.elem a.issuer committee.members)
        assertMsg "[RegisterDevice] algId mismatch" (a.algId == algId)

        case algId of
          ALG_X25519_AESGCM_ED25519 ->
            assertMsg "[RegisterDevice] pqPubKey must be empty for classical AlgId"
              (pqPubKeyOpt == None)
          ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG ->
            assertHybridPqKeyOk pqPubKeyOpt

        let pqNorm =
              case pqPubKeyOpt of
                None   -> None
                Some t -> Some (normalizeB64 t)

        create Device with
          owner
          broker   = operator
          edge
          name
          publicKey
          algId
          attributes
          pqPubKey = pqNorm

    nonconsuming choice VerifyAndRelayMessage : ContractId RelayLog
      with
        edge               : Party
        sp                 : Party
        senderId           : Text
        algId              : AlgId
        targetDevice       : ContractId Device
        encryptedMessage   : Text
        devicePublicKey    : Text
        senderPublicKey    : Text
        digest             : Text
        msgTimestamp       : Time
        epoch              : Int
        merkleRoot         : Text
        useZkPac           : Bool
        policyProof        : Optional PolicyProof
        attestations       : [ContractId SigAttestation]
        spSignatureB64     : Text
        spEd25519PubHex    : Text
        ephX25519Hex       : Text
        aad                : Optional Text
        counter            : Int
        pqSignatureB64     : Optional Text
        pqPubKey           : Optional Text
        kyberCiphertextB64 : Optional Text
      controller edge, operator
      do
        now <- getTime

        assertMsg "[Verify] edge not in edgeNodes"
          (Foldable.elem edge [ p | (p, _) <- edgeNodes ])
        assertMsg "[Verify] cache expired; call RefreshCache"
          (now <= validUntil)
        assertMsg "[Verify] edge not in cachedValidNodes"
          (Foldable.elem edge [ p | (p, _) <- cachedValidNodes ])

        device <- fetch targetDevice
        assertMsg "[Verify] device broker mismatch"
          (device.broker == operator)
        assertMsg "[Verify] devicePublicKey mismatch"
          (devicePublicKey == device.publicKey)
        assertMsg "[Verify] algId mismatch (device vs message)"
          (device.algId == algId)

        case algId of
          ALG_X25519_AESGCM_ED25519 ->
            case (pqSignatureB64, pqPubKey, kyberCiphertextB64, device.pqPubKey) of
              (None, None, None, None) -> pure ()
              _ -> abort "[Hybrid] PQ fields must be empty for classical AlgId"

          ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG ->
            case (pqSignatureB64, pqPubKey, kyberCiphertextB64, device.pqPubKey) of
              (Some _, Some p, Some _, Some devP) -> do
                let pN    = normalizeB64 p
                let devPN = normalizeB64 devP
                assertMsg "[Hybrid] pqPubKey mismatch vs registered device" (pN == devPN)
                assertMsg "[Hybrid] pqPubKey size/charset sanity check failed"
                  (isLikelyHybridPqPubB64 pN)
                pure ()
              _ ->
                abort "[Hybrid] Missing pqSignatureB64 / pqPubKey / kyberCiphertextB64 or device pqPubKey for hybrid AlgId"

        mSnapCid <- lookupByKey @TaSnapshot (operator, epoch)
        snap <- case mSnapCid of
          Some cid -> fetch cid
          None     -> abort "[Verify] snapshot missing for this epoch"
        assertMsg "[Verify] snapshot Merkle root mismatch"
          (snap.merkleRoot == merkleRoot)

        rkDev <- lookupByKey @RevokedKey (operator, (epoch, devicePublicKey))
        case rkDev of
          Some _ -> abort "[Verify] device key revoked for this epoch"
          None   -> pure ()

        rkSp <- lookupByKey @RevokedKey (operator, (epoch, spEd25519PubHex))
        case rkSp of
          Some _ -> abort "[Verify] SP key revoked for this epoch"
          None   -> pure ()

        assertMsg "[Verify] stale/future message"
          (msgTimestamp <= now &&
             now <= addRelTime msgTimestamp (seconds 300))

        if useZkPac then
          case policyProof of
            None -> abort "[ZK-PAC] useZkPac=True but no policyProof supplied"
            Some pf -> do
              mPrCid <- lookupByKey @PolicyRoot (operator, pf.policyId)
              case mPrCid of
                None -> abort "[ZK-PAC] PolicyRoot missing for policyId"
                Some prCid -> do
                  pr <- fetch prCid
                  assertMsg "[ZK-PAC] Merkle root mismatch with PolicyRoot"
                    (pr.merkleRoot == merkleRoot)
              mLeafCid <- lookupByKey @PolicyLeaf (operator, (pf.policyId, pf.leafHash))
              case mLeafCid of
                None      -> abort "[ZK-PAC] No PolicyLeaf anchor for leafHash"
                Some lcid -> do
                  leaf <- fetch lcid
                  assertMsg "[ZK-PAC] revealedAttrs not allowed by leaf"
                    (isSubset pf.revealedAttrs leaf.allowedAttrs)
              assertMsg "[ZK-PAC] invalid proof (empty leafHash)" (pf.leafHash /= "")
              pure ()
        else do
          mPolCid <- lookupByKey @AccessPolicy (operator, sp)
          polCid <- case mPolCid of
            Some cid -> pure cid
            None     -> abort "[Verify] AccessPolicy missing for this SP"
          pol <- fetch polCid

          assertMsg "[Verify] policy-deviceOwner mismatch"
            (pol.deviceOwner == device.owner)
          assertMsg "[Verify] policy-deviceKey mismatch"
            (pol.deviceKey == device.publicKey)
          assertMsg "[Verify] outside access window"
            (withinWindow now pol.windowStart pol.windowEnd)

          mProfCid <- lookupByKey @SPProfile (operator, sp)
          profCid <- case mProfCid of
            Some cid -> pure cid
            None     -> abort "[Verify] SPProfile missing for this SP"
          spProfile <- fetch profCid

          assertMsg "[Verify] SP profile expired"
            (now <= spProfile.expires)
          assertMsg "[Verify] RBAC roles unmet"
            (isSubset pol.requiredRoles spProfile.roles)
          assertMsg "[Verify] ABAC attrs unmet"
            (isSubset pol.requiredAttrs spProfile.attrs)

        (_, committee) <- fetchByKey @TACommittee operator
        let
          validateOne acc cid = do
            a <- fetch cid
            assertMsg "[Attest] operator mismatch" (a.operator == operator)
            assertMsg "[Attest] digest mismatch" (a.digest == digest)
            assertMsg "[Attest] deviceOwner mismatch" (a.deviceOwner == device.owner)
            assertMsg "[Attest] deviceKey mismatch" (a.devicePublicKey == device.publicKey)
            assertMsg "[Attest] senderKey mismatch" (a.senderPublicKey == senderPublicKey)
            assertMsg "[Attest] algId mismatch" (a.algId == algId)
            assertMsg "[Attest] attestation expired" (now <= a.expires)
            assertMsg "[Attest] issuer not a committee member"
              (Foldable.elem a.issuer committee.members)
            pure (acc + 1)

        attestCount <- foldlUpdate validateOne 0 attestations
        assertMsg "[Attest] insufficient attestations"
          (attestCount >= committee.threshold)

        let ratchetKey = (operator, device.publicKey, senderId, epoch)
        mStateCid <- lookupByKey @RatchetState ratchetKey
        case mStateCid of
          None -> do
            assertMsg "[Ratchet] first counter must be 1" (counter == 1)
            _ <- create RatchetState with
              operator
              edge
              deviceKey = device.publicKey
              senderId
              epoch
              lastCtr = counter
            pure ()
          Some rsCid -> do
            rs <- fetch rsCid
            assertMsg "[Ratchet] non-monotonic or non-consecutive counter"
              (counter == rs.lastCtr + 1)
            archive rsCid
            _ <- create RatchetState with
              operator
              edge
              deviceKey = device.publicKey
              senderId
              epoch
              lastCtr = counter
            pure ()

        create RelayLog with
          operator           = operator
          edge               = edge
          sp                 = sp
          senderId           = senderId
          deviceOwner        = device.owner
          deviceKey          = device.publicKey
          bcCid              = self
          digest             = digest
          ciphertextB64      = encryptedMessage
          ephX25519Hex       = ephX25519Hex
          aad                = aad
          counter            = counter
          ts                 = msgTimestamp
          epoch              = epoch
          merkleRoot         = merkleRoot
          algId              = algId
          spSignatureB64     = spSignatureB64
          spEd25519PubHex    = spEd25519PubHex
          pqSignatureB64     = pqSignatureB64
          pqPubKey           = pqPubKey
          kyberCiphertextB64 = kyberCiphertextB64
          acked              = False

    nonconsuming choice LogExecutionTime : Text
      with
        operation     : Text
        executionTime : Int
      controller operator
      do
        _ <- create LogRequest with
          operator = operator
          logData  =
            "{ \"logs\": [ { \"operator\": \"" <> partyToTextClean operator
            <> "\", \"op\": \"" <> operation
            <> "\", \"time\": " <> show executionTime <> " } ] }"
          endpoint = "http://localhost:5000/log_batch_activity"
        pure "Logged"

-- ─────────────────────────────────────────────────────────────
-- Constants

dev1X25519Hex : Text
dev1X25519Hex =
  "9514e4cdb9003b5bc30cbbb57b87c57e5786eed1b4731e76b0ec4700c72d4926"

dev1PqPubB64 : Text
dev1PqPubB64 =
  "LeCGm0TOTJmFR8UrruNwC1aPrxK+xflosVViRMSkloJcGHBD2ZiErtObCrxqqTiAQ0BjX3mJjAVJqosdekiW5GcbHCoEMjqiiEF1+1G5xtFmTwQtq0m6y/zP2flJ6WZ5X3UVlTdezgV80OpZtltA/0NxHZZEeZnCI/pmbncAaVcgAhlyfAVBLSMeDskHXMFExLU9ThMv/gxks6RCSyGHM9dOJ+vNQMRvz4mHFvBjY0MEIddO9CmtT8sZilYKE9sd1+w8tXK7CuhmKbV+LIy/V0kCfGelNbZmclkyUey7/jrITDEeJDYrbtywsnxHVMIBBAqqc4SwcWFb0SNqfpiOdgoWnjWccTnBkfGdoMJzCkFXYiW02Te9xSQckrozn2s//MEJWcisfMaBBxs0TzceHhZTWMYKknnF1xrMaeWv0RtrR2ol0fO7ygxNvzk6v9Cn35mVRGwxPGRYy2LHRCFmQPIxnWSH1Ee2Cxav+cpZdGamyuo7MhVcJbwYDTDDLqxXs5YjWAWMXHkWHsFc7DHNYStopkp1IteZXyNLD8WKNGyMAjNtcywsqStGUEwokutnq0M5WagLsOMU/5Ig8QV41NWNK2Vt2jq/DDWVbFQ3xUB6v0HBzJmAcdQexTFSRgYVK3ZGgik0xgmFVHFuoKQlGNMU5SAERHmqhwNNeSUUVxkoRVxXAL3HKQRNgYukIMsxFrCGkBajBpgqBaZxtXh0Y8apCeNWWANwwBWDqmqYKrCU3WC6lgCERDp4HZe1sVUAQKe2RCFE0NZsOdB3dgU1sGXIRtor/6R8UJl2IkFL/kiRoFw9rNMwFquhkRqhnrIROcZ8EtaM/YRMX9dTXwasj1VuK+UhY/i7MvEmKWAZArar/BUgIPpOPtll1nJHSnW7i+dO0qy5SHQ4BMtWOUcUarRFWKZ1w4wG9WF0vcm8PRqORtA3RAIflpHNmwybisSsumrAiEjHz5iEQwm9UfMlnyCOAMmECMApJlW/z5cxGwSsuVakUYOZtqMJx0IoXlKRYlcTNnGtphyagoAfYqcAlvAHuKMzFWBwpld5I4APeZvJhVlP4BRQQYhYKGRpZxQJc2I43CxLLFOrk9lRzPWe7CyZmmazmmSxJoomvaIJrQsaKQwusap8rygxEIZ0aSo5IfARQ0EQ5hGtHuqkXBNPnIrPzcGHE6IrbDc8aRK9AXS1OSORlZdTe+s11yh7I4uR7qiFV4I/ypdPwnwoJ3dJcUScgUFp6VPJ0+VjvqJZbXwe/9pALjdrstaEE6pUvngCPlylMgvImdfFKzDBO+Q6JNl31ZtyVMYMlmqmERpM9OkOgwTN8nJcp2U4jHpHOJOdbHkAOemq6JE3kKxs/TPIpEypsHbPYdGclbxFx9dTwnYVfOJGkPPOg7WSzVczIMydq+kuNmcvVqi5V+C6RZlTc9eQJgzEBuoaa3cr7/e2IGp2WZZLKwIJwoKAVgZtTbmyO+OoAwHEwkFvD1IdLoUK0qKaTcYBQwYrAUpFyiysrciqfhyISoUHbHwWvCu5h/mC6atVNtF9dkybVdozvI64LVL4SxRw5N+mlExZfPFc41U="

-- ─────────────────────────────────────────────────────────────
-- Setup & utility scripts

ensureDevice :
  Party -> Party -> Party -> Party -> Text -> Text -> AlgId -> [Text] -> Optional Text -> Script ()
ensureDevice op owner broker edge name publicKey alg attributes pqOpt = do
  devs <- query @Device op

  let pqOptN =
        case pqOpt of
          None   -> None
          Some t -> Some (normalizeB64 t)

  let matches : [(ContractId Device, Device)] =
        [ (cid, d) | (cid, d) <- devs, d.owner == owner && d.publicKey == publicKey ]

  case matches of
    [] -> do
      _ <- submit owner do
        createCmd Device with
          owner
          broker
          edge
          name
          publicKey
          algId      = alg
          attributes = attributes
          pqPubKey   = pqOptN
      debug ("[setup] device created: " <> name <> " pk=" <> publicKey)

    (cid, d) :: _ -> do
      if (   d.broker     == broker
          && d.edge       == edge
          && d.name       == name
          && d.algId      == alg
          && d.attributes == attributes
          && d.pqPubKey   == pqOptN
         )
      then
        debug ("[setup] device exists: " <> name <> " pk=" <> publicKey)
      else do
        debug ("[setup] device differs; replacing: " <> name <> " pk=" <> publicKey)
        _ <- submit owner do exerciseCmd cid Archive
        _ <- submit owner do
          createCmd Device with
            owner
            broker
            edge
            name
            publicKey
            algId      = alg
            attributes = attributes
            pqPubKey   = pqOptN
        debug ("[setup] device replaced: " <> name <> " pk=" <> publicKey)

ensureCommittee : Party -> [Party] -> Int -> Script ()
ensureCommittee op members threshold = do
  cs <- query @TACommittee op
  let exists =
        case [ () | (_, c) <- cs, c.operator == op ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[setup] TACommittee exists"
    False -> do
      _ <- submit op do
        createCmd TACommittee with operator = op, members, threshold
      debug "[setup] TACommittee created"

ensureGenesisSnapshotViaCommittee : Party -> Script ()
ensureGenesisSnapshotViaCommittee op = do
  snaps <- query @TaSnapshot op
  let hasGenesis =
        case [ () | (_, s) <- snaps, s.epoch == 0 ] of
          _ :: _ -> True
          []     -> False
  case hasGenesis of
    True  -> debug "[setup] epoch=0 snapshot exists"
    False -> do
      cs <- query @TACommittee op
      committee <-
        case [ c | (_, c) <- cs, c.operator == op ] of
          c :: _ -> pure c
          []     -> abort "TACommittee missing"

      propCid <- submit op do
        createCmd SnapshotProposal with
          operator         = op
          epoch            = 0
          merkleRoot       = "genesis"
          approvers        = []
          committeeMembers = committee.members

      let toApprove : [Party] =
            L.take committee.threshold committee.members

      _ <- foldlScript
            (\cid m -> do
               _ <- submitMulti [m, op] [] (exerciseCmd cid Approve with approver = m)
               pure cid)
            propCid
            toApprove

      _ <- submit op do exerciseCmd propCid Publish
      debug "[setup] created genesis snapshot"

ensureSPProfile : Party -> Party -> [Text] -> [Text] -> Time -> Script ()
ensureSPProfile op sp roles attrs expT = do
  prof <- query @SPProfile op
  let exists =
        case [ () | (_, p) <- prof, p.subject == sp ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[setup] SPProfile exists"
    False -> do
      _ <- submit op do
        createCmd SPProfile with
          operator = op
          subject  = sp
          roles
          attrs
          expires  = expT
      debug "[setup] SPProfile created"

ensurePolicy
  : Party -> Party -> Party -> Text
  -> [Text] -> [Text]
  -> Time -> Time
  -> Script ()
ensurePolicy op sp devOwner devKey reqRoles reqAttrs wStart wEnd = do
  pols <- query @AccessPolicy op
  let bySubject = [ (c,p) | (c,p) <- pols, p.subject == sp ]
  case bySubject of
    (cid, p) :: _ ->
      if p.deviceOwner == devOwner && p.deviceKey == devKey
      then
        debug "[setup] AccessPolicy exists (same device); OK"
      else do
        _ <- submit op do exerciseCmd cid Archive
        _ <- submit op do
          createCmd AccessPolicy with
            operator      = op
            subject       = sp
            deviceOwner   = devOwner
            deviceKey     = devKey
            requiredRoles = reqRoles
            requiredAttrs = reqAttrs
            windowStart   = wStart
            windowEnd     = wEnd
        debug "[setup] AccessPolicy replaced (device/key changed)"
    [] -> do
      _ <- submit op do
        createCmd AccessPolicy with
          operator      = op
          subject       = sp
          deviceOwner   = devOwner
          deviceKey     = devKey
          requiredRoles = reqRoles
          requiredAttrs = reqAttrs
          windowStart   = wStart
          windowEnd     = wEnd
      debug "[setup] AccessPolicy created"

setup : Script (ContractId BrokerContract)
setup = script do
  parties <- listKnownParties
  let cache =
        Foldable.foldl
          (\m p -> case p.displayName of
              Some n -> Map.insert n p.party m
              None   -> m)
          Map.empty
          parties

  let getOrAlloc name =
        case Map.lookup name cache of
          Some p -> debug ("[setup] reusing " <> name) >> pure p
          None   -> debug ("[setup] allocating " <> name)
                 >> allocatePartyWithHint name (PartyIdHint name)

  op     <- getOrAlloc "Operator"
  edge1  <- getOrAlloc "EdgeNode1"
  edge2  <- getOrAlloc "EdgeNode2"
  sp1    <- getOrAlloc "ServiceProvider1"
  sp2    <- getOrAlloc "ServiceProvider2"
  dev1   <- getOrAlloc "IoTDevice1"
  dev2   <- getOrAlloc "IoTDevice2"
  dev3   <- getOrAlloc "IoTDevice3"

  now <- getTime
  let edges   = [(edge1, now), (edge2, now)]
  let dev1Pk  = dev1X25519Hex
  let dev2Pk  = "9514e4cdb9003b5bc30cbbb57b87c57e5786eed1b4731e76b0ec4700c72d4926"
  let dev3Pk  = "PK3"
  let devices = [(dev1, dev1Pk), (dev2, dev2Pk), (dev3, dev3Pk)]

  bcs <- query @BrokerContract op
  bcCid <-
    case [ c | (c,b) <- bcs, b.operator == op ] of
      c :: _ -> debug "[setup] BrokerContract exists" >> pure c
      [] -> do
        debug "[setup] creating BrokerContract"
        submit op do
          createCmd BrokerContract with
            operator         = op
            edgeNodes        = edges
            iotDevices       = devices
            cachedValidNodes = edges
            validUntil       = addRelTime now (seconds 3600)

  ensureDevice op dev1 op edge1 "Device1" dev1Pk
    ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG
    ["loc=office","status=active"]
    (Some dev1PqPubB64)

  ensureDevice op dev2 op edge1 "Device2" dev2Pk
    ALG_X25519_AESGCM_ED25519
    ["loc=yard","status=active"]
    None

  ensureDevice op dev3 op edge1 "Device3" dev3Pk
    ALG_X25519_AESGCM_ED25519
    ["loc=quay","status=maintenance"]
    None

  ensureCommittee op [edge1, edge2] 2
  ensureGenesisSnapshotViaCommittee op

  let winStart = now
      winEnd   = addRelTime now (seconds 86400)

  ensureSPProfile op sp1
    ["writer","partner"]
    ["clearance=A","region=EU"]
    (addRelTime now (seconds 86400))

  ensurePolicy op sp1 dev1 dev1Pk
    ["writer"]
    ["clearance=A"]
    winStart
    winEnd

  ensureSPProfile op sp2
    ["writer","partner"]
    ["clearance=A","region=EU"]
    (addRelTime now (seconds 86400))

  ensurePolicy op sp2 dev2 dev2Pk
    ["writer"]
    ["clearance=A"]
    winStart
    winEnd

  debug "[setup] done"
  pure bcCid

-- ─────────────────────────────────────────────────────────────────────────────
-- ✅ Fresh-run helpers

resetAllRatchets : Party -> Script ()
resetAllRatchets op = do
  rats <- query @RatchetState op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        rats
  debug ("[setupFresh] cleared RatchetStates=" <> show (L.length rats))
  pure ()

resetAllRelayLogs : Party -> Script ()
resetAllRelayLogs op = do
  logs <- query @RelayLog op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        logs
  debug ("[setupFresh] cleared RelayLogs=" <> show (L.length logs))
  pure ()

setupFresh : Script (ContractId BrokerContract)
setupFresh = script do
  parties <- listKnownParties
  let op = findParty parties "Operator"
  resetAllRatchets op
  resetAllRelayLogs op
  setup

-- ─────────────────────────────────────────────────────────────────────────────
-- Tests

testList : Script ()
testList = script do
  ps <- listKnownParties
  let ops : [Party] =
        [ p.party | p <- ps, p.displayName == Some "Operator" ]
  op <- case ops of
    x :: _ -> pure x
    []     -> abort "Operator not found"

  bcs   <- query @BrokerContract op
  devs  <- query @Device op
  snaps <- query @TaSnapshot op
  comms <- query @TACommittee op
  props <- query @SnapshotProposal op
  atts  <- query @SigAttestation op
  pols  <- query @AccessPolicy op
  profs <- query @SPProfile op
  rks   <- query @RevokedKey op
  rats  <- query @RatchetState op
  logs  <- query @RelayLog op

  debug ("[list] BrokerContracts=" <> show bcs)
  debug ("[list] Devices="         <> show devs)
  debug ("[list] TaSnapshots="     <> show snaps)
  debug ("[list] Committees="      <> show comms)
  debug ("[list] Proposals="       <> show props)
  debug ("[list] Attestations="    <> show atts)
  debug ("[list] Policies="        <> show pols)
  debug ("[list] Profiles="        <> show profs)
  debug ("[list] RevokedKeys="     <> show rks)
  debug ("[list] RatchetStates="   <> show rats)
  debug ("[list] RelayLogs="       <> show logs)
  pure ()

testVerify : Script (ContractId RelayLog)
testVerify = script do
  _ <- setup

  ps <- listKnownParties
  let op       = findParty ps "Operator"
  let edge     = findParty ps "EdgeNode1"
  let edge2    = findParty ps "EdgeNode2"
  let sp       = findParty ps "ServiceProvider2"
  let devOwner = findParty ps "IoTDevice2"

  bcs <- query @BrokerContract op
  bcCid <-
    case bcs of
      (c, _) :: _ -> pure c
      []          -> abort "No BrokerContract"

  devs <- query @Device op
  (devCid, dev) <-
    case [ (c, d) | (c, d) <- devs, d.name == "Device2" ] of
      x :: _ -> pure x
      []     -> abort "Device2 not found"
  let devPk = dev.publicKey

  snaps <- query @TaSnapshot op
  snapshot0 <-
    case [ s | (_, s) <- snaps, s.epoch == 0 ] of
      s :: _ -> pure s
      []     -> abort "No epoch 0 snapshot"
  let merkleRoot0 = snapshot0.merkleRoot

  now <- getTime
  let senderPk = "deadbeef"
  let senderId = "Sender1"
  let alg      = ALG_X25519_AESGCM_ED25519

  let ciphertext = "HELLO_ENC"
  let eph =
        "0000000000000000000000000000000000000000000000000000000000000000"
  let spPub = "deadbeef"
  let ctr = 1
  let dg = mkDigestText ciphertext eph None spPub devPk senderPk now 0 ctr

  att1 <- submit edge do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = devPk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  att2 <- submit edge2 do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge2
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = devPk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  relayCid <- submitMulti [edge, op] [] do
    exerciseCmd bcCid VerifyAndRelayMessage with
      edge               = edge
      sp                 = sp
      senderId           = senderId
      algId              = alg
      targetDevice       = devCid
      encryptedMessage   = ciphertext
      devicePublicKey    = devPk
      senderPublicKey    = senderPk
      digest             = dg
      msgTimestamp       = now
      epoch              = 0
      merkleRoot         = merkleRoot0
      useZkPac           = False
      policyProof        = None
      attestations       = [att1, att2]
      spSignatureB64     = "ZHVtbXk="
      spEd25519PubHex    = spPub
      ephX25519Hex       = eph
      aad                = None
      counter            = ctr
      pqSignatureB64     = None
      pqPubKey           = None
      kyberCiphertextB64 = None

  pure relayCid

testVerifyHybrid : Script (ContractId RelayLog)
testVerifyHybrid = script do
  _ <- setup

  ps <- listKnownParties
  let op       = findParty ps "Operator"
  let edge     = findParty ps "EdgeNode1"
  let edge2    = findParty ps "EdgeNode2"
  let sp       = findParty ps "ServiceProvider1"
  let devOwner = findParty ps "IoTDevice1"

  bcs <- query @BrokerContract op
  bcCid <-
    case bcs of
      (c, _) :: _ -> pure c
      []          -> abort "No BrokerContract"

  devs <- query @Device op
  (dev1Cid, dev1) <-
    case [ (c, d) | (c, d) <- devs, d.name == "Device1" ] of
      x :: _ -> pure x
      []     -> abort "Device1 not found"
  let dev1Pk = dev1.publicKey

  snaps <- query @TaSnapshot op
  snapshot0 <-
    case [ s | (_, s) <- snaps, s.epoch == 0 ] of
      s :: _ -> pure s
      []     -> abort "No epoch 0 snapshot"
  let merkleRoot0 = snapshot0.merkleRoot

  now <- getTime
  let senderPk = "deadbeef"
  let senderId = "Sender1"
  let alg      = ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG

  let pqSigB64 = "cHFfc2lnX2R1bW15"
  let kybCtB64 = "a3liZXJfY3Q="
  let pqPubB64 = dev1PqPubB64

  let ciphertext = "HELLO_ENC"
  let eph =
        "0000000000000000000000000000000000000000000000000000000000000000"
  let spPub = "deadbeef"
  let ctr = 1
  let dg = mkDigestText ciphertext eph None spPub dev1Pk senderPk now 0 ctr

  att1 <- submit edge do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = dev1Pk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  att2 <- submit edge2 do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge2
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = dev1Pk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  relayCid <- submitMulti [edge, op] [] do
    exerciseCmd bcCid VerifyAndRelayMessage with
      edge               = edge
      sp                 = sp
      senderId           = senderId
      algId              = alg
      targetDevice       = dev1Cid
      encryptedMessage   = ciphertext
      devicePublicKey    = dev1Pk
      senderPublicKey    = senderPk
      digest             = dg
      msgTimestamp       = now
      epoch              = 0
      merkleRoot         = merkleRoot0
      useZkPac           = False
      policyProof        = None
      attestations       = [att1, att2]
      spSignatureB64     = "ZHVtbXk="
      spEd25519PubHex    = spPub
      ephX25519Hex       = eph
      aad                = None
      counter            = ctr
      pqSignatureB64     = Some pqSigB64
      pqPubKey           = Some pqPubB64
      kyberCiphertextB64 = Some kybCtB64

  pure relayCid



template RelayLog
  with
    operator           : Party
    edge               : Party
    sp                 : Party
    senderId           : Text
    deviceOwner        : Party
    deviceKey          : Text
    bcCid              : ContractId BrokerContract
    digest             : Text
    ciphertextB64      : Text
    ephX25519Hex       : Text
    aad                : Optional Text
    counter            : Int
    ts                 : Time
    epoch              : Int
    merkleRoot         : Text
    algId              : AlgId
    spSignatureB64     : Text
    spEd25519PubHex    : Text
    pqSignatureB64     : Optional Text
    pqPubKey           : Optional Text
    kyberCiphertextB64 : Optional Text
    acked              : Bool
  where
    signatory operator, edge
    observer (operator :: deviceOwner :: sp :: [edge])
    key (operator, deviceKey, epoch, senderId, counter)
        : (Party, Text, Int, Text, Int)
    maintainer (case key of (op, _, _, _, _) -> op)

    -- ✅ NEW: on-ledger acknowledgement (archives + recreates with acked=True)
    choice Acknowledge : ContractId RelayLog
      controller operator, edge
      do
        let updated = this with acked = True
        archive self
        create updated
---------------------------------------main final 2----------
can you plz fix it and make strong security and frmakework choice structure wise which compliments my ack part module Main where 

import Daml.Script
import DA.Time
import DA.Foldable as Foldable
import DA.List as L
import DA.Map as Map
import DA.Text as T

-- ─────────────────────────────────────────────────────────────────────────────
-- Small helper: convert Party -> Text without surrounding quotes

partyToTextClean : Party -> Text
partyToTextClean p =
  let raw = show p
  in T.dropSuffix "'" (T.dropPrefix "'" raw)

-- ─────────────────────────────────────────────────────────────────────────────
-- Algorithm identifiers (metadata only; crypto is off-ledger)

data AlgId
  = ALG_X25519_AESGCM_ED25519
  | ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG
  deriving (Eq, Show)

-- ZK-PAC: Minimal policy proof object (Merkle-style commitment)
data PolicyProof = PolicyProof
  with
    policyId      : Text
    leafHash      : Text
    merklePath    : [Text]
    revealedAttrs : [Text]
  deriving (Eq, Show)

-- NEW: ZK-PAC leaf anchor.
template PolicyLeaf
  with
    operator     : Party
    policyId     : Text
    leafHash     : Text
    allowedAttrs : [Text]
  where
    signatory operator
    observer operator
    key (operator, (policyId, leafHash)) : (Party, (Text, Text))
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- Helpers

intersect : Eq a => [a] -> [a] -> [a]
intersect xs ys = [x | x <- xs, Foldable.elem x ys]

isSubset : Eq a => [a] -> [a] -> Bool
isSubset req have = Foldable.all (\x -> Foldable.elem x have) req

withinWindow : Time -> Time -> Time -> Bool
withinWindow t start end = (start <= t) && (t <= end)

nub : Eq a => [a] -> [a] -> [a]
nub [] _ = []
nub (x :: xs) seen =
  if Foldable.elem x seen
  then nub xs seen
  else x :: nub xs (x :: seen)

foldlScript : (b -> a -> Script b) -> b -> [a] -> Script b
foldlScript _ acc [] = pure acc
foldlScript f acc (x :: xs) = do
  acc' <- f acc x
  foldlScript f acc' xs

foldlUpdate : (b -> a -> Update b) -> b -> [a] -> Update b
foldlUpdate _ acc [] = pure acc
foldlUpdate f acc (x :: xs) = do
  acc' <- f acc x
  foldlUpdate f acc' xs

-- Find a party by display name (exported for RunAll)
findParty : [PartyDetails] -> Text -> Party
findParty ps name =
  case [ p.party | p <- ps, p.displayName == Some name ] of
    x :: _ -> x
    []     -> error ("Missing " <> name)

-- ─────────────────────────────────────────────────────────────────────────────
-- Base64 / PQ sanity checks (lightweight: we don't decode on-ledger)

normalizeB64 : Text -> Text
normalizeB64 t =
  T.replace "\n" "" (
  T.replace "\r" "" (
  T.replace "\t" "" (
  T.replace " "  "" t )))

stripB64Padding : Text -> Text
stripB64Padding t =
  T.dropWhileEnd (\c -> c == "=") t

allowedB64Chars : [Text]
allowedB64Chars =
  T.explode "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

firstBadB64CharGo : [Text] -> Optional Text
firstBadB64CharGo [] = None
firstBadB64CharGo (c :: rest) =
  if Foldable.elem c allowedB64Chars
  then firstBadB64CharGo rest
  else Some c

firstBadB64Char : Text -> Optional Text
firstBadB64Char t =
  firstBadB64CharGo (T.explode (normalizeB64 t))

isBase64Text : Text -> Bool
isBase64Text t =
  case firstBadB64Char t of
    None   -> True
    Some _ -> False

isLikelyHybridPqPubB64 : Text -> Bool
isLikelyHybridPqPubB64 b64Raw =
  let b64 = normalizeB64 b64Raw
      n   = T.length (stripB64Padding b64)
  in (n >= 900 && n <= 2300) && isBase64Text b64

assertHybridPqKeyOk : Optional Text -> Update ()
assertHybridPqKeyOk pqOpt =
  case pqOpt of
    None -> abort "[Hybrid] pqPubKey required for hybrid AlgId"
    Some b64Raw -> do
      let b64 = normalizeB64 b64Raw
      case firstBadB64Char b64 of
        Some bad ->
          abort ("[Hybrid] pqPubKey invalid Base64 char: " <> show bad)
        None ->
          assertMsg "[Hybrid] pqPubKey size sanity check failed"
            (isLikelyHybridPqPubB64 b64)

-- ─────────────────────────────────────────────────────────────────────────────
-- Deterministic digest helper for tests

mkDigestText
  : Text -> Text -> Optional Text -> Text -> Text -> Text
  -> Time -> Int -> Int -> Text
mkDigestText ciphertext eph aad spPub devicePk senderPk ts epoch counter =
  "ct=" <> ciphertext
  <> "|eph=" <> eph
  <> "|aad=" <> (case aad of None -> ""; Some a -> a)
  <> "|sp=" <> spPub
  <> "|dev=" <> devicePk
  <> "|sender=" <> senderPk
  <> "|ts=" <> show ts
  <> "|epoch=" <> show epoch
  <> "|ctr=" <> show counter

-- ─────────────────────────────────────────────────────────────────────────────
-- TA committee

template TACommittee
  with
    operator  : Party
    members   : [Party]
    threshold : Int
  where
    signatory operator
    observer (operator :: members)
    key operator : Party
    maintainer key

template TaSnapshot
  with
    operator   : Party
    epoch      : Int
    merkleRoot : Text
  where
    signatory operator
    observer operator
    key (operator, epoch) : (Party, Int)
    maintainer (fst key)

template PolicyRoot
  with
    operator   : Party
    policyId   : Text
    merkleRoot : Text
  where
    signatory operator
    observer operator
    key (operator, policyId) : (Party, Text)
    maintainer (fst key)

template RevokedKey
  with
    operator : Party
    epoch    : Int
    keyText  : Text
  where
    signatory operator
    observer operator
    key (operator, (epoch, keyText)) : (Party, (Int, Text))
    maintainer (fst key)

template SigAttestation
  with
    operator        : Party
    issuer          : Party
    digest          : Text
    deviceOwner     : Party
    devicePublicKey : Text
    senderPublicKey : Text
    algId           : AlgId
    ts              : Time
    expires         : Time
  where
    signatory issuer
    observer (operator :: deviceOwner :: [issuer])
    key (operator, digest, issuer) : (Party, Text, Party)
    maintainer (case key of (_, _, iss) -> iss)

template SnapshotApproval
  with
    operator : Party
    epoch    : Int
    approver : Party
  where
    signatory operator, approver
    observer (operator :: [approver])
    key (operator, (epoch, approver)) : (Party, (Int, Party))
    maintainer (fst key)

template SnapshotProposal
  with
    operator         : Party
    epoch            : Int
    merkleRoot       : Text
    approvers        : [Party]
    committeeMembers : [Party]
  where
    signatory operator
    observer (operator :: committeeMembers)

    nonconsuming choice Approve : ()
      with approver : Party
      controller approver
      do
        (_, committee) <- fetchByKey @TACommittee operator
        assertMsg "[Approve] approver not a committee member"
          (Foldable.elem approver committee.members)
        exists <- lookupByKey @SnapshotApproval (operator, (epoch, approver))
        case exists of
          Some _ -> abort "[Approve] duplicate approval"
          None   -> do
            _ <- create SnapshotApproval with operator, epoch, approver
            pure ()

    choice Publish : ContractId TaSnapshot
      controller operator
      do
        (_, committee) <- fetchByKey @TACommittee operator
        approvalsCount <-
          foldlUpdate
            (\acc m -> do
               e <- lookupByKey @SnapshotApproval (operator, (epoch, m))
               case e of Some _ -> pure (acc + 1); None -> pure acc)
            0
            committee.members
        assertMsg "[Publish] not enough approvals"
          (approvalsCount >= committee.threshold)
        existing <- lookupByKey @TaSnapshot (operator, epoch)
        case existing of
          Some _ -> abort "[Publish] snapshot already exists"
          None   -> create TaSnapshot with operator, epoch, merkleRoot

-- ─────────────────────────────────────────────────────────────────────────────
-- Access control

template SPProfile
  with
    operator : Party
    subject  : Party
    roles    : [Text]
    attrs    : [Text]
    expires  : Time
  where
    signatory operator
    observer (operator :: [subject])
    key (operator, subject) : (Party, Party)
    maintainer (fst key)

template AccessPolicy
  with
    operator      : Party
    subject       : Party
    deviceOwner   : Party
    deviceKey     : Text
    requiredRoles : [Text]
    requiredAttrs : [Text]
    windowStart   : Time
    windowEnd     : Time
  where
    signatory operator
    observer (operator :: subject :: deviceOwner :: [])
    key (operator, subject) : (Party, Party)
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- IoT device

template Device
  with
    owner      : Party
    broker     : Party
    edge       : Party
    name       : Text
    publicKey  : Text
    algId      : AlgId
    attributes : [Text]
    pqPubKey   : Optional Text
  where
    signatory owner
    observer (owner :: [broker, edge])
    key (owner, publicKey) : (Party, Text)
    maintainer (fst key)

-- ─────────────────────────────────────────────────────────────────────────────
-- Ratchet state

template RatchetState
  with
    operator  : Party
    edge      : Party
    deviceKey : Text
    senderId  : Text
    epoch     : Int
    lastCtr   : Int
  where
    signatory operator
    observer (operator :: [edge])
    key (operator, deviceKey, senderId, epoch) : (Party, Text, Text, Int)
    maintainer (case key of (op, _, _, _) -> op)

-- ─────────────────────────────────────────────────────────────────────────────
-- Relay log

template RelayLog
  with
    operator           : Party
    edge               : Party
    sp                 : Party
    senderId           : Text
    deviceOwner        : Party
    deviceKey          : Text
    bcCid              : ContractId BrokerContract
    digest             : Text
    ciphertextB64      : Text
    ephX25519Hex       : Text
    aad                : Optional Text
    counter            : Int
    ts                 : Time
    epoch              : Int
    merkleRoot         : Text
    algId              : AlgId
    spSignatureB64     : Text
    spEd25519PubHex    : Text
    pqSignatureB64     : Optional Text
    pqPubKey           : Optional Text
    kyberCiphertextB64 : Optional Text
    acked              : Bool
  where
    signatory operator, edge
    observer (operator :: deviceOwner :: sp :: [edge])
    key (operator, deviceKey, epoch, senderId, counter)
        : (Party, Text, Int, Text, Int)
    maintainer (case key of (op, _, _, _, _) -> op)

    -- ✅ NEW: On-ledger acknowledgement (archives + recreates with acked=True)
    -- - Controller is deviceOwner (the device acknowledges its own message)
    -- - Nonconsuming so we can make it idempotent: if already acked, return same CID.
    nonconsuming choice Acknowledge : ContractId RelayLog
      controller deviceOwner
      do
        if acked then
          pure self
        else do
          archive self
          create (this with acked = True)

-- ─────────────────────────────────────────────────────────────────────────────
-- Broker contract + logging envelope

template LogRequest
  with
    operator : Party
    logData  : Text
    endpoint : Text
  where
    signatory operator
    observer operator

template BrokerContract
  with
    operator         : Party
    edgeNodes        : [(Party, Time)]
    iotDevices       : [(Party, Text)]
    cachedValidNodes : [(Party, Time)]
    validUntil       : Time
  where
    signatory operator
    observer ([ p | (p, _) <- edgeNodes ] ++ [ p | (p, _) <- iotDevices ])

    key operator : Party
    maintainer key

    -- ✅ FIXED RefreshCache: build updated record BEFORE archive
    choice RefreshCache : ContractId BrokerContract
      with
        newValidUntil : Time
        newCached     : [(Party, Time)]
      controller operator
      do
        assertMsg "[RefreshCache] cannot shorten validity"
          (validUntil <= newValidUntil)

        let updated =
              this with
                cachedValidNodes = newCached
                validUntil       = newValidUntil

        archive self
        create updated

    nonconsuming choice RegisterDevice : ContractId Device
      with
        edge        : Party
        owner       : Party
        name        : Text
        publicKey   : Text
        attributes  : [Text]
        algId       : AlgId
        attestation : ContractId SigAttestation
        pqPubKeyOpt : Optional Text
      controller edge
      do
        now <- getTime
        assertMsg "[RegisterDevice] edge not in edgeNodes"
          (Foldable.elem edge [ p | (p, _) <- edgeNodes ])
        assertMsg "[RegisterDevice] cache expired; call RefreshCache"
          (now <= validUntil)

        a <- fetch attestation
        (_, committee) <- fetchByKey @TACommittee operator
        assertMsg "[RegisterDevice] attestation operator mismatch"
          (a.operator == operator)
        assertMsg "[RegisterDevice] deviceOwner mismatch"
          (a.deviceOwner == owner)
        assertMsg "[RegisterDevice] deviceKey mismatch"
          (a.devicePublicKey == publicKey)
        assertMsg "[RegisterDevice] attestation expired"
          (now <= a.expires)
        assertMsg "[RegisterDevice] issuer not a committee member"
          (Foldable.elem a.issuer committee.members)
        assertMsg "[RegisterDevice] algId mismatch" (a.algId == algId)

        case algId of
          ALG_X25519_AESGCM_ED25519 ->
            assertMsg "[RegisterDevice] pqPubKey must be empty for classical AlgId"
              (pqPubKeyOpt == None)
          ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG ->
            assertHybridPqKeyOk pqPubKeyOpt

        let pqNorm =
              case pqPubKeyOpt of
                None   -> None
                Some t -> Some (normalizeB64 t)

        create Device with
          owner
          broker   = operator
          edge
          name
          publicKey
          algId
          attributes
          pqPubKey = pqNorm

    nonconsuming choice VerifyAndRelayMessage : ContractId RelayLog
      with
        edge               : Party
        sp                 : Party
        senderId           : Text
        algId              : AlgId
        targetDevice       : ContractId Device
        encryptedMessage   : Text
        devicePublicKey    : Text
        senderPublicKey    : Text
        digest             : Text
        msgTimestamp       : Time
        epoch              : Int
        merkleRoot         : Text
        useZkPac           : Bool
        policyProof        : Optional PolicyProof
        attestations       : [ContractId SigAttestation]
        spSignatureB64     : Text
        spEd25519PubHex    : Text
        ephX25519Hex       : Text
        aad                : Optional Text
        counter            : Int
        pqSignatureB64     : Optional Text
        pqPubKey           : Optional Text
        kyberCiphertextB64 : Optional Text
      controller edge, operator
      do
        now <- getTime

        assertMsg "[Verify] edge not in edgeNodes"
          (Foldable.elem edge [ p | (p, _) <- edgeNodes ])
        assertMsg "[Verify] cache expired; call RefreshCache"
          (now <= validUntil)
        assertMsg "[Verify] edge not in cachedValidNodes"
          (Foldable.elem edge [ p | (p, _) <- cachedValidNodes ])

        device <- fetch targetDevice
        assertMsg "[Verify] device broker mismatch"
          (device.broker == operator)
        assertMsg "[Verify] devicePublicKey mismatch"
          (devicePublicKey == device.publicKey)
        assertMsg "[Verify] algId mismatch (device vs message)"
          (device.algId == algId)

        case algId of
          ALG_X25519_AESGCM_ED25519 ->
            case (pqSignatureB64, pqPubKey, kyberCiphertextB64, device.pqPubKey) of
              (None, None, None, None) -> pure ()
              _ -> abort "[Hybrid] PQ fields must be empty for classical AlgId"

          ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG ->
            case (pqSignatureB64, pqPubKey, kyberCiphertextB64, device.pqPubKey) of
              (Some _, Some p, Some _, Some devP) -> do
                let pN    = normalizeB64 p
                let devPN = normalizeB64 devP
                assertMsg "[Hybrid] pqPubKey mismatch vs registered device" (pN == devPN)
                assertMsg "[Hybrid] pqPubKey size/charset sanity check failed"
                  (isLikelyHybridPqPubB64 pN)
                pure ()
              _ ->
                abort "[Hybrid] Missing pqSignatureB64 / pqPubKey / kyberCiphertextB64 or device pqPubKey for hybrid AlgId"

        mSnapCid <- lookupByKey @TaSnapshot (operator, epoch)
        snap <- case mSnapCid of
          Some cid -> fetch cid
          None     -> abort "[Verify] snapshot missing for this epoch"
        assertMsg "[Verify] snapshot Merkle root mismatch"
          (snap.merkleRoot == merkleRoot)

        rkDev <- lookupByKey @RevokedKey (operator, (epoch, devicePublicKey))
        case rkDev of
          Some _ -> abort "[Verify] device key revoked for this epoch"
          None   -> pure ()

        rkSp <- lookupByKey @RevokedKey (operator, (epoch, spEd25519PubHex))
        case rkSp of
          Some _ -> abort "[Verify] SP key revoked for this epoch"
          None   -> pure ()

        assertMsg "[Verify] stale/future message"
          (msgTimestamp <= now &&
             now <= addRelTime msgTimestamp (seconds 300))

        if useZkPac then
          case policyProof of
            None -> abort "[ZK-PAC] useZkPac=True but no policyProof supplied"
            Some pf -> do
              mPrCid <- lookupByKey @PolicyRoot (operator, pf.policyId)
              case mPrCid of
                None -> abort "[ZK-PAC] PolicyRoot missing for policyId"
                Some prCid -> do
                  pr <- fetch prCid
                  assertMsg "[ZK-PAC] Merkle root mismatch with PolicyRoot"
                    (pr.merkleRoot == merkleRoot)
              mLeafCid <- lookupByKey @PolicyLeaf (operator, (pf.policyId, pf.leafHash))
              case mLeafCid of
                None      -> abort "[ZK-PAC] No PolicyLeaf anchor for leafHash"
                Some lcid -> do
                  leaf <- fetch lcid
                  assertMsg "[ZK-PAC] revealedAttrs not allowed by leaf"
                    (isSubset pf.revealedAttrs leaf.allowedAttrs)
              assertMsg "[ZK-PAC] invalid proof (empty leafHash)" (pf.leafHash /= "")
              pure ()
        else do
          mPolCid <- lookupByKey @AccessPolicy (operator, sp)
          polCid <- case mPolCid of
            Some cid -> pure cid
            None     -> abort "[Verify] AccessPolicy missing for this SP"
          pol <- fetch polCid

          assertMsg "[Verify] policy-deviceOwner mismatch"
            (pol.deviceOwner == device.owner)
          assertMsg "[Verify] policy-deviceKey mismatch"
            (pol.deviceKey == device.publicKey)
          assertMsg "[Verify] outside access window"
            (withinWindow now pol.windowStart pol.windowEnd)

          mProfCid <- lookupByKey @SPProfile (operator, sp)
          profCid <- case mProfCid of
            Some cid -> pure cid
            None     -> abort "[Verify] SPProfile missing for this SP"
          spProfile <- fetch profCid

          assertMsg "[Verify] SP profile expired"
            (now <= spProfile.expires)
          assertMsg "[Verify] RBAC roles unmet"
            (isSubset pol.requiredRoles spProfile.roles)
          assertMsg "[Verify] ABAC attrs unmet"
            (isSubset pol.requiredAttrs spProfile.attrs)

        (_, committee) <- fetchByKey @TACommittee operator
        let
          validateOne acc cid = do
            a <- fetch cid
            assertMsg "[Attest] operator mismatch" (a.operator == operator)
            assertMsg "[Attest] digest mismatch" (a.digest == digest)
            assertMsg "[Attest] deviceOwner mismatch" (a.deviceOwner == device.owner)
            assertMsg "[Attest] deviceKey mismatch" (a.devicePublicKey == device.publicKey)
            assertMsg "[Attest] senderKey mismatch" (a.senderPublicKey == senderPublicKey)
            assertMsg "[Attest] algId mismatch" (a.algId == algId)
            assertMsg "[Attest] attestation expired" (now <= a.expires)
            assertMsg "[Attest] issuer not a committee member"
              (Foldable.elem a.issuer committee.members)
            pure (acc + 1)

        attestCount <- foldlUpdate validateOne 0 attestations
        assertMsg "[Attest] insufficient attestations"
          (attestCount >= committee.threshold)

        let ratchetKey = (operator, device.publicKey, senderId, epoch)
        mStateCid <- lookupByKey @RatchetState ratchetKey
        case mStateCid of
          None -> do
            assertMsg "[Ratchet] first counter must be 1" (counter == 1)
            _ <- create RatchetState with
              operator
              edge
              deviceKey = device.publicKey
              senderId
              epoch
              lastCtr = counter
            pure ()
          Some rsCid -> do
            rs <- fetch rsCid
            assertMsg "[Ratchet] non-monotonic or non-consecutive counter"
              (counter == rs.lastCtr + 1)
            archive rsCid
            _ <- create RatchetState with
              operator
              edge
              deviceKey = device.publicKey
              senderId
              epoch
              lastCtr = counter
            pure ()

        create RelayLog with
          operator           = operator
          edge               = edge
          sp                 = sp
          senderId           = senderId
          deviceOwner        = device.owner
          deviceKey          = device.publicKey
          bcCid              = self
          digest             = digest
          ciphertextB64      = encryptedMessage
          ephX25519Hex       = ephX25519Hex
          aad                = aad
          counter            = counter
          ts                 = msgTimestamp
          epoch              = epoch
          merkleRoot         = merkleRoot
          algId              = algId
          spSignatureB64     = spSignatureB64
          spEd25519PubHex    = spEd25519PubHex
          pqSignatureB64     = pqSignatureB64
          pqPubKey           = pqPubKey
          kyberCiphertextB64 = kyberCiphertextB64
          acked              = False

    nonconsuming choice LogExecutionTime : Text
      with
        operation     : Text
        executionTime : Int
      controller operator
      do
        _ <- create LogRequest with
          operator = operator
          logData  =
            "{ \"logs\": [ { \"operator\": \"" <> partyToTextClean operator
            <> "\", \"op\": \"" <> operation
            <> "\", \"time\": " <> show executionTime <> " } ] }"
          endpoint = "http://localhost:5000/log_batch_activity"
        pure "Logged"

-- ─────────────────────────────────────────────────────────────
-- Constants

dev1X25519Hex : Text
dev1X25519Hex =
  "9514e4cdb9003b5bc30cbbb57b87c57e5786eed1b4731e76b0ec4700c72d4926"

dev1PqPubB64 : Text
dev1PqPubB64 =
  "LeCGm0TOTJmFR8UrruNwC1aPrxK+xflosVViRMSkloJcGHBD2ZiErtObCrxqqTiAQ0BjX3mJjAVJqosdekiW5GcbHCoEMjqiiEF1+1G5xtFmTwQtq0m6y/zP2flJ6WZ5X3UVlTdezgV80OpZtltA/0NxHZZEeZnCI/pmbncAaVcgAhlyfAVBLSMeDskHXMFExLU9ThMv/gxks6RCSyGHM9dOJ+vNQMRvz4mHFvBjY0MEIddO9CmtT8sZilYKE9sd1+w8tXK7CuhmKbV+LIy/V0kCfGelNbZmclkyUey7/jrITDEeJDYrbtywsnxHVMIBBAqqc4SwcWFb0SNqfpiOdgoWnjWccTnBkfGdoMJzCkFXYiW02Te9xSQckrozn2s//MEJWcisfMaBBxs0TzceHhZTWMYKknnF1xrMaeWv0RtrR2ol0fO7ygxNvzk6v9Cn35mVRGwxPGRYy2LHRCFmQPIxnWSH1Ee2Cxav+cpZdGamyuo7MhVcJbwYDTDDLqxXs5YjWAWMXHkWHsFc7DHNYStopkp1IteZXyNLD8WKNGyMAjNtcywsqStGUEwokutnq0M5WagLsOMU/5Ig8QV41NWNK2Vt2jq/DDWVbFQ3xUB6v0HBzJmAcdQexTFSRgYVK3ZGgik0xgmFVHFuoKQlGNMU5SAERHmqhwNNeSUUVxkoRVxXAL3HKQRNgYukIMsxFrCGkBajBpgqBaZxtXh0Y8apCeNWWANwwBWDqmqYKrCU3WC6lgCERDp4HZe1sVUAQKe2RCFE0NZsOdB3dgU1sGXIRtor/6R8UJl2IkFL/kiRoFw9rNMwFquhkRqhnrIROcZ8EtaM/YRMX9dTXwasj1VuK+UhY/i7MvEmKWAZArar/BUgIPpOPtll1nJHSnW7i+dO0qy5SHQ4BMtWOUcUarRFWKZ1w4wG9WF0vcm8PRqORtA3RAIflpHNmwybisSsumrAiEjHz5iEQwm9UfMlnyCOAMmECMApJlW/z5cxGwSsuVakUYOZtqMJx0IoXlKRYlcTNnGtphyagoAfYqcAlvAHuKMzFWBwpld5I4APeZvJhVlP4BRQQYhYKGRpZxQJc2I43CxLLFOrk9lRzPWe7CyZmmazmmSxJoomvaIJrQsaKQwusap8rygxEIZ0aSo5IfARQ0EQ5hGtHuqkXBNPnIrPzcGHE6IrbDc8aRK9AXS1OSORlZdTe+s11yh7I4uR7qiFV4I/ypdPwnwoJ3dJcUScgUFp6VPJ0+VjvqJZbXwe/9pALjdrstaEE6pUvngCPlylMgvImdfFKzDBO+Q6JNl31ZtyVMYMlmqmERpM9OkOgwTN8nJcp2U4jHpHOJOdbHkAOemq6JE3kKxs/TPIpEypsHbPYdGclbxFx9dTwnYVfOJGkPPOg7WSzVczIMydq+kuNmcvVqi5V+C6RZlTc9eQJgzEBuoaa3cr7/e2IGp2WZZLKwIJwoKAVgZtTbmyO+OoAwHEwkFvD1IdLoUK0qKaTcYBQwYrAUpFyiysrciqfhyISoUHbHwWvCu5h/mC6atVNtF9dkybVdozvI64LVL4SxRw5N+mlExZfPFc41U="

-- ─────────────────────────────────────────────────────────────
-- Setup & utility scripts

ensureDevice :
  Party -> Party -> Party -> Party -> Text -> Text -> AlgId -> [Text] -> Optional Text -> Script ()
ensureDevice op owner broker edge name publicKey alg attributes pqOpt = do
  devs <- query @Device op

  let pqOptN =
        case pqOpt of
          None   -> None
          Some t -> Some (normalizeB64 t)

  let matches : [(ContractId Device, Device)] =
        [ (cid, d) | (cid, d) <- devs, d.owner == owner && d.publicKey == publicKey ]

  case matches of
    [] -> do
      _ <- submit owner do
        createCmd Device with
          owner
          broker
          edge
          name
          publicKey
          algId      = alg
          attributes = attributes
          pqPubKey   = pqOptN
      debug ("[setup] device created: " <> name <> " pk=" <> publicKey)

    (cid, d) :: _ -> do
      if (   d.broker     == broker
          && d.edge       == edge
          && d.name       == name
          && d.algId      == alg
          && d.attributes == attributes
          && d.pqPubKey   == pqOptN
         )
      then
        debug ("[setup] device exists: " <> name <> " pk=" <> publicKey)
      else do
        debug ("[setup] device differs; replacing: " <> name <> " pk=" <> publicKey)
        _ <- submit owner do exerciseCmd cid Archive
        _ <- submit owner do
          createCmd Device with
            owner
            broker
            edge
            name
            publicKey
            algId      = alg
            attributes = attributes
            pqPubKey   = pqOptN
        debug ("[setup] device replaced: " <> name <> " pk=" <> publicKey)

ensureCommittee : Party -> [Party] -> Int -> Script ()
ensureCommittee op members threshold = do
  cs <- query @TACommittee op
  let exists =
        case [ () | (_, c) <- cs, c.operator == op ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[setup] TACommittee exists"
    False -> do
      _ <- submit op do
        createCmd TACommittee with operator = op, members, threshold
      debug "[setup] TACommittee created"

ensureGenesisSnapshotViaCommittee : Party -> Script ()
ensureGenesisSnapshotViaCommittee op = do
  snaps <- query @TaSnapshot op
  let hasGenesis =
        case [ () | (_, s) <- snaps, s.epoch == 0 ] of
          _ :: _ -> True
          []     -> False
  case hasGenesis of
    True  -> debug "[setup] epoch=0 snapshot exists"
    False -> do
      cs <- query @TACommittee op
      committee <-
        case [ c | (_, c) <- cs, c.operator == op ] of
          c :: _ -> pure c
          []     -> abort "TACommittee missing"

      propCid <- submit op do
        createCmd SnapshotProposal with
          operator         = op
          epoch            = 0
          merkleRoot       = "genesis"
          approvers        = []
          committeeMembers = committee.members

      let toApprove : [Party] =
            L.take committee.threshold committee.members

      _ <- foldlScript
            (\cid m -> do
               _ <- submitMulti [m, op] [] (exerciseCmd cid Approve with approver = m)
               pure cid)
            propCid
            toApprove

      _ <- submit op do exerciseCmd propCid Publish
      debug "[setup] created genesis snapshot"

ensureSPProfile : Party -> Party -> [Text] -> [Text] -> Time -> Script ()
ensureSPProfile op sp roles attrs expT = do
  prof <- query @SPProfile op
  let exists =
        case [ () | (_, p) <- prof, p.subject == sp ] of
          _ :: _ -> True
          []     -> False
  case exists of
    True  -> debug "[setup] SPProfile exists"
    False -> do
      _ <- submit op do
        createCmd SPProfile with
          operator = op
          subject  = sp
          roles
          attrs
          expires  = expT
      debug "[setup] SPProfile created"

ensurePolicy
  : Party -> Party -> Party -> Text
  -> [Text] -> [Text]
  -> Time -> Time
  -> Script ()
ensurePolicy op sp devOwner devKey reqRoles reqAttrs wStart wEnd = do
  pols <- query @AccessPolicy op
  let bySubject = [ (c,p) | (c,p) <- pols, p.subject == sp ]
  case bySubject of
    (cid, p) :: _ ->
      if p.deviceOwner == devOwner && p.deviceKey == devKey
      then
        debug "[setup] AccessPolicy exists (same device); OK"
      else do
        _ <- submit op do exerciseCmd cid Archive
        _ <- submit op do
          createCmd AccessPolicy with
            operator      = op
            subject       = sp
            deviceOwner   = devOwner
            deviceKey     = devKey
            requiredRoles = reqRoles
            requiredAttrs = reqAttrs
            windowStart   = wStart
            windowEnd     = wEnd
        debug "[setup] AccessPolicy replaced (device/key changed)"
    [] -> do
      _ <- submit op do
        createCmd AccessPolicy with
          operator      = op
          subject       = sp
          deviceOwner   = devOwner
          deviceKey     = devKey
          requiredRoles = reqRoles
          requiredAttrs = reqAttrs
          windowStart   = wStart
          windowEnd     = wEnd
      debug "[setup] AccessPolicy created"

setup : Script (ContractId BrokerContract)
setup = script do
  parties <- listKnownParties
  let cache =
        Foldable.foldl
          (\m p -> case p.displayName of
              Some n -> Map.insert n p.party m
              None   -> m)
          Map.empty
          parties

  let getOrAlloc name =
        case Map.lookup name cache of
          Some p -> debug ("[setup] reusing " <> name) >> pure p
          None   -> debug ("[setup] allocating " <> name)
                 >> allocatePartyWithHint name (PartyIdHint name)

  op     <- getOrAlloc "Operator"
  edge1  <- getOrAlloc "EdgeNode1"
  edge2  <- getOrAlloc "EdgeNode2"
  sp1    <- getOrAlloc "ServiceProvider1"
  sp2    <- getOrAlloc "ServiceProvider2"
  dev1   <- getOrAlloc "IoTDevice1"
  dev2   <- getOrAlloc "IoTDevice2"
  dev3   <- getOrAlloc "IoTDevice3"

  now <- getTime
  let edges   = [(edge1, now), (edge2, now)]
  let dev1Pk  = dev1X25519Hex
  let dev2Pk  = "9514e4cdb9003b5bc30cbbb57b87c57e5786eed1b4731e76b0ec4700c72d4926"
  let dev3Pk  = "PK3"
  let devices = [(dev1, dev1Pk), (dev2, dev2Pk), (dev3, dev3Pk)]

  bcs <- query @BrokerContract op
  bcCid <-
    case [ c | (c,b) <- bcs, b.operator == op ] of
      c :: _ -> debug "[setup] BrokerContract exists" >> pure c
      [] -> do
        debug "[setup] creating BrokerContract"
        submit op do
          createCmd BrokerContract with
            operator         = op
            edgeNodes        = edges
            iotDevices       = devices
            cachedValidNodes = edges
            validUntil       = addRelTime now (seconds 3600)

  ensureDevice op dev1 op edge1 "Device1" dev1Pk
    ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG
    ["loc=office","status=active"]
    (Some dev1PqPubB64)

  ensureDevice op dev2 op edge1 "Device2" dev2Pk
    ALG_X25519_AESGCM_ED25519
    ["loc=yard","status=active"]
    None

  ensureDevice op dev3 op edge1 "Device3" dev3Pk
    ALG_X25519_AESGCM_ED25519
    ["loc=quay","status=maintenance"]
    None

  ensureCommittee op [edge1, edge2] 2
  ensureGenesisSnapshotViaCommittee op

  let winStart = now
      winEnd   = addRelTime now (seconds 86400)

  ensureSPProfile op sp1
    ["writer","partner"]
    ["clearance=A","region=EU"]
    (addRelTime now (seconds 86400))

  ensurePolicy op sp1 dev1 dev1Pk
    ["writer"]
    ["clearance=A"]
    winStart
    winEnd

  ensureSPProfile op sp2
    ["writer","partner"]
    ["clearance=A","region=EU"]
    (addRelTime now (seconds 86400))

  ensurePolicy op sp2 dev2 dev2Pk
    ["writer"]
    ["clearance=A"]
    winStart
    winEnd

  debug "[setup] done"
  pure bcCid

-- ─────────────────────────────────────────────────────────────────────────────
-- ✅ Fresh-run helpers

resetAllRatchets : Party -> Script ()
resetAllRatchets op = do
  rats <- query @RatchetState op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        rats
  debug ("[setupFresh] cleared RatchetStates=" <> show (L.length rats))
  pure ()

resetAllRelayLogs : Party -> Script ()
resetAllRelayLogs op = do
  logs <- query @RelayLog op
  _ <- foldlScript
        (\() (cid, _) -> do
           _ <- submit op do exerciseCmd cid Archive
           pure ())
        ()
        logs
  debug ("[setupFresh] cleared RelayLogs=" <> show (L.length logs))
  pure ()

setupFresh : Script (ContractId BrokerContract)
setupFresh = script do
  parties <- listKnownParties
  let op = findParty parties "Operator"
  resetAllRatchets op
  resetAllRelayLogs op
  setup

-- ─────────────────────────────────────────────────────────────────────────────
-- Tests

testList : Script ()
testList = script do
  ps <- listKnownParties
  let ops : [Party] =
        [ p.party | p <- ps, p.displayName == Some "Operator" ]
  op <- case ops of
    x :: _ -> pure x
    []     -> abort "Operator not found"

  bcs   <- query @BrokerContract op
  devs  <- query @Device op
  snaps <- query @TaSnapshot op
  comms <- query @TACommittee op
  props <- query @SnapshotProposal op
  atts  <- query @SigAttestation op
  pols  <- query @AccessPolicy op
  profs <- query @SPProfile op
  rks   <- query @RevokedKey op
  rats  <- query @RatchetState op
  logs  <- query @RelayLog op

  debug ("[list] BrokerContracts=" <> show bcs)
  debug ("[list] Devices="         <> show devs)
  debug ("[list] TaSnapshots="     <> show snaps)
  debug ("[list] Committees="      <> show comms)
  debug ("[list] Proposals="       <> show props)
  debug ("[list] Attestations="    <> show atts)
  debug ("[list] Policies="        <> show pols)
  debug ("[list] Profiles="        <> show profs)
  debug ("[list] RevokedKeys="     <> show rks)
  debug ("[list] RatchetStates="   <> show rats)
  debug ("[list] RelayLogs="       <> show logs)
  pure ()

testVerify : Script (ContractId RelayLog)
testVerify = script do
  _ <- setup

  ps <- listKnownParties
  let op       = findParty ps "Operator"
  let edge     = findParty ps "EdgeNode1"
  let edge2    = findParty ps "EdgeNode2"
  let sp       = findParty ps "ServiceProvider2"
  let devOwner = findParty ps "IoTDevice2"

  bcs <- query @BrokerContract op
  bcCid <-
    case bcs of
      (c, _) :: _ -> pure c
      []          -> abort "No BrokerContract"

  devs <- query @Device op
  (devCid, dev) <-
    case [ (c, d) | (c, d) <- devs, d.name == "Device2" ] of
      x :: _ -> pure x
      []     -> abort "Device2 not found"
  let devPk = dev.publicKey

  snaps <- query @TaSnapshot op
  snapshot0 <-
    case [ s | (_, s) <- snaps, s.epoch == 0 ] of
      s :: _ -> pure s
      []     -> abort "No epoch 0 snapshot"
  let merkleRoot0 = snapshot0.merkleRoot

  now <- getTime
  let senderPk = "deadbeef"
  let senderId = "Sender1"
  let alg      = ALG_X25519_AESGCM_ED25519

  let ciphertext = "HELLO_ENC"
  let eph =
        "0000000000000000000000000000000000000000000000000000000000000000"
  let spPub = "deadbeef"
  let ctr = 1
  let dg = mkDigestText ciphertext eph None spPub devPk senderPk now 0 ctr

  att1 <- submit edge do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = devPk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  att2 <- submit edge2 do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge2
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = devPk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  relayCid <- submitMulti [edge, op] [] do
    exerciseCmd bcCid VerifyAndRelayMessage with
      edge               = edge
      sp                 = sp
      senderId           = senderId
      algId              = alg
      targetDevice       = devCid
      encryptedMessage   = ciphertext
      devicePublicKey    = devPk
      senderPublicKey    = senderPk
      digest             = dg
      msgTimestamp       = now
      epoch              = 0
      merkleRoot         = merkleRoot0
      useZkPac           = False
      policyProof        = None
      attestations       = [att1, att2]
      spSignatureB64     = "ZHVtbXk="
      spEd25519PubHex    = spPub
      ephX25519Hex       = eph
      aad                = None
      counter            = ctr
      pqSignatureB64     = None
      pqPubKey           = None
      kyberCiphertextB64 = None

  pure relayCid

testVerifyHybrid : Script (ContractId RelayLog)
testVerifyHybrid = script do
  _ <- setup

  ps <- listKnownParties
  let op       = findParty ps "Operator"
  let edge     = findParty ps "EdgeNode1"
  let edge2    = findParty ps "EdgeNode2"
  let sp       = findParty ps "ServiceProvider1"
  let devOwner = findParty ps "IoTDevice1"

  bcs <- query @BrokerContract op
  bcCid <-
    case bcs of
      (c, _) :: _ -> pure c
      []          -> abort "No BrokerContract"

  devs <- query @Device op
  (dev1Cid, dev1) <-
    case [ (c, d) | (c, d) <- devs, d.name == "Device1" ] of
      x :: _ -> pure x
      []     -> abort "Device1 not found"
  let dev1Pk = dev1.publicKey

  snaps <- query @TaSnapshot op
  snapshot0 <-
    case [ s | (_, s) <- snaps, s.epoch == 0 ] of
      s :: _ -> pure s
      []     -> abort "No epoch 0 snapshot"
  let merkleRoot0 = snapshot0.merkleRoot

  now <- getTime
  let senderPk = "deadbeef"
  let senderId = "Sender1"
  let alg      = ALG_HYBRID_X25519_KYBER_AESGCM_HYBRID_SIG

  let pqSigB64 = "cHFfc2lnX2R1bW15"
  let kybCtB64 = "a3liZXJfY3Q="
  let pqPubB64 = dev1PqPubB64

  let ciphertext = "HELLO_ENC"
  let eph =
        "0000000000000000000000000000000000000000000000000000000000000000"
  let spPub = "deadbeef"
  let ctr = 1
  let dg = mkDigestText ciphertext eph None spPub dev1Pk senderPk now 0 ctr

  att1 <- submit edge do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = dev1Pk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  att2 <- submit edge2 do
    createCmd SigAttestation with
      operator        = op
      issuer          = edge2
      digest          = dg
      deviceOwner     = devOwner
      devicePublicKey = dev1Pk
      senderPublicKey = senderPk
      algId           = alg
      ts              = now
      expires         = addRelTime now (seconds 3600)

  relayCid <- submitMulti [edge, op] [] do
    exerciseCmd bcCid VerifyAndRelayMessage with
      edge               = edge
      sp                 = sp
      senderId           = senderId
      algId              = alg
      targetDevice       = dev1Cid
      encryptedMessage   = ciphertext
      devicePublicKey    = dev1Pk
      senderPublicKey    = senderPk
      digest             = dg
      msgTimestamp       = now
      epoch              = 0
      merkleRoot         = merkleRoot0
      useZkPac           = False
      policyProof        = None
      attestations       = [att1, att2]
      spSignatureB64     = "ZHVtbXk="
      spEd25519PubHex    = spPub
      ephX25519Hex       = eph
      aad                = None
      counter            = ctr
      pqSignatureB64     = Some pqSigB64
      pqPubKey           = Some pqPubB64
      kyberCiphertextB64 = Some kybCtB64

  pure relayCid
----------------------