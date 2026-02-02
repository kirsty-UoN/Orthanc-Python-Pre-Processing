# ----------------------------Setup------------------------------#
# --------------------------------------------------
# Import necessary libraries
# --------------------------------------------------
# Orthanc for DICOM server interaction,
import orthanc
 # Requests for API calls
import requests
# Standard libraries for file operations, JSON parsing, timing, cryptographic hashing, and date handling.
import os
import json
import time
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet

# -------------------------------------------------
# Secure Credentials Management
# -------------------------------------------------
# Retrieve REDCap API credentials
def load_encryption_key(key_file_path):
    """
    Load encryption key from file.
    The key file should be created during initial setup and kept secure.

    Args:
        key_file_path: Path to the encryption key file

    Returns:
        bytes: Encryption key
    """
    try:
        with open(key_file_path, 'rb') as key_file:
            encryption_key = key_file.read()
        orthanc.LogInfo(f"[CREDENTIALS] Encryption key loaded from {key_file_path}")
        return encryption_key
    except FileNotFoundError:
        orthanc.LogError(f"[CREDENTIALS] Encryption key not found: {key_file_path}")
        orthanc.LogError("[CREDENTIALS] Run the setup script to create encryption key")
        raise
    except Exception as error:
        orthanc.LogError(f"[CREDENTIALS] Error loading encryption key: {error}")
        raise


def load_credentials_from_encrypted_file(encrypted_file_path, key_file_path):
    """
    Decrypt and load REDCap credentials from encrypted text file.

    File format (before encryption):
        REDCAP_API_URL=https://redcap.yourserver.edu/api/
        REDCAP_API_TOKEN=your_token_here

    Args:
        encrypted_file_path: Path to encrypted credentials file
        key_file_path: Path to encryption key file

    Returns:
        tuple: (REDCAP_URL, REDCAP_TOKEN)
    """
    try:
        # Load encryption key
        encryption_key = load_encryption_key(key_file_path)
        cipher = Fernet(encryption_key)

        # Read encrypted file
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_text = decrypted_data.decode('utf-8')

        # Parse the decrypted text (key=value format)
        credentials = {}
        for line in decrypted_text.split('\n'):
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            # Parse key=value
            if '=' in line:
                key, value = line.split('=', 1)  # Split only on first =
                credentials[key.strip()] = value.strip()

        # Extract required credentials
        redcap_url = credentials.get('REDCAP_API_URL')
        redcap_token = credentials.get('REDCAP_API_TOKEN')

        if not redcap_url or not redcap_token:
            raise ValueError("Missing REDCAP_API_URL or REDCAP_API_TOKEN in credentials file")

        orthanc.LogInfo(f"[CREDENTIALS] Successfully loaded credentials from {encrypted_file_path}")
        return redcap_url, redcap_token

    except FileNotFoundError:
        orthanc.LogError(f"[CREDENTIALS] Encrypted credentials file not found: {encrypted_file_path}")
        orthanc.LogError("[CREDENTIALS] Run the setup script to create encrypted credentials")
        raise
    except Exception as error:
        orthanc.LogError(f"[CREDENTIALS] Failed to decrypt credentials: {error}")
        raise

# -------------------------------------------------
# Configuration
# -------------------------------------------------
# Paths to credential files
CREDENTIALS_FILE = "/etc/orthanc/____________"
KEY_FILE = "/etc/orthanc/___________"
# Load credentials from encrypted file
try:
    URL, REDCAP_TOKEN = load_credentials_from_encrypted_file(
        CREDENTIALS_FILE,
        KEY_FILE
    )
except Exception as error:
    orthanc.LogError(f"[CREDENTIALS] FATAL: Could not load credentials: {error}.")
    orthanc.LogError("[CREDENTIALS] System cannot function without valid credentials.")
    raise SystemExit("Failed to load REDCap credentials.")

# Cache configuration
CACHE_FILE = "/var/lib/orthanc/storage/policy_cache.json"
CACHE_TTL = 600  # seconds (10 minutes)

# Quarantine configuration
QUARANTINE_STATUS_KEY = "QuarantineStatus"
QUARANTINE_REASON_KEY = "QuarantineReason"
POLICY_VERSION_KEY = "PolicyVersion"
POLICY_TIMESTAMP_KEY = "PolicyTimestamp"
REEVALUATE_KEY = "Reevaluate"
REEVALUATION_MINS = 5  # Reevaluate quarantined instances every # minutes
REEVALUATION = REEVALUATION_MINS * 60
EMAIL_NOTIFIED_KEY = "EmailNotificationSent"

# XNAT verification settings
XNAT_UPLOAD_STATUS_KEY = "XNATUploadStatus"
XNAT_VERIFICATION_CONFIG = {
    "enabled": True,  # Enable/disable XNAT verification
    "retries": 3,  # Number of retry attempts
    "retry_delay": 2,  # Seconds between retries
    "modality_name": "XNAT",  # Name in orthanc.json DicomModalities
    "test_on_startup": True  # Test XNAT connection when Orthanc starts
}
# Delete anonymized immediately after upload attempt (success or failure)
DELETE_ANONYMIZED_IMMEDIATELY = True
RETRY_XNAT_VERIFICATION = 30 * 60 # Every # minutes * seconds in a minute

# Metadata keys for deletion scheduling
DELETION_SCHEDULED_KEY = "DeletionScheduled"
FORWARDED_TIMESTAMP_KEY = "ForwardedToXNAT"

# Retention and cleanup configuration
RETENTION_DAYS = 7
SECONDS_PER_DAY = 86400
CLEANUP_HOURS = 24  # cleanup reoccurs every # hours
CLEANUP = CLEANUP_HOURS * 3600


#----------------------------REDCap Information Import, Cacheing and Policy Creation------------------------------#

# -------------------------------------------------
# Retrieve REDCap snapshot via API token
# -------------------------------------------------
def fetch_policy_snapshot():
   """
   Constructs the API request to REDCap asking for all records in flat JSON format.
   """
   payload = {
       "token": REDCAP_TOKEN,
       "content": "record",
       "format": "json",
       "type": "flat",
       # Specify which database fields to retrieve: participant demographics, visit/scan details, expected scan parameters (volumes), and protocol approval status.
       "fields": [
           "protocol_id",
           "approved",
           "expiry_date",
           "participant_id",
           "first_name",
           "last_name",
           "visit_id",
           "scan_sequence",
           "sequence_id",
           "expected_volumes"
       ]
   }
   #Send the POST request with 15-second timeout, raise an exception if the request fails, and return the JSON response.
   r = requests.post(URL, data=payload, timeout=15)
   r.raise_for_status()
   data = r.json()
   if isinstance(data, dict) and "error" in data:
       raise RuntimeError(f"REDCap API error: {data['error']}")
   return data

# -------------------------------------------------
# Global policy cache
# -------------------------------------------------
# Create an in-memory cache structure to store the current policy snapshot, when it was loaded, and a version hash to detect policy changes.
_policy_cache = {
   "timestamp": 0,
   "version": None,
   "policy": None
}

# -------------------------------------------------
# Logging helper
# -------------------------------------------------
def log_check(name, status, message):
   """
   Defines log for auditing by retrieving just the metadata (version and timestamp) from the policy cache without triggering a full refresh.
   """
   policy_meta = get_policy_cache(meta_only=True)
   # Log validation results at INFO level for passes, WARNING level for failures, including which policy version was used for the check.
   level = orthanc.LogInfo if status == "PASS" else orthanc.LogWarning
   level(f"[CHECK: {name}] {status} {message} "
         f"Policy Version={policy_meta['version']} "
         f"Policy Timestamp={policy_meta['timestamp']}")

# -------------------------------------------------
# Build policy cache
# -------------------------------------------------
def build_policy(records):
    """
    Initialises and maps the REDCap data to a nested policy structure (participant → visit → sequence → expected parameters).
    """
    # Initialise policy structure with an empty dictionary for participants and a set for unique approved protocols.
    today = datetime.today().date()
    policy = {"participants": {}, "protocols": set()}

    # Iterate through REDCap records, checking if protocols are marked as approved (value "1").
    for rec in records:
        if rec.get("approved") == "1":
            protocol = rec.get("protocol\_name", "").strip()
            if protocol:
                # Check protocol expiry dates and only add protocols that haven't expired to the approved set.
                expiry = rec.get("expiry\_date", "").strip()
                if expiry:
                    if datetime.strptime(expiry, "%Y-%m-%d").date() < today:
                        orthanc.LogWarning(f"[ETHICS] Ethics approval expired on {expiry}. If renewed, update in REDCap.")
                        continue

                policy["protocols"].add(protocol)

        # Participants / visits / sequences: Extract participant ID and skip records without one.
        pid = rec.get("participant\_id", "").strip()
        if not pid:
            continue

        # Create or retrieve participant entry, storing normalised (lowercase, trimmed) first and last names for comparison with DICOM data.
        participant = policy["participants"].setdefault(
            pid,
            {
                "first": rec.get("first_name", "").strip().lower(),
                "last": rec.get("last_name", "").strip().lower(),
                "visits": {}
            }
        )

        # Build a nested structure: participant → visit → sequence → expected parameters. Store expected volume counts when specified.
        visit = rec.get("visit_id", "").strip()
        seq = rec.get("scan_sequence", "").strip()
        seq_id = rec.get("sequence_id", "").strip()
        volumes = rec.get("expected_volumes")

        if visit and (seq or seq_id):
            seq_dict = participant["visits"].setdefault(visit, {}).setdefault(seq_id, {})
            seq_dict["sequence_name"] = seq
            if volumes is not None:
                seq_dict["expected_volumes"] = int(volumes)

    # Return the complete policy structure for cacheing.
    return policy

# -------------------------------------------------
# Load / refresh cache
# -------------------------------------------------
# Fetch fresh data from REDCap and build the policy structure.
def refresh_policy_cache():
   """
   Refresh the policy with content from the REDCap API. Apply a new version number.
   """
   global _policy_cache
   records = fetch_policy_snapshot()
   policy = build_policy(records)

   # Serialise the policy to JSON with sorted keys to ensure consistent ordering for version hashing.
   serialized = json.dumps(
       {
           "policy": {
               "participants": policy["participants"],
               "protocols": sorted(policy["protocols"])
           }
       },
       sort_keys=True
   )

   # Generate a SHA256 hash of the serialised policy as a version identifier, allowing detection of any policy changes.
   version = hashlib.sha256(serialized.encode()).hexdigest()
   timestamp = int(time.time())

   # Update the in-memory cache and persist it to disk for recovery after restarts.
   _policy_cache = {
       "timestamp": timestamp,
       "version": version,
       "policy": policy
   }

   with open(CACHE_FILE, "w") as f:
       json.dump(_policy_cache, f, indent=2)

   # Log summary statistics about the loaded policy.
   orthanc.LogInfo(
       f"[POLICY] Loaded snapshot version={version}. "
       f"Participants={len(policy['participants'])}. "
       f"Protocols={len(policy['protocols'])}."
   )

# Check if the cache needs refreshing (empty or older than 10 minutes).
def get_policy_cache(meta_only=False):
   """
   Defines when the Cache needs refreshing (empty or every 10 minutes). If REDCap is offline, the version saved to disc is used.
   """
   now = time.time()
   if _policy_cache["policy"] is None or now - _policy_cache["timestamp"] > CACHE_TTL:
       # Attempt to refresh the policy; if that fails, fall back to loading the last successful cache from disk.
       try:
           refresh_policy_cache()
       except Exception as error:
           orthanc.LogError(f"[POLICY] Refresh failed: {error}")
           if os.path.exists(CACHE_FILE):
               with open(CACHE_FILE) as f:
                   cached = json.load(f)
                   _policy_cache.update(cached)
   # Return either just metadata (version/timestamp) or the full cache depending on the request.
   if meta_only:
       return {"version": _policy_cache["version"], "timestamp": _policy_cache["timestamp"]}
   return _policy_cache

#----------------------------Validation Functions------------------------------#
# -------------------------------------------------
# Helpers - Naming Normalisation
# -------------------------------------------------
def normalize_name(value):
   """
   Standardises participant names for validation, making them not case-specific.
   """
   return value.strip().lower().replace(" ", "")

def parse_dicom_name(name):
   """
   Parse DICOM name format (LastName^FirstName) and return normalised (first, last) tuple.
   """
   parts = name.split("^")
   return (
       normalize_name(parts[1]) if len(parts) > 1 else "",
       normalize_name(parts[0]) if len(parts) > 0 else ""
   )

# -------------------------------------------------
# Shared Validation Logic
# -------------------------------------------------
def validate_instance(tags):
    """
    Validates a DICOM instance against policy.
    Returns: (is_valid: bool, all_failures: list of str or None)
    """
    all_failures = []

    # Run protocol validation
    protocol_valid, protocol_reason = validate_protocol(tags)
    if not protocol_valid:
        all_failures.append(protocol_reason)

    # Run other validations
    participant_valid, participant_reasons = validate_participant_sequence_volumes(tags)
    if not participant_valid:
        if isinstance(participant_reasons, list):
            all_failures.extend(participant_reasons)
        else:
            all_failures.append(participant_reasons)

    if all_failures:
        return False, all_failures
    return True, None

# -------------------------------------------------
# Validations
# -------------------------------------------------
def validate_protocol(tags):
    """
    Validates the protocolID: DICOM protocolID is not empty and is present in REDCap Cache of approved projects.
    Returns tuple: (is_valid, failure_reason or None)
    """
    protocol = tags.get("ProtocolName", "").strip()    #DICOM
    cache = get_policy_cache()
    policy = cache["policy"]    #REDCap
    assert isinstance(policy, dict), "Policy cache['policy'] not initialized"

    #Fail validation if the DICOM file lacks a protocol name.
    if not protocol:
        log_check("PROTOCOL", "FAIL", "Missing protocol name.")
        return False, "Missing protocol name."

    # Check if the protocol is in the approved set; fail if not found or expired.
    if protocol not in policy["protocols"]:
        log_check("PROTOCOL", "FAIL", f"Protocol='{protocol}' not approved, expired or not in REDCap.")
        return False, "Protocol not approved, expired or not in REDCap."

    # Return success if protocol is valid.
    log_check("PROTOCOL", "PASS", f"Protocol='{protocol}'")
    return True, None

# Extract participant ID, visit ID, scanning sequence and expected volumes from DICOM metadata.
def validate_participant_sequence_volumes(tags):
    """
    Validates the participant ID, participant name, visit ID, sequence and volumes in REDCap Cache against DICOM metadata.
    Returns all failures as tuple: (is_valid, list_of_failure_reasons or None).
    """
    pid = tags.get("PatientID", "").strip()
    visit = tags.get("StudyDescription", "").strip()
    seq = tags.get("ScanningSequence", "").strip()
    seq_id = tags.get("SeriesDescription", "").strip()
    series_id = tags.get("SeriesInstanceUID", "").strip()
    dicom_volumes = len(orthanc.GetSeriesInstances(series_id))
    cache = get_policy_cache()
    policy = cache["policy"]    #REDCap
    assert isinstance(policy, dict), "Policy cache['policy'] not initialized"

    failures = []    # Collect all failures instead of returning immediately

    # Verify the participant is registered in REDCap.
    participant = policy["participants"].get(pid)
    if not participant:
        log_check("PARTICIPANT", "FAIL", f"{pid} not in policy.")
        failures.append(f"Participant '{pid}' not registered in REDCap.")
        # Cannot continue other checks without participant data
        return False, failures

    # Compare the DICOM patient name against the registered name (to catch potential ID swaps or entry errors).
    dicom_first, dicom_last = parse_dicom_name(tags.get("PatientName", ""))
    if dicom_first != participant["first"] or dicom_last != participant["last"]:
        log_check("NAME", "FAIL", "Name mismatch.")
        failures.append(
            f"Name mismatch: DICOM has '{tags.get('PatientName','')}'. REDCap has '{participant.get('first')} {participant.get('last')}'."
        )
    else:
        log_check("NAME", "PASS", "Name match.")

    # Verify this specific visit and sequence combination was planned for this participant. Need to correlate this with how sequences are entered into REDCap - recommend dropdown.

    seq_policy = participant["visits"].get(visit, {}).get(seq_id)
    if not seq_policy:
        log_check("VISIT/SEQ", "FAIL", f"Visit='{visit}' or Seq='{seq} / {seq_id}' not defined.")
        failures.append(
            f"Visit '{visit}' with sequence '{seq}' ('{seq_id}') not defined in REDCap for participant {pid}"
        )
        # Cannot check volumes without sequence policy
        if failures:
            return False, failures
        return True, None
    else:
        log_check("SEQUENCE", "PASS", f"Seq='{seq}' ('{seq_id}') found in REDCap for participant {pid}")

    # Verify volumes
    expected_volumes = seq_policy.get("expected_volumes")
    # Fail if the actual volume count doesn't match expectations, which could indicate an incomplete or incorrect scan or incorrect entry into REDCap.
    if dicom_volumes != expected_volumes:
        log_check(
            "SEQUENCE_VOLUME", "FAIL",
            f"Seq='{seq}' DICOM volumes={dicom_volumes} Expected={expected_volumes}."
        )
        failures.append(
            f"Volumes mismatch for sequence '{seq}': DICOM has {dicom_volumes} but REDCap expects {expected_volumes}."
        )
    else:
        log_check("SEQUENCE_VOLUME", "PASS", f"Seq='{seq}' DICOM volumes={dicom_volumes} matches expected")

    #Return result of validation
    if failures:
        return False, failures
    return True, None

#----------------------------Quarantine Functions: Invalid Instances Only------------------------------#
# -------------------------------------------------
# Quarantine
# -------------------------------------------------
# Tag the DICOM instance with quarantine status and the specific reason it failed validation.
def quarantine(original_instance_id, failure_reasons):
    """
    Tag DICOMs that fail validation as quarantined and with all reasons for failure.
    Args:
        original_instance_id: Orthanc instance ID
        failure_reasons: List of failure reason strings, or single string
    """
    policy_meta = get_policy_cache(meta_only=True)

    # Handle both single (string) and multiple reasons (list)
    if isinstance(failure_reasons, list):
        combined_reason = " | ".join(failure_reasons)
    else:
        combined_reason = failure_reasons

    # Set quarantine metadata
    orthanc.SetMetadata(original_instance_id, QUARANTINE_STATUS_KEY, "QUARANTINED")
    orthanc.SetMetadata(original_instance_id, QUARANTINE_REASON_KEY, combined_reason)

    # Record which policy version was used for the validation decision to enable future re-evaluation if policies change.
    orthanc.SetMetadata(original_instance_id, POLICY_VERSION_KEY, policy_meta["version"])
    orthanc.SetMetadata(original_instance_id, POLICY_TIMESTAMP_KEY, str(policy_meta["timestamp"]))

    # Log the quarantine action with all reasons for audit trails.
    orthanc.LogWarning(f"[QUARANTINE] {original_instance_id}: {combined_reason} validation failure(s).")
    if isinstance(failure_reasons, list):
        for i, reason in enumerate(failure_reasons, 1):
            orthanc.LogWarning(f"  [{i}] {reason}")
    else:
        orthanc.LogWarning(f"  [1] {failure_reasons}")
# CODE FOR UI FOR CHANGING INFORMATION AND TAGGING THE INSTANCE FOR RE-EVALUATION?

# -------------------------------------------------
# Re-evaluation (Quarantined Instances)
# -------------------------------------------------
def reevaluate_quarantined():
    """
    Re-validates quarantined instances against current policy. Reports all validation failures.
    """

    orthanc.LogInfo("[REEVALUATE] Starting re-evaluation of quarantined instances.")

    released_count = 0
    quarantined_count = 0

    for study in orthanc.GetStudies():
        # Only process quarantined studies marked for re-evaluation
        try:
            if orthanc.GetMetadata(study, QUARANTINE_STATUS_KEY) != "QUARANTINED":
                continue
            if orthanc.GetMetadata(study, REEVALUATE_KEY) != "TRUE":
                continue
        except RuntimeError as exc:
            orthanc.LogDebug(
                f"[REEVALUATE] Skipping study {study}: metadata missing ({exc})"
            )
            continue  # Metadata doesn't exist, skip this study

        for quarantined_instance_id in orthanc.GetStudyInstances(study):

            tags = orthanc.GetInstanceTags(quarantined_instance_id)
            is_valid, failure_reasons = validate_instance(tags)

            if not is_valid:
                # Still fails - Update quarantine with new reasons
                quarantine(quarantined_instance_id, failure_reasons)

                orthanc.SetMetadata(quarantined_instance_id, QUARANTINE_REASON_KEY, failure_reasons)
                policy_meta = get_policy_cache(meta_only=True)
                orthanc.SetMetadata(quarantined_instance_id, POLICY_VERSION_KEY, policy_meta["version"])
                orthanc.SetMetadata(quarantined_instance_id, POLICY_TIMESTAMP_KEY, str(policy_meta["timestamp"]))
                orthanc.LogWarning(f"[REEVALUATE] {quarantined_instance_id} still fails: {failure_reasons}")
                quarantined_count += 1
            else:
            # Now valid - release from quarantine
                orthanc.DeleteMetadata(quarantined_instance_id, QUARANTINE_STATUS_KEY)
                orthanc.DeleteMetadata(quarantined_instance_id, QUARANTINE_REASON_KEY)
                orthanc.DeleteMetadata(quarantined_instance_id, "QuarantineReasonCount")
                orthanc.DeleteMetadata(quarantined_instance_id, REEVALUATE_KEY)
                orthanc.DeleteMetadata(quarantined_instance_id, POLICY_VERSION_KEY)
                orthanc.DeleteMetadata(quarantined_instance_id, POLICY_TIMESTAMP_KEY)

                process_valid_instance(quarantined_instance_id)
                orthanc.LogInfo(f"[RELEASE] Instance {quarantined_instance_id} released after re-evaluation.")
                released_count += 1

    if released_count > 0 or quarantined_count > 0:
        orthanc.LogInfo(
            f"[REEVALUATE] Complete: released={released_count}, "
            f"Still quarantined={quarantined_count}."
        )

# QUARANTINE REPORTING

#----------------------------Processing Functions: Valid Instances Only------------------------------#
def process_valid_instance(original_instance_id):
    """
    Anonymise and forward a validated instance to XNAT.
    Delete anonymised instance after upload attempt.
    Delete original instance after 30 days if upload to XNAT was verified successfully (DICOM C-FIND verification).
    Keep original indefinitely if upload fails (for manual retry)
    """
    # Get original tags for logging/linking
    # original_tags = orthanc.GetInstanceTags(original_instance_id)

# -------------------------------------------------
# Anonymisation
# -------------------------------------------------
    # Create a new instance for the anonymised DICOM.
    anonymized_instance_id = orthanc.AnonymizeInstance(
        original_instance_id,
        # Define anonymisation to be performed.
        {
            "Remove": [
                "PatientBirthDate",
                "PatientSex",
                "PatientAge",
                "InstitutionName",
                "InstitutionAddress",
                "RequestingPhysician",
                "ReferringPhysicianName",
                "PerformingPhysicianName",
                "Manufacturer",
                "StationName"
            ],
            "Keep": [
                "PatientID",
                "StudyID",
                "StudyDescription",  # Keep visit ID
                "SeriesDescription",
                "SequenceName",
                "ProtocolName",
                "ScanningSequence",
                "InstanceNumber"
            ],
            "Replace": {
                "PatientName": "ANONYMISED"
            },
            "KeepPrivateTags": False
        }
    )
        # Link instances for audit trail
    orthanc.SetMetadata(anonymized_instance_id, "AnonymizedFrom", original_instance_id)
    orthanc.SetMetadata(original_instance_id, "AnonymizedTo", anonymized_instance_id)

    if not anonymized_instance_id:
        orthanc.LogError(f"[ANONYMISE] Failed to create anonymized instance for {original_instance_id}.")
        quarantine(original_instance_id, "Anonymization failed.")
        return False
    orthanc.LogInfo(f"[ANONYMISE] {original_instance_id} anonymised as {anonymized_instance_id}.")





    # -------------------------------------------------
    # Forward to XNAT
    # -------------------------------------------------

    # upload_success = False
    verification_success = False

    # Should there be a separate log/text file that stores the identifiable information against the anonymised information for emergency recover, which is deleted after 30 days?

    try:
        # Forward the anonymized instance to XNAT with DICOM C-FIND verification.
        orthanc.SendToModality(anonymized_instance_id, "XNAT")
        orthanc.LogInfo(f"[FORWARD] Anonymised instance {anonymized_instance_id} sent to XNAT.")
        upload_success = True

        # Verify receipt if enabled
        if XNAT_VERIFICATION_CONFIG.get('enabled', False):
            orthanc.LogInfo(f"[FORWARD] Verifying XNAT receipt via DICOM C-FIND for {anonymized_instance_id}")

            verified, verification_details = verify_xnat_received(
                anonymized_instance_id,
                max_retries=XNAT_VERIFICATION_CONFIG.get('retries', 3),
                retry_delay=XNAT_VERIFICATION_CONFIG.get('retry_delay', 2)
            )

            if verified:
                verification_success = True
                orthanc.LogInfo(
                    f"[FORWARD] XNAT receipt verified for {anonymized_instance_id} "
                    f"(verified in {verification_details.get('attempts', 1)} attempt(s))"
                )
            else:
                # Verification failed - keep original instance
                error_msg = verification_details.get('error', 'Unknown error')
                orthanc.LogError(f"[FORWARD] XNAT verification failed for {anonymized_instance_id}: {error_msg}")
        else:
            # Verification disabled - assume success if upload didn't throw error
            orthanc.LogError("[FORWARD] XNAT verification disabled.")

    except Exception as error:
        orthanc.LogError(f"[FORWARD] Failed to send to XNAT: {error}")
        upload_success = False
        verification_success = False

    # DELETE ANONYMIZED INSTANCE IMMEDIATELY (regardless of success/failure)
    try:
        orthanc.DeleteInstance(anonymized_instance_id)
        orthanc.LogInfo(
            f"[DELETE] Anonymized instance {anonymized_instance_id} deleted immediately "
            f"(space conservation strategy)."
        )
    except Exception as error:
        orthanc.LogError(f"[DELETE] Failed to delete anonymized instance {anonymized_instance_id}: {error}")

    # Handle original instance based on upload success
    if upload_success and verification_success:
        # SUCCESS: Schedule original for deletion in 30 days
        current_time = int(time.time())
        deletion_time = current_time + (RETENTION_DAYS * SECONDS_PER_DAY)

        # Update metadata on original
        orthanc.SetMetadata(original_instance_id, XNAT_UPLOAD_STATUS_KEY, "SUCCESS")
        orthanc.SetMetadata(original_instance_id, FORWARDED_TIMESTAMP_KEY, str(current_time))
        orthanc.SetMetadata(original_instance_id, DELETION_SCHEDULED_KEY, str(deletion_time))
        orthanc.SetMetadata(original_instance_id, "XNATVerified", "TRUE")

        deletion_date = datetime.fromtimestamp(deletion_time).strftime("%Y-%m-%d %H:%M:%S")
        orthanc.LogInfo(
            f"[SCHEDULE] {anonymized_instance_id}, anonymised instance of {original_instance_id}, successfully uploaded to XNAT. "
            f"{original_instance_id} is scheduled for deletion on {deletion_date} ({str(RETENTION_DAYS)} days from now)"
        )

        return True

    else:
        # FAILURE: Keep original for manual changes and retry
        orthanc.SetMetadata(original_instance_id, XNAT_UPLOAD_STATUS_KEY, "FAILED")
        orthanc.SetMetadata(original_instance_id, "XNATUploadFailed", "TRUE")
        orthanc.SetMetadata(original_instance_id, "XNATUploadFailedTime", str(int(time.time())))

        if not upload_success:
            failure_reason = "Upload to XNAT failed (DICOM send error)."
        else:
            failure_reason = "XNAT verification failed (instance not found in XNAT)."

        orthanc.SetMetadata(original_instance_id, "XNATUploadFailureReason", failure_reason)

        orthanc.LogWarning(
            f"[UPLOAD] Upload failed for {original_instance_id}. "
            f"Original instance retained for manual retry. "
            f"Reason: {failure_reason}"
        )

        return False






# -------------------------------------------------
# XNAT Verification via DICOM C-FIND
# -------------------------------------------------
def verify_xnat_received(anonymized_instance_id, max_retries=3, retry_delay=2):
    """
    Verify that an anonymized instance was successfully received by XNAT using DICOM C-FIND.

    Requirements:
    - XNAT must be configured as a DICOM modality in orthanc.json
    - XNAT must support DICOM C-FIND queries

    Args:
        anonymized_instance_id: Orthanc instance ID of anonymized DICOM
        max_retries: Number of verification attempts
        retry_delay: Seconds to wait between retries

    Returns:
        tuple: (success: bool, details: dict)
    """

    orthanc.LogInfo(f"[XNAT_VERIFY] Verifying instance {anonymized_instance_id} in XNAT via DICOM C-FIND")

    # Check if XNAT modality is configured
    if not is_xnat_modality_configured():
        orthanc.LogError("[XNAT_VERIFY] XNAT modality not configured in Orthanc")
        return False, {
            "error": "XNAT modality not configured",
            "hint": "Add XNAT to DicomModalities section in orthanc.json"
        }

    # Get DICOM tags from anonymized instance
    try:
        tags = orthanc.GetInstanceTags(anonymized_instance_id)
    except Exception as error:
        orthanc.LogError(f"[XNAT_VERIFY] Cannot read instance tags: {error}")
        return False, {"error": f"Cannot read instance tags: {error}"}

    # Extract DICOM UIDs
    study_instance_uid = tags.get("StudyInstanceUID", "")
    series_instance_uid = tags.get("SeriesInstanceUID", "")
    sop_instance_uid = tags.get("SOPInstanceUID", "")

    if not all([study_instance_uid, series_instance_uid, sop_instance_uid]):
        orthanc.LogError("[XNAT_VERIFY] Missing required DICOM UIDs")
        return False, {"error": "Missing DICOM UIDs in instance"}

    # Attempt verification with retries
    for attempt in range(1, max_retries + 1):
        orthanc.LogInfo(f"[XNAT_VERIFY] Verification attempt {attempt}/{max_retries}")

        # Perform DICOM C-FIND query
        success = query_xnat_for_instance(
            study_uid=study_instance_uid,
            series_uid=series_instance_uid,
            instance_uid=sop_instance_uid
        )

        if success:
            orthanc.LogInfo(f"[XNAT_VERIFY] Instance {anonymized_instance_id} verified in XNAT")
            return True, {
                "method": "DICOM C-FIND",
                "study_uid": study_instance_uid,
                "series_uid": series_instance_uid,
                "instance_uid": sop_instance_uid,
                "verified_at": datetime.now().isoformat(),
                "attempts": attempt
            }

        # Wait before retry
        if attempt < max_retries:
            orthanc.LogInfo(f"[XNAT_VERIFY] Instance not found, waiting {retry_delay}s before retry...")
            time.sleep(retry_delay)

    # All attempts failed
    orthanc.LogWarning(
        f"[XNAT_VERIFY] Instance {anonymized_instance_id} not found in XNAT "
        f"after {max_retries} attempts"
    )
    return False, {
        "error": "Instance not found in XNAT",
        "attempts": max_retries,
        "study_uid": study_instance_uid,
        "hint": "Instance may not have been received by XNAT or query permissions may be insufficient"
    }

def is_xnat_modality_configured():
    """
    Check if XNAT is configured as a DICOM modality in Orthanc.

    Returns:
        bool: True if XNAT modality exists
    """
    try:
        modalities = json.loads(orthanc.RestApiGet('/modalities'))

        if 'XNAT' in modalities:
            orthanc.LogInfo("[XNAT_VERIFY] XNAT modality found in configuration")
            return True
        else:
            orthanc.LogWarning(
                "[XNAT_VERIFY] XNAT modality not found. "
                "Available modalities: " + ", ".join(modalities)
            )
            return False

    except Exception as error:
        orthanc.LogError(f"[XNAT_VERIFY] Error checking modalities: {error}")
        return False

def query_xnat_for_instance(study_uid, series_uid, instance_uid):
    """
    Query XNAT for a specific DICOM instance using C-FIND.

    Args:
        study_uid: DICOM Study Instance UID
        series_uid: DICOM Series Instance UID
        instance_uid: DICOM SOP Instance UID

    Returns:
        bool: True if instance found in XNAT
    """
    try:
        # Construct DICOM C-FIND query at Instance level
        query = {
            "Level": "Instance",
            "Query": {
                "StudyInstanceUID": study_uid,
                "SeriesInstanceUID": series_uid,
                "SOPInstanceUID": instance_uid
            }
        }

        orthanc.LogInfo(
            f"[XNAT_VERIFY] Querying XNAT for instance: "
            f"Study={study_uid[:16]}..., "
            f"Series={series_uid[:16]}..., "
            f"Instance={instance_uid[:16]}..."
        )

        # Send C-FIND query to XNAT modality
        query_result = orthanc.RestApiPost(
            '/modalities/XNAT/query',
            json.dumps(query)
        )

        # Parse query response
        query_info = json.loads(query_result)
        query_id = query_info.get("ID")

        if not query_id:
            orthanc.LogError("[XNAT_VERIFY] No query ID returned from DICOM C-FIND")
            return False

        # Get query answers
        answers_json = orthanc.RestApiGet(f'/queries/{query_id}/answers')
        answers = json.loads(answers_json)

        # Get query details for logging
        # query_details = json.loads(orthanc.RestApiGet(f'/queries/{query_id}'))

        # Clean up query from Orthanc
        orthanc.RestApiDelete(f'/queries/{query_id}')

        # Check if we got results
        if len(answers) > 0:
            orthanc.LogInfo(
                f"[XNAT_VERIFY] Instance found in XNAT. "
                f"Query returned {len(answers)} matching instance(s)"
            )
            return True
        else:
            orthanc.LogInfo("[XNAT_VERIFY] Instance not found in XNAT (query returned 0 results)")
            return False

    except Exception as error:
        orthanc.LogError(f"[XNAT_VERIFY] DICOM C-FIND query failed: {error}")
        return False

def test_xnat_connection():
    """
    Test DICOM connection to XNAT using DICOM C-ECHO.

    Returns:
        bool: True if XNAT responds to DICOM echo
    """
    try:
        orthanc.LogInfo("[XNAT_VERIFY] Testing DICOM connection to XNAT (C-ECHO)")

        # Send DICOM echo to XNAT
        orthanc.RestApiPost('/modalities/XNAT/echo', '')

        orthanc.LogInfo("[XNAT_VERIFY] DICOM C-ECHO successful - XNAT is reachable")
        return True

    except Exception as error:
        orthanc.LogError(f"[XNAT_VERIFY] DICOM C-ECHO failed: {error}")
        orthanc.LogError("[XNAT_VERIFY] Check XNAT configuration in orthanc.json")
        return False

def retry_failed_xnat_verifications():
    """
    Retry DICOM C-FIND verification for instances that previously failed.
    Run periodically to catch instances that were delayed in XNAT.
    """
    orthanc.LogInfo("[XNAT_RETRY] Retrying failed XNAT verifications")

    retry_count = 0
    success_count = 0

    for study_id in orthanc.GetStudies():
        for instance_id in orthanc.GetStudyInstances(study_id):
            try:
                # Only retry instances that failed verification
                if orthanc.GetMetadata(instance_id, "XNATVerificationFailed") != "TRUE":
                    continue

                # Check how old the failure is (don't retry too soon)
                failed_time_str = orthanc.GetMetadata(instance_id, "ForwardingFailed")
                if failed_time_str:
                    failed_time = int(failed_time_str)
                    age_minutes = (int(time.time()) - failed_time) // 60

                    # Only retry if failure is at least 15 minutes old
                    if age_minutes < 15:
                        continue

                orthanc.LogInfo(f"[XNAT_RETRY] Retrying verification for {instance_id}")
                retry_count += 1

                # Attempt verification again
                verified, verification_details = verify_xnat_received(instance_id)

                if verified:
                    # Success! Update metadata
                    orthanc.DeleteMetadata(instance_id, "XNATVerificationFailed")
                    orthanc.DeleteMetadata(instance_id, "XNATVerificationError")
                    orthanc.DeleteMetadata(instance_id, "ForwardingFailed")
                    orthanc.SetMetadata(instance_id, "XNATVerified", "TRUE")
                    orthanc.SetMetadata(
                        instance_id,
                        "XNATVerificationDetails",
                        json.dumps(verification_details)
                    )

                    # Now safe to delete original if it still exists
                    try:
                        original_id = orthanc.GetMetadata(instance_id, "AnonymizedFrom")
                        if original_id and orthanc.InstanceExists(original_id):
                            orthanc.DeleteInstance(original_id)
                            orthanc.LogInfo(
                                f"[XNAT_RETRY] Deleted original instance {original_id} "
                                f"after successful verification"
                            )
                    except Exception as error:
                        orthanc.LogWarning(
                            f"[XNAT_RETRY] Cleanup failed for original instance linked to {instance_id}: {error}"
                        )

                    success_count += 1
                    orthanc.LogInfo(f"[XNAT_RETRY] Successfully verified {instance_id} on retry")

            except Exception as error:
                orthanc.LogError(f"[XNAT_RETRY] Error retrying instance {instance_id}: {error}")
                continue

    if retry_count > 0:
        orthanc.LogInfo(
            f"[XNAT_RETRY] Complete: Retried={retry_count}, "
            f"Successful={success_count}, Still Failed={retry_count - success_count}"
        )

# -------------------------------------------------
# XNAT Verification Reporting *INTEGRATE INTO EMAIL + ORTHANC REPORTING FOR ALL QUARANTINED/SUCCESSFUL INSTANCES*
# -------------------------------------------------
# def generate_xnat_verification_report():
#     """
#     Generate report of XNAT verification status.
#     Shows instances that failed DICOM C-FIND verification.
#     """
#     orthanc.LogInfo("[XNAT_REPORT] Generating XNAT verification report")
#
#     verified_count = 0
#     failed_count = 0
#     pending_count = 0
#     failed_instances = []
#
#     for study_id in orthanc.GetStudies():
#         for instance_id in orthanc.GetStudyInstances(study_id):
#             try:
#                 # Check verification status
#                 if orthanc.GetMetadata(instance_id, "XNATVerified") == "TRUE":
#                     verified_count += 1
#
#                 elif orthanc.GetMetadata(instance_id, "XNATVerificationFailed") == "TRUE":
#                     failed_count += 1
#
#                     # Get failure details
#                     error_json = orthanc.GetMetadata(instance_id, "XNATVerificationError")
#                     error_details = json.loads(error_json) if error_json else {}
#
#                     tags = orthanc.GetInstanceTags(instance_id)
#                     failed_instances.append({
#                         "instance_id": instance_id,
#                         "patient_id": tags.get("PatientID", "Unknown"),
#                         "study_description": tags.get("StudyDescription", "Unknown"),
#                         "study_uid": tags.get("StudyInstanceUID", "Unknown"),
#                         "error": error_details.get("error", "Unknown"),
#                         "hint": error_details.get("hint", "")
#                     })
#
#                 elif orthanc.GetMetadata(instance_id, FORWARDED_TIMESTAMP_KEY):
#                     # Forwarded but not verified (verification might be disabled)
#                     pending_count += 1
#
#             except:
#                 continue
#
#     orthanc.LogInfo(
#         f"[XNAT_REPORT] Verification status: "
#         f"Verified={verified_count}, Failed={failed_count}, Pending={pending_count}"
#     )
#
#     if failed_instances:
#         orthanc.LogWarning(f"[XNAT_REPORT] {len(failed_instances)} instances failed XNAT verification:")
#         for instance in failed_instances:
#             orthanc.LogWarning(
#                 f"  Instance: {instance['instance_id']}, "
#                 f"Patient: {instance['patient_id']}, "
#                 f"Study: {instance['study_description']}, "
#                 f"Error: {instance['error']}"
#             )
#             if instance['hint']:
#                 orthanc.LogWarning(f"    Hint: {instance['hint']}")
#
#     return {
#         "verified": verified_count,
#         "failed": failed_count,
#         "pending": pending_count,
#         "failed_instances": failed_instances
#     }
#

# -------------------------------------------------
# XNAT Connection Test on Startup
# -------------------------------------------------
def test_xnat_on_startup():
    """
    Test XNAT DICOM connection when Orthanc starts.
    Helps identify configuration issues early.
    """
    orthanc.LogInfo("[STARTUP] Testing XNAT DICOM connection")

    # Check if XNAT modality is configured
    if not is_xnat_modality_configured():
        orthanc.LogError(
            "[STARTUP] XNAT modality NOT configured in orthanc.json. "
            "XNAT verification will not work!"
        )
        orthanc.LogError(
            "[STARTUP] Add XNAT to DicomModalities section in /etc/orthanc/orthanc.json"
        )
        return False

    # Test DICOM echo
    if test_xnat_connection():
        orthanc.LogInfo("[STARTUP] XNAT DICOM connection test PASSED")

        # Log XNAT modality details
        try:
            xnat_config = json.loads(orthanc.RestApiGet('/modalities/XNAT'))
            orthanc.LogInfo(f"[STARTUP] XNAT AET: {xnat_config.get('AET', 'Unknown')}")
            orthanc.LogInfo(f"[STARTUP] XNAT Host: {xnat_config.get('Host', 'Unknown')}")
            orthanc.LogInfo(f"[STARTUP] XNAT Port: {xnat_config.get('Port', 'Unknown')}")
        except Exception as error:
            # Non-fatal: startup can proceed without these details
            orthanc.LogDebug(f"[STARTUP] Unable to read XNAT modality details: {error}")

            return True
    else:
        orthanc.LogError("[STARTUP] XNAT DICOM connection test FAILED")
        orthanc.LogError("[STARTUP] Check XNAT configuration in orthanc.json")
        return False


# Run test if configured
if XNAT_VERIFICATION_CONFIG.get('test_on_startup', False):
    test_xnat_on_startup()

# -------------------------------------------------
# Cleanup Old Instances (runs periodically)
# -------------------------------------------------
def cleanup_expired_instances():
    """
    Delete original instances that have exceeded their 30-day retention period.
    This function is called periodically by Orthanc.
    """
    now = int(time.time())
    deleted_count = 0
    checked_count = 0

    orthanc.LogInfo("[CLEANUP] Starting cleanup of expired instances.")

    # Check all studies in Orthanc
    for study in orthanc.GetStudies():
        for instance_id in orthanc.GetStudyInstances(study):
            checked_count += 1
            try:
                #  Filter: Only process instances with scheduled deletion.
                deletion_time_str = orthanc.GetMetadata(instance_id, DELETION_SCHEDULED_KEY)
                if not deletion_time_str:
                    continue  # Skip instances without scheduled deletion

                deletion_time = int(deletion_time_str)

                # Check if deletion time has passed
                if now < deletion_time:
                    continue  # Not expired yet, skip

                # Safety check: Verify forwarding confirmation exists
                forwarded_timestamp = orthanc.GetMetadata(instance_id, FORWARDED_TIMESTAMP_KEY)
                if not forwarded_timestamp:
                    orthanc.LogWarning(
                        f"[CLEANUP] Skipping {instance_id} - no XNAT forwarding confirmation found."
                    )
                    continue

                # All checks passed - delete the instance
                orthanc.DeleteInstance(instance_id)

            except Exception as error:
                orthanc.LogError(
                    f"[CLEANUP] Failed to delete instance {instance_id}: {error}"
                )
                continue

            else:
                # Deletion succeeded → safe cleanup
                try:
                    orthanc.DeleteMetadata(instance_id, DELETION_SCHEDULED_KEY)
                    orthanc.DeleteMetadata(instance_id, FORWARDED_TIMESTAMP_KEY)
                except Exception as meta_error:
                    orthanc.LogWarning(
                        f"[CLEANUP] Instance {instance_id} deleted but metadata cleanup failed: {meta_error}"
                    )

                deleted_count += 1
                orthanc.LogInfo(
                    f"[CLEANUP] Deleted instance {instance_id} after retention period."
                )

    orthanc.LogInfo(
        f"[CLEANUP] Complete: Checked={checked_count}, Deleted={deleted_count}"
    )

# EMAILS: QUARANTINE NOTIFICATION (Researchers)
# EMAILS: DAILY LOG SUMMARY (Administration)

#----------------------------Call Validation, Quarantine, and Processing Functions------------------------------#
# -------------------------------------------------
# Ingest Call (New Arrivals)
# -------------------------------------------------
# Checks if a new DICOM instance is valid when it arrives; quarantine and stop processing on first failure. Record and present all failures for efficiency?
def on_stored_instance(original_instance_id, tags):
    """
    Validates newly arrived DICOM instances and reports all validation failures.
    """
    is_valid, failure_reasons = validate_instance(tags)

    if not is_valid:
        quarantine(original_instance_id, failure_reasons)
        # Log user-friendly summary
        if isinstance(failure_reasons, list):
            orthanc.LogInfo(
                f"[VALIDATION] Instance {original_instance_id} failed {len(failure_reasons)} checks. "
                f"Correct these issues in REDCap or DICOM metadata and trigger re-evaluation."
            )
        return

    # Valid - send for processing
    process_valid_instance(original_instance_id)

# -------------------------------------------------
# Registration
# -------------------------------------------------
# Test XNAT connection on startup
if XNAT_VERIFICATION_CONFIG.get('test_on_startup', True):
    test_xnat_on_startup()

# Register the validation function to run automatically whenever new DICOM data arrives.
orthanc.RegisterOnStoredInstanceCallback(on_stored_instance)

# Schedule the re-evaluation function to run as specified in configuration to check if previously quarantined data now passes updated policies.
orthanc.RegisterPeriodicTask(reevaluate_quarantined, REEVALUATION)

# Schedule anonymised and expired instances
orthanc.RegisterPeriodicTask(cleanup_expired_instances, CLEANUP)

# Generate general report every 24 hours
# orthanc.RegisterPeriodicTask(generate_xnat_verification_report, 21600)

# Retry failed XNAT verifications every 30 minutes
orthanc.RegisterPeriodicTask(retry_failed_xnat_verifications, RETRY_XNAT_VERIFICATION)

# Log startup message
orthanc.LogInfo("[STARTUP] Orthanc validation system initialized")
orthanc.LogInfo("[STARTUP] XNAT verification enabled via DICOM C-FIND")
