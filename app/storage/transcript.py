"""Append-only transcript + TranscriptHash helpers."""
import hashlib
from pathlib import Path
from typing import List

class Transcript:
    """Manages append-only transcript for non-repudiation."""

    def __init__(self, filepath: str):
        """Initialize transcript.

        Args:
            filepath: Path to transcript file
        """
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

        # Create file if it doesn't exist
        if not self.filepath.exists():
            self.filepath.touch()

        self.entries: List[str] = []

    def append(self, seqno: int, ts: int, ct: str, sig: str, peer_cert_fingerprint: str):
        """Append entry to transcript.

        Format: seqno | ts | ct | sig | peer-cert-fingerprint

        Args:
            seqno: Sequence number
            ts: Timestamp in milliseconds
            ct: Ciphertext (base64)
            sig: Signature (base64)
            peer_cert_fingerprint: Peer certificate fingerprint (hex)
        """
        entry = f"{seqno}|{ts}|{ct}|{sig}|{peer_cert_fingerprint}\n"
        self.entries.append(entry)

        # Append to file
        with open(self.filepath, 'a') as f:
            f.write(entry)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of entire transcript.

        Returns:
            Hex string of SHA-256 hash
        """
        # Read all entries from file
        with open(self.filepath, 'r') as f:
            content = f.read()

        # Compute SHA-256
        transcript_hash = hashlib.sha256(content.encode()).hexdigest()

        return transcript_hash

    def get_entries(self) -> List[str]:
        """Get all transcript entries.

        Returns:
            List of transcript entry strings
        """
        with open(self.filepath, 'r') as f:
            return f.readlines()

    def get_first_seqno(self) -> int:
        """Get first sequence number in transcript.

        Returns:
            First sequence number, or 0 if empty
        """
        entries = self.get_entries()
        if not entries:
            return 0

        first_entry = entries[0].strip()
        if not first_entry:
            return 0

        seqno = first_entry.split('|')[0]
        return int(seqno)

    def get_last_seqno(self) -> int:
        """Get last sequence number in transcript.

        Returns:
            Last sequence number, or 0 if empty
        """
        entries = self.get_entries()
        if not entries:
            return 0

        last_entry = entries[-1].strip()
        if not last_entry:
            return 0

        seqno = last_entry.split('|')[0]
        return int(seqno)

def verify_transcript(transcript_path: str, transcript_hash: str) -> bool:
    """Verify transcript hash.

    Args:
        transcript_path: Path to transcript file
        transcript_hash: Expected hash (hex)

    Returns:
        True if hash matches
    """
    transcript = Transcript(transcript_path)
    computed_hash = transcript.compute_hash()

    return computed_hash == transcript_hash
