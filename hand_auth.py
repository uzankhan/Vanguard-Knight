#!/usr/bin/env python3
"""
Vanguard Knight - Hand Gesture Authentication
=================================================
Deactivation ke waqt password ki jagah camera se HAND detect karke
authenticate karta hai. Iska use sirf DEACTIVATE karte waqt hota hai
(activate karne ke liye kuch nahi chahiye -- jaisa Uzan Khan ne bataya).

Technology: MediaPipe Hands (Google ka open-source hand-tracking model) --
ye 21 hand-landmarks detect karta hai per frame, bohat accurate aur fast hai,
aur fully offline chalta hai (koi cloud API call nahi -- privacy-safe).

Security design decision -- ye SIMPLE "hath dikha" wala check nahi hai
(jo koi bhi hath dikha kar bypass kar sake). Iske do layers hain:

LAYER 1: Hand PRESENCE + gesture verification
  Sirf koi bhi hath nahi -- ek SPECIFIC gesture (jo setup ke waqt "trained"
  hoti hai, jaisa PIN set karte hain) verify hoti hai. Gesture = specific
  finger positions (open palm, fist, peace-sign, thumbs-up, custom combo).

LAYER 2: Hand Geometry Fingerprint (basic anti-spoof)
  Har insaan ke hath ka proportional geometry (finger-length ratios,
  palm-width-to-length ratio) thoda unique hota hai. Setup ke waqt hum
  ye ratios bhi record karte hain -- taake koi "random" hath dikha kar na
  bypass kar sake, sirf tumhara apna hath (jiska geometry match kare) chalega.

  NOTE: Ye biometric-grade fingerprint-level security nahi hai (jaisa
  medical/forensic hand-geometry scanners), ye ek ADDITIONAL friction layer
  hai jo casual bypass (koi aur hath dikha de) ko rokta hai. True
  high-security biometric ke liye specialized hardware chahiye hota hai --
  yahan hum best-effort camera-based verification de rahe hain.
"""

import json
import time
import math
import logging
from pathlib import Path
from typing import Optional, List, Tuple, Callable
from dataclasses import dataclass, asdict

logger = logging.getLogger("VanguardKnight.HandAuth")

HAND_PROFILE_PATH = r"C:\VanguardKnight_Vault\hand_auth_profile.json"

try:
    import cv2
    import mediapipe as mp
    HAVE_VISION = True
except ImportError:
    HAVE_VISION = False
    logger.warning("opencv-python / mediapipe not installed -- hand auth unavailable. "
                   "Install with: pip install opencv-python mediapipe")

# MediaPipe hand landmark indices we care about for geometry + gesture
WRIST = 0
THUMB_TIP, THUMB_MCP = 4, 2
INDEX_TIP, INDEX_MCP = 8, 5
MIDDLE_TIP, MIDDLE_MCP = 12, 9
RING_TIP, RING_MCP = 16, 13
PINKY_TIP, PINKY_MCP = 20, 17

GESTURE_MATCH_TOLERANCE = 0.10       # how close finger-extension pattern must match
GEOMETRY_MATCH_TOLERANCE = 0.08      # how close hand-proportion ratios must match (tightened --
                                      # this is the "whose hand is this" signal, so it needs to
                                      # actually discriminate between different people, not just
                                      # between different gestures)
COMBINED_MATCH_TOLERANCE = 0.09      # extra safety net: a weighted blend of both distances must
                                      # ALSO be tight, so a mismatch that barely sneaks under one
                                      # individual threshold can't be "rescued" by the other being
                                      # very close -- both signals have to genuinely agree
REQUIRED_CONSECUTIVE_MATCHES = 15    # frames of consistent match needed (avoid one lucky frame)
CAMERA_TIMEOUT_SECONDS = 20          # give up if no valid hand shown in this time


@dataclass
class HandProfile:
    """The 'enrolled' hand data captured during first-time setup."""
    finger_extension_pattern: List[float]  # 5 values (thumb..pinky), 0=curled, 1=extended
    geometry_ratios: List[float]           # normalized finger-length ratios (anti-spoof)
    enrolled_at: str = ""


def _landmark_distance(p1, p2) -> float:
    # Real MediaPipe landmarks carry x, y, AND z (relative depth). Using
    # all three dimensions (not just the 2D image-plane x/y) gives more
    # discriminative power for telling different people's hands apart --
    # two hands can look similar in a flat 2D projection but have
    # different depth/thickness profiles. Falls back to 2D if a landmark
    # object doesn't expose .z (e.g. older test mocks).
    z1 = getattr(p1, 'z', 0.0)
    z2 = getattr(p2, 'z', 0.0)
    return math.sqrt((p1.x - p2.x) ** 2 + (p1.y - p2.y) ** 2 + (z1 - z2) ** 2)


def _compute_finger_extension_pattern(landmarks) -> List[float]:
    """
    Returns 5 values (0.0-1.0) representing how extended each finger is,
    based on tip-to-wrist distance relative to the palm's own scale.
    This captures the GESTURE (which fingers are up/down).
    """
    wrist = landmarks[WRIST]
    # Use middle-finger MCP-to-wrist distance as a scale reference
    # (roughly constant per-hand, lets us normalize across distances from camera)
    scale = _landmark_distance(wrist, landmarks[MIDDLE_MCP]) or 0.001

    tips_and_mcps = [
        (THUMB_TIP, THUMB_MCP), (INDEX_TIP, INDEX_MCP), (MIDDLE_TIP, MIDDLE_MCP),
        (RING_TIP, RING_MCP), (PINKY_TIP, PINKY_MCP),
    ]
    pattern = []
    for tip_idx, mcp_idx in tips_and_mcps:
        tip_to_wrist = _landmark_distance(landmarks[tip_idx], wrist)
        mcp_to_wrist = _landmark_distance(landmarks[mcp_idx], wrist)
        # Extended finger: tip is much farther from wrist than its MCP joint
        extension = (tip_to_wrist - mcp_to_wrist) / scale
        pattern.append(max(0.0, min(2.0, extension)))  # clamp for stability
    return pattern


def _compute_geometry_ratios(landmarks) -> List[float]:
    """
    Returns proportional ratios of finger lengths relative to palm width --
    this is the anti-spoof 'whose hand is this' signal. Different people's
    hands have measurably different proportions even when making the same gesture.
    """
    wrist = landmarks[WRIST]
    palm_width = _landmark_distance(landmarks[INDEX_MCP], landmarks[PINKY_MCP]) or 0.001

    finger_lengths = [
        _landmark_distance(landmarks[THUMB_MCP], landmarks[THUMB_TIP]),
        _landmark_distance(landmarks[INDEX_MCP], landmarks[INDEX_TIP]),
        _landmark_distance(landmarks[MIDDLE_MCP], landmarks[MIDDLE_TIP]),
        _landmark_distance(landmarks[RING_MCP], landmarks[RING_TIP]),
        _landmark_distance(landmarks[PINKY_MCP], landmarks[PINKY_TIP]),
    ]
    return [length / palm_width for length in finger_lengths]


def _pattern_distance(a: List[float], b: List[float]) -> float:
    """Simple normalized Euclidean distance between two pattern vectors."""
    if len(a) != len(b):
        return float('inf')
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b))) / len(a)


class HandAuthManager:
    """
    Two responsibilities:
      1. enroll()  -- first-time setup: capture the user's hand pattern + geometry
      2. verify()  -- deactivation-time: confirm the hand shown matches enrollment
    """

    def __init__(self, profile_path: str = HAND_PROFILE_PATH):
        self.profile_path = Path(profile_path)
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        self.profile: Optional[HandProfile] = self._load_profile()

    def _load_profile(self) -> Optional[HandProfile]:
        if self.profile_path.exists():
            try:
                data = json.loads(self.profile_path.read_text(encoding='utf-8'))
                return HandProfile(**data)
            except Exception as e:
                logger.error(f"Could not load hand profile: {e}")
        return None

    def is_enrolled(self) -> bool:
        return self.profile is not None

    def enroll_from_landmarks(self, landmarks) -> HandProfile:
        """Called during first-run setup wizard once a stable hand frame is captured."""
        pattern = _compute_finger_extension_pattern(landmarks)
        geometry = _compute_geometry_ratios(landmarks)
        profile = HandProfile(
            finger_extension_pattern=pattern,
            geometry_ratios=geometry,
            enrolled_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        self.profile_path.write_text(json.dumps(asdict(profile), indent=2), encoding='utf-8')
        self.profile = profile
        logger.info("[HAND_AUTH] Hand profile enrolled successfully.")
        return profile

    def verify_landmarks(self, landmarks) -> Tuple[bool, float, float]:
        """
        Checks one frame's landmarks against the enrolled profile.
        Returns (is_match, gesture_distance, geometry_distance) -- lower distance = better match.
        """
        if not self.profile:
            return False, 999.0, 999.0

        pattern = _compute_finger_extension_pattern(landmarks)
        geometry = _compute_geometry_ratios(landmarks)

        gesture_dist = _pattern_distance(pattern, self.profile.finger_extension_pattern)
        geometry_dist = _pattern_distance(geometry, self.profile.geometry_ratios)
        combined_dist = (0.5 * gesture_dist) + (0.5 * geometry_dist)

        is_match = (gesture_dist < GESTURE_MATCH_TOLERANCE and
                    geometry_dist < GEOMETRY_MATCH_TOLERANCE and
                    combined_dist < COMBINED_MATCH_TOLERANCE)
        return is_match, gesture_dist, geometry_dist

    def run_live_verification(self, on_frame_status: Optional[Callable] = None) -> bool:
        """
        Opens the camera and waits for the enrolled hand gesture to be shown
        consistently for REQUIRED_CONSECUTIVE_MATCHES frames in a row (this
        prevents a single lucky/noisy frame from granting access).

        Returns True if verified within CAMERA_TIMEOUT_SECONDS, else False.
        `on_frame_status` is an optional callback(consecutive_matches, required)
        for the GUI to show live progress (e.g. a filling progress ring).
        """
        if not HAVE_VISION:
            raise RuntimeError("opencv-python and mediapipe are required for hand auth. "
                               "Install: pip install opencv-python mediapipe")
        if not self.profile:
            raise RuntimeError("No hand profile enrolled yet -- run setup first.")

        mp_hands = mp.solutions.hands
        cap = cv2.VideoCapture(0)
        consecutive_matches = 0
        start_time = time.time()
        verified = False

        try:
            with mp_hands.Hands(static_image_mode=False, max_num_hands=1,
                                min_detection_confidence=0.7, min_tracking_confidence=0.6) as hands:
                while time.time() - start_time < CAMERA_TIMEOUT_SECONDS:
                    ok, frame = cap.read()
                    if not ok:
                        continue

                    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    results = hands.process(frame_rgb)

                    if results.multi_hand_landmarks:
                        landmarks = results.multi_hand_landmarks[0].landmark
                        is_match, g_dist, geo_dist = self.verify_landmarks(landmarks)
                        if is_match:
                            consecutive_matches += 1
                        else:
                            consecutive_matches = 0
                    else:
                        consecutive_matches = 0

                    if on_frame_status:
                        on_frame_status(consecutive_matches, REQUIRED_CONSECUTIVE_MATCHES)

                    if consecutive_matches >= REQUIRED_CONSECUTIVE_MATCHES:
                        verified = True
                        break
        finally:
            cap.release()

        logger.info(f"[HAND_AUTH] Verification {'SUCCEEDED' if verified else 'FAILED/TIMED OUT'}.")
        return verified


if __name__ == "__main__":
    # Simulate landmarks without a real camera (unit-testable logic).
    # MediaPipe landmark objects normally come from real detection; here we
    # build lightweight mock objects with .x/.y attributes to test the pure
    # geometry/gesture math, which is the actual security-relevant logic.

    class MockLandmark:
        def __init__(self, x, y, z=0.0):
            self.x, self.y, self.z = x, y, z

    def make_open_hand(scale=1.0, offset=0.0, z_jitter=0.0):
        """Simulates an open-palm hand (all fingers extended) -- 'Person A'."""
        base = {
            WRIST: (0.5, 0.9, 0.0), THUMB_MCP: (0.4, 0.75, -0.01), THUMB_TIP: (0.3, 0.55, -0.02),
            INDEX_MCP: (0.45, 0.6, -0.01), INDEX_TIP: (0.45, 0.25, -0.03),
            MIDDLE_MCP: (0.5, 0.58, -0.01), MIDDLE_TIP: (0.5, 0.2, -0.03),
            RING_MCP: (0.55, 0.6, -0.01), RING_TIP: (0.55, 0.25, -0.03),
            PINKY_MCP: (0.6, 0.65, -0.01), PINKY_TIP: (0.6, 0.35, -0.02),
        }
        lm = [MockLandmark(0, 0, 0) for _ in range(21)]
        for idx, (x, y, z) in base.items():
            lm[idx] = MockLandmark(x * scale + offset, y * scale + offset, z + z_jitter)
        return lm

    def make_open_hand_different_person(scale=1.0):
        """
        Simulates a DIFFERENT PERSON's open palm -- same GESTURE (all
        fingers extended) but different hand PROPORTIONS: notably longer
        fingers relative to palm width, and a narrower palm. This is the
        exact scenario that was previously (incorrectly) being accepted --
        a different hand making a similar-looking gesture.
        """
        base = {
            WRIST: (0.5, 0.9, 0.0), THUMB_MCP: (0.42, 0.74, -0.01), THUMB_TIP: (0.28, 0.48, -0.02),
            INDEX_MCP: (0.47, 0.59, -0.01), INDEX_TIP: (0.47, 0.12, -0.03),
            MIDDLE_MCP: (0.5, 0.57, -0.01), MIDDLE_TIP: (0.5, 0.08, -0.03),
            RING_MCP: (0.53, 0.59, -0.01), RING_TIP: (0.53, 0.13, -0.03),
            PINKY_MCP: (0.58, 0.63, -0.01), PINKY_TIP: (0.58, 0.22, -0.02),
        }
        lm = [MockLandmark(0, 0, 0) for _ in range(21)]
        for idx, (x, y, z) in base.items():
            lm[idx] = MockLandmark(x * scale, y * scale, z)
        return lm

    def make_fist(scale=1.0):
        """Simulates a closed fist (all fingers curled -- tips near palm)."""
        base = {
            WRIST: (0.5, 0.9, 0.0), THUMB_MCP: (0.4, 0.75, -0.01), THUMB_TIP: (0.42, 0.72, -0.01),
            INDEX_MCP: (0.45, 0.6, -0.01), INDEX_TIP: (0.46, 0.62, -0.01),
            MIDDLE_MCP: (0.5, 0.58, -0.01), MIDDLE_TIP: (0.5, 0.6, -0.01),
            RING_MCP: (0.55, 0.6, -0.01), RING_TIP: (0.54, 0.62, -0.01),
            PINKY_MCP: (0.6, 0.65, -0.01), PINKY_TIP: (0.59, 0.66, -0.01),
        }
        lm = [MockLandmark(0, 0, 0) for _ in range(21)]
        for idx, (x, y, z) in base.items():
            lm[idx] = MockLandmark(x * scale, y * scale, z)
        return lm

    import tempfile
    mgr = HandAuthManager(profile_path=tempfile.mktemp(suffix='.json'))

    print("=" * 70)
    print("TEST 1: Enroll an open-hand gesture")
    print("=" * 70)
    enrolled_hand = make_open_hand()
    profile = mgr.enroll_from_landmarks(enrolled_hand)
    print(f"✓ Enrolled. Gesture pattern: {[round(p, 2) for p in profile.finger_extension_pattern]}")

    print("\n" + "=" * 70)
    print("TEST 2: Same open-hand gesture (slightly different scale/position) -- should MATCH")
    print("=" * 70)
    # Simulates the same hand shown again, slightly closer/farther from camera
    same_hand_different_scale = make_open_hand(scale=1.15, offset=0.02)
    is_match, g_dist, geo_dist = mgr.verify_landmarks(same_hand_different_scale)
    print(f"  gesture_distance={g_dist:.3f}, geometry_distance={geo_dist:.3f}")
    assert is_match, "Same gesture at different scale should match (scale-normalized)!"
    print("✓ Correctly MATCHED -- scale/position invariant as expected")

    print("\n" + "=" * 70)
    print("TEST 3: DIFFERENT gesture (closed fist) -- should NOT match")
    print("=" * 70)
    fist_hand = make_fist()
    is_match, g_dist, geo_dist = mgr.verify_landmarks(fist_hand)
    print(f"  gesture_distance={g_dist:.3f}, geometry_distance={geo_dist:.3f}")
    assert not is_match, "Different gesture (fist vs open palm) should NOT match!"
    print("✓ Correctly REJECTED -- wrong gesture blocked")

    print("\n" + "=" * 70)
    print("TEST 4: DIFFERENT PERSON's hand, SAME gesture (open palm) -- should NOT match")
    print("=" * 70)
    print("  (This is the critical real-world case: someone else showing a similar")
    print("   open-hand gesture must NOT be accepted as the enrolled owner.)")
    other_persons_hand = make_open_hand_different_person()
    is_match, g_dist, geo_dist = mgr.verify_landmarks(other_persons_hand)
    combined = 0.5 * g_dist + 0.5 * geo_dist
    print(f"  gesture_distance={g_dist:.3f}, geometry_distance={geo_dist:.3f}, combined={combined:.3f}")
    assert not is_match, "A DIFFERENT PERSON'S hand was incorrectly accepted -- security failure!"
    print("✓ Correctly REJECTED -- different hand proportions caught despite similar gesture")

    print("\nAll hand-auth self-tests passed (pure geometry/gesture logic verified).")
    print(f"\n[Live camera mode available: {HAVE_VISION}]")
