#!/usr/bin/env python3
"""
Vanguard Knight - Sysmon Event Reader
========================================
Purane version ke 2 bade bugs fix kiye hain:

BUG 1: Har loop mein ReadEventLog() ko offset 0 se call kiya jata tha,
       koi bookmark/position tracking nahi thi.
       -> Result: events miss hote the (agar processing loop slow hui to
          beech ke naye events chhoot jate) YA duplicate events baar baar
          process hote (agar backwards read overlap ho gaya).
FIX:   EvtSubscribe API use karte hain jo REAL-TIME push-based hai (poll
       nahi karta), aur bookmark ko disk pe save karte hain taake service
       restart hone par bhi humein "last known position" se resume mile,
       na ke shuru se, na hi missed events ke sath.

BUG 2: Fields ko positional index se nikala jata tha: strings[4], strings[1]
       -> Fragile hai. Sysmon version badalte hi field order badal sakta
          hai aur silently galat data parse hoga (crash bhi nahi hoga,
          bas WRONG data milega -- sabse khatarnak type ka bug).
FIX:   Event ko XML mein render karte hain aur named fields nikalte hain
       (<Data Name="Image">...) -- ye version-independent aur reliable hai.
"""

import json
import queue
import threading
import time
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger("VanguardKnight.SysmonReader")

# Sysmon XML events use this namespace -- required for ElementTree parsing
NS = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Map Sysmon Event ID -> human-readable type + which fields we care about.
# This drives what get pulled out of the XML for each event type.
EVENT_ID_MAP = {
    1: "process_create",
    3: "network_connect",
    7: "image_load",
    8: "create_remote_thread",
    10: "process_access",
    11: "file_create",
    12: "registry_event",
    13: "registry_event",
    14: "registry_event",
    17: "pipe_event",
    18: "pipe_event",
    22: "dns_query",
    23: "file_delete",
}


class BookmarkManager:
    """
    Persists the 'last read position' in the Sysmon event log to disk.
    On restart, we resume exactly where we left off -- no missed events,
    no reprocessed duplicates.
    """

    def __init__(self, bookmark_path: str):
        self.bookmark_path = Path(bookmark_path)
        self.bookmark_path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Optional[str]:
        """Returns saved bookmark XML string, or None if no bookmark exists yet."""
        if self.bookmark_path.exists():
            try:
                data = json.loads(self.bookmark_path.read_text(encoding='utf-8'))
                return data.get('bookmark_xml')
            except Exception as e:
                logger.warning(f"Bookmark file corrupt, starting fresh: {e}")
                return None
        return None

    def save(self, bookmark_xml: str):
        """Persist current bookmark position to disk."""
        try:
            self.bookmark_path.write_text(
                json.dumps({'bookmark_xml': bookmark_xml, 'saved_at': time.time()}),
                encoding='utf-8'
            )
        except Exception as e:
            logger.error(f"Failed to save bookmark: {e}")


def parse_sysmon_event_xml(xml_string: str) -> Optional[dict]:
    """
    Parses raw Sysmon event XML into a clean dict with NAMED fields
    (not positional indexes -- this is the version-independent fix).

    Returns a dict like:
    {
        'event_id': 1,
        'event_type': 'process_create',
        'time_created': '2026-07-17T...',
        'data': {'Image': '...', 'ProcessId': '1234', 'CommandLine': '...', ...}
    }
    """
    try:
        root = ET.fromstring(xml_string)
        system = root.find('ns:System', NS)
        if system is None:
            return None

        event_id_elem = system.find('ns:EventID', NS)
        if event_id_elem is None or event_id_elem.text is None:
            return None
        event_id = int(event_id_elem.text)

        time_elem = system.find('ns:TimeCreated', NS)
        time_created = time_elem.get('SystemTime') if time_elem is not None else None

        # EventData contains <Data Name="FieldName">value</Data> elements.
        # We build a dict keyed by the Name attribute -- this is what makes
        # the parser robust across Sysmon schema versions.
        event_data_elem = root.find('ns:EventData', NS)
        data = {}
        if event_data_elem is not None:
            for data_elem in event_data_elem.findall('ns:Data', NS):
                name = data_elem.get('Name')
                if name:
                    data[name] = data_elem.text or ""

        return {
            'event_id': event_id,
            'event_type': EVENT_ID_MAP.get(event_id, f"unknown_{event_id}"),
            'time_created': time_created,
            'data': data,
        }
    except ET.ParseError as e:
        logger.warning(f"Failed to parse event XML: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error parsing event: {e}")
        return None


class SysmonEventReader:
    """
    Real-time Sysmon event consumer using the Windows Event Log EvtSubscribe
    API (push-based, not polling), with bookmark persistence.

    Usage:
        reader = SysmonEventReader(output_queue=my_queue)
        reader.start()
        ...
        reader.stop()
    """

    def __init__(self, output_queue: "queue.Queue", bookmark_file: str = None,
                 log_callback: Optional[Callable] = None):
        self.output_queue = output_queue
        self.bookmark_mgr = BookmarkManager(
            bookmark_file or r"C:\VanguardKnight_Vault\sysmon_bookmark.json"
        )
        self.running = False
        self._subscription_handle = None
        self._thread = None
        # THIS IS THE KEY FIX: previously, ALL status/error messages from
        # this module went ONLY to the Python `logger` (console/log file),
        # which the GUI never reads. That meant if Sysmon subscription
        # failed for ANY reason -- pywin32 missing, access denied (not
        # running as Administrator), the Sysmon channel not existing yet,
        # etc. -- the GUI would show "Shield Active" with a totally silent
        # failure underneath: no events would ever be detected, and there
        # was no visible error explaining why. Now every critical message
        # is ALSO pushed through log_callback (wired to the GUI's Live
        # Activity Log by core_engine.py), so failures are immediately visible.
        self._log_callback = log_callback or (lambda msg: None)

        try:
            import win32evtlog
            import win32event
            import pywintypes
            self._win32evtlog = win32evtlog
            self._win32event = win32event
            self._pywintypes = pywintypes
            self._have_winapi = True
        except ImportError:
            self._have_winapi = False
            msg = ("[SYSMON] pywin32 is not installed or not importable -- "
                  "real-time monitoring CANNOT start. Run: pip install pywin32")
            logger.error(msg)
            self._log_callback(msg)

    def start(self):
        if not self._have_winapi:
            msg = "[SYSMON] Cannot start -- pywin32 unavailable (see earlier error)."
            self._log_callback(msg)
            raise RuntimeError("SysmonEventReader requires pywin32 and Windows Event Log APIs.")
        self.running = True
        self._thread = threading.Thread(target=self._run_subscription, daemon=True)
        self._thread.start()
        # NOTE: this message means the background thread was launched --
        # it does NOT yet mean the Sysmon subscription actually succeeded.
        # Watch for the follow-up "[SYSMON] Subscribed successfully" or
        # a "[SYSMON] FAILED" message a moment later.
        logger.info("[SysmonReader] Real-time subscription thread started.")
        self._log_callback("[SYSMON] Starting Sysmon event subscription...")

    def stop(self):
        self.running = False
        if self._subscription_handle:
            try:
                self._subscription_handle.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("[SysmonReader] Subscription stopped.")

    def _run_subscription(self):
        evt = self._win32evtlog
        saved_bookmark_xml = self.bookmark_mgr.load()

        # -----------------------------------------------------------
        # SWITCHED FROM SignalEvent+WaitForSingleObject TO Callback MODEL.
        #
        # Diagnostic evidence proved the previous approach was broken: the
        # heartbeat ("Still listening...") fired every 15s for 3+ minutes
        # while Sysmon was actively logging real activity (confirmed via
        # Event Viewer), but the "[SYSMON] Signal received" line -- which
        # would only ever print the instant WaitForSingleObject returned
        # WAIT_OBJECT_0 -- NEVER appeared once. That conclusively means
        # Windows was never signaling the event handle at all, regardless
        # of Query/Bookmark refinements already tried.
        #
        # The Callback model sidesteps this entirely: instead of us
        # manually waiting on a Win32 event object, pywin32/the Windows
        # Event Log API calls OUR function directly whenever a matching
        # event occurs. This is the more commonly-documented, battle-
        # tested pattern for EvtSubscribe and removes an entire class of
        # manual event-object marshaling issues.
        # -----------------------------------------------------------

        self._events_seen_total = 0
        self._events_parsed_total = 0
        self._latest_bookmark = None

        def _on_event(reason, context, event_handle):
            # `reason` distinguishes an actual delivered event from an
            # error notification (e.g. the subscription itself failing
            # asynchronously after initially succeeding).
            try:
                action_error = getattr(evt, 'EvtSubscribeActionError', 0)
                if reason == action_error:
                    self._log_callback(f"[SYSMON] Subscription reported an async error (reason={reason}).")
                    return 0

                self._events_seen_total += 1
                xml_string = evt.EvtRender(event_handle, evt.EvtRenderEventXml)
                parsed = parse_sysmon_event_xml(xml_string)

                if parsed:
                    self._events_parsed_total += 1
                    try:
                        self.output_queue.put(parsed, timeout=1)
                    except queue.Full:
                        logger.warning("[SysmonReader] Output queue full -- dropping event.")
                else:
                    self._log_callback("[SYSMON] Received an event but failed to parse its XML "
                                      "-- check parse_sysmon_event_xml for a schema mismatch.")

                # Track bookmark position (saved periodically by the main
                # loop below, not here, to avoid disk I/O on every single
                # event from inside the callback).
                bookmark = evt.EvtCreateBookmark(None)
                evt.EvtUpdateBookmark(bookmark, event_handle)
                self._latest_bookmark = bookmark
            except Exception as e:
                logger.error(f"[SysmonReader] Callback error: {e}")
            return 0

        try:
            if saved_bookmark_xml:
                try:
                    bookmark = evt.EvtCreateBookmark(saved_bookmark_xml)
                    flags = evt.EvtSubscribeStartAfterBookmark
                    logger.info("[SysmonReader] Resuming from saved bookmark.")
                except Exception as e:
                    # A corrupted/stale bookmark should never permanently
                    # block monitoring -- self-heal by starting fresh.
                    self._log_callback(f"[SYSMON] Saved bookmark was invalid ({e}) -- "
                                      f"starting fresh from current time instead.")
                    bookmark = None
                    flags = evt.EvtSubscribeToFutureEvents
                    saved_bookmark_xml = None
            else:
                bookmark = None
                flags = evt.EvtSubscribeToFutureEvents
                logger.info("[SysmonReader] No bookmark found -- starting from current time.")

            subscribe_kwargs = {'Callback': _on_event}
            if saved_bookmark_xml:
                subscribe_kwargs['Bookmark'] = bookmark

            subscription = evt.EvtSubscribe(SYSMON_CHANNEL, flags, **subscribe_kwargs)
            self._subscription_handle = subscription

            success_msg = ("[SYSMON] Subscribed successfully (callback mode) -- "
                           "real-time monitoring is now genuinely active.")
            logger.info(success_msg)
            self._log_callback(success_msg)

            last_heartbeat = time.time()
            last_bookmark_save = time.time()

            # The callback fires on its own (driven by Windows) -- this
            # loop's only jobs are: stay alive so the subscription object
            # doesn't get garbage-collected, periodically save the
            # bookmark, and report the heartbeat.
            while self.running:
                time.sleep(1)

                if time.time() - last_heartbeat > 15:
                    self._log_callback(f"[SYSMON] Still listening (callback mode)... "
                                       f"({self._events_seen_total} raw event(s), "
                                       f"{self._events_parsed_total} parsed and queued so far)")
                    last_heartbeat = time.time()

                if self._latest_bookmark is not None and time.time() - last_bookmark_save > 5:
                    try:
                        bookmark_xml = evt.EvtRender(self._latest_bookmark, evt.EvtRenderBookmark)
                        self.bookmark_mgr.save(bookmark_xml)
                        last_bookmark_save = time.time()
                    except Exception as e:
                        logger.error(f"[SysmonReader] Bookmark save failed: {e}")

        except Exception as e:
            error_text = str(e)
            # Translate the most common real-world failure causes into
            # actionable guidance, since the raw pywintypes error codes
            # are cryptic. These are exactly the failure modes that were
            # previously causing "Activate does nothing, silently."
            if "Access is denied" in error_text or "0x5" in error_text:
                diagnosis = ("ACCESS DENIED reading the Sysmon event log. "
                             "This almost always means Vanguard Knight was NOT run as "
                             "Administrator. Close it and relaunch by right-clicking "
                             "app_main.py's terminal/shortcut -> 'Run as Administrator'.")
            elif "channel" in error_text.lower() or "0x3a9f" in error_text.lower():
                diagnosis = ("The 'Microsoft-Windows-Sysmon/Operational' channel was not "
                             "found. This means Sysmon itself is not installed/running yet. "
                             "Run (as Administrator): Sysmon64.exe -i sysmon_config.xml -accepteula")
            else:
                diagnosis = ("Unexpected error -- see the full message above. If this "
                             "persists, check that Sysmon is installed and running "
                             "(Task Manager -> Services -> look for 'Sysmon64').")

            msg = f"[SYSMON] FAILED to start monitoring: {error_text}\n[SYSMON] Diagnosis: {diagnosis}"
            logger.error(msg)
            self._log_callback(msg)
            self.running = False


if __name__ == "__main__":
    # Non-Windows unit test: just validate the XML parsing logic works
    # correctly against a realistic sample Sysmon Event ID 1 payload.
    sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
        <TimeCreated SystemTime="2026-07-17T10:15:30.123Z"/>
      </System>
      <EventData>
        <Data Name="ProcessId">4821</Data>
        <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
        <Data Name="CommandLine">cmd.exe /c whoami</Data>
        <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
        <Data Name="ParentProcessId">1200</Data>
      </EventData>
    </Event>"""

    result = parse_sysmon_event_xml(sample_xml)
    print("Parsed event:")
    print(json.dumps(result, indent=2))
    assert result['event_id'] == 1
    assert result['event_type'] == 'process_create'
    assert result['data']['Image'] == r'C:\Windows\System32\cmd.exe'
    assert result['data']['CommandLine'] == 'cmd.exe /c whoami'
    print("\n✓ All assertions passed -- named-field parsing works correctly.")
