# Splunk ships Python 3.9 linked against OpenSSL 1.0.2 which cannot negotiate
# modern TLS cipher suites. Re-exec once with LD_LIBRARY_PATH pointing to the
# system OpenSSL 1.1.1+ so the ssl module can handle TLS 1.2+.
# Also set REQUESTS_CA_BUNDLE so requests finds the system CA certificates.
import os  # noqa: E402
import sys  # noqa: E402

_SYSTEM_SSL_DIR = "/usr/lib64"
_SYSTEM_CA_BUNDLE = "/etc/pki/tls/certs/ca-bundle.crt"

if os.environ.get("_DARKSTRATA_SSL_BOOTSTRAPPED") != "1" and os.path.exists(
    os.path.join(_SYSTEM_SSL_DIR, "libssl.so.1.1")
):
    os.environ["_DARKSTRATA_SSL_BOOTSTRAPPED"] = "1"
    os.environ["LD_LIBRARY_PATH"] = _SYSTEM_SSL_DIR + ":" + os.environ.get("LD_LIBRARY_PATH", "")
    if os.path.exists(_SYSTEM_CA_BUNDLE):
        os.environ["REQUESTS_CA_BUNDLE"] = _SYSTEM_CA_BUNDLE
    os.execv(sys.executable, [sys.executable] + sys.argv)

import import_declare_test  # noqa: F401

import json
import logging
import sys
from datetime import datetime, timezone

from solnlib import conf_manager
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi

from darkstrata_inputs import (
    GHOST_CURSOR_RE,
    GHOST_SEVERITIES,
    DarkStrataAPIClient,
    SOURCETYPE_GHOST_EVENT,
)

APP_NAME = "TA-darkstrata"


class DarkStrataGhostEvents(smi.Script):
    def get_scheme(self):
        scheme = smi.Scheme("darkstrata_ghost_events")
        scheme.description = "DarkStrata Ghost Events"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(smi.Argument("name", title="Name", required_on_create=True))
        scheme.add_argument(smi.Argument("account", required_on_create=True))
        scheme.add_argument(smi.Argument("include_test", required_on_create=False))
        scheme.add_argument(smi.Argument("min_severity", required_on_create=False))
        return scheme

    def validate_input(self, definition):
        return

    def stream_events(self, inputs, ew):
        logger = logging.getLogger("ta_darkstrata_ghost_events")
        logger.setLevel(logging.INFO)

        for input_name, input_item in inputs.inputs.items():
            session_key = inputs.metadata.get("session_key", "")
            account_name = input_item.get("account")
            include_test = input_item.get("include_test", "0") in ("1", "true", True)
            min_severity = (input_item.get("min_severity") or "").upper() or None
            index = input_item.get("index", "default")

            if min_severity and min_severity not in GHOST_SEVERITIES:
                logger.error("Ignoring invalid min_severity %r for input %s", min_severity, input_name)
                min_severity = None

            logger.info("Starting ghost events collection for account: %s", account_name)

            # Get account credentials
            try:
                cfm = conf_manager.ConfManager(
                    session_key,
                    APP_NAME,
                    realm=f"__REST_CREDENTIAL__#{APP_NAME}#configs/conf-ta_darkstrata_account",
                )
                account_config = cfm.get_conf("ta_darkstrata_account").get(account_name, {})
            except Exception as e:
                logger.error("Failed to get account config: %s", e)
                continue

            api_base_url = account_config.get("api_base_url")
            api_key = account_config.get("api_key")

            if not api_base_url or not api_key:
                logger.error("Missing API configuration for account: %s", account_name)
                continue

            # Get proxy settings
            proxy_settings = None
            try:
                settings_cfm = conf_manager.ConfManager(session_key, APP_NAME)
                proxy_settings = settings_cfm.get_conf("ta_darkstrata_settings").get("proxy", {})
            except Exception:
                pass

            # Initialise API client
            client = DarkStrataAPIClient(
                api_base_url=api_base_url,
                api_key=api_key,
                proxy_settings=proxy_settings,
                logger=logger,
            )

            # The checkpoint holds the seq of the last event written; the feed
            # resumes strictly after it, so each event is ingested once.
            checkpoint_key = f"darkstrata_ghost_events_{input_name}"
            cursor = None
            ckpt = None
            try:
                ckpt = checkpointer.KVStoreCheckpointer(
                    collection_name="ta_darkstrata_checkpoints",
                    session_key=session_key,
                    app=APP_NAME,
                )
                checkpoint = ckpt.get(checkpoint_key)
                if checkpoint and GHOST_CURSOR_RE.match(str(checkpoint.get("cursor", ""))):
                    cursor = str(checkpoint["cursor"])
            except Exception as e:
                logger.error("Failed to read checkpoint: %s", e)

            logger.info("Starting ghost events sync from cursor: %s", cursor)

            event_count = 0
            try:
                for ghost_event in client.fetch_ghost_events(
                    cursor=cursor,
                    include_test=include_test,
                    min_severity=min_severity,
                ):
                    event = smi.Event(
                        data=json.dumps(ghost_event),
                        time=_parse_timestamp(ghost_event.get("received_at") or ghost_event.get("observed_at")),
                        index=index,
                        sourcetype=SOURCETYPE_GHOST_EVENT,
                    )
                    ew.write_event(event)
                    event_count += 1

                    # ponytail: one KV Store write per event keeps the replay window
                    # to a single event on a crash; batch per page if volumes grow.
                    seq = str(ghost_event.get("seq", ""))
                    if ckpt is not None and GHOST_CURSOR_RE.match(seq):
                        try:
                            ckpt.update(
                                checkpoint_key,
                                {
                                    "cursor": seq,
                                    "last_run": datetime.now(timezone.utc).isoformat(),
                                    "event_count": event_count,
                                },
                            )
                        except Exception as e:
                            logger.error("Failed to save checkpoint: %s", e)

            except Exception as e:
                logger.error("Error collecting ghost events: %s", e)
                raise

            logger.info("Collected %d ghost events", event_count)


def _parse_timestamp(timestamp_str):
    if not timestamp_str:
        return None
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except ValueError:
        return None


if __name__ == "__main__":
    sys.exit(DarkStrataGhostEvents().run(sys.argv))
